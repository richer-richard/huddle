pub mod events;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use libp2p::PeerId;
use tokio::sync::{broadcast, Mutex as TokioMutex};
use tracing::{error, info, warn};

use crate::config;
use crate::error::Result;
use crate::identity::Identity;
use crate::network::events::NetworkEvent;
use crate::network::{self, NetworkHandle};
use crate::session::SessionManager;
use crate::storage::repo;
use crate::storage::{self, Db};

use self::events::AppEvent;

pub struct AppHandle {
    identity: Arc<Identity>,
    network: NetworkHandle,
    session_mgr: Arc<TokioMutex<SessionManager>>,
    db: Db,
    app_event_tx: broadcast::Sender<AppEvent>,
}

impl AppHandle {
    pub async fn start() -> Result<Self> {
        config::ensure_data_dir()?;
        let db = storage::open_db(&config::db_path())?;
        Self::start_with_db(db).await
    }

    pub async fn start_with_db(db: Db) -> Result<Self> {
        let identity = Self::load_or_create_identity(&db)?;
        let identity = Arc::new(identity);
        info!(fingerprint = %identity.fingerprint(), peer_id = %identity.peer_id(), "identity loaded");

        let account = Self::load_or_create_account(&db, &identity)?;
        let session_mgr = SessionManager::new(account, db.clone(), identity.secret_bytes());
        let session_mgr = Arc::new(TokioMutex::new(session_mgr));

        let (net_event_tx, mut net_event_rx) = tokio::sync::mpsc::channel::<NetworkEvent>(256);
        let (app_event_tx, _) = broadcast::channel::<AppEvent>(256);

        let network = network::start_network(&identity, net_event_tx)?;

        let handle = Self {
            identity,
            network,
            session_mgr,
            db,
            app_event_tx,
        };

        let app_tx = handle.app_event_tx.clone();
        let net_handle = handle.network.clone();
        let sess_mgr = handle.session_mgr.clone();
        let db = handle.db.clone();
        let our_fingerprint = handle.identity.fingerprint().to_string();

        tokio::spawn(async move {
            loop {
                match net_event_rx.recv().await {
                    Some(net_event) => {
                        Self::process_network_event(
                            net_event,
                            &app_tx,
                            &net_handle,
                            &sess_mgr,
                            &db,
                            &our_fingerprint,
                        )
                        .await;
                    }
                    None => {
                        info!("network event channel closed");
                        break;
                    }
                }
            }
        });

        Ok(handle)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<AppEvent> {
        self.app_event_tx.subscribe()
    }

    pub fn fingerprint(&self) -> &str {
        self.identity.fingerprint()
    }

    pub fn peer_id(&self) -> PeerId {
        self.identity.peer_id()
    }

    pub async fn initiate_session(&self, peer_id: PeerId) -> Result<()> {
        let mut mgr = self.session_mgr.lock().await;
        let bundle = mgr.our_prekey_bundle()?;
        let fp = self.identity.fingerprint().to_string();
        drop(mgr);
        self.network.send_handshake(peer_id, fp, bundle).await;
        Ok(())
    }

    pub async fn send_message(&self, peer_id: PeerId, body: &str) -> Result<()> {
        let mut mgr = self.session_mgr.lock().await;
        let peer_id_str = peer_id.to_string();
        let (ciphertext, msg_type) = mgr.encrypt(&peer_id_str, body.as_bytes())?;
        drop(mgr);

        let now = now_unix();
        let msg_id = repo::insert_message(&self.db, &peer_id_str, "out", body, now)?;
        self.network
            .send_encrypted_message(peer_id, ciphertext, msg_type)
            .await;
        let _ = self.app_event_tx.send(AppEvent::MessageSent {
            peer_id,
            body: body.to_string(),
            message_id: msg_id,
        });
        Ok(())
    }

    pub fn get_messages(&self, peer_id: &PeerId, limit: i64) -> Result<Vec<repo::StoredMessage>> {
        repo::get_messages(&self.db, &peer_id.to_string(), limit)
    }

    pub fn list_peers(&self) -> Result<Vec<repo::StoredPeer>> {
        repo::list_peers(&self.db)
    }

    pub async fn shutdown(&self) {
        self.network.shutdown().await;
    }

    fn load_or_create_identity(db: &Db) -> Result<Identity> {
        if let Some(stored) = repo::load_identity(db)? {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&stored.ed25519_secret);
            Identity::from_secret_bytes(bytes)
        } else {
            Identity::generate()
        }
    }

    fn load_or_create_account(db: &Db, identity: &Identity) -> Result<vodozemac::olm::Account> {
        use crate::session::store;
        match store::load_account(db)? {
            Some(account) => Ok(account),
            None => store::create_and_persist_account(db, &identity.secret_bytes()),
        }
    }

    async fn process_network_event(
        event: NetworkEvent,
        app_tx: &broadcast::Sender<AppEvent>,
        network: &NetworkHandle,
        session_mgr: &Arc<TokioMutex<SessionManager>>,
        db: &Db,
        our_fingerprint: &str,
    ) {
        match event {
            NetworkEvent::PeerDiscovered { peer_id } => {
                let _ = app_tx.send(AppEvent::PeerDiscovered {
                    peer_id,
                    fingerprint: None,
                });
            }
            NetworkEvent::PeerExpired { peer_id } => {
                let _ = app_tx.send(AppEvent::PeerExpired { peer_id });
            }
            NetworkEvent::HandshakeReceived {
                peer_id,
                sender_fingerprint,
                prekey_bundle,
                channel,
            } => {
                info!(%peer_id, %sender_fingerprint, "handshake received");
                let peer_id_str = peer_id.to_string();
                repo::upsert_peer(
                    db,
                    &repo::StoredPeer {
                        peer_id: peer_id_str,
                        fingerprint: sender_fingerprint.clone(),
                        display_name: None,
                        olm_session_data: None,
                        last_seen: Some(now_unix()),
                    },
                )
                .ok();

                let mut mgr = session_mgr.lock().await;
                match mgr.our_prekey_bundle() {
                    Ok(our_bundle) => {
                        network
                            .respond_handshake(channel, our_fingerprint.to_string(), our_bundle)
                            .await;
                    }
                    Err(e) => {
                        error!(%e, "failed to generate prekey bundle for response");
                    }
                }
                drop(mgr);

                let _ = app_tx.send(AppEvent::PeerDiscovered {
                    peer_id,
                    fingerprint: Some(sender_fingerprint),
                });
            }
            NetworkEvent::HandshakeCompleted {
                peer_id,
                sender_fingerprint,
                prekey_bundle,
            } => {
                info!(%peer_id, %sender_fingerprint, "handshake completed");
                let peer_id_str = peer_id.to_string();
                repo::upsert_peer(
                    db,
                    &repo::StoredPeer {
                        peer_id: peer_id_str.clone(),
                        fingerprint: sender_fingerprint.clone(),
                        display_name: None,
                        olm_session_data: None,
                        last_seen: Some(now_unix()),
                    },
                )
                .ok();

                let mut mgr = session_mgr.lock().await;
                match mgr.create_outbound_session(&peer_id_str, &prekey_bundle) {
                    Ok(()) => {
                        info!(%peer_id, "outbound Olm session created");
                        let _ = app_tx.send(AppEvent::SessionEstablished {
                            peer_id,
                            fingerprint: sender_fingerprint,
                        });
                    }
                    Err(e) => {
                        error!(%e, "failed to create outbound session");
                        let _ = app_tx.send(AppEvent::Error {
                            description: format!("session creation failed: {e}"),
                        });
                    }
                }
            }
            NetworkEvent::EncryptedMessageReceived {
                peer_id,
                ciphertext,
                msg_type,
                channel,
            } => {
                let peer_id_str = peer_id.to_string();
                let mut mgr = session_mgr.lock().await;

                let plaintext = if msg_type == 0 && !mgr.has_session(&peer_id_str) {
                    match vodozemac::olm::PreKeyMessage::from_bytes(&ciphertext) {
                        Ok(pkm) => {
                            let their_ik = pkm.identity_key().to_base64();
                            match mgr.create_inbound_session(
                                &peer_id_str,
                                &their_ik,
                                &ciphertext,
                            ) {
                                Ok(pt) => {
                                    let _ = app_tx.send(AppEvent::SessionEstablished {
                                        peer_id,
                                        fingerprint: peer_id_str.clone(),
                                    });
                                    Some(pt)
                                }
                                Err(e) => {
                                    error!(%e, "inbound session creation failed");
                                    None
                                }
                            }
                        }
                        Err(e) => {
                            error!(%e, "failed to parse pre-key message");
                            None
                        }
                    }
                } else {
                    match mgr.decrypt(&peer_id_str, &ciphertext, msg_type) {
                        Ok(pt) => Some(pt),
                        Err(e) => {
                            error!(%e, "decryption failed");
                            None
                        }
                    }
                };
                drop(mgr);

                if let Some(pt) = plaintext {
                    let body = String::from_utf8_lossy(&pt).to_string();
                    let now = now_unix();
                    let msg_id = repo::insert_message(db, &peer_id_str, "in", &body, now).ok();
                    network.respond_ack(channel, msg_id).await;
                    let _ = app_tx.send(AppEvent::MessageReceived {
                        peer_id,
                        body,
                        sent_at: now,
                    });
                } else {
                    network.respond_ack(channel, None).await;
                }
            }
            NetworkEvent::AckReceived {
                peer_id,
                message_id,
            } => {
                if let Some(id) = message_id {
                    repo::mark_delivered(db, id, now_unix()).ok();
                    let _ = app_tx.send(AppEvent::MessageAcked {
                        peer_id,
                        message_id: id,
                    });
                }
            }
            NetworkEvent::ConnectionEstablished { peer_id } => {
                let _ = app_tx.send(AppEvent::ConnectionEstablished { peer_id });
            }
            NetworkEvent::ConnectionClosed { peer_id } => {
                let _ = app_tx.send(AppEvent::ConnectionClosed { peer_id });
            }
            NetworkEvent::ListeningOn { address } => {
                let _ = app_tx.send(AppEvent::ListeningOn {
                    address: address.to_string(),
                });
            }
        }
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
