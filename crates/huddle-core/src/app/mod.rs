pub mod events;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::PeerId;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use crate::config;
use crate::crypto::passphrase::{self, KEY_LEN, SALT_LEN};
use crate::crypto::RoomCrypto;
use crate::error::{HuddleError, Result};
use crate::identity::Identity;
use crate::network::events::NetworkEvent;
use crate::network::protocol::{RoomAnnouncement, RoomMessage};
use crate::network::{self, NetworkHandle};
use crate::storage::repo::{self, derive_room_id, StoredRoom, StoredRoomMember};
use crate::storage::{self, Db};

pub use self::events::{AppEvent, DiscoveredRoom};

/// State for a room we've created or joined this session.
struct ActiveRoom {
    info: StoredRoom,
    crypto: Option<RoomCrypto>,
    /// Argon2id-derived 32-byte key for unwrapping incoming session keys.
    /// None for unencrypted rooms.
    passphrase_key: Option<[u8; KEY_LEN]>,
    /// Fingerprints of members currently known to be in the room.
    members: HashSet<String>,
}

/// TTL for a discovered room before it's considered stale (re-announcements
/// happen every 15 seconds; after 45s of silence we drop it).
const DISCOVERED_TTL_SECS: i64 = 45;
const ANNOUNCE_INTERVAL_SECS: u64 = 15;

#[derive(Clone)]
pub struct AppHandle {
    identity: Arc<Identity>,
    network: NetworkHandle,
    active_rooms: Arc<Mutex<HashMap<String, ActiveRoom>>>,
    discovered_rooms: Arc<Mutex<HashMap<String, DiscoveredRoom>>>,
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

        let (net_event_tx, net_event_rx) = tokio::sync::mpsc::channel::<NetworkEvent>(256);
        let (app_event_tx, _) = broadcast::channel::<AppEvent>(256);
        let network = network::start_network(&identity, net_event_tx)?;

        let active_rooms = Arc::new(Mutex::new(HashMap::new()));
        let discovered_rooms = Arc::new(Mutex::new(HashMap::new()));

        let handle = Self {
            identity,
            network,
            active_rooms,
            discovered_rooms,
            db,
            app_event_tx,
        };

        handle.spawn_event_processor(net_event_rx);
        handle.spawn_announcement_ticker();
        handle.spawn_discovered_room_pruner();

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

    pub fn discovered_rooms(&self) -> Vec<DiscoveredRoom> {
        let map = self.discovered_rooms.lock().unwrap();
        let mut v: Vec<DiscoveredRoom> = map.values().cloned().collect();
        v.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        v
    }

    pub fn active_room_ids(&self) -> Vec<String> {
        self.active_rooms.lock().unwrap().keys().cloned().collect()
    }

    pub fn active_room_info(&self, room_id: &str) -> Option<StoredRoom> {
        self.active_rooms
            .lock()
            .unwrap()
            .get(room_id)
            .map(|r| r.info.clone())
    }

    pub fn room_members(&self, room_id: &str) -> Vec<String> {
        self.active_rooms
            .lock()
            .unwrap()
            .get(room_id)
            .map(|r| {
                let mut m: Vec<String> = r.members.iter().cloned().collect();
                m.sort();
                m
            })
            .unwrap_or_default()
    }

    pub fn room_messages(&self, room_id: &str, limit: i64) -> Result<Vec<repo::StoredRoomMessage>> {
        repo::get_room_messages(&self.db, room_id, limit)
    }

    /// Create a new room. Returns its room_id.
    pub async fn start_room(
        &self,
        name: &str,
        encrypted: bool,
        passphrase: Option<&str>,
    ) -> Result<String> {
        if encrypted && passphrase.is_none() {
            return Err(HuddleError::Other(
                "encrypted room requires a passphrase".into(),
            ));
        }

        let created_at = now_unix();
        let creator_fp = self.identity.fingerprint().to_string();
        let room_id = derive_room_id(&creator_fp, name, created_at);

        let (passphrase_salt, passphrase_key) = if encrypted {
            let salt = passphrase::random_salt();
            let key = passphrase::derive_key(passphrase.unwrap(), &salt)?;
            (Some(salt.to_vec()), Some(key))
        } else {
            (None, None)
        };

        let info = StoredRoom {
            id: room_id.clone(),
            name: name.to_string(),
            creator_fingerprint: creator_fp.clone(),
            encrypted,
            passphrase_salt: passphrase_salt.clone(),
            created_at,
            last_active: Some(created_at),
        };
        repo::insert_room(&self.db, &info)?;

        let crypto = if encrypted {
            Some(RoomCrypto::new_for_room(
                self.db.clone(),
                room_id.clone(),
                creator_fp.clone(),
            )?)
        } else {
            None
        };

        let mut members = HashSet::new();
        members.insert(creator_fp.clone());

        self.active_rooms.lock().unwrap().insert(
            room_id.clone(),
            ActiveRoom {
                info: info.clone(),
                crypto,
                passphrase_key,
                members,
            },
        );

        self.network.subscribe_room(room_id.clone()).await;
        self.announce_room_now(&info, 1).await;

        // Broadcast our presence in the room (with our wrapped session key
        // if encrypted). Use a small delay so the subscription propagates.
        let app = self.clone();
        let rid = room_id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if let Err(e) = app.broadcast_member_announce(&rid).await {
                warn!(%e, "broadcast member announce");
            }
        });

        let _ = self.app_event_tx.send(AppEvent::RoomJoined {
            room_id: room_id.clone(),
        });

        Ok(room_id)
    }

    /// Join an existing discovered room.
    pub async fn join_room(&self, room_id: &str, passphrase: Option<&str>) -> Result<()> {
        let discovered = self
            .discovered_rooms
            .lock()
            .unwrap()
            .get(room_id)
            .cloned()
            .ok_or_else(|| HuddleError::Other(format!("room {room_id} not discovered")))?;

        if discovered.encrypted && passphrase.is_none() {
            return Err(HuddleError::Other(
                "encrypted room requires a passphrase".into(),
            ));
        }

        // Re-fetch the announcement so we get the salt.
        // (discovered_rooms stores the DiscoveredRoom struct which doesn't carry salt;
        // we cache the salt separately in announcement_salts.)
        let salt_opt = self.get_room_salt(room_id);

        let passphrase_key = if discovered.encrypted {
            let salt = salt_opt
                .clone()
                .ok_or_else(|| HuddleError::Other("missing salt for encrypted room".into()))?;
            Some(passphrase::derive_key(passphrase.unwrap(), &salt)?)
        } else {
            None
        };

        let info = StoredRoom {
            id: room_id.to_string(),
            name: discovered.name.clone(),
            creator_fingerprint: discovered.creator_fingerprint.clone(),
            encrypted: discovered.encrypted,
            passphrase_salt: salt_opt.clone(),
            created_at: now_unix(),
            last_active: Some(now_unix()),
        };
        repo::insert_room(&self.db, &info)?;

        let crypto = if discovered.encrypted {
            Some(RoomCrypto::new_for_room(
                self.db.clone(),
                room_id.to_string(),
                self.identity.fingerprint().to_string(),
            )?)
        } else {
            None
        };

        let mut members = HashSet::new();
        members.insert(self.identity.fingerprint().to_string());

        self.active_rooms.lock().unwrap().insert(
            room_id.to_string(),
            ActiveRoom {
                info: info.clone(),
                crypto,
                passphrase_key,
                members,
            },
        );

        self.network.subscribe_room(room_id.to_string()).await;

        let app = self.clone();
        let rid = room_id.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if let Err(e) = app.broadcast_member_announce(&rid).await {
                warn!(%e, "broadcast member announce");
            }
            // Ask existing members for their session keys.
            let req = RoomMessage::SessionKeyRequest {
                requester_fingerprint: app.identity.fingerprint().to_string(),
            };
            if let Ok(bytes) = serde_json::to_vec(&req) {
                app.network.publish_room_message(rid.clone(), bytes).await;
            }
        });

        let _ = self.app_event_tx.send(AppEvent::RoomJoined {
            room_id: room_id.to_string(),
        });

        Ok(())
    }

    pub async fn leave_room(&self, room_id: &str) -> Result<()> {
        // Broadcast a leave message before unsubscribing.
        let leave_msg = RoomMessage::MemberLeave {
            sender_fingerprint: self.identity.fingerprint().to_string(),
        };
        if let Ok(bytes) = serde_json::to_vec(&leave_msg) {
            self.network
                .publish_room_message(room_id.to_string(), bytes)
                .await;
        }

        self.active_rooms.lock().unwrap().remove(room_id);
        self.network.unsubscribe_room(room_id.to_string()).await;

        let _ = self.app_event_tx.send(AppEvent::RoomLeft {
            room_id: room_id.to_string(),
        });
        Ok(())
    }

    pub async fn send_room_message(&self, room_id: &str, body: &str) -> Result<()> {
        let our_fp = self.identity.fingerprint().to_string();
        let msg = {
            let mut rooms = self.active_rooms.lock().unwrap();
            let room = rooms
                .get_mut(room_id)
                .ok_or_else(|| HuddleError::Other(format!("not in room {room_id}")))?;

            if room.info.encrypted {
                let crypto = room
                    .crypto
                    .as_mut()
                    .ok_or_else(|| HuddleError::Session("encrypted room missing crypto".into()))?;
                let (session_id, ct_bytes) = crypto.encrypt(body.as_bytes())?;
                RoomMessage::Encrypted {
                    sender_fingerprint: our_fp.clone(),
                    session_id,
                    ciphertext_b64: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &ct_bytes,
                    ),
                }
            } else {
                RoomMessage::Plain {
                    sender_fingerprint: our_fp.clone(),
                    body: body.to_string(),
                }
            }
        };

        let bytes = serde_json::to_vec(&msg)?;
        self.network
            .publish_room_message(room_id.to_string(), bytes)
            .await;

        let now = now_unix();
        let msg_id =
            repo::insert_room_message(&self.db, room_id, &our_fp, "out", body, now)?;
        repo::update_room_last_active(&self.db, room_id, now)?;

        let _ = self.app_event_tx.send(AppEvent::MessageSent {
            room_id: room_id.to_string(),
            body: body.to_string(),
            message_id: msg_id,
        });

        Ok(())
    }

    pub async fn shutdown(&self) {
        self.network.shutdown().await;
    }

    // -------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------

    fn load_or_create_identity(db: &Db) -> Result<Identity> {
        if let Some(stored) = repo::load_identity(db)? {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&stored.ed25519_secret);
            Identity::from_secret_bytes(bytes)
        } else {
            let id = Identity::generate()?;
            repo::save_identity(db, &id.secret_bytes(), now_unix())?;
            Ok(id)
        }
    }

    fn get_room_salt(&self, room_id: &str) -> Option<Vec<u8>> {
        self.active_rooms
            .lock()
            .unwrap()
            .get(room_id)
            .and_then(|r| r.info.passphrase_salt.clone())
            .or_else(|| {
                // Try the cached announcement salt
                ROOM_SALT_CACHE
                    .lock()
                    .unwrap()
                    .get(room_id)
                    .cloned()
            })
    }

    async fn announce_room_now(&self, info: &StoredRoom, member_count: u32) {
        let ann = RoomAnnouncement {
            room_id: info.id.clone(),
            name: info.name.clone(),
            encrypted: info.encrypted,
            passphrase_salt: info.passphrase_salt.clone(),
            member_count,
            creator_fingerprint: info.creator_fingerprint.clone(),
            announced_at: now_unix(),
        };
        self.network.announce_room(ann).await;
    }

    async fn broadcast_member_announce(&self, room_id: &str) -> Result<()> {
        let our_fp = self.identity.fingerprint().to_string();
        let wrapped = {
            let mut rooms = self.active_rooms.lock().unwrap();
            let room = rooms
                .get_mut(room_id)
                .ok_or_else(|| HuddleError::Other("not in room".into()))?;
            if room.info.encrypted {
                let crypto = room.crypto.as_mut().unwrap();
                let session_key = crypto.our_session_key_b64();
                let passphrase_key = room
                    .passphrase_key
                    .as_ref()
                    .ok_or_else(|| HuddleError::Session("missing passphrase key".into()))?;
                Some(passphrase::wrap(session_key.as_bytes(), passphrase_key)?)
            } else {
                None
            }
        };
        let msg = RoomMessage::MemberAnnounce {
            sender_fingerprint: our_fp,
            wrapped_session_key: wrapped,
        };
        let bytes = serde_json::to_vec(&msg)?;
        self.network
            .publish_room_message(room_id.to_string(), bytes)
            .await;
        Ok(())
    }

    fn spawn_event_processor(&self, mut net_rx: tokio::sync::mpsc::Receiver<NetworkEvent>) {
        let handle = self.clone();
        tokio::spawn(async move {
            while let Some(event) = net_rx.recv().await {
                handle.process_network_event(event).await;
            }
            info!("event processor stopped");
        });
    }

    fn spawn_announcement_ticker(&self) {
        let handle = self.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(ANNOUNCE_INTERVAL_SECS));
            interval.tick().await; // skip the immediate tick
            loop {
                interval.tick().await;
                let snapshot: Vec<(StoredRoom, u32)> = {
                    let active = handle.active_rooms.lock().unwrap();
                    active
                        .values()
                        .map(|r| (r.info.clone(), r.members.len() as u32))
                        .collect()
                };
                for (info, member_count) in snapshot {
                    handle.announce_room_now(&info, member_count).await;
                }
            }
        });
    }

    fn spawn_discovered_room_pruner(&self) {
        let handle = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            interval.tick().await;
            loop {
                interval.tick().await;
                let now = now_unix();
                let mut to_drop = Vec::new();
                {
                    let mut map = handle.discovered_rooms.lock().unwrap();
                    map.retain(|id, r| {
                        if now - r.last_seen > DISCOVERED_TTL_SECS {
                            to_drop.push(id.clone());
                            false
                        } else {
                            true
                        }
                    });
                }
                for id in to_drop {
                    let _ = handle.app_event_tx.send(AppEvent::RoomLost { room_id: id });
                }
            }
        });
    }

    async fn process_network_event(&self, event: NetworkEvent) {
        match event {
            NetworkEvent::PeerDiscovered { peer_id } => {
                let _ = self.app_event_tx.send(AppEvent::PeerDiscovered { peer_id });
            }
            NetworkEvent::PeerExpired { .. } => {}
            NetworkEvent::ListeningOn { address } => {
                let _ = self.app_event_tx.send(AppEvent::ListeningOn {
                    address: address.to_string(),
                });
            }
            NetworkEvent::RoomAnnouncementReceived(ann) => {
                let our_fp = self.identity.fingerprint();
                // Cache the salt for join_room
                if let Some(salt) = &ann.passphrase_salt {
                    ROOM_SALT_CACHE
                        .lock()
                        .unwrap()
                        .insert(ann.room_id.clone(), salt.clone());
                }
                let discovered = DiscoveredRoom {
                    room_id: ann.room_id.clone(),
                    name: ann.name.clone(),
                    encrypted: ann.encrypted,
                    member_count: ann.member_count,
                    creator_fingerprint: ann.creator_fingerprint.clone(),
                    last_seen: now_unix(),
                };
                // Skip our own announcements
                if ann.creator_fingerprint == our_fp
                    && self.active_rooms.lock().unwrap().contains_key(&ann.room_id)
                {
                    // It's our room — still cache it so others can join, but don't emit.
                    self.discovered_rooms
                        .lock()
                        .unwrap()
                        .insert(ann.room_id.clone(), discovered);
                    return;
                }
                self.discovered_rooms
                    .lock()
                    .unwrap()
                    .insert(ann.room_id.clone(), discovered.clone());
                let _ = self.app_event_tx.send(AppEvent::RoomDiscovered(discovered));
            }
            NetworkEvent::RoomMessageReceived {
                room_id,
                payload,
                from_peer: _,
            } => {
                let msg: RoomMessage = match serde_json::from_slice(&payload) {
                    Ok(m) => m,
                    Err(e) => {
                        warn!(%e, "bad room message");
                        return;
                    }
                };
                self.handle_room_message(&room_id, msg).await;
            }
        }
    }

    async fn handle_room_message(&self, room_id: &str, msg: RoomMessage) {
        let our_fp = self.identity.fingerprint().to_string();
        match msg {
            RoomMessage::MemberAnnounce {
                sender_fingerprint,
                wrapped_session_key,
            } => {
                if sender_fingerprint == our_fp {
                    return;
                }
                let need_inbound = {
                    let mut rooms = self.active_rooms.lock().unwrap();
                    let room = match rooms.get_mut(room_id) {
                        Some(r) => r,
                        None => return,
                    };
                    let newly_added = room.members.insert(sender_fingerprint.clone());
                    if newly_added {
                        let _ = self.app_event_tx.send(AppEvent::MemberJoined {
                            room_id: room_id.to_string(),
                            fingerprint: sender_fingerprint.clone(),
                        });
                    }
                    // Persist member
                    let _ = repo::upsert_room_member(
                        &self.db,
                        &StoredRoomMember {
                            room_id: room_id.to_string(),
                            peer_id: String::new(), // unknown at this layer
                            fingerprint: sender_fingerprint.clone(),
                            last_seen: Some(now_unix()),
                        },
                    );
                    room.info.encrypted && wrapped_session_key.is_some()
                };

                if need_inbound {
                    let wrapped = wrapped_session_key.unwrap();
                    let result = {
                        let mut rooms = self.active_rooms.lock().unwrap();
                        let room = rooms.get_mut(room_id).unwrap();
                        let passphrase_key = match &room.passphrase_key {
                            Some(k) => k,
                            None => {
                                warn!("no passphrase key when receiving session key");
                                return;
                            }
                        };
                        match passphrase::unwrap(&wrapped, passphrase_key) {
                            Ok(plain) => match String::from_utf8(plain) {
                                Ok(key_b64) => {
                                    let crypto = room.crypto.as_mut().unwrap();
                                    crypto.add_inbound_session(&sender_fingerprint, &key_b64)
                                }
                                Err(e) => Err(HuddleError::Session(format!("utf8: {e}"))),
                            },
                            Err(e) => Err(e),
                        }
                    };
                    if let Err(e) = result {
                        error!(%e, "add inbound session failed");
                    }
                }
            }
            RoomMessage::SessionKeyRequest {
                requester_fingerprint,
            } => {
                if requester_fingerprint == our_fp {
                    return;
                }
                // Re-announce ourselves to share our session key with the new joiner.
                if let Err(e) = self.broadcast_member_announce(room_id).await {
                    warn!(%e, "broadcast member announce on request");
                }
            }
            RoomMessage::Encrypted {
                sender_fingerprint,
                session_id,
                ciphertext_b64,
            } => {
                if sender_fingerprint == our_fp {
                    return;
                }
                let ct_bytes = match base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &ciphertext_b64,
                ) {
                    Ok(b) => b,
                    Err(e) => {
                        warn!(%e, "bad base64 ciphertext");
                        return;
                    }
                };
                let plaintext = {
                    let mut rooms = self.active_rooms.lock().unwrap();
                    let room = match rooms.get_mut(room_id) {
                        Some(r) => r,
                        None => return,
                    };
                    let crypto = match room.crypto.as_mut() {
                        Some(c) => c,
                        None => return,
                    };
                    crypto.decrypt(&sender_fingerprint, &session_id, &ct_bytes)
                };
                match plaintext {
                    Ok(pt) => {
                        let body = String::from_utf8_lossy(&pt).to_string();
                        let sent_at = now_unix();
                        let _ = repo::insert_room_message(
                            &self.db,
                            room_id,
                            &sender_fingerprint,
                            "in",
                            &body,
                            sent_at,
                        );
                        let _ = repo::update_room_last_active(&self.db, room_id, sent_at);
                        let _ = self.app_event_tx.send(AppEvent::MessageReceived {
                            room_id: room_id.to_string(),
                            sender_fingerprint,
                            body,
                            sent_at,
                        });
                    }
                    Err(e) => {
                        debug!(%e, "decrypt failed (probably missing session key)");
                    }
                }
            }
            RoomMessage::Plain {
                sender_fingerprint,
                body,
            } => {
                if sender_fingerprint == our_fp {
                    return;
                }
                let sent_at = now_unix();
                let _ = repo::insert_room_message(
                    &self.db,
                    room_id,
                    &sender_fingerprint,
                    "in",
                    &body,
                    sent_at,
                );
                let _ = repo::update_room_last_active(&self.db, room_id, sent_at);
                let _ = self.app_event_tx.send(AppEvent::MessageReceived {
                    room_id: room_id.to_string(),
                    sender_fingerprint,
                    body,
                    sent_at,
                });
            }
            RoomMessage::MemberLeave { sender_fingerprint } => {
                if sender_fingerprint == our_fp {
                    return;
                }
                let removed = {
                    let mut rooms = self.active_rooms.lock().unwrap();
                    if let Some(room) = rooms.get_mut(room_id) {
                        room.members.remove(&sender_fingerprint)
                    } else {
                        false
                    }
                };
                if removed {
                    let _ = self.app_event_tx.send(AppEvent::MemberLeft {
                        room_id: room_id.to_string(),
                        fingerprint: sender_fingerprint,
                    });
                }
            }
        }
    }
}

// Module-level salt cache: room_id -> salt. Populated when we receive
// announcements; queried by join_room.
static ROOM_SALT_CACHE: std::sync::LazyLock<Mutex<HashMap<String, Vec<u8>>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

#[allow(dead_code)]
fn salt_len() -> usize {
    SALT_LEN
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
