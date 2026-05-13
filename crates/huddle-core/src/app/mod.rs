pub mod events;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use libp2p::{Multiaddr, PeerId};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use crate::config;
use crate::crypto::passphrase::{self, KEY_LEN, SALT_LEN};
use crate::crypto::RoomCrypto;
use crate::error::{HuddleError, Result};
use crate::files::encryption::{self as file_encryption, EncryptedFileMeta};
use crate::files::FileManager;
use crate::identity::Identity;
use crate::network::events::NetworkEvent;
use crate::network::protocol::{RoomAnnouncement, RoomMessage};
use crate::network::{self, NetworkHandle, NetworkMode};
use crate::storage::repo::{
    self, derive_room_id, AttachmentStatus, KnownPeer, StoredAttachment, StoredRoom,
    StoredRoomMember,
};
use crate::storage::{self, Db};

pub use self::events::{AppEvent, DiscoveredRoom};

/// Lobby-facing view of a known dial peer: persisted address plus
/// runtime "is the connection currently up?" status.
#[derive(Debug, Clone)]
pub struct KnownPeerStatus {
    pub address: String,
    pub label: Option<String>,
    pub last_connected_at: Option<i64>,
    pub connected_peer_id: Option<PeerId>,
}

/// Parse a user-entered dial address into a libp2p `Multiaddr`.
/// Accepts `ip:port`, `[ipv6]:port`, or a raw multiaddr starting with `/`.
pub fn parse_dial_address(input: &str) -> Result<Multiaddr> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(HuddleError::Other("address is empty".into()));
    }
    if trimmed.starts_with('/') {
        return trimmed
            .parse::<Multiaddr>()
            .map_err(|e| HuddleError::Other(format!("invalid multiaddr: {e}")));
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or_else(|| HuddleError::Other(format!("expected [ipv6]:port, got {trimmed}")))?;
        let port: u16 = port
            .parse()
            .map_err(|_| HuddleError::Other(format!("invalid port: {port}")))?;
        return format!("/ip6/{}/tcp/{}", host, port)
            .parse::<Multiaddr>()
            .map_err(|e| HuddleError::Other(format!("invalid ipv6 address: {e}")));
    }
    let (host, port) = trimmed
        .rsplit_once(':')
        .ok_or_else(|| HuddleError::Other(format!("expected ip:port, got {trimmed}")))?;
    if host.contains(':') {
        return Err(HuddleError::Other(format!(
            "ambiguous IPv6 address — wrap host in brackets: [{host}]:{port}"
        )));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| HuddleError::Other(format!("invalid port: {port}")))?;
    format!("/ip4/{}/tcp/{}", host, port)
        .parse::<Multiaddr>()
        .map_err(|e| HuddleError::Other(format!("invalid address: {e}")))
}

/// State for a room we've created or joined this session.
struct ActiveRoom {
    info: StoredRoom,
    crypto: Option<RoomCrypto>,
    /// Argon2id-derived 32-byte key for unwrapping incoming session keys.
    /// None for unencrypted rooms.
    passphrase_key: Option<[u8; KEY_LEN]>,
    /// Fingerprints of members currently known to be in the room.
    members: HashSet<String>,
    /// Ephemeral typing indicators: fingerprint → unix expiry. Pruned
    /// on read; never persisted.
    typers: HashMap<String, i64>,
}

const TYPING_TTL_SECS: i64 = 3;

/// TTL for a discovered room before it's considered stale (re-announcements
/// happen every 15 seconds; after 45s of silence we drop it).
const DISCOVERED_TTL_SECS: i64 = 45;
const ANNOUNCE_INTERVAL_SECS: u64 = 15;

#[derive(Clone)]
pub struct AppHandle {
    identity: Arc<Identity>,
    network: NetworkHandle,
    mode: NetworkMode,
    active_rooms: Arc<Mutex<HashMap<String, ActiveRoom>>>,
    discovered_rooms: Arc<Mutex<HashMap<String, DiscoveredRoom>>>,
    /// Encrypted rooms loaded from storage that we haven't rejoined yet
    /// in this session (their passphrase-derived key isn't in memory).
    /// Surfaced in the lobby so the user can re-enter with passphrase.
    restorable_rooms: Arc<Mutex<HashMap<String, StoredRoom>>>,
    /// Peer addresses we've dialed in this process; tracks "is the
    /// connection currently up" for known peers shown in the lobby.
    connected_dial_addrs: Arc<Mutex<HashMap<String, PeerId>>>,
    /// File chunking + cache + downloads.
    file_manager: Arc<FileManager>,
    db: Db,
    app_event_tx: broadcast::Sender<AppEvent>,
}

impl AppHandle {
    pub async fn start() -> Result<Self> {
        Self::start_with_options(NetworkMode::Mdns, 0).await
    }

    pub async fn start_with_options(mode: NetworkMode, port: u16) -> Result<Self> {
        config::ensure_data_dir()?;
        let db = storage::open_db(&config::db_path())?;
        Self::start_with_db_and_options(db, mode, port).await
    }

    pub async fn start_with_db(db: Db) -> Result<Self> {
        Self::start_with_db_and_options(db, NetworkMode::Mdns, 0).await
    }

    pub async fn start_with_db_and_options(
        db: Db,
        mode: NetworkMode,
        port: u16,
    ) -> Result<Self> {
        let identity = Self::load_or_create_identity(&db)?;
        let identity = Arc::new(identity);
        info!(fingerprint = %identity.fingerprint(), peer_id = %identity.peer_id(), mode = %mode.as_str(), port, "identity loaded");

        let (net_event_tx, net_event_rx) = tokio::sync::mpsc::channel::<NetworkEvent>(256);
        let (app_event_tx, _) = broadcast::channel::<AppEvent>(256);
        let network = network::start_network_with(&identity, net_event_tx, mode, port)?;

        let active_rooms = Arc::new(Mutex::new(HashMap::new()));
        let discovered_rooms = Arc::new(Mutex::new(HashMap::new()));
        let restorable_rooms = Arc::new(Mutex::new(HashMap::new()));
        let connected_dial_addrs = Arc::new(Mutex::new(HashMap::new()));
        let file_manager = Arc::new(FileManager::new(&config::data_dir())?);

        let handle = Self {
            identity,
            network,
            mode,
            active_rooms,
            discovered_rooms,
            restorable_rooms,
            connected_dial_addrs,
            file_manager,
            db,
            app_event_tx,
        };

        handle.spawn_event_processor(net_event_rx);
        handle.spawn_announcement_ticker();
        handle.spawn_discovered_room_pruner();
        handle.spawn_known_peer_reconnector();
        handle.restore_rooms_from_db().await;

        Ok(handle)
    }

    pub fn mode(&self) -> NetworkMode {
        self.mode
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
        let now = now_unix();
        let mut by_id: HashMap<String, DiscoveredRoom> = self
            .discovered_rooms
            .lock()
            .unwrap()
            .clone();

        // Merge in rooms we're currently in — gossipsub doesn't echo our
        // own announcements back to us, so without this our own hosted
        // rooms wouldn't appear in the lobby.
        for room in self.active_rooms.lock().unwrap().values() {
            let entry = DiscoveredRoom {
                room_id: room.info.id.clone(),
                name: room.info.name.clone(),
                encrypted: room.info.encrypted,
                member_count: room.members.len() as u32,
                creator_fingerprint: room.info.creator_fingerprint.clone(),
                last_seen: now,
                restorable: false,
            };
            by_id
                .entry(room.info.id.clone())
                .and_modify(|d| {
                    d.last_seen = now;
                    if entry.member_count > d.member_count {
                        d.member_count = entry.member_count;
                    }
                    d.restorable = false;
                })
                .or_insert(entry);
        }

        // Encrypted rooms we have on disk but haven't rejoined this
        // session. Only surface them when no fresh discovery / active
        // entry exists for the same room.
        for (id, stored) in self.restorable_rooms.lock().unwrap().iter() {
            if by_id.contains_key(id) {
                continue;
            }
            by_id.insert(
                id.clone(),
                DiscoveredRoom {
                    room_id: id.clone(),
                    name: stored.name.clone(),
                    encrypted: stored.encrypted,
                    member_count: 0,
                    creator_fingerprint: stored.creator_fingerprint.clone(),
                    last_seen: stored.last_active.unwrap_or(stored.created_at),
                    restorable: true,
                },
            );
        }

        let mut v: Vec<DiscoveredRoom> = by_id.into_values().collect();
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

    pub fn search_room_messages(
        &self,
        room_id: &str,
        query: &str,
        limit: i64,
    ) -> Result<Vec<repo::StoredRoomMessage>> {
        repo::search_room_messages(&self.db, room_id, query, limit)
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
                typers: HashMap::new(),
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

    /// Join an existing room. The room may come from a live announcement
    /// (preferred), our restorable set, or the DB directly — whichever has
    /// the freshest copy. For encrypted rooms `passphrase` is required.
    pub async fn join_room(&self, room_id: &str, passphrase: Option<&str>) -> Result<()> {
        // Resolve room metadata from the freshest available source.
        let (name, creator_fingerprint, encrypted, salt_opt) = {
            if let Some(d) = self.discovered_rooms.lock().unwrap().get(room_id).cloned() {
                let salt = self.get_room_salt(room_id);
                (d.name, d.creator_fingerprint, d.encrypted, salt)
            } else if let Some(stored) = self.restorable_rooms.lock().unwrap().get(room_id).cloned()
            {
                (
                    stored.name,
                    stored.creator_fingerprint,
                    stored.encrypted,
                    stored.passphrase_salt,
                )
            } else if let Some(stored) = repo::get_room(&self.db, room_id)? {
                (
                    stored.name,
                    stored.creator_fingerprint,
                    stored.encrypted,
                    stored.passphrase_salt,
                )
            } else {
                return Err(HuddleError::Other(format!("room {room_id} not found")));
            }
        };

        if encrypted && passphrase.is_none() {
            return Err(HuddleError::Other(
                "encrypted room requires a passphrase".into(),
            ));
        }

        let passphrase_key = if encrypted {
            let salt = salt_opt
                .clone()
                .ok_or_else(|| HuddleError::Other("missing salt for encrypted room".into()))?;
            Some(passphrase::derive_key(passphrase.unwrap(), &salt)?)
        } else {
            None
        };

        let info = StoredRoom {
            id: room_id.to_string(),
            name,
            creator_fingerprint,
            encrypted,
            passphrase_salt: salt_opt.clone(),
            created_at: now_unix(),
            last_active: Some(now_unix()),
        };
        repo::insert_room(&self.db, &info)?;

        let crypto = if encrypted {
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
                typers: HashMap::new(),
            },
        );
        // No longer "restorable" now that we've rejoined.
        self.restorable_rooms.lock().unwrap().remove(room_id);

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

    /// Walk the rooms table at startup. Non-encrypted rooms are silently
    /// restored (subscribed + re-announced). Encrypted rooms get added to
    /// `restorable_rooms` so the lobby surfaces them and the user can
    /// re-enter via the join flow with passphrase.
    async fn restore_rooms_from_db(&self) {
        let rooms = match repo::list_rooms(&self.db) {
            Ok(v) => v,
            Err(e) => {
                warn!(%e, "list rooms on restore");
                return;
            }
        };
        let our_fp = self.identity.fingerprint().to_string();
        let count = rooms.len();
        for info in rooms {
            if info.encrypted {
                self.restorable_rooms
                    .lock()
                    .unwrap()
                    .insert(info.id.clone(), info);
                continue;
            }
            let mut members = HashSet::new();
            members.insert(our_fp.clone());
            if let Ok(stored_members) = repo::list_room_members(&self.db, &info.id) {
                for m in stored_members {
                    members.insert(m.fingerprint);
                }
            }
            self.active_rooms.lock().unwrap().insert(
                info.id.clone(),
                ActiveRoom {
                    info: info.clone(),
                    crypto: None,
                    passphrase_key: None,
                    members,
                    typers: HashMap::new(),
                },
            );
            self.network.subscribe_room(info.id.clone()).await;
            self.announce_room_now(&info, 1).await;
            info!(room_id = %info.id, name = %info.name, "restored room");
        }
        if count > 0 {
            debug!(count, "restored rooms from db");
        }
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
    // Dial / known peers
    // -------------------------------------------------------------------

    /// Dial a peer by a user-entered address. Accepts:
    /// - `1.2.3.4:9000`
    /// - `[fe80::1]:9000`
    /// - `/ip4/.../tcp/...[/p2p/<peer>]` (raw multiaddr)
    pub async fn dial(&self, input: &str) -> Result<()> {
        let multiaddr = parse_dial_address(input)?;
        let canonical = multiaddr.to_string();
        info!(%canonical, "dialing");

        repo::upsert_known_peer(
            &self.db,
            &KnownPeer {
                address: canonical.clone(),
                label: None,
                last_connected_at: None,
                last_attempt_at: Some(now_unix()),
                created_at: now_unix(),
            },
        )?;

        let _ = self.app_event_tx.send(AppEvent::Dialing {
            address: canonical.clone(),
        });
        self.network.dial(multiaddr).await;
        Ok(())
    }

    pub fn known_peers(&self) -> Vec<KnownPeerStatus> {
        let connected = self.connected_dial_addrs.lock().unwrap().clone();
        let stored = repo::list_known_peers(&self.db).unwrap_or_default();
        stored
            .into_iter()
            .map(|p| {
                let connected_peer = connected.get(&p.address).copied();
                KnownPeerStatus {
                    address: p.address,
                    label: p.label,
                    last_connected_at: p.last_connected_at,
                    connected_peer_id: connected_peer,
                }
            })
            .collect()
    }

    pub async fn forget_peer(&self, address: &str) -> Result<()> {
        repo::forget_known_peer(&self.db, address)?;
        self.connected_dial_addrs.lock().unwrap().remove(address);
        Ok(())
    }

    /// Re-dial a stored address — used by the lobby's "reconnect" action.
    pub async fn redial(&self, address: &str) -> Result<()> {
        self.dial(address).await
    }

    fn spawn_known_peer_reconnector(&self) {
        let handle = self.clone();
        tokio::spawn(async move {
            // Brief delay so listeners come up first.
            tokio::time::sleep(Duration::from_millis(500)).await;
            let known = repo::list_known_peers(&handle.db).unwrap_or_default();
            for peer in known {
                if let Err(e) = handle.dial(&peer.address).await {
                    debug!(%e, addr = %peer.address, "auto-reconnect failed");
                }
            }
        });
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
                    restorable: false,
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
            NetworkEvent::DialSucceeded { peer_id, address } => {
                let addr_s = address.to_string();
                self.connected_dial_addrs
                    .lock()
                    .unwrap()
                    .insert(addr_s.clone(), peer_id);
                let _ = repo::upsert_known_peer(
                    &self.db,
                    &KnownPeer {
                        address: addr_s.clone(),
                        label: None,
                        last_connected_at: Some(now_unix()),
                        last_attempt_at: Some(now_unix()),
                        created_at: now_unix(),
                    },
                );
                let _ = self.app_event_tx.send(AppEvent::DialSucceeded {
                    address: addr_s,
                    peer_id,
                });
            }
            NetworkEvent::DialFailed { address, error } => {
                let addr_s = address.to_string();
                let _ = self.app_event_tx.send(AppEvent::DialFailed {
                    address: addr_s,
                    error,
                });
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
                            verified: false,
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
                        self.maybe_emit_mention(room_id, &body);
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
                self.maybe_emit_mention(room_id, &body);
                let _ = self.app_event_tx.send(AppEvent::MessageReceived {
                    room_id: room_id.to_string(),
                    sender_fingerprint,
                    body,
                    sent_at,
                });
            }
            RoomMessage::Typing { sender_fingerprint } => {
                if sender_fingerprint == our_fp {
                    return;
                }
                let expiry = now_unix() + TYPING_TTL_SECS;
                let mut rooms = self.active_rooms.lock().unwrap();
                if let Some(room) = rooms.get_mut(room_id) {
                    room.typers.insert(sender_fingerprint, expiry);
                }
                drop(rooms);
                let _ = self.app_event_tx.send(AppEvent::TypingChanged {
                    room_id: room_id.to_string(),
                });
            }
            RoomMessage::RotateRoomKey {
                rotator_fingerprint,
                new_salt,
            } => {
                if rotator_fingerprint == our_fp {
                    return;
                }
                let _ = self.app_event_tx.send(AppEvent::RotationRequested {
                    room_id: room_id.to_string(),
                    rotator_fingerprint,
                    new_salt,
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
            RoomMessage::FileOffer {
                sender_fingerprint,
                file_id,
                name,
                size_bytes,
                mime,
                chunk_count,
                encrypted_meta,
            } => {
                if sender_fingerprint == our_fp {
                    return; // ignore our own broadcast
                }
                self.handle_file_offer(
                    room_id,
                    sender_fingerprint,
                    file_id,
                    name,
                    size_bytes,
                    mime,
                    chunk_count,
                    encrypted_meta,
                );
            }
            RoomMessage::FileChunk {
                sender_fingerprint,
                file_id,
                chunk_index,
                total_chunks,
                data_b64,
            } => {
                if sender_fingerprint == our_fp {
                    return;
                }
                self.handle_file_chunk(
                    room_id,
                    sender_fingerprint,
                    file_id,
                    chunk_index,
                    total_chunks,
                    data_b64,
                );
            }
        }
    }

    // -------------------------------------------------------------------
    // File transfer — public API
    // -------------------------------------------------------------------

    /// Send a local file to a room. Reads the file, optionally encrypts
    /// it for encrypted rooms, chunks it, broadcasts a FileOffer then
    /// each FileChunk. Returns the file_id once all chunks are queued.
    pub async fn send_file(&self, room_id: &str, path: &Path) -> Result<String> {
        let bytes = std::fs::read(path)?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "untitled".into());
        let mime = crate::files::guess_mime(&name);
        let original_path = path.to_path_buf();

        let (room_encrypted, mut maybe_session_id, encrypted_meta_opt, wire_bytes) = {
            let mut rooms = self.active_rooms.lock().unwrap();
            let room = rooms
                .get_mut(room_id)
                .ok_or_else(|| HuddleError::Other(format!("not in room {room_id}")))?;
            if room.info.encrypted {
                let crypto = room
                    .crypto
                    .as_mut()
                    .ok_or_else(|| HuddleError::Session("missing room crypto".into()))?;
                let (ciphertext, meta) = file_encryption::encrypt_file(&bytes, crypto)?;
                (true, Some(meta.megolm_session_id.clone()), Some(meta), ciphertext)
            } else {
                (false, None, None, bytes)
            }
        };
        let _ = &mut maybe_session_id; // silence unused warning when non-encrypted

        let plan =
            self.file_manager
                .prepare_outgoing_from_bytes(&name, mime.clone(), wire_bytes)?;
        let file_id = plan.file_id.clone();
        let total = plan.chunks.len() as u32;
        let our_fp = self.identity.fingerprint().to_string();

        let attachment = StoredAttachment {
            id: 0,
            room_id: room_id.to_string(),
            message_id: None,
            sender_fingerprint: our_fp.clone(),
            file_id: file_id.clone(),
            name: name.clone(),
            mime: mime.clone(),
            size_bytes: plan.size_bytes as i64,
            status: AttachmentStatus::Ready,
            cache_path: Some(self.file_manager.cache_path(&file_id).to_string_lossy().into()),
            saved_path: Some(original_path.to_string_lossy().into()),
            error: None,
            encrypted: room_encrypted,
            wrapped_key: encrypted_meta_opt.as_ref().map(|m| m.wrapped_key_b64.clone()),
            nonce: encrypted_meta_opt.as_ref().map(|m| m.nonce_b64.clone()),
            megolm_session_id: encrypted_meta_opt
                .as_ref()
                .map(|m| m.megolm_session_id.clone()),
            created_at: now_unix(),
        };
        repo::upsert_attachment(&self.db, &attachment)?;
        let _ = self.app_event_tx.send(AppEvent::FileOffered {
            room_id: room_id.to_string(),
            file_id: file_id.clone(),
            name: name.clone(),
            size_bytes: plan.size_bytes,
            sender_fingerprint: our_fp.clone(),
        });

        // Publish the offer.
        let offer = RoomMessage::FileOffer {
            sender_fingerprint: our_fp.clone(),
            file_id: file_id.clone(),
            name,
            size_bytes: plan.size_bytes,
            mime,
            chunk_count: total,
            encrypted_meta: encrypted_meta_opt,
        };
        if let Ok(bytes) = serde_json::to_vec(&offer) {
            self.network
                .publish_room_message(room_id.to_string(), bytes)
                .await;
        }

        // Stream chunks. Brief pacing so gossipsub doesn't see a thundering
        // herd from a single peer.
        let net = self.network.clone();
        let room = room_id.to_string();
        let our = our_fp.clone();
        let fid = file_id.clone();
        let chunks = plan.chunks.clone();
        tokio::spawn(async move {
            for (i, data) in chunks.iter().enumerate() {
                let msg = RoomMessage::FileChunk {
                    sender_fingerprint: our.clone(),
                    file_id: fid.clone(),
                    chunk_index: i as u32,
                    total_chunks: total,
                    data_b64: B64.encode(data),
                };
                if let Ok(bytes) = serde_json::to_vec(&msg) {
                    net.publish_room_message(room.clone(), bytes).await;
                }
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
        });

        Ok(file_id)
    }

    /// Save a completed/ready attachment to the user's Downloads folder.
    /// Decrypts encrypted attachments on the way out.
    pub async fn save_to_downloads(&self, room_id: &str, file_id: &str) -> Result<PathBuf> {
        let attachment = repo::get_attachment(&self.db, room_id, file_id)?
            .ok_or_else(|| HuddleError::Other("attachment not found".into()))?;
        if !matches!(
            attachment.status,
            AttachmentStatus::Ready | AttachmentStatus::Saved
        ) {
            return Err(HuddleError::Other(format!(
                "attachment is not ready (status={})",
                attachment.status.as_str()
            )));
        }
        let cached = self.file_manager.read_cache(file_id)?;
        let plaintext = if attachment.encrypted {
            let meta = EncryptedFileMeta {
                megolm_session_id: attachment
                    .megolm_session_id
                    .clone()
                    .ok_or_else(|| HuddleError::Other("missing megolm_session_id".into()))?,
                wrapped_key_b64: attachment
                    .wrapped_key
                    .clone()
                    .ok_or_else(|| HuddleError::Other("missing wrapped_key".into()))?,
                nonce_b64: attachment
                    .nonce
                    .clone()
                    .ok_or_else(|| HuddleError::Other("missing nonce".into()))?,
            };
            // For our own sent files we don't have an inbound session
            // keyed by ourselves; the file_manager cache for the sender
            // already holds the ciphertext. To open our own attachment
            // we just open the original saved_path via open_saved (which
            // doesn't decrypt — the bytes already exist on disk).
            if attachment.sender_fingerprint == self.identity.fingerprint() {
                return Err(HuddleError::Other(
                    "this attachment is your own — use [o] open to open the source file".into(),
                ));
            }
            self.decrypt_attachment(room_id, &attachment.sender_fingerprint, &cached, &meta)?
        } else {
            cached
        };
        let saved = self.file_manager.write_to_downloads(&attachment.name, &plaintext)?;
        repo::update_attachment_paths(
            &self.db,
            room_id,
            file_id,
            None,
            Some(&saved.to_string_lossy()),
        )?;
        repo::update_attachment_status(&self.db, room_id, file_id, AttachmentStatus::Saved, None)?;
        let _ = self.app_event_tx.send(AppEvent::FileSaved {
            file_id: file_id.into(),
            path: saved.to_string_lossy().into(),
        });
        Ok(saved)
    }

    /// Drop any in-flight chunks and remove the attachment row.
    pub async fn cancel_transfer(&self, room_id: &str, file_id: &str) -> Result<()> {
        self.file_manager.cancel_incoming(file_id);
        repo::update_attachment_status(
            &self.db,
            room_id,
            file_id,
            AttachmentStatus::Cancelled,
            None,
        )?;
        Ok(())
    }

    /// Launch the system's default opener on a saved file.
    pub fn open_saved(&self, room_id: &str, file_id: &str) -> Result<()> {
        let attachment = repo::get_attachment(&self.db, room_id, file_id)?
            .ok_or_else(|| HuddleError::Other("attachment not found".into()))?;
        let path = attachment
            .saved_path
            .ok_or_else(|| HuddleError::Other("not saved yet — press Enter to save first".into()))?;
        open_with_system(&path)
    }

    pub fn list_room_attachments(&self, room_id: &str) -> Result<Vec<StoredAttachment>> {
        repo::list_room_attachments(&self.db, room_id)
    }

    /// Mark a peer's fingerprint as verified in the given room. Used by
    /// the `^V` verification modal after the user has compared the
    /// fingerprint out-of-band.
    pub fn set_member_verified(
        &self,
        room_id: &str,
        fingerprint: &str,
        verified: bool,
    ) -> Result<()> {
        // Make sure there's a member row to flip — peer_id is unknown
        // at this layer when the user verifies an out-of-band identity,
        // so we use the fingerprint as the canonical identity key with
        // an empty peer_id placeholder if none exists.
        let members = repo::list_room_members(&self.db, room_id).unwrap_or_default();
        if !members.iter().any(|m| m.fingerprint == fingerprint) {
            repo::upsert_room_member(
                &self.db,
                &StoredRoomMember {
                    room_id: room_id.to_string(),
                    peer_id: String::new(),
                    fingerprint: fingerprint.to_string(),
                    last_seen: Some(now_unix()),
                    verified,
                },
            )?;
        }
        repo::set_member_verified(&self.db, room_id, fingerprint, verified)
    }

    pub fn verified_fingerprints(&self, room_id: &str) -> Vec<String> {
        repo::list_verified_fingerprints(&self.db, room_id).unwrap_or_default()
    }

    pub fn is_room_muted(&self, room_id: &str) -> bool {
        repo::is_room_muted(&self.db, room_id).unwrap_or(false)
    }

    pub fn set_room_muted(&self, room_id: &str, muted: bool) -> Result<()> {
        repo::set_room_muted(&self.db, room_id, muted)
    }

    /// Broadcast a "I'm typing" pulse to the given room. Caller is
    /// responsible for debouncing (don't fire more than every ~500ms).
    pub async fn broadcast_typing(&self, room_id: &str) {
        if !self.active_rooms.lock().unwrap().contains_key(room_id) {
            return;
        }
        let msg = RoomMessage::Typing {
            sender_fingerprint: self.identity.fingerprint().to_string(),
        };
        if let Ok(bytes) = serde_json::to_vec(&msg) {
            self.network
                .publish_room_message(room_id.to_string(), bytes)
                .await;
        }
    }

    /// Returns the fingerprints of peers currently typing in `room_id`,
    /// pruning entries past their TTL.
    pub fn typers_in_room(&self, room_id: &str) -> Vec<String> {
        let now = now_unix();
        let mut rooms = self.active_rooms.lock().unwrap();
        let room = match rooms.get_mut(room_id) {
            Some(r) => r,
            None => return Vec::new(),
        };
        room.typers.retain(|_, exp| *exp > now);
        let mut v: Vec<String> = room.typers.keys().cloned().collect();
        v.sort();
        v
    }

    // -------------------------------------------------------------------
    // Room key rotation
    // -------------------------------------------------------------------

    /// Rotate this room's outbound Megolm session under a fresh
    /// passphrase. Broadcasts `RotateRoomKey` (so other members know to
    /// expect a new passphrase) and a fresh `MemberAnnounce` with the
    /// new wrapped session key. Old inbound sessions stay in storage
    /// for decrypting historic messages.
    pub async fn rotate_room(&self, room_id: &str, new_passphrase: &str) -> Result<()> {
        if new_passphrase.is_empty() {
            return Err(HuddleError::Other("new passphrase is empty".into()));
        }
        let new_salt = passphrase::random_salt();
        let new_key = passphrase::derive_key(new_passphrase, &new_salt)?;

        let info = {
            let mut rooms = self.active_rooms.lock().unwrap();
            let room = rooms
                .get_mut(room_id)
                .ok_or_else(|| HuddleError::Other(format!("not in room {room_id}")))?;
            if !room.info.encrypted {
                return Err(HuddleError::Other(
                    "rotation only applies to encrypted rooms".into(),
                ));
            }
            // Generate a fresh outbound Megolm session for this member.
            let new_crypto = RoomCrypto::new_for_room(
                self.db.clone(),
                room_id.to_string(),
                self.identity.fingerprint().to_string(),
            )?;
            room.crypto = Some(new_crypto);
            room.passphrase_key = Some(new_key);
            room.info.passphrase_salt = Some(new_salt.to_vec());
            room.info.clone()
        };

        // Persist the new salt on the stored row.
        repo::insert_room(&self.db, &info)?;

        // Broadcast the rotation signal.
        let rot = RoomMessage::RotateRoomKey {
            rotator_fingerprint: self.identity.fingerprint().to_string(),
            new_salt: new_salt.to_vec(),
        };
        if let Ok(bytes) = serde_json::to_vec(&rot) {
            self.network
                .publish_room_message(room_id.to_string(), bytes)
                .await;
        }

        // Re-announce ourselves with the new wrapped session key.
        if let Err(e) = self.broadcast_member_announce(room_id).await {
            warn!(%e, "rotate: broadcast announce failed");
        }
        Ok(())
    }

    /// Used by the TUI when another member rotates a room we're in.
    /// Derives the new key, updates our local state, and re-announces
    /// so the rotator can share their fresh outbound session with us.
    pub async fn accept_rotation(
        &self,
        room_id: &str,
        new_salt: &[u8],
        new_passphrase: &str,
    ) -> Result<()> {
        let new_key = passphrase::derive_key(new_passphrase, new_salt)?;
        let info = {
            let mut rooms = self.active_rooms.lock().unwrap();
            let room = rooms
                .get_mut(room_id)
                .ok_or_else(|| HuddleError::Other(format!("not in room {room_id}")))?;
            room.passphrase_key = Some(new_key);
            room.info.passphrase_salt = Some(new_salt.to_vec());
            room.info.clone()
        };
        repo::insert_room(&self.db, &info)?;
        // Ask the rotator (and anyone) to re-share their session key.
        let req = RoomMessage::SessionKeyRequest {
            requester_fingerprint: self.identity.fingerprint().to_string(),
        };
        if let Ok(bytes) = serde_json::to_vec(&req) {
            self.network
                .publish_room_message(room_id.to_string(), bytes)
                .await;
        }
        Ok(())
    }

    // -------------------------------------------------------------------
    // File transfer — internal handlers
    // -------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn handle_file_offer(
        &self,
        room_id: &str,
        sender_fingerprint: String,
        file_id: String,
        name: String,
        size_bytes: u64,
        mime: Option<String>,
        _chunk_count: u32,
        encrypted_meta: Option<EncryptedFileMeta>,
    ) {
        let encrypted = encrypted_meta.is_some();
        let attachment = StoredAttachment {
            id: 0,
            room_id: room_id.to_string(),
            message_id: None,
            sender_fingerprint: sender_fingerprint.clone(),
            file_id: file_id.clone(),
            name: name.clone(),
            mime,
            size_bytes: size_bytes as i64,
            status: AttachmentStatus::Offered,
            cache_path: None,
            saved_path: None,
            error: None,
            encrypted,
            wrapped_key: encrypted_meta.as_ref().map(|m| m.wrapped_key_b64.clone()),
            nonce: encrypted_meta.as_ref().map(|m| m.nonce_b64.clone()),
            megolm_session_id: encrypted_meta.as_ref().map(|m| m.megolm_session_id.clone()),
            created_at: now_unix(),
        };
        if let Err(e) = repo::upsert_attachment(&self.db, &attachment) {
            warn!(%e, "upsert attachment");
            return;
        }
        let _ = self.app_event_tx.send(AppEvent::FileOffered {
            room_id: room_id.to_string(),
            file_id,
            name,
            size_bytes,
            sender_fingerprint,
        });
    }

    fn handle_file_chunk(
        &self,
        room_id: &str,
        _sender_fingerprint: String,
        file_id: String,
        chunk_index: u32,
        total_chunks: u32,
        data_b64: String,
    ) {
        let data = match B64.decode(&data_b64) {
            Ok(d) => d,
            Err(e) => {
                warn!(%e, "bad chunk base64");
                return;
            }
        };
        // Pull the announced size from our stored offer.
        let expected_size = repo::get_attachment(&self.db, room_id, &file_id)
            .ok()
            .flatten()
            .map(|a| a.size_bytes as u64)
            .unwrap_or(crate::files::MAX_FILE_SIZE);

        let result = self.file_manager.accept_chunk(
            &file_id,
            chunk_index,
            total_chunks,
            data,
            expected_size,
        );
        match result {
            Ok(None) => {
                // Move offered → downloading on first chunk.
                let _ = repo::update_attachment_status(
                    &self.db,
                    room_id,
                    &file_id,
                    AttachmentStatus::Downloading,
                    None,
                );
                // Best-effort progress event — we know we've processed
                // (chunk_index+1)/total_chunks chunks.
                let bytes_so_far = self
                    .file_manager
                    .progress(&file_id)
                    .map(|(b, _)| b)
                    .unwrap_or(0);
                let _ = self.app_event_tx.send(AppEvent::FileProgress {
                    file_id: file_id.clone(),
                    bytes_received: bytes_so_far,
                    total_bytes: expected_size,
                });
            }
            Ok(Some(completed)) => {
                let _ = repo::update_attachment_paths(
                    &self.db,
                    room_id,
                    &file_id,
                    Some(&completed.cache_path.to_string_lossy()),
                    None,
                );
                let _ = repo::update_attachment_status(
                    &self.db,
                    room_id,
                    &file_id,
                    AttachmentStatus::Ready,
                    None,
                );
                let _ = self.app_event_tx.send(AppEvent::FileReady {
                    file_id: file_id.clone(),
                });
            }
            Err(e) => {
                let msg = e.to_string();
                warn!(%msg, "chunk processing failed");
                let _ = repo::update_attachment_status(
                    &self.db,
                    room_id,
                    &file_id,
                    AttachmentStatus::Failed,
                    Some(&msg),
                );
                let _ = self.app_event_tx.send(AppEvent::FileFailed {
                    file_id: file_id.clone(),
                    reason: msg,
                });
            }
        }
    }

    /// Emit MentionReceived if `body` contains either our full
    /// fingerprint or its short form (first hex group).
    fn maybe_emit_mention(&self, room_id: &str, body: &str) {
        let full = self.identity.fingerprint();
        let short = full.split('-').next().unwrap_or(full);
        let lower = body.to_lowercase();
        if lower.contains(&full.to_lowercase()) || lower.contains(&short.to_lowercase()) {
            let _ = self.app_event_tx.send(AppEvent::MentionReceived {
                room_id: room_id.to_string(),
                body: body.to_string(),
            });
        }
    }

    fn decrypt_attachment(
        &self,
        room_id: &str,
        sender_fingerprint: &str,
        ciphertext: &[u8],
        meta: &EncryptedFileMeta,
    ) -> Result<Vec<u8>> {
        let mut rooms = self.active_rooms.lock().unwrap();
        let room = rooms
            .get_mut(room_id)
            .ok_or_else(|| HuddleError::Other("not in room".into()))?;
        let crypto = room
            .crypto
            .as_mut()
            .ok_or_else(|| HuddleError::Session("missing room crypto".into()))?;
        file_encryption::decrypt_file(ciphertext, meta, crypto, sender_fingerprint)
    }
}

/// Use the platform's default opener on `path`.
fn open_with_system(path: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    let cmd = "open";
    #[cfg(target_os = "linux")]
    let cmd = "xdg-open";
    #[cfg(target_os = "windows")]
    let cmd = "cmd";
    #[cfg(target_os = "windows")]
    let args = vec!["/C", "start", "", path];
    #[cfg(not(target_os = "windows"))]
    let args = vec![path];

    std::process::Command::new(cmd)
        .args(args)
        .spawn()
        .map_err(|e| HuddleError::Other(format!("spawn opener: {e}")))?;
    Ok(())
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

#[cfg(test)]
mod parser_tests {
    use super::parse_dial_address;

    #[test]
    fn parses_ipv4_port() {
        let m = parse_dial_address("10.3.72.53:9027").unwrap();
        assert_eq!(m.to_string(), "/ip4/10.3.72.53/tcp/9027");
    }

    #[test]
    fn parses_bracketed_ipv6() {
        let m = parse_dial_address("[::1]:9027").unwrap();
        assert_eq!(m.to_string(), "/ip6/::1/tcp/9027");
    }

    #[test]
    fn rejects_unbracketed_ipv6() {
        let err = parse_dial_address("fe80::1:9027").unwrap_err();
        assert!(err.to_string().contains("brackets"));
    }

    #[test]
    fn passes_through_raw_multiaddr() {
        let m = parse_dial_address("/ip4/1.2.3.4/tcp/9000").unwrap();
        assert_eq!(m.to_string(), "/ip4/1.2.3.4/tcp/9000");
    }

    #[test]
    fn empty_address_is_error() {
        assert!(parse_dial_address("   ").is_err());
    }

    #[test]
    fn rejects_bad_port() {
        assert!(parse_dial_address("1.2.3.4:notaport").is_err());
    }
}
