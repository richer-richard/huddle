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
use crate::network::protocol::{encode_wire, RoomAnnouncement, RoomMessage, WireMessage};
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
    /// Phase F: we joined via a short-lived code rather than the
    /// passphrase. We have other members' session keys (delivered via
    /// the CodeJoinResponse ECDH handshake) so we can decrypt; but
    /// without the passphrase we can't wrap our own outbound session
    /// key for other members. Read-only until an owner re-onboards us
    /// with the full passphrase. Defaults false for passphrase joins.
    #[allow(dead_code)]
    read_only: bool,
    /// Phase F: owner-issued join codes for this room (owner side
    /// only). Pairs of (code, expires_at_unix). Single-use; entries
    /// removed after a successful CodeJoinResponse goes out.
    issued_codes: Vec<(String, i64)>,
}

const TYPING_TTL_SECS: i64 = 3;

/// TTL for a discovered room before it's considered stale (re-announcements
/// happen every 15 seconds; after 45s of silence we drop it).
const DISCOVERED_TTL_SECS: i64 = 45;
const ANNOUNCE_INTERVAL_SECS: u64 = 15;

/// Phase G: in-flight SAS verification state, keyed by tx_id. Held in
/// memory only; survives just long enough for the two-message
/// handshake + the user pressing Match on both sides.
struct SasFlow {
    room_id: String,
    partner_fingerprint: String,
    our_secret: x25519_dalek::StaticSecret,
    /// Set once we know both sides' pubkeys → the derived SAS code.
    sas_code: Option<crate::crypto::sas::SasCode>,
    our_confirmed: bool,
    their_confirmed: bool,
}

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
    /// 32-byte key Megolm session pickles are encrypted under at rest —
    /// an HKDF subkey of the master key, or all-zero on the
    /// `--no-master-passphrase` / unencrypted-DB path.
    session_persist_key: [u8; 32],
    /// Phase G: active SAS verifications. Keyed by tx_id (the random
    /// 16-byte salt picked by the initiator + base64'd).
    sas_flows: Arc<Mutex<HashMap<String, SasFlow>>>,
    /// Phase F: ephemeral X25519 secrets the joiner is holding while
    /// they wait for the owner's `CodeJoinResponse`. Keyed by room_id
    /// — we only have one in-flight code join per room at a time.
    pending_code_secrets: Arc<Mutex<HashMap<String, x25519_dalek::StaticSecret>>>,
    app_event_tx: broadcast::Sender<AppEvent>,
}

impl AppHandle {
    pub async fn start() -> Result<Self> {
        Self::start_with_options(NetworkMode::Mdns, 0, None, Vec::new()).await
    }

    pub async fn start_with_options(
        mode: NetworkMode,
        port: u16,
        master_key: Option<&[u8; 32]>,
        relays: Vec<Multiaddr>,
    ) -> Result<Self> {
        config::ensure_data_dir()?;
        // Megolm session state is encrypted at rest with an HKDF subkey
        // of the master key. With no master key (--no-master-passphrase /
        // tests) it's persisted under the all-zero key, matching the
        // unencrypted-DB story.
        let session_persist_key = match master_key {
            Some(mk) => storage::keychain::derive_subkey(mk, b"megolm-persist"),
            None => [0u8; 32],
        };
        let db = storage::open_db(&config::db_path(), master_key)?;
        Self::start_with_db_and_options(db, mode, port, session_persist_key, relays).await
    }

    pub async fn start_with_db(db: Db) -> Result<Self> {
        Self::start_with_db_and_options(db, NetworkMode::Mdns, 0, [0u8; 32], Vec::new()).await
    }

    pub async fn start_with_db_and_options(
        db: Db,
        mode: NetworkMode,
        port: u16,
        session_persist_key: [u8; 32],
        relays: Vec<Multiaddr>,
    ) -> Result<Self> {
        let identity = Self::load_or_create_identity(&db)?;
        let identity = Arc::new(identity);
        info!(fingerprint = %identity.fingerprint(), peer_id = %identity.peer_id(), mode = %mode.as_str(), port, relay_count = relays.len(), "identity loaded");

        let (net_event_tx, net_event_rx) = tokio::sync::mpsc::channel::<NetworkEvent>(256);
        let (app_event_tx, _) = broadcast::channel::<AppEvent>(256);
        let network =
            network::start_network_with(&identity, net_event_tx, mode, port, relays)?;

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
            session_persist_key,
            sas_flows: Arc::new(Mutex::new(HashMap::new())),
            pending_code_secrets: Arc::new(Mutex::new(HashMap::new())),
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
                self.session_persist_key,
            )?)
        } else {
            None
        };

        let mut members = HashSet::new();
        members.insert(creator_fp.clone());

        // Phase B: the room creator is the first owner. Persisted now so
        // the very first announcement includes our fingerprint in
        // `owner_fingerprints`, letting joiners know who's authorized.
        repo::upsert_room_member(
            &self.db,
            &StoredRoomMember {
                room_id: room_id.clone(),
                peer_id: String::new(),
                fingerprint: creator_fp.clone(),
                last_seen: Some(created_at),
                verified: true, // we trust ourselves
                ed25519_pubkey: Some(B64.encode(self.identity.public_bytes())),
                role: "owner".into(),
            },
        )?;

        self.active_rooms.lock().unwrap().insert(
            room_id.clone(),
            ActiveRoom {
                info: info.clone(),
                crypto,
                passphrase_key,
                members,
                typers: HashMap::new(),
                read_only: false,
                issued_codes: Vec::new(),
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
            // Reuse persisted Megolm sessions on re-join; only mint a fresh
            // outbound session when nothing is stored for this room yet.
            let our_fp = self.identity.fingerprint().to_string();
            let existing = RoomCrypto::load(
                self.db.clone(),
                room_id.to_string(),
                our_fp.clone(),
                self.session_persist_key,
            )?;
            Some(match existing {
                Some(c) => c,
                None => RoomCrypto::new_for_room(
                    self.db.clone(),
                    room_id.to_string(),
                    our_fp,
                    self.session_persist_key,
                )?,
            })
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
                read_only: false,
                issued_codes: Vec::new(),
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
            if let Ok(bytes) = encode_wire(&req) {
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
            let member_count = members.len() as u32;
            self.active_rooms.lock().unwrap().insert(
                info.id.clone(),
                ActiveRoom {
                    info: info.clone(),
                    crypto: None,
                    passphrase_key: None,
                    members,
                    typers: HashMap::new(),
                    read_only: false,
                    issued_codes: Vec::new(),
                },
            );
            self.network.subscribe_room(info.id.clone()).await;
            self.announce_room_now(&info, member_count).await;
            info!(room_id = %info.id, name = %info.name, "restored room");
        }
        if count > 0 {
            debug!(count, "restored rooms from db");
        }
    }

    /// Leave a room. Returns `true` when the `MemberLeave` notice was
    /// handed to the network layer, `false` when it couldn't be encoded
    /// (peers then only notice via the discovered-room TTL). The local
    /// leave always succeeds regardless.
    pub async fn leave_room(&self, room_id: &str) -> Result<bool> {
        // Broadcast a leave notice before unsubscribing.
        let leave_msg = RoomMessage::MemberLeave {
            sender_fingerprint: self.identity.fingerprint().to_string(),
        };
        let dispatched = match encode_wire(&leave_msg) {
            Ok(bytes) => {
                self.network
                    .publish_room_message(room_id.to_string(), bytes)
                    .await;
                true
            }
            Err(e) => {
                warn!(%e, %room_id, "failed to encode MemberLeave notice");
                false
            }
        };

        self.active_rooms.lock().unwrap().remove(room_id);
        self.network.unsubscribe_room(room_id.to_string()).await;

        let _ = self.app_event_tx.send(AppEvent::RoomLeft {
            room_id: room_id.to_string(),
        });
        Ok(dispatched)
    }

    pub async fn send_room_message(&self, room_id: &str, body: &str) -> Result<()> {
        let our_fp = self.identity.fingerprint().to_string();
        let msg = {
            let mut rooms = self.active_rooms.lock().unwrap();
            let room = rooms
                .get_mut(room_id)
                .ok_or_else(|| HuddleError::Other(format!("not in room {room_id}")))?;

            if room.read_only {
                return Err(HuddleError::Other(
                    "this room is read-only — you joined via code without the passphrase. Ask an owner for the passphrase or wait for a key rotation that includes you.".into(),
                ));
            }

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

        let bytes = encode_wire(&msg)?;
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
                // Fingerprint isn't known until Identify lands after the
                // dial completes; the connection-success handler upserts
                // again with the fingerprint and trusted=true.
                fingerprint: None,
                trusted: false,
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

    /// Phase A: user pressed Accept on the inbound-dial modal. Promotes
    /// the peer to the gossipsub mesh. Does NOT mark them trusted —
    /// that's `trust_inbound`, the explicit "remember and bypass next
    /// time" path.
    pub async fn accept_inbound(&self, peer_id: PeerId, address: &str) {
        self.network.accept_inbound(peer_id).await;
        self.connected_dial_addrs
            .lock()
            .unwrap()
            .insert(address.to_string(), peer_id);
    }

    /// Phase A: user pressed Reject on the inbound-dial modal. Disconnects
    /// the peer, adds them to the persistent blocklist, and ensures every
    /// subsequent connection attempt from this fingerprint is auto-
    /// dropped without re-prompting.
    pub async fn reject_inbound(&self, peer_id: PeerId, fingerprint: &str) -> Result<()> {
        self.network.reject_inbound(peer_id).await;
        repo::block_peer(&self.db, fingerprint, now_unix())?;
        Ok(())
    }

    /// Phase A: user pressed Trust+Accept — accept the connection AND
    /// remember the peer so subsequent connections bypass the modal.
    pub async fn trust_inbound(
        &self,
        peer_id: PeerId,
        fingerprint: &str,
        address: &str,
    ) -> Result<()> {
        self.network.accept_inbound(peer_id).await;
        self.connected_dial_addrs
            .lock()
            .unwrap()
            .insert(address.to_string(), peer_id);
        // Persist the row with trusted=true so future inbound from
        // this fingerprint short-circuits the modal in
        // `process_network_event`'s InboundDial handler.
        repo::upsert_known_peer(
            &self.db,
            &KnownPeer {
                address: address.to_string(),
                label: None,
                last_connected_at: Some(now_unix()),
                last_attempt_at: Some(now_unix()),
                created_at: now_unix(),
                fingerprint: Some(fingerprint.to_string()),
                trusted: true,
            },
        )?;
        Ok(())
    }

    fn spawn_known_peer_reconnector(&self) {
        let handle = self.clone();
        tokio::spawn(async move {
            // Brief delay so our own listeners come up first.
            tokio::time::sleep(Duration::from_millis(500)).await;
            let known = repo::list_known_peers(&handle.db).unwrap_or_default();
            // Reconnect each peer from its own task on a staggered, jittered
            // delay so a long known-peer list doesn't fire a synchronized
            // burst of dials (and serialized DB writes) all at once.
            for (i, peer) in known.into_iter().enumerate() {
                let handle = handle.clone();
                tokio::spawn(async move {
                    // Deterministic per-address jitter de-correlates peers
                    // without pulling an RNG into scope.
                    let jitter = (peer.address.len() as u64 * 37) % 200;
                    tokio::time::sleep(Duration::from_millis(150 * i as u64 + jitter)).await;
                    if let Err(e) = handle.dial(&peer.address).await {
                        debug!(%e, addr = %peer.address, "auto-reconnect failed");
                    }
                });
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
        let owner_fingerprints =
            repo::list_room_owners(&self.db, &info.id).unwrap_or_default();
        let verified_only = repo::get_room_verified_only(&self.db, &info.id).unwrap_or(false);
        let ann = RoomAnnouncement {
            room_id: info.id.clone(),
            name: info.name.clone(),
            encrypted: info.encrypted,
            passphrase_salt: info.passphrase_salt.clone(),
            member_count,
            creator_fingerprint: info.creator_fingerprint.clone(),
            announced_at: now_unix(),
            owner_fingerprints,
            verified_only,
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
        let display_name = repo::get_display_name(&self.db).unwrap_or(None);
        let msg = RoomMessage::MemberAnnounce {
            sender_fingerprint: our_fp,
            wrapped_session_key: wrapped,
            display_name,
            sender_ed25519_pubkey: Some(B64.encode(self.identity.public_bytes())),
        };
        let bytes = encode_wire(&msg)?;
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
            NetworkEvent::PeerExpired { peer_id } => {
                // Drop any tracked dial-connection entry for this peer so
                // the lobby's online/offline dots stay accurate. mDNS
                // expiry only gives us a PeerId (no fingerprint), so we
                // can't touch room membership here — that relies on the
                // explicit MemberLeave path and the discovered-room TTL.
                self.connected_dial_addrs
                    .lock()
                    .unwrap()
                    .retain(|_addr, pid| *pid != peer_id);
                let _ = self.app_event_tx.send(AppEvent::PeerExpired { peer_id });
            }
            NetworkEvent::ListeningOn { address } => {
                let _ = self.app_event_tx.send(AppEvent::ListeningOn {
                    address: address.to_string(),
                });
            }
            NetworkEvent::RoomAnnouncementReceived(ann) => {
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
                // If we're already in this room, cache the announcement so
                // others can still discover it through us, but don't emit
                // RoomDiscovered — it isn't "newly discovered" to us, and
                // emitting it spuriously re-opens the lobby join prompt.
                if self.active_rooms.lock().unwrap().contains_key(&ann.room_id) {
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
                // v0.3.0+: every wire message is a `WireMessage` envelope.
                // `Plain` carries an unsigned `RoomMessage`; `Signed` is an
                // app-level Ed25519 envelope that we verify before
                // unwrapping. A failed verify is logged and dropped — we
                // never dispatch unverified-but-claiming-to-be-signed
                // messages.
                let wire: WireMessage = match serde_json::from_slice(&payload) {
                    Ok(w) => w,
                    Err(e) => {
                        warn!(%e, "bad wire envelope");
                        return;
                    }
                };
                let (msg, verified_signer) = match wire {
                    WireMessage::Plain(m) => (m, None),
                    WireMessage::Signed(env) => {
                        match crate::crypto::verify_signed(&env) {
                            Ok((m, fp)) => (m, Some(fp)),
                            Err(e) => {
                                warn!(%e, fp = %env.fingerprint, "signed envelope verify failed");
                                return;
                            }
                        }
                    }
                };
                self.handle_room_message(&room_id, msg, verified_signer).await;
            }
            NetworkEvent::DialSucceeded { peer_id, address } => {
                let addr_s = address.to_string();
                self.connected_dial_addrs
                    .lock()
                    .unwrap()
                    .insert(addr_s.clone(), peer_id);
                // Fingerprint isn't known yet (Identify hasn't landed);
                // the PeerIdentified handler below upserts again to add
                // the fingerprint and flip trusted=true once it does.
                let _ = repo::upsert_known_peer(
                    &self.db,
                    &KnownPeer {
                        address: addr_s.clone(),
                        label: None,
                        last_connected_at: Some(now_unix()),
                        last_attempt_at: Some(now_unix()),
                        created_at: now_unix(),
                        fingerprint: None,
                        trusted: false,
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
            NetworkEvent::PeerIdentified { peer_id, fingerprint } => {
                // For any address we user-dialed for this peer, retroactively
                // backfill the fingerprint and flip trusted=true. The
                // upsert's COALESCE preserves fingerprint once set and
                // its trusted-is-sticky-once-true clause means we don't
                // accidentally demote a row that was already trusted.
                let matched_addrs: Vec<String> = {
                    let map = self.connected_dial_addrs.lock().unwrap();
                    map.iter()
                        .filter_map(|(addr, pid)| {
                            if *pid == peer_id {
                                Some(addr.clone())
                            } else {
                                None
                            }
                        })
                        .collect()
                };
                for addr in matched_addrs {
                    let _ = repo::upsert_known_peer(
                        &self.db,
                        &KnownPeer {
                            address: addr,
                            label: None,
                            last_connected_at: Some(now_unix()),
                            last_attempt_at: Some(now_unix()),
                            created_at: now_unix(),
                            fingerprint: Some(fingerprint.clone()),
                            trusted: true,
                        },
                    );
                }
            }
            NetworkEvent::RelayReservationEstablished { address } => {
                // Treat the circuit address like any other listen
                // address — the TUI's ListeningOn handler dedups + adds
                // it to the addresses pane. Also emit a status hint via
                // ListeningOn so the lobby's reachability line updates.
                info!(addr = %address, "relay reservation established");
                let _ = self.app_event_tx.send(AppEvent::ListeningOn {
                    address: address.to_string(),
                });
            }
            NetworkEvent::InboundDial {
                peer_id,
                fingerprint,
                address,
            } => {
                // First: cheap server-side filters before bothering the user.
                if repo::is_peer_blocked(&self.db, &fingerprint).unwrap_or(false) {
                    info!(%fingerprint, "inbound dial auto-rejected: peer is blocked");
                    self.network.reject_inbound(peer_id).await;
                    return;
                }
                // Phase E: global verified-only inbound mode. If on,
                // reject any unverified fingerprint without prompting.
                // SAS-verified (Phase G) and already-trusted (Phase A)
                // peers still come through.
                let global_verified_only =
                    repo::get_setting(&self.db, "verified_only_inbound")
                        .ok()
                        .flatten()
                        .map(|v| v == "1")
                        .unwrap_or(false);
                if global_verified_only {
                    let is_verified =
                        repo::is_globally_verified(&self.db, &fingerprint).unwrap_or(false)
                            || repo::is_fingerprint_trusted(&self.db, &fingerprint)
                                .unwrap_or(false);
                    if !is_verified {
                        info!(
                            %fingerprint,
                            "inbound dial auto-rejected: verified-only mode"
                        );
                        self.network.reject_inbound(peer_id).await;
                        return;
                    }
                }
                if repo::is_fingerprint_trusted(&self.db, &fingerprint).unwrap_or(false) {
                    info!(%fingerprint, "inbound dial auto-accepted: peer is trusted");
                    // Persist the address → peer_id mapping just as a
                    // user-dial would, so the lobby's online dot lights up.
                    self.connected_dial_addrs
                        .lock()
                        .unwrap()
                        .insert(address.to_string(), peer_id);
                    let _ = repo::upsert_known_peer(
                        &self.db,
                        &KnownPeer {
                            address: address.to_string(),
                            label: None,
                            last_connected_at: Some(now_unix()),
                            last_attempt_at: Some(now_unix()),
                            created_at: now_unix(),
                            fingerprint: Some(fingerprint),
                            trusted: true,
                        },
                    );
                    self.network.accept_inbound(peer_id).await;
                    return;
                }
                // Unknown peer — surface the modal in the TUI.
                let _ = self.app_event_tx.send(AppEvent::InboundDial {
                    peer_id,
                    fingerprint,
                    address: address.to_string(),
                });
            }
        }
    }

    /// `verified_signer` is `Some(fp)` if this message arrived inside a
    /// successfully-verified `WireMessage::Signed` envelope — in which
    /// case the inner sender_fingerprint *must* match. `None` for
    /// `WireMessage::Plain`. Phase B's `OwnerGrant`/`BanMember` arms
    /// require it to be `Some` AND the signer to be a current owner.
    async fn handle_room_message(
        &self,
        room_id: &str,
        msg: RoomMessage,
        verified_signer: Option<String>,
    ) {
        let our_fp = self.identity.fingerprint().to_string();
        match msg {
            RoomMessage::MemberAnnounce {
                sender_fingerprint,
                wrapped_session_key,
                display_name,
                sender_ed25519_pubkey,
            } => {
                if sender_fingerprint == our_fp {
                    return;
                }
                // Drop announcements from banned fingerprints — they
                // can't rejoin until an owner unbans them (Phase B).
                if repo::is_member_banned(&self.db, room_id, &sender_fingerprint)
                    .unwrap_or(false)
                {
                    info!(%sender_fingerprint, %room_id, "dropping MemberAnnounce from banned peer");
                    return;
                }
                // Phase E per-room enforcement: if this room is
                // verified-only and the joiner isn't globally SAS-
                // verified, refuse to add them. The lowest-fp owner
                // (deterministic across honest peers) also sends a
                // signed `JoinRefused` so the joiner gets an explicit
                // message instead of a silent hang.
                if repo::get_room_verified_only(&self.db, room_id).unwrap_or(false)
                    && !repo::is_globally_verified(&self.db, &sender_fingerprint).unwrap_or(false)
                {
                    info!(
                        %sender_fingerprint, %room_id,
                        "dropping MemberAnnounce: room is verified-only and joiner isn't verified"
                    );
                    let owners = repo::list_room_owners(&self.db, room_id).unwrap_or_default();
                    let lowest_owner = owners.iter().min().cloned();
                    if lowest_owner.as_deref() == Some(&our_fp) {
                        let msg = RoomMessage::JoinRefused {
                            room_id: room_id.to_string(),
                            target_fingerprint: sender_fingerprint.clone(),
                            reason: "room requires SAS verification — ask an existing member to verify you".into(),
                        };
                        if let Ok(env) = crate::crypto::sign_message(&self.identity, &msg) {
                            if let Ok(bytes) =
                                crate::network::protocol::encode_wire_signed(&env)
                            {
                                self.network
                                    .publish_room_message(room_id.to_string(), bytes)
                                    .await;
                            }
                        }
                    }
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
                    // Persist member with optional display name + pubkey.
                    // `ed25519_pubkey` is `None` for pre-0.3 peers; the
                    // upsert COALESCEs so once we learn it we never lose
                    // it on a later announce that drops the field.
                    let _ = repo::upsert_room_member(
                        &self.db,
                        &StoredRoomMember {
                            room_id: room_id.to_string(),
                            peer_id: String::new(), // unknown at this layer
                            fingerprint: sender_fingerprint.clone(),
                            last_seen: Some(now_unix()),
                            verified: false,
                            ed25519_pubkey: sender_ed25519_pubkey.clone(),
                            // Role is set on first insert only — the
                            // upsert ON CONFLICT clause preserves an
                            // existing 'owner' on re-announce. A genuine
                            // new fingerprint is a 'member' until an
                            // OwnerGrant lands.
                            role: "member".into(),
                        },
                    );
                    if let Some(name) = display_name.as_deref() {
                        let _ = repo::set_member_display_name(
                            &self.db,
                            room_id,
                            &sender_fingerprint,
                            Some(name),
                        );
                    }
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
            RoomMessage::OwnerGrant {
                room_id: announced_room_id,
                target_fingerprint,
            } => {
                // Both: payload room_id must match the topic's room_id
                // (no cross-room replay), AND the signer must be a
                // current owner of this room. Unsigned forgeries land in
                // `verified_signer = None` and are dropped here.
                if announced_room_id != room_id {
                    warn!(payload_room = %announced_room_id, topic_room = %room_id, "OwnerGrant room mismatch");
                    return;
                }
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!(%room_id, "OwnerGrant arrived unsigned; dropping");
                        return;
                    }
                };
                if !self.is_owner(room_id, &signer) {
                    warn!(%signer, %room_id, "OwnerGrant signer isn't an owner; dropping");
                    return;
                }
                info!(%signer, %target_fingerprint, %room_id, "OwnerGrant applied");
                if let Err(e) =
                    repo::set_member_role(&self.db, room_id, &target_fingerprint, "owner")
                {
                    warn!(%e, "OwnerGrant: set_member_role failed");
                }
            }
            RoomMessage::BanMember {
                room_id: announced_room_id,
                target_fingerprint,
            } => {
                if announced_room_id != room_id {
                    warn!(payload_room = %announced_room_id, topic_room = %room_id, "BanMember room mismatch");
                    return;
                }
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!(%room_id, "BanMember arrived unsigned; dropping");
                        return;
                    }
                };
                if !self.is_owner(room_id, &signer) {
                    warn!(%signer, %room_id, "BanMember signer isn't an owner; dropping");
                    return;
                }
                if target_fingerprint == our_fp {
                    // We've been kicked. Locally evict ourselves so the
                    // TUI tabs close; the kicker's subsequent
                    // RotateRoomKey will arrive separately and we
                    // simply won't be able to decrypt the new key,
                    // matching the "soft kick" semantics.
                    info!(%room_id, %signer, "we were kicked from this room");
                    self.active_rooms.lock().unwrap().remove(room_id);
                    let _ = self.app_event_tx.send(AppEvent::RoomLeft {
                        room_id: room_id.to_string(),
                    });
                    return;
                }
                info!(%signer, %target_fingerprint, %room_id, "BanMember applied");
                if let Err(e) = repo::add_room_ban(
                    &self.db,
                    room_id,
                    &target_fingerprint,
                    &signer,
                    "", // signature lives in the envelope, not the row
                    now_unix(),
                ) {
                    warn!(%e, "BanMember: add_room_ban failed");
                }
                self.evict_banned_member(room_id, &target_fingerprint);
            }
            RoomMessage::SasInit {
                tx_id,
                ephemeral_x25519_pubkey_b64,
                target_fingerprint,
            } => {
                if target_fingerprint != our_fp {
                    // Not addressed to us — ignore. Phase G is point-
                    // to-point even though it travels over the room
                    // topic, so members of the room who aren't the
                    // target don't need to act.
                    return;
                }
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!("SasInit arrived unsigned; dropping");
                        return;
                    }
                };
                let their_pub =
                    match crate::crypto::sas::parse_pubkey(&ephemeral_x25519_pubkey_b64) {
                        Ok(pk) => pk,
                        Err(e) => {
                            warn!(%e, "SasInit: bad x25519 pubkey");
                            return;
                        }
                    };
                let tx_id_bytes = match B64.decode(&tx_id) {
                    Ok(b) if b.len() == crate::crypto::sas::TX_ID_LEN => {
                        let mut arr = [0u8; crate::crypto::sas::TX_ID_LEN];
                        arr.copy_from_slice(&b);
                        arr
                    }
                    _ => {
                        warn!(%tx_id, "SasInit: bad tx_id length");
                        return;
                    }
                };
                let (_, our_secret, our_pub) = crate::crypto::sas::new_session();
                let sas_code =
                    crate::crypto::sas::derive_sas_code(&our_secret, &their_pub, &tx_id_bytes);
                self.sas_flows.lock().unwrap().insert(
                    tx_id.clone(),
                    SasFlow {
                        room_id: room_id.to_string(),
                        partner_fingerprint: signer.clone(),
                        our_secret,
                        sas_code: Some(sas_code.clone()),
                        our_confirmed: false,
                        their_confirmed: false,
                    },
                );
                // Respond with our pubkey so the initiator can compute
                // the same code.
                let response = RoomMessage::SasResponse {
                    tx_id: tx_id.clone(),
                    ephemeral_x25519_pubkey_b64: B64.encode(our_pub.as_bytes()),
                };
                if let Ok(env) = crate::crypto::sign_message(&self.identity, &response) {
                    if let Ok(bytes) = crate::network::protocol::encode_wire_signed(&env) {
                        self.network
                            .publish_room_message(room_id.to_string(), bytes)
                            .await;
                    }
                }
                let _ = self.app_event_tx.send(AppEvent::SasCodeReady {
                    room_id: room_id.to_string(),
                    partner_fingerprint: signer,
                    tx_id,
                    emoji_string: sas_code.emoji_string(),
                    emoji_labels: sas_code.emoji_labels(),
                    decimal: sas_code.decimal,
                });
            }
            RoomMessage::SasResponse {
                tx_id,
                ephemeral_x25519_pubkey_b64,
            } => {
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!("SasResponse arrived unsigned; dropping");
                        return;
                    }
                };
                let their_pub =
                    match crate::crypto::sas::parse_pubkey(&ephemeral_x25519_pubkey_b64) {
                        Ok(pk) => pk,
                        Err(e) => {
                            warn!(%e, "SasResponse: bad x25519 pubkey");
                            return;
                        }
                    };
                let tx_id_bytes = match B64.decode(&tx_id) {
                    Ok(b) if b.len() == crate::crypto::sas::TX_ID_LEN => {
                        let mut arr = [0u8; crate::crypto::sas::TX_ID_LEN];
                        arr.copy_from_slice(&b);
                        arr
                    }
                    _ => return,
                };
                let emit = {
                    let mut flows = self.sas_flows.lock().unwrap();
                    let flow = match flows.get_mut(&tx_id) {
                        Some(f) => f,
                        None => {
                            warn!(%tx_id, "SasResponse for unknown tx_id");
                            return;
                        }
                    };
                    if flow.partner_fingerprint != signer {
                        warn!(
                            expected = %flow.partner_fingerprint, got = %signer,
                            "SasResponse signer doesn't match flow's partner; dropping"
                        );
                        return;
                    }
                    let code = crate::crypto::sas::derive_sas_code(
                        &flow.our_secret,
                        &their_pub,
                        &tx_id_bytes,
                    );
                    flow.sas_code = Some(code.clone());
                    code
                };
                let _ = self.app_event_tx.send(AppEvent::SasCodeReady {
                    room_id: room_id.to_string(),
                    partner_fingerprint: signer,
                    tx_id,
                    emoji_string: emit.emoji_string(),
                    emoji_labels: emit.emoji_labels(),
                    decimal: emit.decimal,
                });
            }
            RoomMessage::CodeJoinRequest {
                room_id: announced_room_id,
                joiner_x25519_pubkey_b64,
                code,
            } => {
                if announced_room_id != room_id {
                    return;
                }
                let joiner_fp = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!("CodeJoinRequest unsigned; dropping");
                        return;
                    }
                };
                // Only owners with an active code are interested in
                // responding. Other peers (incl. non-issuing owners)
                // simply ignore.
                let our_fp = self.identity.fingerprint().to_string();
                if !self.is_owner(room_id, &our_fp) {
                    return;
                }
                // Match + consume the code. Single use.
                let now = now_unix();
                let (code_ok, our_session_id, wrap_input) = {
                    let mut rooms = self.active_rooms.lock().unwrap();
                    let room = match rooms.get_mut(room_id) {
                        Some(r) => r,
                        None => return,
                    };
                    if room.passphrase_key.is_none() {
                        warn!("CodeJoinRequest: no passphrase key locally; can't respond");
                        return;
                    }
                    let original_len = room.issued_codes.len();
                    room.issued_codes.retain(|(c, exp)| !(c == &code && *exp > now));
                    let matched = room.issued_codes.len() < original_len;
                    if !matched {
                        info!(%joiner_fp, "CodeJoinRequest: code invalid or expired; ignoring");
                        return;
                    }
                    let crypto = room.crypto.as_ref().unwrap();
                    (
                        true,
                        crypto.our_session_id(),
                        crypto.our_session_key_b64(),
                    )
                };
                let _ = code_ok;
                // ECDH with the joiner's ephemeral pubkey.
                let their_pub = match crate::crypto::sas::parse_pubkey(&joiner_x25519_pubkey_b64) {
                    Ok(pk) => pk,
                    Err(e) => {
                        warn!(%e, "CodeJoinRequest: bad pubkey");
                        return;
                    }
                };
                use x25519_dalek::{PublicKey, StaticSecret};
                let our_secret = StaticSecret::random_from_rng(rand::thread_rng());
                let our_pub = PublicKey::from(&our_secret);
                let shared = our_secret.diffie_hellman(&their_pub);
                // HKDF the shared secret into a 32-byte wrap key.
                let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, shared.as_bytes());
                let mut wrap_key = [0u8; passphrase::KEY_LEN];
                hk.expand(b"huddle-code-join-v1", &mut wrap_key)
                    .expect("32 bytes is within HKDF limits");
                // Wrap our session key under the ECDH-derived key,
                // reusing the existing AEAD primitives.
                let wrapped = match passphrase::wrap(wrap_input.as_bytes(), &wrap_key) {
                    Ok(w) => w,
                    Err(e) => {
                        warn!(%e, "CodeJoinRequest: wrap failed");
                        return;
                    }
                };
                let response = RoomMessage::CodeJoinResponse {
                    room_id: room_id.to_string(),
                    target_fingerprint: joiner_fp.clone(),
                    owner_x25519_pubkey_b64: B64.encode(our_pub.as_bytes()),
                    owner_session_id: our_session_id,
                    wrapped_session_key_b64: wrapped,
                    nonce_b64: String::new(), // nonce is embedded in `wrapped` per passphrase::wrap
                };
                if let Ok(env) = crate::crypto::sign_message(&self.identity, &response) {
                    if let Ok(bytes) = crate::network::protocol::encode_wire_signed(&env) {
                        self.network
                            .publish_room_message(room_id.to_string(), bytes)
                            .await;
                    }
                }
                info!(%joiner_fp, %room_id, "issued CodeJoinResponse");
            }
            RoomMessage::CodeJoinResponse {
                room_id: announced_room_id,
                target_fingerprint,
                owner_x25519_pubkey_b64,
                owner_session_id,
                wrapped_session_key_b64,
                nonce_b64: _,
            } => {
                if announced_room_id != room_id || target_fingerprint != our_fp {
                    return;
                }
                let owner_fp = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!("CodeJoinResponse unsigned; dropping");
                        return;
                    }
                };
                let our_secret = match self
                    .pending_code_secrets
                    .lock()
                    .unwrap()
                    .remove(room_id)
                {
                    Some(s) => s,
                    None => {
                        warn!(%room_id, "CodeJoinResponse with no pending code-join state");
                        return;
                    }
                };
                let owner_pub = match crate::crypto::sas::parse_pubkey(&owner_x25519_pubkey_b64) {
                    Ok(pk) => pk,
                    Err(e) => {
                        warn!(%e, "CodeJoinResponse: bad owner pubkey");
                        return;
                    }
                };
                let shared = our_secret.diffie_hellman(&owner_pub);
                let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, shared.as_bytes());
                let mut wrap_key = [0u8; passphrase::KEY_LEN];
                hk.expand(b"huddle-code-join-v1", &mut wrap_key)
                    .expect("32 bytes within HKDF limits");
                let session_key_bytes =
                    match passphrase::unwrap(&wrapped_session_key_b64, &wrap_key) {
                        Ok(b) => b,
                        Err(e) => {
                            warn!(%e, "CodeJoinResponse: unwrap failed");
                            return;
                        }
                    };
                let session_key_str = match String::from_utf8(session_key_bytes) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(%e, "CodeJoinResponse: session key wasn't valid utf8");
                        return;
                    }
                };
                // Install as an inbound session keyed by the owner's fp.
                let mut rooms = self.active_rooms.lock().unwrap();
                if let Some(room) = rooms.get_mut(room_id) {
                    if let Some(crypto) = room.crypto.as_mut() {
                        if let Err(e) =
                            crypto.add_inbound_session(&owner_fp, &session_key_str)
                        {
                            warn!(%e, "CodeJoinResponse: add_inbound_session failed");
                        } else {
                            info!(%room_id, %owner_fp, %owner_session_id, "code-join completed; can decrypt owner's messages");
                            room.members.insert(owner_fp.clone());
                            let _ = self.app_event_tx.send(AppEvent::MemberJoined {
                                room_id: room_id.to_string(),
                                fingerprint: owner_fp,
                            });
                        }
                    }
                }
            }
            RoomMessage::JoinRefused {
                room_id: announced_room_id,
                target_fingerprint,
                reason,
            } => {
                if announced_room_id != room_id || target_fingerprint != our_fp {
                    return;
                }
                // Surface the refusal as an Error so the user sees why
                // their join didn't take. The Phase 3 modal-queue rule
                // means this won't clobber typing in another modal.
                let _ = self.app_event_tx.send(AppEvent::Error {
                    description: format!("join refused: {reason}"),
                });
            }
            RoomMessage::SasConfirm { tx_id, matched } => {
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => return,
                };
                let (room_id_done, partner_fp_done, both_done) = {
                    let mut flows = self.sas_flows.lock().unwrap();
                    let flow = match flows.get_mut(&tx_id) {
                        Some(f) => f,
                        None => return,
                    };
                    if flow.partner_fingerprint != signer {
                        return;
                    }
                    if !matched {
                        // Partner declined / mismatch — drop the flow.
                        let _ = flow;
                        flows.remove(&tx_id);
                        return;
                    }
                    flow.their_confirmed = true;
                    if flow.our_confirmed && flow.their_confirmed {
                        (
                            Some(flow.room_id.clone()),
                            Some(flow.partner_fingerprint.clone()),
                            true,
                        )
                    } else {
                        (None, None, false)
                    }
                };
                if both_done {
                    if let (Some(rid), Some(pfp)) = (room_id_done, partner_fp_done) {
                        if let Err(e) = self.finish_sas(&tx_id, &rid, &pfp).await {
                            warn!(%e, "finish_sas failed");
                        }
                    }
                }
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
            content_hash: encrypted_meta_opt.as_ref().map(|m| m.content_hash.clone()),
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
        if let Ok(bytes) = encode_wire(&offer) {
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
                if let Ok(bytes) = encode_wire(&msg) {
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
        // Our own encrypted attachment: the file_manager cache holds the
        // ciphertext and we have no inbound Megolm session keyed by
        // ourselves, so it can't be decrypted back. But `saved_path` still
        // points at the original plaintext we sent — copy from there.
        let plaintext = if attachment.encrypted
            && attachment.sender_fingerprint == self.identity.fingerprint()
        {
            match attachment
                .saved_path
                .as_deref()
                .filter(|p| Path::new(p).exists())
            {
                Some(src) => std::fs::read(src)?,
                None => {
                    return Err(HuddleError::Other(
                        "your original file has moved or been deleted — it can't be \
                         recovered from the encrypted cache"
                            .into(),
                    ));
                }
            }
        } else {
            let cached = self.file_manager.read_cache(file_id)?;
            if attachment.encrypted {
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
                    content_hash: attachment
                        .content_hash
                        .clone()
                        .ok_or_else(|| HuddleError::Other("missing content_hash".into()))?,
                };
                self.decrypt_attachment(
                    room_id,
                    &attachment.sender_fingerprint,
                    &cached,
                    &meta,
                )?
            } else {
                cached
            }
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
                    ed25519_pubkey: None,
                    role: "member".into(),
                },
            )?;
        }
        repo::set_member_verified(&self.db, room_id, fingerprint, verified)
    }

    pub fn verified_fingerprints(&self, room_id: &str) -> Vec<String> {
        repo::list_verified_fingerprints(&self.db, room_id).unwrap_or_default()
    }

    /// Phase B: is `fingerprint` an owner of `room_id`? Used by the TUI
    /// to gate `^K` / `^G` and the kick/grant member-picker actions.
    pub fn is_owner(&self, room_id: &str, fingerprint: &str) -> bool {
        repo::list_room_owners(&self.db, room_id)
            .unwrap_or_default()
            .iter()
            .any(|fp| fp == fingerprint)
    }

    pub fn we_are_owner(&self, room_id: &str) -> bool {
        self.is_owner(room_id, &self.identity.fingerprint().to_string())
    }

    /// Phase B: list current owner fingerprints for `room_id` — used to
    /// render an owner badge in the member panel.
    pub fn room_owners(&self, room_id: &str) -> Vec<String> {
        repo::list_room_owners(&self.db, room_id).unwrap_or_default()
    }

    /// Phase E: global toggle — when true, inbound dials from
    /// unverified fingerprints are auto-rejected without prompting.
    pub fn verified_only_inbound(&self) -> bool {
        repo::get_setting(&self.db, "verified_only_inbound")
            .unwrap_or(None)
            .map(|v| v == "1")
            .unwrap_or(false)
    }

    pub fn set_verified_only_inbound(&self, on: bool) -> Result<()> {
        repo::set_setting(&self.db, "verified_only_inbound", if on { "1" } else { "0" })
    }

    /// Phase E: per-room verified-only-join. When true, the host (and
    /// every honest existing member) drops MemberAnnounce from joiners
    /// who aren't globally SAS-verified, and the lowest-fp owner sends
    /// back a signed `JoinRefused` so the joiner sees an explanation.
    pub fn room_verified_only(&self, room_id: &str) -> bool {
        repo::get_room_verified_only(&self.db, room_id).unwrap_or(false)
    }

    pub fn set_room_verified_only(&self, room_id: &str, on: bool) -> Result<()> {
        repo::set_room_verified_only(&self.db, room_id, on)
    }

    /// Phase H: first-launch onboarding flag.
    pub fn onboarding_seen(&self) -> bool {
        repo::is_onboarding_seen(&self.db).unwrap_or(true)
    }

    pub fn mark_onboarding_seen(&self) -> Result<()> {
        repo::mark_onboarding_seen(&self.db)
    }

    /// Phase B: promote `target_fingerprint` to owner. Builds a signed
    /// `OwnerGrant`, broadcasts it, and applies it locally. Returns an
    /// error if we ourselves aren't an owner — only owners can grant.
    pub async fn grant_owner(&self, room_id: &str, target_fingerprint: &str) -> Result<()> {
        let our_fp = self.identity.fingerprint().to_string();
        if !self.is_owner(room_id, &our_fp) {
            return Err(HuddleError::Other(
                "only an owner can grant owner".into(),
            ));
        }
        let msg = RoomMessage::OwnerGrant {
            room_id: room_id.to_string(),
            target_fingerprint: target_fingerprint.to_string(),
        };
        let env = crate::crypto::sign_message(&self.identity, &msg)?;
        let bytes = crate::network::protocol::encode_wire_signed(&env)?;
        self.network
            .publish_room_message(room_id.to_string(), bytes)
            .await;
        // Apply locally too — peers will converge on the next announce.
        repo::set_member_role(&self.db, room_id, target_fingerprint, "owner")?;
        Ok(())
    }

    /// Phase B: kick `target_fingerprint` from `room_id`. Broadcasts a
    /// signed `BanMember`, records the ban locally, then immediately
    /// rotates the room key under a freshly-generated passphrase. Returns
    /// the new passphrase so the caller can show it to the owner for
    /// out-of-band sharing with remaining members.
    ///
    /// The rotation is the cryptographic enforcement: a banned peer can
    /// still subscribe to the gossipsub topic and see the ciphertext,
    /// but they can't unwrap the new session key without the new
    /// passphrase, so they can't decrypt anything sent after the kick.
    pub async fn kick_member(
        &self,
        room_id: &str,
        target_fingerprint: &str,
    ) -> Result<String> {
        let our_fp = self.identity.fingerprint().to_string();
        if !self.is_owner(room_id, &our_fp) {
            return Err(HuddleError::Other("only an owner can kick".into()));
        }
        if target_fingerprint == our_fp {
            return Err(HuddleError::Other("can't kick yourself".into()));
        }
        let info = self
            .active_rooms
            .lock()
            .unwrap()
            .get(room_id)
            .map(|r| r.info.clone())
            .ok_or_else(|| HuddleError::Other(format!("not in room {room_id}")))?;
        if !info.encrypted {
            // Without a key to rotate, a "kick" is purely advisory —
            // ban only. Honest clients drop their messages, but anyone
            // can still read the room. Honest in v1; documented.
            let msg = RoomMessage::BanMember {
                room_id: room_id.to_string(),
                target_fingerprint: target_fingerprint.to_string(),
            };
            let env = crate::crypto::sign_message(&self.identity, &msg)?;
            let bytes = crate::network::protocol::encode_wire_signed(&env)?;
            self.network
                .publish_room_message(room_id.to_string(), bytes)
                .await;
            repo::add_room_ban(
                &self.db,
                room_id,
                target_fingerprint,
                &our_fp,
                &env.signature_b64,
                now_unix(),
            )?;
            self.evict_banned_member(room_id, target_fingerprint);
            return Ok(String::new());
        }
        // Encrypted room — full kick path.
        let new_passphrase = generate_join_passphrase();
        let msg = RoomMessage::BanMember {
            room_id: room_id.to_string(),
            target_fingerprint: target_fingerprint.to_string(),
        };
        let env = crate::crypto::sign_message(&self.identity, &msg)?;
        let bytes = crate::network::protocol::encode_wire_signed(&env)?;
        self.network
            .publish_room_message(room_id.to_string(), bytes)
            .await;
        repo::add_room_ban(
            &self.db,
            room_id,
            target_fingerprint,
            &our_fp,
            &env.signature_b64,
            now_unix(),
        )?;
        self.evict_banned_member(room_id, target_fingerprint);
        // Reuse the existing rotation flow so all the existing salt /
        // session / persistence logic stays in one place.
        self.rotate_room(room_id, &new_passphrase).await?;
        Ok(new_passphrase)
    }

    /// Phase F: generate an 8-char alphanumeric join code for `room_id`,
    /// good for 10 minutes. Stored in memory only on the issuing owner's
    /// machine — a single use clears it. Caller is responsible for
    /// sharing the code OOB with the prospective joiner.
    ///
    /// Owner-only. Errors if `room_id` isn't active or we're not an owner.
    pub fn generate_join_code(&self, room_id: &str) -> Result<String> {
        let our_fp = self.identity.fingerprint().to_string();
        if !self.is_owner(room_id, &our_fp) {
            return Err(HuddleError::Other(
                "only an owner can issue join codes".into(),
            ));
        }
        let code = generate_alphanumeric_code(8);
        let expires_at = now_unix() + 10 * 60;
        let mut rooms = self.active_rooms.lock().unwrap();
        let room = rooms
            .get_mut(room_id)
            .ok_or_else(|| HuddleError::Other(format!("not in room {room_id}")))?;
        // Prune expired entries while we're here so the list doesn't grow.
        let now = now_unix();
        room.issued_codes.retain(|(_, exp)| *exp > now);
        room.issued_codes.push((code.clone(), expires_at));
        Ok(code)
    }

    /// Phase F: join `room_id` using a short-lived code instead of the
    /// passphrase. Generates an ephemeral X25519 keypair, broadcasts a
    /// signed `CodeJoinRequest`, and waits for the owner's
    /// `CodeJoinResponse`. The receive arm builds an `ActiveRoom`
    /// flagged read-only (no passphrase = can't share our outbound
    /// session key with others).
    pub async fn join_room_with_code(
        &self,
        room_id: &str,
        code: &str,
    ) -> Result<()> {
        // Resolve discovered metadata so we know name/encrypted/etc.
        let info = {
            let d = self.discovered_rooms.lock().unwrap().get(room_id).cloned();
            match d {
                Some(d) => StoredRoom {
                    id: room_id.to_string(),
                    name: d.name,
                    creator_fingerprint: d.creator_fingerprint,
                    encrypted: d.encrypted,
                    passphrase_salt: None, // unused on code-join path
                    created_at: now_unix(),
                    last_active: Some(now_unix()),
                },
                None => {
                    return Err(HuddleError::Other(format!(
                        "room {room_id} not visible — wait for an announcement"
                    )))
                }
            }
        };
        if !info.encrypted {
            return Err(HuddleError::Other(
                "code-join only applies to encrypted rooms".into(),
            ));
        }
        let our_fp = self.identity.fingerprint().to_string();
        // Generate ephemeral X25519 keypair; remember the secret so the
        // CodeJoinResponse receive arm can complete ECDH on this peer.
        use x25519_dalek::{PublicKey, StaticSecret};
        let our_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let our_pub = PublicKey::from(&our_secret);
        // Stash the secret keyed by room_id; the response handler
        // matches on target_fingerprint=our_fp + room_id.
        self.pending_code_secrets
            .lock()
            .unwrap()
            .insert(room_id.to_string(), our_secret);
        // Create a placeholder ActiveRoom with no crypto yet; we'll
        // fill in the inbound session in the response handler.
        self.active_rooms.lock().unwrap().insert(
            room_id.to_string(),
            ActiveRoom {
                info: info.clone(),
                crypto: Some(RoomCrypto::new_for_room(
                    self.db.clone(),
                    room_id.to_string(),
                    our_fp.clone(),
                    self.session_persist_key,
                )?),
                passphrase_key: None,
                members: {
                    let mut s = HashSet::new();
                    s.insert(our_fp.clone());
                    s
                },
                typers: HashMap::new(),
                read_only: true,
                issued_codes: Vec::new(),
            },
        );
        self.network.subscribe_room(room_id.to_string()).await;
        // Broadcast the request.
        let req = RoomMessage::CodeJoinRequest {
            room_id: room_id.to_string(),
            joiner_x25519_pubkey_b64: B64.encode(our_pub.as_bytes()),
            code: code.to_string(),
        };
        let env = crate::crypto::sign_message(&self.identity, &req)?;
        let bytes = crate::network::protocol::encode_wire_signed(&env)?;
        self.network
            .publish_room_message(room_id.to_string(), bytes)
            .await;
        // Emit RoomJoined so the TUI opens the tab. Subsequent ability
        // to read messages depends on receiving the owner's response.
        let _ = self.app_event_tx.send(AppEvent::RoomJoined {
            room_id: room_id.to_string(),
        });
        Ok(())
    }

    /// Phase G: start an SAS verification with `target_fingerprint` in
    /// `room_id`. Returns the tx_id so the caller can correlate
    /// subsequent events. The full flow is asynchronous — the partner
    /// must accept on their end, both compute the ECDH-derived SAS
    /// code, OOB-compare it, and each press Match.
    pub async fn sas_start(&self, room_id: &str, target_fingerprint: &str) -> Result<String> {
        let (tx_id_bytes, our_secret, our_pub) = crate::crypto::sas::new_session();
        let tx_id = B64.encode(tx_id_bytes);
        let msg = RoomMessage::SasInit {
            tx_id: tx_id.clone(),
            ephemeral_x25519_pubkey_b64: B64.encode(our_pub.as_bytes()),
            target_fingerprint: target_fingerprint.to_string(),
        };
        let env = crate::crypto::sign_message(&self.identity, &msg)?;
        let bytes = crate::network::protocol::encode_wire_signed(&env)?;
        self.sas_flows.lock().unwrap().insert(
            tx_id.clone(),
            SasFlow {
                room_id: room_id.to_string(),
                partner_fingerprint: target_fingerprint.to_string(),
                our_secret,
                sas_code: None,
                our_confirmed: false,
                their_confirmed: false,
            },
        );
        self.network
            .publish_room_message(room_id.to_string(), bytes)
            .await;
        Ok(tx_id)
    }

    /// Phase G: user pressed Match on the SAS code modal — broadcast our
    /// signed `SasConfirm{matched: true}`. If the partner has already
    /// matched, this completes verification on both sides.
    pub async fn sas_match(&self, tx_id: &str) -> Result<()> {
        let (room_id, partner_fp, both_done) = {
            let mut flows = self.sas_flows.lock().unwrap();
            let flow = flows
                .get_mut(tx_id)
                .ok_or_else(|| HuddleError::Other("unknown SAS tx_id".into()))?;
            flow.our_confirmed = true;
            (
                flow.room_id.clone(),
                flow.partner_fingerprint.clone(),
                flow.our_confirmed && flow.their_confirmed,
            )
        };
        let msg = RoomMessage::SasConfirm {
            tx_id: tx_id.to_string(),
            matched: true,
        };
        let env = crate::crypto::sign_message(&self.identity, &msg)?;
        let bytes = crate::network::protocol::encode_wire_signed(&env)?;
        self.network
            .publish_room_message(room_id.clone(), bytes)
            .await;
        if both_done {
            self.finish_sas(tx_id, &room_id, &partner_fp).await?;
        }
        Ok(())
    }

    /// Phase G: cancel an in-flight SAS — drop our local state. Doesn't
    /// broadcast a "matched=false" notice in v1 (partner's flow stays
    /// dangling; they can cancel their side too). Quiet teardown.
    pub fn sas_cancel(&self, tx_id: &str) {
        self.sas_flows.lock().unwrap().remove(tx_id);
    }

    /// Phase G internal: both sides have confirmed — flip the partner's
    /// fingerprint to verified (per-room AND global) and clean up.
    async fn finish_sas(
        &self,
        tx_id: &str,
        room_id: &str,
        partner_fingerprint: &str,
    ) -> Result<()> {
        repo::set_member_verified(&self.db, room_id, partner_fingerprint, true)?;
        repo::add_verified_peer(&self.db, partner_fingerprint, now_unix())?;
        self.sas_flows.lock().unwrap().remove(tx_id);
        let _ = self.app_event_tx.send(AppEvent::SasVerified {
            room_id: room_id.to_string(),
            partner_fingerprint: partner_fingerprint.to_string(),
        });
        Ok(())
    }

    /// Phase B internal: drop a banned member's in-memory presence in a
    /// room. Persistent ban already went to `room_bans`. Called from
    /// `kick_member` (locally banning ourselves) and from the
    /// `RoomMessage::BanMember` receive arm (peer-initiated ban).
    fn evict_banned_member(&self, room_id: &str, fingerprint: &str) {
        if let Some(room) = self.active_rooms.lock().unwrap().get_mut(room_id) {
            room.members.remove(fingerprint);
        }
        let _ = self.app_event_tx.send(AppEvent::MemberLeft {
            room_id: room_id.to_string(),
            fingerprint: fingerprint.to_string(),
        });
    }

    pub fn display_name(&self) -> Option<String> {
        repo::get_display_name(&self.db).unwrap_or(None)
    }

    pub fn set_display_name(&self, name: Option<&str>) -> Result<()> {
        repo::set_display_name(&self.db, name)
    }

    /// Look up the display name we've seen for a peer in any room.
    pub fn lookup_member_display_name(&self, fingerprint: &str) -> Option<String> {
        repo::lookup_display_name(&self.db, fingerprint).unwrap_or(None)
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
        if let Ok(bytes) = encode_wire(&msg) {
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
                self.session_persist_key,
            )?;
            room.crypto = Some(new_crypto);
            room.passphrase_key = Some(new_key);
            room.info.passphrase_salt = Some(new_salt.to_vec());
            room.info.clone()
        };

        // Broadcast before persisting: peers learn about the rotation even
        // if we crash before the DB write lands, and our own restore path
        // can recover from the persisted Megolm session plus the announced
        // salt. Persisting first would risk a DB row that's ahead of what
        // any peer knows.
        let rot = RoomMessage::RotateRoomKey {
            rotator_fingerprint: self.identity.fingerprint().to_string(),
            new_salt: new_salt.to_vec(),
        };
        if let Ok(bytes) = encode_wire(&rot) {
            self.network
                .publish_room_message(room_id.to_string(), bytes)
                .await;
        }
        // Re-announce ourselves with the new wrapped session key.
        if let Err(e) = self.broadcast_member_announce(room_id).await {
            warn!(%e, "rotate: broadcast announce failed");
        }

        // Now persist the new salt on the stored row.
        repo::insert_room(&self.db, &info)?;
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
        // Ask the rotator (and anyone) to re-share their session key
        // before persisting, so a crash before the DB write still leaves
        // peers aware we've moved to the new salt.
        let req = RoomMessage::SessionKeyRequest {
            requester_fingerprint: self.identity.fingerprint().to_string(),
        };
        if let Ok(bytes) = encode_wire(&req) {
            self.network
                .publish_room_message(room_id.to_string(), bytes)
                .await;
        }
        repo::insert_room(&self.db, &info)?;
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
            content_hash: encrypted_meta.as_ref().map(|m| m.content_hash.clone()),
            created_at: now_unix(),
        };
        if let Err(e) = repo::upsert_attachment(&self.db, &attachment) {
            warn!(%e, "upsert attachment");
            return;
        }
        // If chunks started arriving before this offer, the transfer's
        // size denominator was a guess — correct it with the real size.
        self.file_manager.set_expected_size(&file_id, size_bytes);
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
        // Pull the announced size + lifecycle state from our stored offer.
        // A terminal-state row means the user cancelled or the transfer
        // already failed — late chunks must not resurrect it.
        let expected_size = match repo::get_attachment(&self.db, room_id, &file_id) {
            Ok(Some(a)) => {
                if matches!(
                    a.status,
                    AttachmentStatus::Cancelled | AttachmentStatus::Failed
                ) {
                    return;
                }
                a.size_bytes as u64
            }
            Ok(None) => crate::files::MAX_FILE_SIZE,
            Err(e) => {
                warn!(%e, "get attachment for chunk");
                crate::files::MAX_FILE_SIZE
            }
        };

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
        let full = self.identity.fingerprint().to_lowercase();
        // First hex group, e.g. "a3b1" of "a3b1-c2d4-...".
        let short: &str = full.split('-').next().unwrap_or(&full);
        let lower = body.to_lowercase();
        // The full fingerprint anywhere counts; the short form counts only
        // as a standalone hex token, so it can't match an arbitrary
        // substring of an unrelated hash, URL, or word.
        let hit = lower.contains(full.as_str())
            || lower
                .split(|c: char| !c.is_ascii_hexdigit())
                .any(|tok| tok == short);
        if hit {
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

/// Phase B: generate a fresh 24-char base64-ish passphrase for the
/// rotation that follows a kick. Sourced from `OsRng` directly so the
/// kicker doesn't have to think up a strong one on the spot. Returned
/// to the owner via the kick-result modal for OOB sharing with the
/// remaining members.
fn generate_join_passphrase() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    // Use URL-safe-no-pad so the user can read aloud / paste without
    // worrying about `=` padding or `+` getting URL-escaped.
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Phase F: short human-readable join code. 8 chars from a 32-symbol
/// alphabet (no easily-confused chars like 0/O/I/1) ≈ 40 bits — plenty
/// for a 10-minute online gate since the owner's client checks
/// exact-match (not brute-force-able offline).
fn generate_alphanumeric_code(len: usize) -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    let mut out = String::with_capacity(len + 1);
    for i in 0..len {
        if i == 4 && len == 8 {
            out.push('-'); // pretty: XXXX-XXXX
        }
        let idx = rng.gen_range(0..ALPHABET.len());
        out.push(ALPHABET[idx] as char);
    }
    out
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
