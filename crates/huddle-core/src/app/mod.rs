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
use crate::network::server::{ServerClient, ServerEvent};
use crate::network::protocol::{encode_wire, RoomAnnouncement, RoomMessage, WireMessage};
use crate::network::transport::{self, TransportId, TransportProfile};
use crate::network::{self, NetworkHandle, NetworkMode};
use crate::storage::repo::{
    self, derive_room_id, AttachmentStatus, KnownPeer, RoomKind, StoredAttachment, StoredRoom,
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
    /// Ed25519 fingerprint learned from libp2p Identify. `None` until
    /// the first successful connect completes. The TUI uses this to
    /// resolve usernames + start DMs against the dialed peer.
    pub fingerprint: Option<String>,
}

/// huddle 1.0: a unified, display-ready contact assembled from the durable
/// `contacts` address book joined with live, derived state. Unlike
/// [`KnownPeerStatus`] (one row per ephemeral libp2p multiaddr), this is
/// keyed by the stable fingerprint, so it survives a peer leaving the LAN —
/// the durable link that lets two people keep chatting over the relay.
#[derive(Debug, Clone)]
pub struct ContactView {
    pub fingerprint: String,
    /// User-chosen alias, if set.
    pub alias: Option<String>,
    /// Signed self-declared username from `peer_profiles`, if any.
    pub username: Option<String>,
    /// Canonical DM room id for one-step messaging.
    pub dm_room_id: String,
    pub verified: bool,
    pub trusted: bool,
    /// True when we currently have *any* live path to the peer: a libp2p
    /// connection (LAN/direct) OR the relay is up (reachable via mailbox).
    pub reachable: bool,
    /// True specifically when a direct libp2p connection is live (LAN).
    pub lan_connected: bool,
    /// How the contact entered the book: dm / request / dial / lan / invite.
    pub source: String,
    pub added_at: i64,
    pub last_seen: Option<i64>,
}

/// huddle 0.7: compute the deterministic room_id for a 1-1 DM between two
/// fingerprints. Both peers, regardless of who calls `start_direct` first,
/// derive identical IDs — no `created_at` mixing, no creator-fingerprint
/// asymmetry. The pair is sorted lexicographically so the function is
/// commutative.
///
/// Format: `hex(sha256("huddle-dm-v1\0" || min(a, b) || "\0" || max(a, b)))`
/// truncated to 16 bytes (32 hex chars), matching the `derive_room_id`
/// output length so the new DM IDs are indistinguishable from group IDs
/// at the topic-name layer (small attacker uniformity benefit).
pub fn canonical_dm_room_id(a: &str, b: &str) -> String {
    use sha2::{Digest, Sha256};
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut hasher = Sha256::new();
    hasher.update(b"huddle-dm-v1\0");
    hasher.update(lo.as_bytes());
    hasher.update(b"\0");
    hasher.update(hi.as_bytes());
    hex::encode(&hasher.finalize()[..16])
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
    /// huddle 0.7.11: latch that flips true the first time `finish_sas`
    /// runs for this flow. Prevents a race between `sas_match` and the
    /// inbound `SasConfirm{matched:true}` handler both observing
    /// `both_done = true` and each calling `finish_sas` — pre-0.7.11
    /// that double-fired `SasVerified` and re-ran the DB writes.
    finalized: bool,
}

/// huddle 0.8: the canonical centralized server, reachable only as a Tor
/// v3 onion. Baked in so the client connects to the operator's relay by
/// default; override with the `--server <ws-url>` CLI flag, disable with
/// `--no-server`. Reached through the local Tor SOCKS5 proxy.
pub const DEFAULT_SERVER_URL: &str =
    "ws://huddleg2647kbrmngflqai23f4rrc7l5dnszz5lij76uhqzmkebx2mid.onion:80/ws";
/// Local Tor SOCKS5 proxy used to dial `.onion` server URLs.
pub const DEFAULT_TOR_SOCKS: &str = "127.0.0.1:9050";

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
    /// they wait for the owner's `CodeJoinResponse`. Keyed by
    /// `(room_id, joiner_fp)` so multiple joiners in the same room can
    /// be in flight concurrently without trampling each other; and so
    /// the 30s timeout task (see `join_room_with_code`) can clean up
    /// its own entry by composite key without racing with peers.
    pending_code_secrets:
        Arc<Mutex<HashMap<(String, String), x25519_dalek::StaticSecret>>>,
    /// Phase C follow-up: tracks "we dialed this multiaddr because of
    /// an invite link claiming this fingerprint." When the peer
    /// identifies (and we can derive their real fp), the post-dial arm
    /// looks the multiaddr up here and compares — if the claimed and
    /// derived fingerprints don't match, we disconnect and surface
    /// an `InviteFingerprintMismatch` event.
    ///
    /// libp2p's `/p2p/<peer-id>` segment already enforces this at the
    /// transport level when present (and our invite generator always
    /// includes it), so this is defense in depth — but it also makes
    /// the assert explicit so future invite-format changes can't slip
    /// in a forgeable fingerprint label.
    pending_invite_dials: Arc<Mutex<HashMap<String, String>>>,
    /// Phase D follow-up: addresses confirmed reachable by AutoNAT v2
    /// probes. We emit a `NatStatusChanged` whenever this set
    /// transitions between empty (private / undetected) and
    /// non-empty (reachable), so the TUI badge doesn't flap on every
    /// individual probe.
    nat_reachable_addrs: Arc<Mutex<HashSet<String>>>,
    /// Phase D follow-up: `/p2p-circuit` reservation addresses we've
    /// established via configured relays. These are populated when
    /// `RelayReservationEstablished` arrives and feed into the
    /// `RoomAnnouncement.host_addrs` field so cross-internet peers
    /// can bootstrap without an invite link.
    relay_circuit_addrs: Arc<Mutex<HashSet<String>>>,
    /// Phase D follow-up: per-creator-fingerprint last-dial timestamp.
    /// Throttles the opportunistic dial we issue when an announcement
    /// arrives carrying `host_addrs` — we re-dial the same announcer
    /// at most once per `HOST_ADDR_DIAL_BACKOFF_SECS`.
    host_addr_dial_attempts: Arc<Mutex<HashMap<String, i64>>>,
    /// huddle 0.5: per-peer last-broadcast timestamp (ms) for our own
    /// `ProfileUpdate`. The `PeerIdentified` handler re-broadcasts our
    /// current username to a newly-identified peer so they learn it
    /// without waiting for a change, but we dedupe with a
    /// `PROFILE_REBROADCAST_FLOOR_MS` floor so a noisy reconnect cycle
    /// doesn't spam the gossipsub mesh.
    last_profile_broadcast_at_ms: Arc<Mutex<HashMap<String, i64>>>,
    /// huddle 0.7.7: addresses the local user just initiated a dial on
    /// (`d` / `a` / paste-invite). When `PeerIdentified` lands for one
    /// of these, we open (or reuse) a DM with the identified peer and
    /// emit `AutoOpenDm` so the TUI can switch into the new pane. The
    /// set is consumed on use, so a passive auto-reconnect or an
    /// inbound dial never triggers the auto-DM.
    pending_auto_dm_addrs: Arc<Mutex<HashSet<String>>>,
    app_event_tx: broadcast::Sender<AppEvent>,
    /// huddle 0.8: whether a centralized-server URL was configured at
    /// startup (i.e. NOT `--no-server`). Drives the TUI relay badge: with
    /// no server configured we show nothing, rather than a permanently
    /// "disconnected" indicator. Set once at construction, never changes.
    server_enabled: bool,
    /// huddle 1.0: relay room ids we subscribe to that aren't chat rooms —
    /// currently just our own `inbox_room_id` for contact requests. Kept
    /// separate from `active_rooms` so they don't appear in the sidebar, but
    /// chained into the `Hello` room set so the relay re-registers the
    /// membership on every reconnect (otherwise inbox requests are missed
    /// after a reconnect).
    aux_subscriptions: Arc<Mutex<HashSet<String>>>,
    /// huddle 1.0: which transport "door" the relay connection is currently
    /// using (set on connect, cleared on disconnect). Surfaced in the UI/CLI
    /// so the user knows which anti-censorship path is live.
    active_transport: Arc<Mutex<Option<TransportId>>>,
    /// huddle 1.0: the full set of transport doors resolved at startup (for
    /// the UI/CLI listing — includes unavailable ones with a reason).
    transport_profiles: Arc<Vec<TransportProfile>>,
}

/// huddle 1.0: how to reach the relay backend — the bundle of transport
/// inputs resolved by `main.rs` (CLI + config) and handed to the core. The
/// core turns these into the ordered set of [`TransportProfile`] doors.
#[derive(Clone, Default)]
pub struct TransportConfig {
    /// The onion relay ws URL (`ws://<onion>.onion:80/ws`), or `None` for
    /// `--no-server`. Resolved by the caller (includes the baked-in default).
    pub onion_url: Option<String>,
    /// A clearnet relay URL — `ws://<ip>:<port>/ws` or `wss://host/ws`. The
    /// scheme decides which clearnet door (plain / TLS) is usable.
    pub clearnet_url: Option<String>,
    /// Local Tor SOCKS5 proxy (`None` → `DEFAULT_TOR_SOCKS`).
    pub tor_socks: Option<String>,
    /// Optional bridge line for the bridge door (Arti build / labeling).
    pub tor_bridge: Option<String>,
    /// Pin a single door by [`TransportId::as_str`] (CLI `--transport`).
    pub pin: Option<String>,
    /// Explicit fallback order as `TransportId::as_str` tokens (CLI
    /// `--transport-order`).
    pub order: Option<Vec<String>>,
}

impl TransportConfig {
    /// An onion-only config (the common case + most tests).
    pub fn onion_only(url: impl Into<String>) -> Self {
        Self {
            onion_url: Some(url.into()),
            ..Default::default()
        }
    }
}

/// huddle 1.0: how a conversation's messages are currently reaching the
/// other side. Status only — the app always picks the path automatically;
/// this just makes the security context legible per chat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomTransport {
    /// A live libp2p connection to a member (same LAN or a direct dial).
    LanDirect,
    /// No direct connection, but the relay is up (messages ride the relay /
    /// its offline mailbox).
    Relay,
    /// Neither a direct connection nor the relay — messages only save locally.
    Offline,
}

impl RoomTransport {
    pub fn label(&self) -> &'static str {
        match self {
            RoomTransport::LanDirect => "lan",
            RoomTransport::Relay => "relay",
            RoomTransport::Offline => "offline",
        }
    }
}

/// Phase D follow-up: minimum seconds between two opportunistic
/// `host_addrs` dials to the same announcer fingerprint.
const HOST_ADDR_DIAL_BACKOFF_SECS: i64 = 300;

/// huddle 0.5: minimum ms between two `PeerIdentified`-triggered
/// re-broadcasts of our own `ProfileUpdate` to the same peer
/// fingerprint. Prevents storm-on-reconnect on flaky transports.
const PROFILE_REBROADCAST_FLOOR_MS: i64 = 60_000;

impl AppHandle {
    pub async fn start() -> Result<Self> {
        Self::start_with_options(NetworkMode::Server, 0, None, Vec::new(), TransportConfig::default())
            .await
    }

    /// huddle 0.7.8: peek the persisted `mdns_enabled` setting without
    /// starting the full AppHandle. Called by the client (`main.rs` /
    /// huddle-gui) before `start_with_options` so the initial
    /// `NetworkMode` reflects the user's saved preference — the in-app
    /// "run LAN mDNS alongside the relay" toggle. The CLI `--mode` flag,
    /// when present, still wins; clients only consult this when `--mode`
    /// is absent.
    ///
    /// huddle 0.9.2: defaults **OFF** when unset. Since 0.8 the relay-only
    /// `Server` mode is the default and libp2p is strictly opt-in, so an
    /// unset preference must mean "no LAN swarm". (Pre-0.7.8 this defaulted
    /// ON; that default predated the onion relay becoming the baseline.)
    pub fn peek_mdns_enabled(master_key: Option<&[u8; 32]>) -> Result<bool> {
        config::ensure_data_dir()?;
        let db = storage::open_db(&config::db_path(), master_key)?;
        let v = repo::get_setting(&db, "mdns_enabled")?
            .map(|s| s == "1")
            .unwrap_or(false);
        Ok(v)
    }

    pub async fn start_with_options(
        mode: NetworkMode,
        port: u16,
        master_key: Option<&[u8; 32]>,
        relays: Vec<Multiaddr>,
        transports: TransportConfig,
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
        Self::start_with_db_and_options(db, mode, port, session_persist_key, relays, transports).await
    }

    pub async fn start_with_db(db: Db) -> Result<Self> {
        Self::start_with_db_and_options(
            db,
            NetworkMode::Mdns,
            0,
            [0u8; 32],
            Vec::new(),
            TransportConfig::default(),
        )
        .await
    }

    pub async fn start_with_db_and_options(
        db: Db,
        mode: NetworkMode,
        port: u16,
        session_persist_key: [u8; 32],
        relays: Vec<Multiaddr>,
        transports: TransportConfig,
    ) -> Result<Self> {
        let identity = Self::load_or_create_identity(&db)?;
        let identity = Arc::new(identity);
        info!(fingerprint = %identity.fingerprint(), peer_id = %identity.peer_id(), mode = %mode.as_str(), port, relay_count = relays.len(), "identity loaded");

        let (net_event_tx, net_event_rx) = tokio::sync::mpsc::channel::<NetworkEvent>(256);
        let (app_event_tx, _) = broadcast::channel::<AppEvent>(256);
        // huddle 0.8: the default `Server` mode runs NO libp2p — the Tor
        // onion relay is the only transport. `--mode mdns|direct` opts back
        // into a libp2p swarm running alongside the relay. In `Server` mode
        // `net_event_tx` is simply dropped, so the event processor (which
        // only carries libp2p events) winds down; server messages reach
        // `process_network_event` directly from `spawn_server_connection`.
        let network = if mode.uses_libp2p() {
            network::start_network_with(&identity, net_event_tx, mode, port, relays)?
        } else {
            network::start_network_disabled()
        };

        let active_rooms = Arc::new(Mutex::new(HashMap::new()));
        let discovered_rooms = Arc::new(Mutex::new(HashMap::new()));
        let restorable_rooms = Arc::new(Mutex::new(HashMap::new()));
        let connected_dial_addrs = Arc::new(Mutex::new(HashMap::new()));
        let file_manager = Arc::new(FileManager::new(&config::data_dir())?);

        // huddle 1.0: resolve the transport "doors" + the order to try them.
        // CLI inputs (in `transports`) win over config.toml; the pin/order
        // also fall back to saved settings, then the default most-private-
        // first fallback.
        let tor_socks = transports
            .tor_socks
            .clone()
            .or_else(config::tor_socks)
            .unwrap_or_else(|| DEFAULT_TOR_SOCKS.to_string());
        // huddle 1.0: clearnet relay precedence is CLI/TransportConfig →
        // config.toml → the persisted `clearnet_url` setting (what the GUI's
        // "Set relay" writes). The DB value is filtered for empty so clearing
        // the relay from the GUI (which writes "") resets to no clearnet door.
        let clearnet_url = transports
            .clearnet_url
            .clone()
            .or_else(config::clearnet_url)
            .or_else(|| {
                repo::get_setting(&db, "clearnet_url")
                    .ok()
                    .flatten()
                    .filter(|s| !s.trim().is_empty())
            });
        let tor_bridge = transports.tor_bridge.clone().or_else(config::tor_bridge);
        let transport_profiles = transport::builtin_profiles(
            transports.onion_url.as_deref(),
            clearnet_url.as_deref(),
            &tor_socks,
            tor_bridge.as_deref(),
        );
        let any_relay = transport_profiles.iter().any(|p| p.available());
        let pin = transports
            .pin
            .as_deref()
            .and_then(TransportId::from_str)
            .or_else(|| {
                repo::get_setting(&db, "transport_pin")
                    .ok()
                    .flatten()
                    .as_deref()
                    .and_then(TransportId::from_str)
            });
        let transport_order = if let Some(pin) = pin {
            vec![pin]
        } else {
            transports
                .order
                .as_ref()
                .map(|v| v.iter().filter_map(|s| TransportId::from_str(s)).collect::<Vec<_>>())
                .filter(|v| !v.is_empty())
                .or_else(|| {
                    repo::get_setting(&db, "transport_order")
                        .ok()
                        .flatten()
                        .map(|s| transport::parse_order(&s))
                        .filter(|v| !v.is_empty())
                })
                .unwrap_or_else(transport::default_fallback_order)
        };
        let transport_profiles = Arc::new(transport_profiles);

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
            pending_invite_dials: Arc::new(Mutex::new(HashMap::new())),
            nat_reachable_addrs: Arc::new(Mutex::new(HashSet::new())),
            relay_circuit_addrs: Arc::new(Mutex::new(HashSet::new())),
            host_addr_dial_attempts: Arc::new(Mutex::new(HashMap::new())),
            last_profile_broadcast_at_ms: Arc::new(Mutex::new(HashMap::new())),
            pending_auto_dm_addrs: Arc::new(Mutex::new(HashSet::new())),
            app_event_tx,
            server_enabled: any_relay,
            aux_subscriptions: Arc::new(Mutex::new(HashSet::new())),
            active_transport: Arc::new(Mutex::new(None)),
            transport_profiles: transport_profiles.clone(),
        };

        handle.spawn_event_processor(net_event_rx);
        handle.spawn_announcement_ticker();
        handle.spawn_discovered_room_pruner();
        handle.spawn_known_peer_reconnector();
        handle.restore_rooms_from_db().await;
        // huddle 1.0: subscribe to our own relay inbox so "add by HD-ID"
        // contact requests reach us over the internet, not just over the LAN
        // mesh. Registered in `aux_subscriptions` so the membership is
        // re-asserted in every reconnect's `Hello` (see
        // spawn_server_connection); the live call here also subscribes the
        // gossipsub topic for the LAN path.
        {
            let inbox =
                crate::network::protocol::inbox_room_id(handle.identity.fingerprint());
            handle.aux_subscriptions.lock().unwrap().insert(inbox.clone());
            handle.network.subscribe_room(inbox).await;
        }
        // huddle 0.8/1.0: now that active rooms are loaded, open the
        // persistent relay connection (if any transport door is usable),
        // trying the doors in `transport_order`. Connecting after restore
        // means our `hello` carries the restored room ids + the inbox, so the
        // server registers our memberships and flushes any offline mailbox.
        if any_relay {
            handle.spawn_server_connection(transport_order);
        }
        // huddle 0.7.7: prune any friend requests that aged out while
        // we were offline. Best-effort — a DB failure here shouldn't
        // block startup, so we log and move on.
        if let Err(e) = repo::cleanup_expired_pending_friend_requests(&handle.db, now_unix()) {
            warn!(%e, "failed to sweep expired pending friend requests");
        }
        // huddle 1.0: same 3-day TTL sweep for relay-inbox contact requests.
        if let Err(e) = repo::cleanup_expired_pending_contact_requests(&handle.db, now_unix()) {
            warn!(%e, "failed to sweep expired pending contact requests");
        }

        Ok(handle)
    }

    pub fn mode(&self) -> NetworkMode {
        self.mode
    }

    /// huddle 0.8: whether the centralized-server connection is currently
    /// up. Used by the TUI status line and by tests waiting for connect.
    pub fn server_connected(&self) -> bool {
        self.network.has_server()
    }

    /// huddle 0.8: whether a centralized server was configured at startup
    /// (vs `--no-server` / a `None` server URL). The TUI uses this to
    /// decide whether to render the relay indicator at all — there's no
    /// point showing a "disconnected" badge for a feature the user turned
    /// off.
    pub fn server_enabled(&self) -> bool {
        self.server_enabled
    }

    /// huddle 1.0: the transport door the relay is currently connected
    /// through (`None` when not connected). For the UI/CLI status line.
    pub fn active_transport(&self) -> Option<TransportId> {
        *self.active_transport.lock().unwrap()
    }

    /// Human label for the live transport door, e.g. "Tor onion (system Tor)".
    pub fn active_transport_label(&self) -> Option<&'static str> {
        self.active_transport().map(|id| id.label())
    }

    /// huddle 1.0: all transport doors (available + unavailable-with-reason)
    /// for the Settings pane and the `huddle transports` listing.
    pub fn transport_profiles(&self) -> Vec<TransportProfile> {
        self.transport_profiles.as_ref().clone()
    }

    /// huddle 1.0: how messages to `room_id` are currently reaching peers —
    /// a live libp2p connection (LAN/direct), the relay, or nobody. Used by
    /// the per-chat transport indicator. Status only.
    pub fn room_transport(&self, room_id: &str) -> RoomTransport {
        let members = self.room_members(room_id);
        if !members.is_empty() {
            let connected = self.connected_dial_addrs.lock().unwrap().clone();
            if !connected.is_empty() {
                if let Ok(known) = repo::list_known_peers(&self.db) {
                    let lan_live = known.iter().any(|p| {
                        p.fingerprint.as_deref().is_some_and(|fp| {
                            members.iter().any(|m| m == fp) && connected.contains_key(&p.address)
                        })
                    });
                    if lan_live {
                        return RoomTransport::LanDirect;
                    }
                }
            }
        }
        if self.server_connected() {
            RoomTransport::Relay
        } else {
            RoomTransport::Offline
        }
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

    /// huddle 0.7.11: bind an invite link to our Ed25519 identity by
    /// signing it. The receiver re-derives the fingerprint from the
    /// embedded pubkey and rejects the invite if any signed field
    /// (host_multiaddr, fingerprint, room id/name/encrypted/salt/
    /// creator_fp/owner_list, signed_at_ms) was tampered with.
    pub fn sign_invite(&self, invite: crate::invite::InviteLink) -> Result<crate::invite::InviteLink> {
        crate::invite::sign_invite(&self.identity, invite)
    }

    pub fn discovered_rooms(&self) -> Vec<DiscoveredRoom> {
        let now = now_unix();
        let our_fp = self.identity.fingerprint().to_string();
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
                host_addrs: Vec::new(),
                kind: room.info.kind,
            };
            by_id
                .entry(room.info.id.clone())
                .and_modify(|d| {
                    d.last_seen = now;
                    if entry.member_count > d.member_count {
                        d.member_count = entry.member_count;
                    }
                    d.restorable = false;
                    d.kind = entry.kind;
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
                    host_addrs: Vec::new(),
                    kind: stored.kind,
                },
            );
        }

        // huddle 0.7 DM-visibility filter: drop any `Direct` room we're
        // not a member of. A DM's canonical room_id is
        // `canonical_dm_room_id(fp_a, fp_b)`. If we're one of the pair we
        // pass; otherwise we drop. Honest 0.7+ peers enforce this at the
        // consumer; combined with the canonical-ID scheme it keeps DMs
        // out of any third party's sidebar even if they happen to relay
        // the gossipsub announcement.
        by_id.retain(|room_id, d| {
            if d.kind != RoomKind::Direct {
                return true;
            }
            // Active rooms we host pass unconditionally — we always know
            // we're a member of our own DM.
            if self
                .active_rooms
                .lock()
                .unwrap()
                .contains_key(room_id)
            {
                return true;
            }
            // Otherwise: the announcer must be the other partner, AND
            // the canonical pair must include us.
            canonical_dm_room_id(&our_fp, &d.creator_fingerprint) == *room_id
        });

        let mut v: Vec<DiscoveredRoom> = by_id.into_values().collect();
        v.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        v
    }

    /// huddle 0.7: returns the fingerprint of the other party in a 1-1
    /// DM. `None` for rooms that are `Group`, missing, or somehow have a
    /// non-2-member state. Used by the DM-pane header to render the
    /// partner's username + HD-ID.
    pub fn dm_partner_fingerprint(&self, room_id: &str) -> Option<String> {
        let our_fp = self.identity.fingerprint().to_string();
        let rooms = self.active_rooms.lock().unwrap();
        let room = rooms.get(room_id)?;
        if room.info.kind != RoomKind::Direct {
            return None;
        }
        room.members
            .iter()
            .find(|m| **m != our_fp)
            .cloned()
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
    ///
    /// huddle 0.7: `kind` is now required. `RoomKind::Group` (the default)
    /// preserves pre-0.7 behavior. `RoomKind::Direct` is reserved for
    /// callers that have already computed a deterministic DM room_id via
    /// `canonical_dm_room_id` — most clients should call `start_direct`
    /// instead, which handles idempotency, kind, and naming.
    pub async fn start_room(
        &self,
        name: &str,
        encrypted: bool,
        passphrase: Option<&str>,
        kind: RoomKind,
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
            kind,
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

    /// huddle 0.7.1: start (or open) a 1-1 DM with `partner_fingerprint`.
    ///
    /// Idempotent across peers and reopens:
    /// 1. Refuses to DM yourself.
    /// 2. Computes `room_id = canonical_dm_room_id(our_fp, partner_fp)`.
    ///    Both peers, regardless of who clicks first, derive identical
    ///    IDs.
    /// 3. If a DM room already exists locally (active or stored), returns
    ///    its id — no new room, no second announcement.
    /// 4. Otherwise creates a `RoomKind::Direct`, **end-to-end encrypted**
    ///    room. The key is derived from Ed25519→X25519 ECDH between the
    ///    two parties' identity keys (see `crypto::dm::derive_dm_key`).
    ///    No shared passphrase, no central key agreement — both peers
    ///    independently derive the same 32-byte room key from their
    ///    own seed + the other's pubkey.
    /// 5. If we don't yet know the partner's Ed25519 pubkey, the room
    ///    is still created encrypted; the key is derived lazily once
    ///    `MemberAnnounce` arrives with the partner's pubkey, after
    ///    which we send our wrapped Megolm session key in a follow-up
    ///    announce.
    /// 6. Subscribes to the room topic and announces on the global topic.
    ///    The announcement is visibility-filtered at honest 0.7+ peers,
    ///    so only the partner sees it in their `discovered_rooms()`.
    pub async fn start_direct(&self, partner_fingerprint: &str) -> Result<String> {
        let our_fp = self.identity.fingerprint().to_string();
        if partner_fingerprint == our_fp {
            return Err(HuddleError::Other("cannot DM yourself".into()));
        }
        let room_id = canonical_dm_room_id(&our_fp, partner_fingerprint);

        // huddle 1.0: a DM is a relationship — record the partner in the
        // durable Contacts book so they persist (and stay chattable over the
        // relay) even after they leave the LAN. Idempotent; best-effort.
        let _ = self.add_contact(partner_fingerprint, "dm");

        // Idempotent reopen: if the room already exists on disk or in
        // memory, surface its id without creating a duplicate. This
        // handles both "I already DM'd them" and "they DM'd me first
        // and we auto-accepted" paths.
        if self.active_rooms.lock().unwrap().contains_key(&room_id) {
            let _ = self.app_event_tx.send(AppEvent::RoomJoined {
                room_id: room_id.clone(),
            });
            return Ok(room_id);
        }
        if repo::get_room(&self.db, &room_id)?.is_some() {
            // Re-bootstrap the in-memory active room from disk.
            return self.bootstrap_direct_room(&room_id, partner_fingerprint).await;
        }

        let created_at = now_unix();
        // The name is internal/derived — the DM pane renders the partner
        // username + HD-ID instead. Including the short fp keeps the row
        // navigable in `sqlite3` if someone digs into the DB.
        let name = format!("dm-{}", short_fp_for_msg(partner_fingerprint));

        // huddle 0.7.1: DMs are always encrypted. The salt slot stores
        // the canonical room_id (16 raw bytes from the SHA-256 prefix)
        // so a re-bootstrap can re-derive the same key. The actual key
        // comes from ECDH below, not from this salt — but we keep the
        // salt slot non-NULL so legacy code paths (which assume
        // encrypted rooms have salts) don't choke.
        let dm_salt = hex::decode(&room_id).unwrap_or_else(|_| room_id.as_bytes().to_vec());
        let info = StoredRoom {
            id: room_id.clone(),
            name,
            creator_fingerprint: our_fp.clone(),
            encrypted: true,
            passphrase_salt: Some(dm_salt),
            created_at,
            last_active: Some(created_at),
            kind: RoomKind::Direct,
        };
        repo::insert_room(&self.db, &info)?;

        let mut members = HashSet::new();
        members.insert(our_fp.clone());
        repo::upsert_room_member(
            &self.db,
            &StoredRoomMember {
                room_id: room_id.clone(),
                peer_id: String::new(),
                fingerprint: our_fp.clone(),
                last_seen: Some(created_at),
                verified: true,
                ed25519_pubkey: Some(B64.encode(self.identity.public_bytes())),
                role: "member".into(),
            },
        )?;

        // Try to derive the ECDH key now. If the partner's pubkey
        // hasn't been observed yet (we know their fingerprint from a
        // QR / invite / username lookup, but never seen a signed
        // message from them), the key is None and gets populated by
        // the `MemberAnnounce` handler below the moment partner's
        // first announcement lands.
        let passphrase_key = self.try_derive_dm_key(&room_id, partner_fingerprint);

        // Always create our outbound Megolm session so we can encrypt
        // *something* the moment the key materializes. RoomCrypto
        // works the same as it does for group rooms — the only
        // difference is where `passphrase_key` comes from.
        let crypto = Some(RoomCrypto::new_for_room(
            self.db.clone(),
            room_id.clone(),
            our_fp.clone(),
            self.session_persist_key,
        )?);

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

        let app = self.clone();
        let rid = room_id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if let Err(e) = app.broadcast_member_announce(&rid).await {
                warn!(%e, "broadcast member announce for DM");
            }
        });

        let _ = self.app_event_tx.send(AppEvent::RoomJoined {
            room_id: room_id.clone(),
        });
        Ok(room_id)
    }

    /// huddle 0.7.1: derive a DM key from a base64-encoded partner
    /// pubkey. Mirrors `try_derive_dm_key` but operates on a pubkey we
    /// just received (e.g. via `MemberAnnounce.sender_ed25519_pubkey`)
    /// without re-querying the DB.
    fn derive_dm_key_from_pubkey_b64(
        &self,
        room_id: &str,
        pubkey_b64: &str,
    ) -> Option<[u8; KEY_LEN]> {
        let bytes = B64.decode(pubkey_b64).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&bytes);
        let our_seed = self.identity.secret_bytes();
        match crate::crypto::dm::derive_dm_key(&our_seed, &pubkey, room_id) {
            Ok(k) => Some(k),
            Err(e) => {
                warn!(%e, "DM key derivation (from announce) failed");
                None
            }
        }
    }

    /// huddle 0.7.1: look up partner's Ed25519 pubkey (from anywhere
    /// we've persisted it) and derive the DM room key via ECDH. Returns
    /// `None` when the pubkey isn't known yet — the caller proceeds
    /// without a key and the `MemberAnnounce` handler retries later.
    fn try_derive_dm_key(
        &self,
        room_id: &str,
        partner_fingerprint: &str,
    ) -> Option<[u8; KEY_LEN]> {
        let pubkey_b64 = repo::lookup_peer_ed25519_pubkey(&self.db, partner_fingerprint)
            .ok()
            .flatten()?;
        let bytes = B64.decode(&pubkey_b64).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&bytes);
        let our_seed = self.identity.secret_bytes();
        match crate::crypto::dm::derive_dm_key(&our_seed, &pubkey, room_id) {
            Ok(k) => Some(k),
            Err(e) => {
                warn!(%e, %partner_fingerprint, "DM key derivation failed");
                None
            }
        }
    }

    /// Internal: re-hydrate an existing on-disk DM room into
    /// `active_rooms` and re-subscribe / re-announce. Used by
    /// `start_direct` when the room exists on disk but not in memory
    /// (e.g. process restart) and by the auto-accept path when a DM
    /// announcement arrives from the partner.
    async fn bootstrap_direct_room(
        &self,
        room_id: &str,
        partner_fingerprint: &str,
    ) -> Result<String> {
        let our_fp = self.identity.fingerprint().to_string();
        let info = repo::get_room(&self.db, room_id)?
            .ok_or_else(|| HuddleError::Other(format!("DM room {room_id} not found on disk")))?;
        let mut members = HashSet::new();
        members.insert(our_fp.clone());
        members.insert(partner_fingerprint.to_string());

        // Pull persisted members so re-bootstrap doesn't lose them.
        if let Ok(stored_members) = repo::list_room_members(&self.db, room_id) {
            for m in stored_members {
                members.insert(m.fingerprint);
            }
        }

        // huddle 0.7.1: rehydrate the ECDH key + Megolm session if the
        // partner's pubkey is on disk (which it always is after at
        // least one previous MemberAnnounce). For older DMs that
        // pre-date 0.7.1 (when DMs were unencrypted on the room
        // layer), `info.encrypted` is false — preserve that and skip
        // the ECDH derivation; the room continues operating as it did
        // before. New 0.7.1+ DMs all have `encrypted = true`.
        let (passphrase_key, crypto) = if info.encrypted {
            let pk = self.try_derive_dm_key(room_id, partner_fingerprint);
            // huddle 0.7.11: bubble up the error instead of .expect. The
            // inbound-DM auto-bootstrap path spawns this on its own task;
            // a transient DB write failure used to panic the task and
            // silently kill all subsequent DM bootstraps.
            let c = match RoomCrypto::load(
                self.db.clone(),
                room_id.to_string(),
                our_fp.clone(),
                self.session_persist_key,
            )? {
                Some(c) => Some(c),
                None => Some(RoomCrypto::new_for_room(
                    self.db.clone(),
                    room_id.to_string(),
                    our_fp.clone(),
                    self.session_persist_key,
                )?),
            };
            (pk, c)
        } else {
            (None, None)
        };

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

        self.network.subscribe_room(room_id.to_string()).await;
        self.announce_room_now(&info, 2).await;

        let app = self.clone();
        let rid = room_id.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if let Err(e) = app.broadcast_member_announce(&rid).await {
                warn!(%e, "broadcast member announce on DM bootstrap");
            }
        });

        let _ = self.app_event_tx.send(AppEvent::RoomJoined {
            room_id: room_id.to_string(),
        });
        Ok(room_id.to_string())
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

        // huddle 0.7: preserve the kind that came from the announcement
        // / restorable cache / DB. If we don't have it (very old row),
        // default to Group — matches the schema column default and the
        // back-fill policy.
        let kind = self
            .discovered_rooms
            .lock()
            .unwrap()
            .get(room_id)
            .map(|d| d.kind)
            .or_else(|| {
                repo::get_room(&self.db, room_id)
                    .ok()
                    .flatten()
                    .map(|r| r.kind)
            })
            .unwrap_or_default();

        let info = StoredRoom {
            id: room_id.to_string(),
            name,
            creator_fingerprint,
            encrypted,
            passphrase_salt: salt_opt.clone(),
            created_at: now_unix(),
            last_active: Some(now_unix()),
            kind,
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

    /// Walk the rooms table at startup. Non-encrypted rooms and DMs are
    /// silently restored (subscribed + re-announced). Encrypted *group*
    /// rooms get added to `restorable_rooms` so the lobby surfaces them
    /// and the user can re-enter via the join flow with the passphrase.
    ///
    /// huddle 1.0: DMs (always encrypted) are now fully re-activated here
    /// rather than parked — their key derives from our identity + the
    /// partner's persisted pubkey, no passphrase needed — so DM chat keeps
    /// flowing continuously across restarts and across networks (relay
    /// mailbox + LAN), instead of going dormant until manually reopened.
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
            // DMs: re-activate fully (key derives from identity + the
            // partner's persisted pubkey, no passphrase). Keeps DMs live so
            // relay-delivered messages are handled, not dropped.
            if info.encrypted && info.kind == RoomKind::Direct {
                let partner = repo::list_room_members(&self.db, &info.id)
                    .ok()
                    .into_iter()
                    .flatten()
                    .map(|m| m.fingerprint)
                    .find(|fp| *fp != our_fp);
                match partner {
                    Some(partner_fp) => {
                        if let Err(e) = self.bootstrap_direct_room(&info.id, &partner_fp).await {
                            warn!(%e, room_id = %info.id, "restore: DM bootstrap failed; parking as restorable");
                            self.restorable_rooms
                                .lock()
                                .unwrap()
                                .insert(info.id.clone(), info);
                        } else {
                            info!(room_id = %info.id, "restored DM");
                        }
                    }
                    // DM created but never reciprocated — partner pubkey
                    // unknown, nothing to re-activate. Park it (no key, no
                    // history anyway).
                    None => {
                        self.restorable_rooms
                            .lock()
                            .unwrap()
                            .insert(info.id.clone(), info);
                    }
                }
                continue;
            }
            // Encrypted GROUP rooms need a passphrase held in memory to
            // decrypt — park them as restorable for the user to re-enter.
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
        // Broadcast a signed leave notice before unsubscribing. huddle
        // 0.7.11: MemberLeave is now signed so peers can't spoof another
        // member's leave to evict them from honest rosters.
        let leave_msg = RoomMessage::MemberLeave {
            sender_fingerprint: self.identity.fingerprint().to_string(),
        };
        let dispatched = match crate::crypto::sign_message(&self.identity, &leave_msg)
            .and_then(|env| {
                crate::network::protocol::encode_wire_signed(&env)
                    .map_err(|e| HuddleError::Session(format!("encode signed leave: {e}")))
            }) {
            Ok(bytes) => {
                self.network
                    .publish_room_message(room_id.to_string(), bytes)
                    .await;
                true
            }
            Err(e) => {
                warn!(%e, %room_id, "failed to sign+encode MemberLeave notice");
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
    /// huddle 0.5.1: resolve an HD- ID or username back to a dialable
    /// multiaddr and dial it.
    ///
    /// `input` is matched against, in order:
    /// 1. an `HD-XXXX-...` prefixed string → strip prefix + lowercase to
    ///    canonical fingerprint;
    /// 2. a raw 24-char hex run (with or without dashes) → group into
    ///    4-char blocks and lowercase;
    /// 3. otherwise → treat as a username and look up `peer_profiles`.
    ///
    /// Resolution to an address: scan `discovered_rooms` for a room
    /// whose `creator_fingerprint` matches; take the first `host_addrs`
    /// entry. Falls back to the `known_peers` table for users we've
    /// dialed before. Both paths require we've seen the peer on our
    /// gossipsub mesh or dialed them before — bare-ID dialing on a
    /// cold mesh is fundamentally impossible without a routing layer
    /// huddle deliberately doesn't run (DHT, central directory). For
    /// cross-internet first contact, paste an invite link instead.
    pub async fn dial_by_id_or_username(&self, input: &str) -> Result<()> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(HuddleError::Other("input is empty".into()));
        }
        let target_fp = if let Some(fp) = normalize_to_fingerprint(trimmed) {
            fp
        } else {
            let matches = repo::find_peers_by_username(&self.db, trimmed)?;
            if matches.is_empty() {
                return Err(HuddleError::Other(format!(
                    "no peer named `{}` known yet — paste their invite link instead",
                    trimmed
                )));
            }
            if matches.len() > 1 {
                return Err(HuddleError::Other(format!(
                    "username `{}` is ambiguous ({} peers share it) — use their HD- ID instead",
                    trimmed,
                    matches.len()
                )));
            }
            matches.into_iter().next().unwrap()
        };
        if target_fp == self.identity.fingerprint() {
            return Err(HuddleError::Other("that's your own ID".into()));
        }
        let candidates = self.resolve_dial_addrs(&target_fp);
        if candidates.is_empty() {
            return Err(HuddleError::Other(format!(
                "haven't seen `{}` on the network yet — ask them for an invite link",
                short_fp_for_msg(&target_fp)
            )));
        }
        // Pre-record every candidate so the lobby's known-peers panel
        // surfaces them even before the post-identify handler lands.
        // We bind each address to the resolved fingerprint so the
        // post-identify trust upgrade has the same fp to confirm.
        let now = now_unix();
        for addr in &candidates {
            let _ = repo::upsert_known_peer(
                &self.db,
                &KnownPeer {
                    address: addr.clone(),
                    label: None,
                    last_connected_at: None,
                    last_attempt_at: Some(now),
                    created_at: now,
                    fingerprint: Some(target_fp.clone()),
                    trusted: false,
                },
            );
        }
        // Parse to Multiaddrs, drop any that don't lex. Empty after
        // parsing would mean every candidate is malformed — unlikely
        // but defended-against.
        let multiaddrs: Vec<Multiaddr> = candidates
            .iter()
            .filter_map(|s| s.parse::<Multiaddr>().ok())
            .collect();
        if multiaddrs.is_empty() {
            return Err(HuddleError::Other(
                "every known address for that peer is malformed".into(),
            ));
        }
        let _ = self.app_event_tx.send(AppEvent::Dialing {
            address: candidates[0].clone(),
        });
        info!(
            target_fp = %target_fp,
            n = multiaddrs.len(),
            "dialing peer with {} candidate addresses",
            multiaddrs.len()
        );
        // huddle 0.7.7: user-initiated dial — register every candidate
        // canonical address so whichever wins the libp2p race triggers
        // the post-identify auto-DM. Reset & insert under one lock.
        {
            let mut pending = self.pending_auto_dm_addrs.lock().unwrap();
            for m in &multiaddrs {
                pending.insert(m.to_string());
            }
        }
        self.network.dial_addresses(multiaddrs).await;
        Ok(())
    }

    /// huddle 0.5.2: every dialable multiaddr we know for `fingerprint`,
    /// sorted by transport preference so libp2p's parallel dialer races
    /// the cheapest paths first. Order: RFC1918 LAN ip4 → loopback (for
    /// tests) → public ip4 → ip6 / dns → relay-hopped (`/p2p-circuit`)
    /// last. libp2p races them concurrently anyway — sorting just
    /// gives the first-attempted slot to the address most likely to
    /// win on a tie.
    fn resolve_dial_addrs(&self, fingerprint: &str) -> Vec<String> {
        let mut set: std::collections::HashSet<String> = std::collections::HashSet::new();
        for room in self.discovered_rooms.lock().unwrap().values() {
            if room.creator_fingerprint == fingerprint {
                for addr in &room.host_addrs {
                    set.insert(addr.clone());
                }
            }
        }
        if let Ok(known) = repo::list_known_peers(&self.db) {
            for peer in known {
                if peer.fingerprint.as_deref() == Some(fingerprint) {
                    set.insert(peer.address);
                }
            }
        }
        let mut v: Vec<String> = set.into_iter().collect();
        v.sort_by_key(|a| address_preference(a));
        v
    }

    pub async fn dial(&self, input: &str) -> Result<()> {
        let multiaddr = parse_dial_address(input)?;
        let canonical = multiaddr.to_string();
        // huddle 0.7.7: user-initiated entry point. Register the address
        // so the post-Identify handler auto-opens a DM with the peer.
        // The auto-reconnector goes through `dial_internal` instead and
        // therefore does NOT trigger an auto-DM on every startup.
        self.pending_auto_dm_addrs
            .lock()
            .unwrap()
            .insert(canonical.clone());
        self.dial_internal(canonical, multiaddr).await
    }

    /// huddle 0.7.7: shared dial body used by the public `dial()` entry
    /// point and by internal reconnect paths. The two callers differ
    /// only in whether they register the address for auto-DM-after-
    /// identify; internal paths (startup reconnector, host-addr
    /// opportunistic dial) do not.
    pub(crate) async fn dial_internal(
        &self,
        canonical: String,
        multiaddr: Multiaddr,
    ) -> Result<()> {
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

    /// Phase D follow-up: snapshot of the NAT reachability state.
    /// Returns the addresses AutoNAT has confirmed as externally
    /// reachable in this session. The lobby renders an emoji badge
    /// from this — non-empty ⇒ 'reachable', empty ⇒ 'LAN only'.
    pub fn nat_reachable_addrs(&self) -> Vec<String> {
        self.nat_reachable_addrs
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect()
    }

    /// Phase D follow-up: addresses suitable for putting on the wire
    /// so other peers can dial us. Union of:
    ///   - AutoNAT-confirmed external addresses (direct internet)
    ///   - active `/p2p-circuit` reservations on configured relays
    /// Capped at 4 entries to keep room announcements small.
    /// Relay-circuit addresses are listed first (they're more likely
    /// to work for NAT'd peers).
    pub fn dialable_addrs(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .relay_circuit_addrs
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect();
        for a in self.nat_reachable_addrs.lock().unwrap().iter() {
            if !out.contains(a) {
                out.push(a.clone());
            }
        }
        out.truncate(4);
        out
    }

    /// Phase C follow-up: dial a peer whose multiaddr came from an
    /// invite link claiming `claimed_fp`. Behaves identically to
    /// `dial`, but additionally stashes `(canonical_addr → claimed_fp)`
    /// in `pending_invite_dials` so the `PeerIdentified` handler can
    /// assert the cryptographic fp matches the human-display one in
    /// the invite. Mismatch ⇒ disconnect + `InviteFingerprintMismatch`
    /// event.
    ///
    /// libp2p's `/p2p/<peer-id>` segment already enforces this at the
    /// transport level (and our invite generator always includes it),
    /// so this is defense in depth — but it makes the assert explicit
    /// rather than relying on a structural side effect.
    pub async fn dial_invite(&self, address: &str, claimed_fp: &str) -> Result<()> {
        let multiaddr = parse_dial_address(address)?;
        let canonical = multiaddr.to_string();
        self.pending_invite_dials
            .lock()
            .unwrap()
            .insert(canonical.clone(), claimed_fp.to_string());
        // Re-use the standard dial path so KnownPeer rows + status
        // events look identical to a plain dial.
        self.dial(address).await
    }

    /// huddle 0.7.12: pre-seed an invite's room so an immediate join
    /// works without waiting for the host's gossip announcement to
    /// arrive over the just-opened connection. Decodes the (optional)
    /// salt into `ROOM_SALT_CACHE` and inserts a `discovered_rooms`
    /// entry, so `join_room` can resolve the room's metadata AND derive
    /// the passphrase key the moment the user submits.
    ///
    /// Pre-0.7.12 the invite's `salt_b64` + room metadata were decoded
    /// and then thrown away; `join_room` could only learn the room from
    /// a live announcement, so submitting the passphrase before that
    /// announcement landed errored "room {id} not found". The invite
    /// already carries everything required — we just plumb it through.
    pub fn seed_invite_room(&self, room: &crate::invite::InviteRoom) {
        if let Some(salt) = room.salt_b64.as_deref().and_then(|b| B64.decode(b).ok()) {
            ROOM_SALT_CACHE
                .lock()
                .unwrap()
                .insert(room.id.clone(), salt);
        }
        let discovered = DiscoveredRoom {
            room_id: room.id.clone(),
            name: room.name.clone(),
            encrypted: room.encrypted,
            member_count: 0,
            creator_fingerprint: room.creator_fingerprint.clone(),
            last_seen: now_unix(),
            restorable: false,
            host_addrs: Vec::new(),
            // Invites are group-scoped — DMs are 1-1 and never invited.
            kind: RoomKind::Group,
        };
        self.discovered_rooms
            .lock()
            .unwrap()
            .insert(room.id.clone(), discovered);
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
                    fingerprint: p.fingerprint,
                }
            })
            .collect()
    }

    pub async fn forget_peer(&self, address: &str) -> Result<()> {
        repo::forget_known_peer(&self.db, address)?;
        self.connected_dial_addrs.lock().unwrap().remove(address);
        Ok(())
    }

    // -------------------------------------------------------------------
    // huddle 1.0: Contacts — the durable, fingerprint-keyed address book
    // -------------------------------------------------------------------

    /// Record (or refresh) a contact. Idempotent; safe to call from every
    /// relationship path (start_direct, trust_inbound, accepted requests).
    /// Caches the partner's Ed25519 pubkey when known and the canonical DM
    /// room id. Never adds ourselves.
    pub fn add_contact(&self, fingerprint: &str, source: &str) -> Result<()> {
        let our_fp = self.identity.fingerprint();
        if fingerprint == our_fp || fingerprint.is_empty() {
            return Ok(());
        }
        let dm_room_id = canonical_dm_room_id(our_fp, fingerprint);
        let pubkey = repo::lookup_peer_ed25519_pubkey(&self.db, fingerprint)
            .ok()
            .flatten();
        let now = now_unix();
        repo::upsert_contact(
            &self.db,
            &repo::Contact {
                fingerprint: fingerprint.to_string(),
                alias: None,
                ed25519_pubkey: pubkey,
                dm_room_id: Some(dm_room_id),
                source: source.to_string(),
                note: None,
                added_at: now,
                last_seen: Some(now),
            },
        )
    }

    pub fn set_contact_alias(&self, fingerprint: &str, alias: Option<&str>) -> Result<()> {
        repo::set_contact_alias(&self.db, fingerprint, alias)
    }

    pub fn remove_contact(&self, fingerprint: &str) -> Result<()> {
        repo::delete_contact(&self.db, fingerprint)
    }

    pub fn is_contact(&self, fingerprint: &str) -> bool {
        repo::is_contact(&self.db, fingerprint).unwrap_or(false)
    }

    /// The unified Contacts list: the durable address book joined with
    /// derived username / verified / trusted / reachability so the UI never
    /// has to stitch four tables together.
    pub fn list_contacts(&self) -> Vec<ContactView> {
        let our_fp = self.identity.fingerprint().to_string();
        let verified: HashSet<String> = repo::list_verified_peers(&self.db)
            .unwrap_or_default()
            .into_iter()
            .collect();
        // A peer is "LAN-connected" when any known_peer row bearing its
        // fingerprint currently maps to a live libp2p connection.
        let connected = self.connected_dial_addrs.lock().unwrap().clone();
        let lan_fps: HashSet<String> = repo::list_known_peers(&self.db)
            .unwrap_or_default()
            .into_iter()
            .filter(|p| connected.contains_key(&p.address))
            .filter_map(|p| p.fingerprint)
            .collect();
        let relay_up = self.server_connected();
        repo::list_contacts(&self.db)
            .unwrap_or_default()
            .into_iter()
            .filter(|c| c.fingerprint != our_fp)
            .map(|c| {
                let lan_connected = lan_fps.contains(&c.fingerprint);
                ContactView {
                    dm_room_id: c
                        .dm_room_id
                        .clone()
                        .unwrap_or_else(|| canonical_dm_room_id(&our_fp, &c.fingerprint)),
                    username: repo::get_peer_username(&self.db, &c.fingerprint).unwrap_or(None),
                    verified: verified.contains(&c.fingerprint),
                    trusted: repo::is_fingerprint_trusted(&self.db, &c.fingerprint)
                        .unwrap_or(false),
                    reachable: lan_connected || relay_up,
                    lan_connected,
                    fingerprint: c.fingerprint,
                    alias: c.alias,
                    source: c.source,
                    added_at: c.added_at,
                    last_seen: c.last_seen,
                }
            })
            .collect()
    }

    // -------------------------------------------------------------------
    // huddle 1.0: contact requests over the relay inbox (Phase 1)
    // -------------------------------------------------------------------

    /// "Add by HD-ID" that works over the internet: publish a signed
    /// `ContactRequest` to the target's relay inbox. The target picks it up
    /// (live, or from the relay's offline mailbox) and surfaces it as a
    /// pending request to accept/decline. On the LAN, the same publish also
    /// rides gossipsub. Refuses self.
    pub async fn send_contact_request(
        &self,
        target_fingerprint: &str,
        note: Option<&str>,
    ) -> Result<()> {
        let our_fp = self.identity.fingerprint().to_string();
        if target_fingerprint == our_fp {
            return Err(HuddleError::Other("that's your own ID".into()));
        }
        // Record the target so their accept-echo is recognized as mutual (see
        // the ContactRequest receive arm) instead of re-prompting us.
        let _ = self.add_contact(target_fingerprint, "request-sent");
        let msg = RoomMessage::ContactRequest {
            requester_fingerprint: our_fp,
            display_name: repo::get_display_name(&self.db).unwrap_or(None),
            note: note.map(|s| s.to_string()),
            sender_ed25519_pubkey: Some(B64.encode(self.identity.public_bytes())),
        };
        let env = crate::crypto::sign_message(&self.identity, &msg)?;
        let bytes = crate::network::protocol::encode_wire_signed(&env)?;
        let inbox = crate::network::protocol::inbox_room_id(target_fingerprint);
        self.network.publish_room_message(inbox, bytes).await;
        Ok(())
    }

    /// Inbound contact requests awaiting an accept/decline decision.
    pub fn list_pending_contact_requests(&self) -> Vec<repo::PendingContactRequest> {
        repo::list_pending_contact_requests(&self.db).unwrap_or_default()
    }

    /// Accept a pending contact request: record the contact and open the DM
    /// (idempotent on the canonical room id). Both sides converge — the
    /// requester opens the same DM when our resulting `MemberAnnounce` /
    /// announcement reaches them. Removes the pending row regardless.
    pub async fn accept_contact_request(&self, fingerprint: &str) -> Result<()> {
        repo::delete_pending_contact_request(&self.db, fingerprint)?;
        self.add_contact(fingerprint, "request")?;
        // start_direct subscribes the canonical DM room + broadcasts our
        // MemberAnnounce, making the DM live on our side.
        self.start_direct(fingerprint).await?;
        // Echo a request back to the requester's inbox so they converge: the
        // requester already has us in their address book (they initiated), so
        // their ContactRequest receive arm treats this as mutual and
        // subscribes the same DM room — essential for the relay path, where
        // our MemberAnnounce can't reach them until they're a room member.
        let _ = self.send_contact_request(fingerprint, None).await;
        Ok(())
    }

    /// Decline a pending contact request. `block` also adds the requester to
    /// the persistent blocklist so they can't re-request.
    pub fn reject_contact_request(&self, fingerprint: &str, block: bool) -> Result<()> {
        repo::delete_pending_contact_request(&self.db, fingerprint)?;
        if block {
            repo::block_peer(&self.db, fingerprint, now_unix())?;
        }
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
        // huddle 1.0: trusting a peer makes them a contact.
        let _ = self.add_contact(fingerprint, "dial");
        Ok(())
    }

    // =========================================================================
    // huddle 0.7.7: pending friend requests (3-day TTL)
    // =========================================================================

    /// Snapshot of every inbound dial we've spilled to disk but haven't
    /// yet accepted or rejected. The People pane renders this as its
    /// own section ("Pending requests (N)").
    pub fn list_pending_friend_requests(&self) -> Vec<repo::PendingFriendRequest> {
        repo::list_pending_friend_requests(&self.db).unwrap_or_default()
    }

    /// Persist an inbound request that the user didn't act on within the
    /// modal window. Called from the TUI's idle-timeout sweep; the live
    /// libp2p connection is also closed by the same path (the request
    /// is effectively rejected *for now* — accept later from People
    /// pane will re-dial the stored address).
    pub fn spill_pending_friend_request(
        &self,
        peer_id: PeerId,
        fingerprint: &str,
        address: &str,
    ) -> Result<()> {
        repo::upsert_pending_friend_request(
            &self.db,
            &repo::PendingFriendRequest {
                fingerprint: fingerprint.to_string(),
                address: address.to_string(),
                peer_id: peer_id.to_string(),
                received_at: now_unix(),
            },
        )?;
        Ok(())
    }

    /// User pressed Accept on a row in the Pending requests list. The
    /// original libp2p connection is long gone (we closed it on
    /// timeout); re-dial the stored address and mark the peer trusted
    /// so the post-Identify handler short-circuits the modal. The
    /// row is removed regardless of dial success — a failed dial is
    /// still a positive intent we don't want to keep re-prompting on.
    pub async fn accept_pending_friend_request(&self, fingerprint: &str) -> Result<()> {
        let mut chosen_addr: Option<String> = None;
        for req in self.list_pending_friend_requests() {
            if req.fingerprint == fingerprint {
                chosen_addr = Some(req.address);
                break;
            }
        }
        repo::delete_pending_friend_requests_for_fp(&self.db, fingerprint)?;
        // huddle 1.0: accepting a friend request makes them a contact.
        let _ = self.add_contact(fingerprint, "request");
        if let Some(addr) = chosen_addr {
            // Pre-mark trusted so the upcoming Identify handler skips
            // the inbound-dial modal. Matches the semantics of
            // `trust_inbound` without needing a live PeerId.
            repo::upsert_known_peer(
                &self.db,
                &KnownPeer {
                    address: addr.clone(),
                    label: None,
                    last_connected_at: None,
                    last_attempt_at: Some(now_unix()),
                    created_at: now_unix(),
                    fingerprint: Some(fingerprint.to_string()),
                    trusted: true,
                },
            )?;
            // User-initiated — register for auto-DM on connect.
            self.dial(&addr).await?;
        }
        Ok(())
    }

    /// User pressed Reject on a row in the Pending requests list.
    /// Mirrors `reject_inbound` semantics: delete the pending row(s)
    /// AND block the fingerprint so any future dial from this peer is
    /// auto-dropped without re-prompting.
    pub fn reject_pending_friend_request(&self, fingerprint: &str) -> Result<()> {
        repo::delete_pending_friend_requests_for_fp(&self.db, fingerprint)?;
        repo::block_peer(&self.db, fingerprint, now_unix())?;
        Ok(())
    }

    /// huddle 0.7.7: close a live libp2p connection without blocking the
    /// peer. Used by the TUI's 15s InboundDial timeout — we need to
    /// drop the dangling socket, but blocking the peer would
    /// contradict "save the request for 3 days, let the user decide
    /// later." `reject_inbound` is the right call when the user
    /// *explicitly* clicks Reject.
    pub async fn disconnect_peer(&self, peer_id: PeerId) {
        self.network.disconnect_peer(peer_id).await;
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
                    // huddle 0.7.7: route through `dial_internal`, NOT
                    // `dial`. Startup reconnects shouldn't pop a DM
                    // every time a known peer comes online — only
                    // explicit user actions trigger the auto-DM.
                    let multiaddr = match peer.address.parse::<Multiaddr>() {
                        Ok(m) => m,
                        Err(_) => return,
                    };
                    if let Err(e) = handle.dial_internal(peer.address.clone(), multiaddr).await {
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
        let host_addrs = self.dialable_addrs();
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
            host_addrs,
            kind: info.kind,
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
                match room.passphrase_key.as_ref() {
                    Some(passphrase_key) => {
                        Some(passphrase::wrap(session_key.as_bytes(), passphrase_key)?)
                    }
                    None if room.info.kind == RoomKind::Direct => {
                        // huddle 0.7.1: DM-specific path — partner's
                        // pubkey hasn't been observed yet, so we can't
                        // derive the ECDH key. Send announce without
                        // a wrapped key — it carries our Ed25519
                        // pubkey, which lets the partner derive the
                        // key on their side. They'll respond with
                        // their own wrapped key in a follow-up
                        // announce; once we receive it we re-broadcast
                        // ours with the wrap filled in.
                        None
                    }
                    None => {
                        return Err(HuddleError::Session("missing passphrase key".into()));
                    }
                }
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
        // huddle 0.7.11: MemberAnnounce is now signed end-to-end. The
        // envelope's Ed25519 pubkey is the canonical TOFU pin for this
        // fingerprint; the inner `sender_ed25519_pubkey` field stays
        // present for back-compat parsing but is no longer authoritative.
        let env = crate::crypto::sign_message(&self.identity, &msg)?;
        let bytes = crate::network::protocol::encode_wire_signed(&env)?;
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

    /// huddle 0.8/1.0: maintain a connection to the relay backend for the
    /// life of the process. Reconnects with capped exponential backoff. Each
    /// attempt tries the transport "doors" in `order` (onion first, clearnet
    /// last, or a single pinned door) until one connects — so a censored user
    /// whose Tor is blocked transparently falls through to a clearnet door.
    /// While connected, the [`NetworkHandle`] mirrors outgoing room traffic
    /// to it (see `attach_server`), and incoming server messages are funneled
    /// into the *same* `RoomMessageReceived` handler as gossipsub — so a
    /// message arriving via the relay is decoded, verified, and decrypted by
    /// exactly the same code path. The live door is recorded in
    /// `active_transport` for the UI/CLI.
    fn spawn_server_connection(&self, order: Vec<TransportId>) {
        let handle = self.clone();
        tokio::spawn(async move {
            let mut backoff = 1u64;
            loop {
                let fp = handle.identity.fingerprint().to_string();
                // huddle 1.0: the Hello room set is every active chat room
                // PLUS our aux subscriptions (the contact inbox), so the relay
                // re-registers inbox membership on every reconnect and flushes
                // any queued contact requests.
                let rooms: Vec<String> = {
                    let mut r: Vec<String> =
                        handle.active_rooms.lock().unwrap().keys().cloned().collect();
                    r.extend(handle.aux_subscriptions.lock().unwrap().iter().cloned());
                    r
                };

                // Try each door in order until one connects. Unavailable
                // doors (no URL / wrong build) are skipped.
                let mut connected: Option<(
                    ServerClient,
                    tokio::sync::mpsc::UnboundedReceiver<ServerEvent>,
                    TransportId,
                )> = None;
                for id in &order {
                    let (url, dial) = match handle
                        .transport_profiles
                        .iter()
                        .find(|p| p.id == *id)
                    {
                        Some(p) if p.available() => {
                            (p.url.clone().unwrap(), p.dial.clone().unwrap())
                        }
                        _ => continue,
                    };
                    match ServerClient::connect(&url, &dial, fp.clone(), rooms.clone()).await {
                        Ok((client, rx)) => {
                            info!(%url, transport = id.as_str(), "connected to relay");
                            connected = Some((client, rx, *id));
                            break;
                        }
                        Err(e) => {
                            debug!(error = %e, transport = id.as_str(), %url, "relay door failed; trying next");
                        }
                    }
                }

                if let Some((client, mut rx, id)) = connected {
                    backoff = 1;
                    handle.network.attach_server(client);
                    *handle.active_transport.lock().unwrap() = Some(id);
                    while let Some(ev) = rx.recv().await {
                        match ev {
                            ServerEvent::Message { room, payload, .. } => {
                                handle
                                    .process_network_event(NetworkEvent::RoomMessageReceived {
                                        room_id: room,
                                        payload,
                                        from_peer: PeerId::random(),
                                    })
                                    .await;
                            }
                            ServerEvent::Ready | ServerEvent::Sent { .. } => {}
                            ServerEvent::Disconnected => break,
                        }
                    }
                    handle.network.detach_server();
                    *handle.active_transport.lock().unwrap() = None;
                    warn!("relay connection closed; reconnecting");
                } else {
                    warn!("all relay doors failed; will retry");
                }
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(30);
            }
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
            NetworkEvent::PeerDisconnected { peer_id } => {
                // huddle 0.7.11: relay / internet peers don't trigger
                // mDNS PeerExpired, so without this their entries in
                // connected_dial_addrs stayed forever and the lobby
                // showed them as "● online" indefinitely after they
                // dropped. Same cleanup shape as PeerExpired.
                self.connected_dial_addrs
                    .lock()
                    .unwrap()
                    .retain(|_addr, pid| *pid != peer_id);
                let _ = self.app_event_tx.send(AppEvent::PeerExpired { peer_id });
            }
            // huddle 0.7.12: `RelayReservationLost` was removed —
            // libp2p 0.56's relay client doesn't surface a failure
            // variant we can listen on. Reservation loss currently
            // manifests as the next AutoNAT probe flipping to
            // "private" once the circuit drops; a future health-
            // check timer can re-introduce the dedicated signal.
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
                // Phase D follow-up: opportunistically dial the
                // announcer's first host_addr if we're not already
                // connected. Skips self-announcements + rate-limits
                // by creator fingerprint so we don't dial-storm.
                let our_fp_for_dial = self.identity.fingerprint().to_string();
                if ann.creator_fingerprint != our_fp_for_dial && !ann.host_addrs.is_empty() {
                    let now = now_unix();
                    let should_dial = {
                        let mut attempts = self.host_addr_dial_attempts.lock().unwrap();
                        match attempts.get(&ann.creator_fingerprint).copied() {
                            Some(last) if now - last < HOST_ADDR_DIAL_BACKOFF_SECS => false,
                            _ => {
                                attempts.insert(ann.creator_fingerprint.clone(), now);
                                true
                            }
                        }
                    };
                    if should_dial {
                        if let Some(first) = ann.host_addrs.first() {
                            info!(
                                announcer = %ann.creator_fingerprint,
                                addr = %first,
                                "opportunistic dial via room announcement host_addrs"
                            );
                            // huddle 0.7.7: NOT user-initiated — go
                            // through `dial_internal` so a passive
                            // announcement-driven dial doesn't pop a
                            // DM in the user's face.
                            if let Ok(multiaddr) = first.parse::<Multiaddr>() {
                                let canonical = multiaddr.to_string();
                                let _ = self.dial_internal(canonical, multiaddr).await;
                            }
                        }
                    }
                }
                let discovered = DiscoveredRoom {
                    room_id: ann.room_id.clone(),
                    name: ann.name.clone(),
                    encrypted: ann.encrypted,
                    member_count: ann.member_count,
                    creator_fingerprint: ann.creator_fingerprint.clone(),
                    last_seen: now_unix(),
                    restorable: false,
                    host_addrs: ann.host_addrs.clone(),
                    kind: ann.kind,
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
                // huddle 0.7 DM-visibility filter (consumer side): a
                // `Direct` announcement is only valid for the two members
                // implied by `canonical_dm_room_id`. If we're not one of
                // them, silently drop — DMs never appear in third
                // parties' discovery caches. A malicious 0.7+ peer can
                // ignore this, but they'd have to subscribe to the
                // canonical DM topic with full knowledge of both
                // fingerprints, which is a stronger threat than the v1
                // sidebar split is trying to mitigate.
                if ann.kind == RoomKind::Direct {
                    let our_fp_for_filter = self.identity.fingerprint().to_string();
                    if canonical_dm_room_id(&our_fp_for_filter, &ann.creator_fingerprint)
                        != ann.room_id
                    {
                        debug!(
                            announcer = %ann.creator_fingerprint,
                            room_id = %ann.room_id,
                            "dropping Direct announcement: not addressed to us"
                        );
                        return;
                    }
                    // Targeted at us. Cache the discovery so the sidebar
                    // can show "DM from <partner>" and auto-bootstrap a
                    // local active room so we can receive messages
                    // immediately without waiting for a user action.
                    //
                    // huddle 0.7.11: drop the auto-bootstrap if the
                    // partner is on the persistent blocklist. Without
                    // this gate, a blocked peer could re-introduce
                    // themselves into our sidebar simply by re-announcing
                    // the DM topic; we'd subscribe and persist a row for
                    // them before any user action.
                    if repo::is_peer_blocked(&self.db, &ann.creator_fingerprint).unwrap_or(false)
                    {
                        debug!(
                            partner = %ann.creator_fingerprint,
                            "ignoring Direct announcement from blocked peer"
                        );
                        return;
                    }
                    self.discovered_rooms
                        .lock()
                        .unwrap()
                        .insert(ann.room_id.clone(), discovered.clone());
                    let _ = self
                        .app_event_tx
                        .send(AppEvent::RoomDiscovered(discovered.clone()));
                    let app = self.clone();
                    let partner = ann.creator_fingerprint.clone();
                    let rid = ann.room_id.clone();
                    tokio::spawn(async move {
                        if let Err(e) = app.start_direct(&partner).await {
                            debug!(%e, room_id = %rid, "auto-bootstrap of inbound DM failed");
                        }
                    });
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
                        let claimed_pubkey = env.ed25519_pubkey_b64.clone();
                        match crate::crypto::verify_signed(&env) {
                            Ok((m, fp)) => {
                                // Defense in depth: if we've persisted
                                // a pubkey for this fingerprint in this
                                // room before, the envelope's pubkey
                                // MUST match it. A different pubkey for
                                // the same fingerprint means identity
                                // drift — TOFU violation — drop.
                                match repo::get_member_ed25519_pubkey(
                                    &self.db, &room_id, &fp,
                                ) {
                                    Ok(Some(known)) if known != claimed_pubkey => {
                                        warn!(
                                            %fp, %room_id,
                                            "pubkey mismatch vs stored; dropping signed message"
                                        );
                                        return;
                                    }
                                    _ => {}
                                }
                                (m, Some(fp))
                            }
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
                // Phase C follow-up: if any of these addresses came
                // from an invite, verify the invite's claimed fp
                // against what we just derived from the pubkey. A
                // mismatch means the invite's fp label disagrees with
                // libp2p's /p2p/<peer-id> cryptographic anchor —
                // structurally impossible when both fields are
                // generated from the same identity, but the explicit
                // assert defends against future invite-format
                // changes or hand-edited links.
                let mismatch = {
                    let mut map = self.pending_invite_dials.lock().unwrap();
                    let mut found: Option<(String, String)> = None;
                    for addr in &matched_addrs {
                        if let Some(claimed) = map.remove(addr) {
                            if claimed != fingerprint {
                                found = Some((addr.clone(), claimed));
                                break;
                            }
                        }
                    }
                    found
                };
                if let Some((addr, claimed)) = mismatch {
                    warn!(
                        %addr, %claimed, actual=%fingerprint,
                        "invite fingerprint mismatch — disconnecting"
                    );
                    self.network.disconnect_peer(peer_id).await;
                    let _ = self.app_event_tx.send(AppEvent::InviteFingerprintMismatch {
                        address: addr,
                        claimed,
                        actual: fingerprint.clone(),
                    });
                    return;
                }
                // huddle 0.7.7: did the local user initiate any of these
                // dials? If so, consume the matching entries from
                // `pending_auto_dm_addrs` now so we don't auto-DM
                // again on a subsequent reconnect. The actual DM
                // start happens after the trust upsert below so the
                // peer is already marked trusted by the time we fire.
                let should_auto_dm = {
                    let mut pending = self.pending_auto_dm_addrs.lock().unwrap();
                    let mut any_matched = false;
                    for addr in &matched_addrs {
                        if pending.remove(addr) {
                            any_matched = true;
                        }
                    }
                    any_matched
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
                // huddle 0.7.7: open (or reuse) a DM with the freshly
                // identified peer and tell the TUI to switch panes.
                // `start_direct` is idempotent on `canonical_dm_room_id`,
                // so this is safe to call even if a DM already exists.
                //
                // huddle 0.7.11: explicitly gate on the persistent
                // blocklist here. The original comment claimed blocked
                // peers "fall through naturally" but that was only true
                // for *inbound* dials — the block check at line ~2237
                // is inbound-only. Outbound user-dials hit Identify and
                // landed here without ever consulting the blocklist,
                // bypassing the user's explicit block.
                let blocked = repo::is_peer_blocked(&self.db, &fingerprint).unwrap_or(false);
                if should_auto_dm && !blocked && fingerprint != self.identity.fingerprint() {
                    match self.start_direct(&fingerprint).await {
                        Ok(room_id) => {
                            let _ = self.app_event_tx.send(AppEvent::AutoOpenDm {
                                room_id,
                                fingerprint: fingerprint.clone(),
                            });
                        }
                        Err(e) => {
                            debug!(%e, fp = %fingerprint, "auto-DM after dial failed");
                        }
                    }
                }
                // huddle 0.5: tell the newly-identified peer our current
                // username via a signed ProfileUpdate, but only if we
                // have one set locally and we haven't already pushed
                // ours to this peer in the last
                // `PROFILE_REBROADCAST_FLOOR_MS`. Without the floor a
                // flapping transport (relay reconnect storms) would
                // republish on every identify event.
                let our_username = repo::get_display_name(&self.db).unwrap_or(None);
                if our_username.is_some() {
                    let now_ms = now_unix_ms();
                    let should_send = {
                        let mut last = self.last_profile_broadcast_at_ms.lock().unwrap();
                        match last.get(&fingerprint) {
                            Some(prev) if now_ms - prev < PROFILE_REBROADCAST_FLOOR_MS => false,
                            _ => {
                                last.insert(fingerprint.clone(), now_ms);
                                true
                            }
                        }
                    };
                    if should_send {
                        let msg = RoomMessage::ProfileUpdate {
                            sender_fingerprint: self.identity.fingerprint().to_string(),
                            username: our_username,
                            updated_at: now_ms,
                        };
                        if let Ok(env) = crate::crypto::sign_message(&self.identity, &msg) {
                            if let Ok(bytes) =
                                crate::network::protocol::encode_wire_signed(&env)
                            {
                                let rooms: Vec<String> = self
                                    .active_rooms
                                    .lock()
                                    .unwrap()
                                    .keys()
                                    .cloned()
                                    .collect();
                                for room_id in rooms {
                                    self.network
                                        .publish_room_message(room_id, bytes.clone())
                                        .await;
                                }
                            }
                        }
                    }
                }
            }
            NetworkEvent::RelayReservationEstablished { address } => {
                // Treat the circuit address like any other listen
                // address — the TUI's ListeningOn handler dedups + adds
                // it to the addresses pane. Also emit a status hint via
                // ListeningOn so the lobby's reachability line updates.
                info!(addr = %address, "relay reservation established");
                self.relay_circuit_addrs
                    .lock()
                    .unwrap()
                    .insert(address.to_string());
                let _ = self.app_event_tx.send(AppEvent::ListeningOn {
                    address: address.to_string(),
                });
            }
            NetworkEvent::NatProbeResult {
                tested_addr,
                reachable,
            } => {
                let addr_s = tested_addr.to_string();
                let (transitioned, becomes_reachable) = {
                    let mut set = self.nat_reachable_addrs.lock().unwrap();
                    let was_empty = set.is_empty();
                    if reachable {
                        set.insert(addr_s.clone());
                    } else {
                        set.remove(&addr_s);
                    }
                    let is_empty = set.is_empty();
                    (was_empty != is_empty, !is_empty)
                };
                if transitioned {
                    let label = if becomes_reachable {
                        "reachable".to_string()
                    } else {
                        "private".to_string()
                    };
                    info!(reachable = %becomes_reachable, "NAT reachability changed");
                    let _ = self.app_event_tx.send(AppEvent::NatStatusChanged {
                        label,
                        reachable: becomes_reachable,
                    });
                }
            }
            NetworkEvent::DcutrUpgrade {
                remote_peer,
                success,
            } => {
                if success {
                    // Render the peer as the last 8 chars of the
                    // PeerId for compactness — full peer id is too long
                    // for a status line.
                    let s = remote_peer.to_base58();
                    let tail: String = s.chars().rev().take(8).collect::<String>()
                        .chars()
                        .rev()
                        .collect();
                    let _ = self.app_event_tx.send(AppEvent::DcutrSucceeded {
                        peer_label: tail,
                    });
                }
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
                // huddle 0.7.11: MemberAnnounce must arrive inside a
                // signed envelope, and the signer's fingerprint must
                // match the claimed announcer. Closes the TOFU-pubkey
                // hijack: pre-0.7.11 a malicious peer could race a
                // victim's first announce on a room and pin a fabricated
                // ed25519 pubkey under the victim's fingerprint, so honest
                // peers would later reject the real victim's signed
                // messages. Now the inner `sender_ed25519_pubkey` is
                // ignored — the envelope's pubkey is the authoritative one.
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!(%sender_fingerprint, %room_id, "MemberAnnounce arrived unsigned; dropping");
                        return;
                    }
                };
                if signer != sender_fingerprint {
                    warn!(%signer, %sender_fingerprint, %room_id, "MemberAnnounce signer mismatch; dropping");
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
                    // huddle 0.7: Direct rooms are 1-1 forever. If a
                    // third fingerprint announces, drop it locally and
                    // skip the persist/wrap-session path. This is honest-
                    // client enforcement — a malicious peer with the
                    // canonical DM passphrase-equivalent could still
                    // chat, but they'd never be visible in our sidebar
                    // or render in the DM pane.
                    if room.info.kind == RoomKind::Direct
                        && !room.members.contains(&sender_fingerprint)
                        && room.members.len() >= 2
                    {
                        info!(
                            %sender_fingerprint, %room_id,
                            "dropping MemberAnnounce on Direct room: already at 2-member cap"
                        );
                        return;
                    }
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

                // huddle 0.7.1: for Direct rooms, the passphrase_key is
                // derived from ECDH between our identity key and the
                // partner's. The partner's pubkey may arrive in *this*
                // MemberAnnounce — so we lazily compute the key now,
                // before the unwrap path runs. Idempotent: if we
                // already have the key, this is a no-op.
                if matches!(
                    self.active_rooms
                        .lock()
                        .unwrap()
                        .get(room_id)
                        .map(|r| (r.info.kind, r.passphrase_key.is_none())),
                    Some((RoomKind::Direct, true))
                ) {
                    if let Some(pubkey_b64) = sender_ed25519_pubkey.as_deref() {
                        if let Some(key) =
                            self.derive_dm_key_from_pubkey_b64(room_id, pubkey_b64)
                        {
                            let mut rooms = self.active_rooms.lock().unwrap();
                            if let Some(room) = rooms.get_mut(room_id) {
                                room.passphrase_key = Some(key);
                            }
                            drop(rooms);
                            // We just got the key — re-broadcast our
                            // MemberAnnounce so the partner gets our
                            // wrapped session key. Fire-and-forget;
                            // failures are logged.
                            let app = self.clone();
                            let rid = room_id.to_string();
                            tokio::spawn(async move {
                                if let Err(e) = app.broadcast_member_announce(&rid).await {
                                    warn!(%e, "re-broadcast DM announce after key derivation");
                                }
                            });
                        }
                    }
                }

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
                // huddle 0.7.11: ban filter on every content-bearing arm.
                // Pre-0.7.11 only MemberAnnounce was filtered, so banned
                // peers could still post Encrypted/Plain after a kick
                // (cosmetically in encrypted rooms post-rotation since
                // they have no inbound session, but in unencrypted rooms
                // their plaintext rendered freely — see RoomMessage::Plain
                // arm below).
                if repo::is_member_banned(&self.db, room_id, &sender_fingerprint)
                    .unwrap_or(false)
                {
                    debug!(%sender_fingerprint, %room_id, "dropping Encrypted from banned peer");
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
                if repo::is_member_banned(&self.db, room_id, &sender_fingerprint)
                    .unwrap_or(false)
                {
                    debug!(%sender_fingerprint, %room_id, "dropping Plain from banned peer");
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
                if repo::is_member_banned(&self.db, room_id, &sender_fingerprint)
                    .unwrap_or(false)
                {
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
                // Rotations are self-attested: the signer must be the
                // claimed rotator. Unsigned forgeries land in
                // `verified_signer = None` and are dropped here, as are
                // signed envelopes where the signer fp doesn't match.
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!(%room_id, "RotateRoomKey arrived unsigned; dropping");
                        return;
                    }
                };
                if signer != rotator_fingerprint {
                    warn!(
                        %signer, %rotator_fingerprint, %room_id,
                        "RotateRoomKey signer mismatch with claimed rotator; dropping"
                    );
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
                // huddle 0.7.11: MemberLeave must arrive inside a signed
                // envelope whose signer matches the claimed leaver.
                // Pre-0.7.11 plain leaves and forged leaves are dropped.
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!(%sender_fingerprint, %room_id, "MemberLeave arrived unsigned; dropping");
                        return;
                    }
                };
                if signer != sender_fingerprint {
                    warn!(%signer, %sender_fingerprint, %room_id, "MemberLeave signer mismatch; dropping");
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
                // huddle 0.7.11: FileOffer must be signed so peers can't
                // spoof attribution. The chunk stream itself stays plain
                // (sha256 over the assembly is the integrity gate), but
                // who *announced* the file is now bound to the signer.
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!(%sender_fingerprint, %room_id, %file_id, "FileOffer arrived unsigned; dropping");
                        return;
                    }
                };
                if signer != sender_fingerprint {
                    warn!(%signer, %sender_fingerprint, %room_id, %file_id, "FileOffer signer mismatch; dropping");
                    return;
                }
                // Drop offers from banned peers in the same shape as
                // MemberAnnounce — keeps moderation invariant tight.
                if repo::is_member_banned(&self.db, room_id, &sender_fingerprint)
                    .unwrap_or(false)
                {
                    info!(%sender_fingerprint, %room_id, %file_id, "dropping FileOffer from banned peer");
                    return;
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
                if repo::is_member_banned(&self.db, room_id, &sender_fingerprint)
                    .unwrap_or(false)
                {
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
                        finalized: false,
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
                    .remove(&(room_id.to_string(), our_fp.clone()))
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
                    // huddle 0.7.11: only fire finalize from this arm
                    // when the flow hasn't already been finalized by
                    // the local `sas_match` path. The `finalized`
                    // latch is set inside `finish_sas` (taken under
                    // this same Mutex), so the two paths can't both
                    // observe it as `false`.
                    if flow.our_confirmed && flow.their_confirmed && !flow.finalized {
                        flow.finalized = true;
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
            RoomMessage::ProfileUpdate {
                sender_fingerprint,
                username,
                updated_at,
            } => {
                // huddle 0.5: username spoof defense. Drop any
                // ProfileUpdate that didn't arrive inside a Signed
                // envelope, or whose signer doesn't match the claimed
                // sender_fingerprint. Without this anyone could pretend
                // to be "alice" by stuffing the field.
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!(
                            sender = %sender_fingerprint,
                            "dropping unsigned ProfileUpdate"
                        );
                        return;
                    }
                };
                if signer != sender_fingerprint {
                    warn!(
                        signer = %signer,
                        claimed = %sender_fingerprint,
                        "dropping ProfileUpdate with signer != sender"
                    );
                    return;
                }
                if let Err(e) = repo::upsert_peer_profile(
                    &self.db,
                    &sender_fingerprint,
                    username.as_deref(),
                    updated_at,
                ) {
                    warn!(%e, "upsert_peer_profile failed");
                    return;
                }
                let _ = self.app_event_tx.send(AppEvent::PeerProfileUpdated {
                    fingerprint: sender_fingerprint,
                    username,
                });
            }
            RoomMessage::ContactRequest {
                requester_fingerprint,
                display_name,
                note,
                sender_ed25519_pubkey: _,
            } => {
                // Only honor a contact request that arrived on OUR own inbox
                // room — never one published into a shared room topic.
                if room_id != crate::network::protocol::inbox_room_id(&our_fp) {
                    return;
                }
                // Must be signed, and the signer must BE the requester — the
                // signature is the whole proof of who's asking.
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!(%requester_fingerprint, "dropping unsigned ContactRequest");
                        return;
                    }
                };
                if signer != requester_fingerprint || requester_fingerprint == our_fp {
                    return;
                }
                if repo::is_peer_blocked(&self.db, &requester_fingerprint).unwrap_or(false) {
                    debug!(%requester_fingerprint, "ignoring ContactRequest from blocked peer");
                    return;
                }
                // Mutual case: if this fingerprint is already in our address
                // book (we requested them, or we're already connected), treat
                // their request as acceptance — open/refresh the DM directly,
                // no prompt. This is also how the acceptor's echo-back
                // converges the relay path: both sides end up subscribed to
                // the canonical DM room, after which the normal MemberAnnounce
                // exchange shares session keys.
                if self.is_contact(&requester_fingerprint) {
                    let _ =
                        repo::delete_pending_contact_request(&self.db, &requester_fingerprint);
                    if let Err(e) = self.start_direct(&requester_fingerprint).await {
                        debug!(%e, "ContactRequest mutual: start_direct failed");
                    }
                    return;
                }
                // Fresh inbound request — persist + surface for the user to
                // accept or decline from the Contacts pane.
                if let Err(e) = repo::upsert_pending_contact_request(
                    &self.db,
                    &repo::PendingContactRequest {
                        fingerprint: requester_fingerprint.clone(),
                        display_name: display_name.clone(),
                        note: note.clone(),
                        received_at: now_unix(),
                    },
                ) {
                    warn!(%e, "upsert pending contact request failed");
                    return;
                }
                let _ = self.app_event_tx.send(AppEvent::ContactRequestReceived {
                    fingerprint: requester_fingerprint,
                    display_name,
                    note,
                });
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
            // huddle 0.7.11: read-only joiners (code-joined peers) cannot
            // send files. Mirrors the check in send_room_message; without
            // it, code-joined peers could broadcast FileOffer/FileChunk
            // even though existing members ignore their chat messages.
            if room.read_only {
                return Err(HuddleError::Other(
                    "this room is read-only — you can't send files".into(),
                ));
            }
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

        // Publish the offer. huddle 0.7.11: FileOffer is now signed so
        // peers can't announce a file in someone else's name (attribution
        // spoof). FileChunks themselves stay plain — the receiver
        // assembles by chunk-index and verifies SHA-256 against
        // `file_id`, so spoofed chunks waste bandwidth but can't smuggle
        // mismatched bytes through the hash gate.
        let offer = RoomMessage::FileOffer {
            sender_fingerprint: our_fp.clone(),
            file_id: file_id.clone(),
            name,
            size_bytes: plan.size_bytes,
            mime,
            chunk_count: total,
            encrypted_meta: encrypted_meta_opt,
        };
        if let Ok(env) = crate::crypto::sign_message(&self.identity, &offer) {
            if let Ok(bytes) = crate::network::protocol::encode_wire_signed(&env) {
                self.network
                    .publish_room_message(room_id.to_string(), bytes)
                    .await;
            }
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

    /// huddle 0.7.6: true iff this session was started with a master
    /// passphrase. The TUI uses this to pick the Go Dark gate — passphrase
    /// if available (the natural strong secret the user already knows),
    /// else the typed `DELETE EVERYTHING` phrase since no-master-passphrase
    /// sessions have nothing else to compare against.
    pub fn has_master_passphrase(&self) -> bool {
        self.session_persist_key != [0u8; 32]
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

    /// huddle 0.7.8: persisted LAN-discovery toggle. When true, the next
    /// launch starts in `NetworkMode::Mdns` so the device joins LAN mDNS
    /// announcements **alongside** the onion relay (both transports run
    /// together). When false, the next launch starts relay-only
    /// (`NetworkMode::Server`).
    ///
    /// huddle 0.9.2: default **OFF** (was ON pre-onion-relay) — the
    /// relay-only `Server` mode is the 0.8+ baseline, so the toggle is a
    /// true opt-in. Restart required to apply (a live `Toggle<Mdns>` flip
    /// would require rebuilding the libp2p behaviour).
    pub fn mdns_enabled(&self) -> bool {
        repo::get_setting(&self.db, "mdns_enabled")
            .unwrap_or(None)
            .map(|v| v == "1")
            .unwrap_or(false)
    }

    pub fn set_mdns_enabled(&self, on: bool) -> Result<()> {
        repo::set_setting(&self.db, "mdns_enabled", if on { "1" } else { "0" })
    }

    /// huddle 1.0: the persisted clearnet relay URL (a `ws://<ip>:<port>/ws`
    /// or `wss://host/ws` door onto the relay backend — e.g. a cloudflared
    /// tunnel). `None` when unset/blank. This is what the GUI "Set relay" field
    /// writes and what [`Self::set_clearnet_relay`] manages; the startup
    /// resolution in `start_with_db_and_options` reads it as the lowest-
    /// precedence source (CLI → config.toml → this).
    pub fn clearnet_relay(&self) -> Option<String> {
        repo::get_setting(&self.db, "clearnet_url")
            .unwrap_or(None)
            .filter(|s| !s.trim().is_empty())
    }

    /// huddle 1.0: persist (or clear) the clearnet relay URL and bias the
    /// transport order so it's tried first.
    ///
    /// `Some(url)` saves the URL AND pins a clearnet-first door order so the
    /// app connects straight to the clearnet relay without paying the onion
    /// connect timeout each reconnect cycle (the point of "my VPS, no Tor").
    /// `None` (or a blank url) clears both, restoring the default
    /// most-private-first order. Takes effect on the next launch — mirrors the
    /// mDNS toggle, since the door order is resolved once at startup.
    pub fn set_clearnet_relay(&self, url: Option<&str>) -> Result<()> {
        match url.map(str::trim).filter(|s| !s.is_empty()) {
            Some(u) => {
                repo::set_setting(&self.db, "clearnet_url", u)?;
                // Clearnet doors first so a no-Tor user connects immediately;
                // onion doors stay in the list as fallback.
                repo::set_setting(
                    &self.db,
                    "transport_order",
                    "clearnet-wss,clearnet-ws,onion-tor,onion-bridge,onion-arti",
                )
            }
            None => {
                repo::set_setting(&self.db, "clearnet_url", "")?;
                // Empty → resolution falls back to the default fallback order.
                repo::set_setting(&self.db, "transport_order", "")
            }
        }
    }

    /// huddle 0.7.8: persisted desktop-notification opt-out. The
    /// notifier itself is a local-only `osascript`/`notify-send`
    /// process call — toggling this OFF skips the call entirely so
    /// nothing reaches the OS notification daemon. Default ON to
    /// preserve current behavior.
    pub fn notifications_enabled(&self) -> bool {
        repo::get_setting(&self.db, "notifications_enabled")
            .unwrap_or(None)
            .map(|v| v == "1")
            .unwrap_or(true)
    }

    pub fn set_notifications_enabled(&self, on: bool) -> Result<()> {
        repo::set_setting(
            &self.db,
            "notifications_enabled",
            if on { "1" } else { "0" },
        )
    }

    /// huddle 0.7.8: stable 12-hex Safety Code derived from our Ed25519
    /// pubkey. Display-only; used as a quick visual fingerprint match in
    /// Profile / Account. SAS-via-emoji remains the actual verification
    /// primitive.
    pub fn safety_code(&self) -> String {
        crate::identity::safety_code(&self.identity.public_bytes())
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

    /// huddle 0.6: version string of huddle the user last finished
    /// onboarding for. Compared against `env!("CARGO_PKG_VERSION")` at
    /// startup so a version bump re-fires the "what's new" card.
    pub fn last_seen_onboarding_version(&self) -> Option<String> {
        repo::get_last_seen_onboarding_version(&self.db).unwrap_or(None)
    }

    pub fn set_last_seen_onboarding_version(&self, version: &str) -> Result<()> {
        repo::set_last_seen_onboarding_version(&self.db, version)
    }

    /// huddle 0.6: opt-in flag for the crates.io update check.
    /// `None` ⇒ the user hasn't been asked yet.
    pub fn update_check_enabled(&self) -> Option<bool> {
        repo::get_update_check_enabled(&self.db).unwrap_or(None)
    }

    pub fn set_update_check_enabled(&self, enabled: bool) -> Result<()> {
        repo::set_update_check_enabled(&self.db, enabled)
    }

    /// huddle 0.6: cache anchor for the once-per-24h crates.io poll.
    /// Returns 0 if nothing has been recorded yet.
    pub fn last_update_check_at(&self) -> i64 {
        repo::get_setting(&self.db, "last_update_check_at")
            .ok()
            .flatten()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    pub fn set_last_update_check_at(&self, ts: i64) -> Result<()> {
        repo::set_setting(&self.db, "last_update_check_at", &ts.to_string())
    }

    /// huddle 0.6: the most recent `max_stable_version` we saw on
    /// crates.io. Persisted so a re-launch within the 24h window
    /// can render the banner without re-fetching.
    pub fn last_known_remote_version(&self) -> Option<String> {
        repo::get_setting(&self.db, "last_known_remote_version")
            .ok()
            .flatten()
    }

    pub fn set_last_known_remote_version(&self, v: &str) -> Result<()> {
        repo::set_setting(&self.db, "last_known_remote_version", v)
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
                    // huddle 0.7: code-join is groups-only by design — DMs
                    // are 1-1 and don't use the code flow.
                    kind: d.kind,
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
        // Stash the secret keyed by (room_id, our_fp); the response
        // handler removes the matching entry when a response targeted
        // at us arrives. The composite key means a second joiner can
        // be in flight in the same room without overwriting our state.
        let key = (room_id.to_string(), our_fp.clone());
        self.pending_code_secrets
            .lock()
            .unwrap()
            .insert(key.clone(), our_secret);
        // Code-join timeout: if no response in 30s, the entry will
        // still be in the map (the response handler removes it on
        // success). Surface a `CodeJoinTimedOut` to the TUI so the
        // user isn't stuck staring at an empty room expecting traffic.
        let map = self.pending_code_secrets.clone();
        let tx = self.app_event_tx.clone();
        let timeout_room = room_id.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let still_pending = map.lock().unwrap().remove(&key).is_some();
            if still_pending {
                let _ = tx.send(AppEvent::CodeJoinTimedOut {
                    room_id: timeout_room,
                    reason: "no response from owner — code may be wrong or expired".into(),
                });
            }
        });
        // Persist the rooms row BEFORE constructing RoomCrypto, whose
        // `persist_outbound()` writes a `room_megolm_sessions` row with
        // a FK to `rooms(id)`. Without this, the FK fires and the
        // join aborts. The salt is left None for now — we don't have
        // the passphrase and the announcing peer's salt is cached in
        // ROOM_SALT_CACHE for whenever we get re-onboarded.
        repo::insert_room(&self.db, &info)?;
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
                finalized: false,
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
            // huddle 0.7.11: latch finalize so the inbound SasConfirm
            // handler won't fire `finish_sas` a second time. See
            // SasConfirm arm for the symmetric guard.
            let do_finish = flow.our_confirmed && flow.their_confirmed && !flow.finalized;
            if do_finish {
                flow.finalized = true;
            }
            (
                flow.room_id.clone(),
                flow.partner_fingerprint.clone(),
                do_finish,
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

    /// huddle 0.5: set the local user's self-declared username (or clear
    /// it with None) and broadcast a signed `ProfileUpdate` to every
    /// joined room. Receivers cache the latest per-fingerprint username
    /// in `peer_profiles`; unsigned envelopes are dropped at the receive
    /// arm so the username can't be spoofed.
    pub async fn set_username(&self, name: Option<&str>) -> Result<()> {
        repo::set_display_name(&self.db, name)?;
        let msg = RoomMessage::ProfileUpdate {
            sender_fingerprint: self.identity.fingerprint().to_string(),
            username: name.map(|s| s.to_string()),
            updated_at: now_unix_ms(),
        };
        let env = crate::crypto::sign_message(&self.identity, &msg)?;
        let bytes = crate::network::protocol::encode_wire_signed(&env)?;
        let rooms: Vec<String> = self.active_rooms.lock().unwrap().keys().cloned().collect();
        for room_id in rooms {
            self.network
                .publish_room_message(room_id, bytes.clone())
                .await;
        }
        Ok(())
    }

    /// huddle 0.5: cached username for a peer (any peer we've ever
    /// received a signed `ProfileUpdate` from), or None if unknown or
    /// the peer cleared their username. Callers render `[anonymous]` on
    /// None.
    pub fn lookup_username(&self, fingerprint: &str) -> Option<String> {
        repo::get_peer_username(&self.db, fingerprint).unwrap_or(None)
    }

    /// Look up the display name we've seen for a peer. Forwards to
    /// `lookup_username` (the new signed-source-of-truth) so existing
    /// call sites get the authenticated value without churn.
    pub fn lookup_member_display_name(&self, fingerprint: &str) -> Option<String> {
        self.lookup_username(fingerprint)
    }

    /// huddle 0.7.12: reverse of `lookup_username` — every fingerprint
    /// that has broadcast `username` via a signed `ProfileUpdate`.
    /// Usernames aren't unique, so callers must handle 0 / 1 / many.
    /// Backs the Compose-DM resolver so typing a contact's name opens a
    /// DM over the existing mesh instead of falling through to a fresh
    /// dial (matching the resolution `dial_by_id_or_username` already
    /// does for the add-friend flow).
    pub fn peers_with_username(&self, username: &str) -> Vec<String> {
        repo::find_peers_by_username(&self.db, username).unwrap_or_default()
    }

    pub fn is_room_muted(&self, room_id: &str) -> bool {
        repo::is_room_muted(&self.db, room_id).unwrap_or(false)
    }

    /// Phase B: list the fingerprints currently banned from a room
    /// (newest first). Backs the `^B` in-room view; intended for
    /// owners but the read itself is harmless and we let callers
    /// gate via `we_are_owner` if they want owner-only display.
    pub fn list_room_bans(&self, room_id: &str) -> Vec<String> {
        repo::list_room_bans(&self.db, room_id).unwrap_or_default()
    }

    /// Phase A: list every globally-blocked peer (one fingerprint per
    /// row). Surfaced in the Settings modal alongside a clear-all
    /// action that calls `unblock_peer` in a loop.
    /// huddle 0.7: every globally SAS-verified peer. Surfaced in the
    /// People pane's "Verified" sub-list.
    pub fn list_verified_peers(&self) -> Vec<String> {
        repo::list_verified_peers(&self.db).unwrap_or_default()
    }

    pub fn list_blocked_peers(&self) -> Vec<String> {
        repo::list_blocked_peers(&self.db).unwrap_or_default()
    }

    /// Phase A: remove `fingerprint` from the persistent blocklist. The
    /// peer will no longer be auto-rejected on connection; they fall
    /// back to the regular inbound-dial accept/reject prompt.
    pub fn unblock_peer(&self, fingerprint: &str) -> Result<()> {
        repo::unblock_peer(&self.db, fingerprint)
    }

    /// huddle 0.7: add `fingerprint` to the persistent blocklist. Used
    /// by the People pane's per-row "block" action. Subsequent inbound
    /// dials from this fingerprint are auto-rejected without prompting.
    pub fn block_peer(&self, fingerprint: &str) -> Result<()> {
        repo::block_peer(&self.db, fingerprint, now_unix())
    }

    /// Phase F: rooms entered via a join code don't have the passphrase
    /// in memory, so the joining peer can't wrap their own outbound
    /// session key for newer members — they can read and send, they
    /// just can't onboard others. The TUI renders a `(read-only)`
    /// badge in the room tab so the user understands.
    pub fn is_room_read_only(&self, room_id: &str) -> bool {
        self.active_rooms
            .lock()
            .unwrap()
            .get(room_id)
            .map(|r| r.read_only)
            .unwrap_or(false)
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
        // Signed: rotations are self-attested, so peers can prove the
        // claimed `rotator_fingerprint` really came from that identity.
        // An unsigned rotation is rejected on the receive side.
        if let Ok(env) = crate::crypto::sign_message(&self.identity, &rot) {
            if let Ok(bytes) = crate::network::protocol::encode_wire_signed(&env) {
                self.network
                    .publish_room_message(room_id.to_string(), bytes)
                    .await;
            }
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
    /// fingerprint or our `HD-XXXX-XXXX` 8-hex-char prefix.
    ///
    /// huddle 0.7.11: pre-0.7.11 the short-form match used only the
    /// first 4-hex group (~65 K possibilities), so unrelated peers
    /// sharing a prefix triggered false mentions — and a hostile peer
    /// could weaponize a 4-hex literal in their message body to spam
    /// the victim's terminal bell, bypassing per-room mute. Bumping to
    /// the first 8 hex chars makes the search space 16^8 ≈ 4 billion
    /// and effectively eliminates collisions while still being short
    /// enough to type as a mention ("hey HD-a3b1c2d4 …").
    fn maybe_emit_mention(&self, room_id: &str, body: &str) {
        let full = self.identity.fingerprint().to_lowercase();
        // First 8 hex chars (two dash-separated groups joined), e.g.
        // "a3b1c2d4" of "a3b1-c2d4-…".
        let short: String = full.chars().filter(|c| c.is_ascii_hexdigit()).take(8).collect();
        let lower = body.to_lowercase();
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

    /// huddle 0.5: irreversibly delete this account. Verifies the
    /// master passphrase, best-effort `MemberLeave`s every joined room
    /// (capped at 2 s so a single unresponsive transport can't hang
    /// the wipe), shuts down the network, then deletes the database,
    /// keychain salt, log, and config files from `config::data_dir()`.
    /// Emits `AppEvent::WentDark` on success so the TUI can show a
    /// goodbye modal and exit.
    ///
    /// In `--no-master-passphrase` mode (`self.session_persist_key`
    /// is all-zero), the passphrase check is skipped — the typed
    /// `DELETE EVERYTHING` confirmation in the TUI is the only gate.
    pub async fn go_dark(&self, master_passphrase: &str) -> Result<()> {
        let no_master = self.session_persist_key == [0u8; 32];
        if !no_master {
            let salt = storage::keychain::load_or_create_salt()?;
            let candidate_master =
                storage::keychain::derive_master_key(master_passphrase, &salt)?;
            let candidate_subkey =
                storage::keychain::derive_subkey(&candidate_master, b"megolm-persist");
            if !ct_eq_32(&candidate_subkey, &self.session_persist_key) {
                return Err(HuddleError::Other(
                    "incorrect master passphrase".into(),
                ));
            }
        }

        let room_ids: Vec<String> = self
            .active_rooms
            .lock()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            for room_id in &room_ids {
                if let Err(e) = self.leave_room(room_id).await {
                    warn!(%room_id, %e, "go_dark: leave_room failed");
                }
            }
        })
        .await;

        self.network.shutdown().await;
        tokio::time::sleep(Duration::from_millis(300)).await;

        let data_dir = config::data_dir();
        let candidates = [
            "huddle.db",
            "huddle.db-shm",
            "huddle.db-wal",
            "keychain.salt",
            "huddle.log",
            "config.toml",
        ];
        for name in &candidates {
            let path = data_dir.join(name);
            wipe_file(&path);
        }
        if let Ok(read) = std::fs::read_dir(&data_dir) {
            for entry in read.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.starts_with("huddle.log.") {
                        wipe_file(&entry.path());
                    }
                }
            }
        }
        // huddle 0.5.1: wipe the attachment cache directory. Each file
        // inside is best-effort zeroed first, then the directory
        // itself is removed.
        let files_dir = data_dir.join("files");
        if let Ok(read) = std::fs::read_dir(&files_dir) {
            for entry in read.flatten() {
                let path = entry.path();
                if path.is_file() {
                    wipe_file(&path);
                } else if path.is_dir() {
                    // Two-level nesting (room_id subdirs) — sweep their
                    // contents too.
                    if let Ok(inner) = std::fs::read_dir(&path) {
                        for inner_entry in inner.flatten() {
                            if inner_entry.path().is_file() {
                                wipe_file(&inner_entry.path());
                            }
                        }
                    }
                    let _ = std::fs::remove_dir(&path);
                }
            }
        }
        let _ = std::fs::remove_dir(&files_dir);
        let _ = std::fs::remove_dir(&data_dir);

        let _ = self.app_event_tx.send(AppEvent::WentDark);
        Ok(())
    }
}

/// huddle 0.5.1: parse `input` as a huddle ID — either `HD-`-prefixed
/// or a bare 24-char hex run with or without dashes — and return it in
/// the canonical lowercase-dashed form `xxxx-xxxx-...-xxxx` that
/// matches `identity::compute_fingerprint`'s output. Returns None for
/// anything that isn't a syntactic ID (the caller falls back to
/// username lookup).
pub fn normalize_to_fingerprint(input: &str) -> Option<String> {
    let s = input
        .trim()
        .trim_start_matches("HD-")
        .trim_start_matches("hd-")
        .to_string();
    let hex_only: String = s.chars().filter(|c| *c != '-').collect();
    if hex_only.len() != 24 || !hex_only.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let lower = hex_only.to_ascii_lowercase();
    let chunks: Vec<String> = lower
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap().to_string())
        .collect();
    Some(chunks.join("-"))
}

/// huddle 0.5.2: rank a multiaddr by transport preference. Lower =
/// better. Used to sort candidate addresses for the parallel dialer so
/// LAN connections get a head-start over relay-hopped ones when wall-
/// times are close. The numeric values are arbitrary; only the
/// ordering matters.
fn address_preference(addr: &str) -> u8 {
    if addr.contains("/p2p-circuit") {
        return 9; // relay-hopped — bottom of the list
    }
    if let Some(rest) = addr.strip_prefix("/ip4/") {
        if let Some(ip_str) = rest.split('/').next() {
            if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                if ip.is_loopback() {
                    return 1; // useful for tests
                }
                if is_rfc1918(&ip) || ip.is_link_local() {
                    return 0; // LAN — wins ties
                }
                return 3; // public ipv4
            }
        }
        return 3;
    }
    if addr.starts_with("/ip6/") {
        return 4;
    }
    if addr.starts_with("/dns4/") || addr.starts_with("/dns6/") || addr.starts_with("/dnsaddr/") {
        return 5;
    }
    7
}

/// True for IPv4 addresses in private (RFC 1918) ranges — 10/8,
/// 172.16/12, 192.168/16. Used by `address_preference` to score LAN
/// dials ahead of public-IP and relay-hopped ones.
fn is_rfc1918(ip: &std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 10
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
}

/// Short label for an HD ID, used only in error messages — strips the
/// fingerprint down to its first four hex chars with the brand prefix
/// so the message reads naturally.
fn short_fp_for_msg(fingerprint: &str) -> String {
    let head: String = fingerprint
        .chars()
        .filter(|c| *c != '-')
        .take(4)
        .collect::<String>()
        .to_ascii_uppercase();
    format!("HD-{}…", head)
}

/// Constant-time 32-byte equality. Used by `go_dark` to compare a
/// re-derived HKDF subkey to the in-memory `session_persist_key`
/// without leaking timing information about which byte differed.
fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Best-effort file wipe: overwrite with zeros, then delete. Missing /
/// permission-denied files are logged and skipped. Called from
/// `go_dark` only — not a general-purpose util.
fn wipe_file(path: &Path) {
    use std::io::Write;
    // huddle 0.7.11: write zeros in a 64 KiB scratch buffer instead of
    // allocating a vec the full file size. The original implementation
    // OOM'd `go_dark` mid-wipe whenever a user had downloaded a
    // multi-GB attachment — the panic aborted before DB / config wipe,
    // leaving a half-wiped data dir.
    const SCRATCH: usize = 64 * 1024;
    if let Ok(meta) = std::fs::metadata(path) {
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
            let zeros = [0u8; SCRATCH];
            let mut remaining = meta.len();
            while remaining > 0 {
                let n = remaining.min(SCRATCH as u64) as usize;
                if f.write_all(&zeros[..n]).is_err() {
                    break;
                }
                remaining -= n as u64;
            }
            let _ = f.sync_all();
        }
    }
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!(?path, %e, "wipe_file: remove failed");
        }
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

/// Public accessor for the Argon2id salt length used when deriving room
/// passphrase keys. Exists so downstream tooling (status pages, debug
/// CLIs, integration tests) can confirm the expected size without
/// re-importing the constant from `crypto::passphrase`.
pub fn salt_len() -> usize {
    SALT_LEN
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
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

/// Phase F: short human-readable join code. 8 chars from a 31-symbol
/// alphabet (no easily-confused chars like 0/O/I/1/L) ≈ 39.6 bits —
/// plenty for a 10-minute online gate since the owner's client checks
/// exact-match (not brute-force-able offline).
///
/// huddle 0.7.11: comment said "32-symbol" but the literal contains 31
/// bytes (A-Z minus I/L/O = 23, plus 2-9 = 8, total 31). Doc updated
/// to match.
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

#[cfg(test)]
mod transport_preference_tests {
    use super::{address_preference, normalize_to_fingerprint};

    #[test]
    fn lan_beats_public_beats_circuit() {
        let lan = address_preference("/ip4/192.168.1.5/tcp/9027");
        let pub_v4 = address_preference("/ip4/8.8.8.8/tcp/9027");
        let circuit = address_preference(
            "/ip4/1.2.3.4/tcp/4001/p2p/12D3Koo/p2p-circuit/p2p/12D3KooXYZ",
        );
        assert!(lan < pub_v4, "LAN {} should beat public {}", lan, pub_v4);
        assert!(
            pub_v4 < circuit,
            "public {} should beat circuit {}",
            pub_v4,
            circuit
        );
    }

    #[test]
    fn all_rfc1918_ranges_are_lan() {
        assert_eq!(
            address_preference("/ip4/10.0.0.1/tcp/9027"),
            address_preference("/ip4/192.168.0.1/tcp/9027"),
        );
        assert_eq!(
            address_preference("/ip4/172.16.0.1/tcp/9027"),
            address_preference("/ip4/192.168.0.1/tcp/9027"),
        );
        // 172.32.x.x is OUTSIDE the 172.16-31 RFC1918 slice.
        assert!(
            address_preference("/ip4/172.32.0.1/tcp/9027")
                > address_preference("/ip4/172.16.0.1/tcp/9027")
        );
    }

    #[test]
    fn normalize_id_accepts_branded_and_raw() {
        let canon = "aaaa-bbbb-cccc-dddd-eeee-ffff";
        assert_eq!(
            normalize_to_fingerprint("HD-AAAA-BBBB-CCCC-DDDD-EEEE-FFFF").as_deref(),
            Some(canon)
        );
        assert_eq!(
            normalize_to_fingerprint("aaaabbbbccccddddeeeeffff").as_deref(),
            Some(canon)
        );
        assert_eq!(normalize_to_fingerprint(canon).as_deref(), Some(canon));
        assert!(normalize_to_fingerprint("alice").is_none());
        assert!(normalize_to_fingerprint("HD-ZZZZ").is_none());
    }
}

#[cfg(test)]
mod canonical_dm_room_id_tests {
    use super::canonical_dm_room_id;

    #[test]
    fn dm_room_id_is_commutative() {
        // The single load-bearing property: both peers, no matter who
        // calls `start_direct` first, derive identical IDs.
        let a = "aaaa-bbbb-cccc-dddd-eeee-ffff";
        let b = "1111-2222-3333-4444-5555-6666";
        assert_eq!(canonical_dm_room_id(a, b), canonical_dm_room_id(b, a));
    }

    #[test]
    fn dm_room_id_differs_per_pair() {
        let a = "aaaa-bbbb-cccc-dddd-eeee-ffff";
        let b = "1111-2222-3333-4444-5555-6666";
        let c = "9999-8888-7777-6666-5555-4444";
        assert_ne!(canonical_dm_room_id(a, b), canonical_dm_room_id(a, c));
        assert_ne!(canonical_dm_room_id(a, b), canonical_dm_room_id(b, c));
    }

    #[test]
    fn dm_room_id_is_stable() {
        // Deterministic by construction; this guards against
        // accidentally mixing in a timestamp or nonce in a future
        // refactor — that would break idempotency across peers.
        let a = "aaaa-bbbb-cccc-dddd-eeee-ffff";
        let b = "1111-2222-3333-4444-5555-6666";
        let id1 = canonical_dm_room_id(a, b);
        let id2 = canonical_dm_room_id(a, b);
        assert_eq!(id1, id2);
        // Same length as `derive_room_id` output (32 hex chars / 16
        // bytes) so DM IDs are indistinguishable from group IDs at the
        // topic-name layer.
        assert_eq!(id1.len(), 32);
    }
}
