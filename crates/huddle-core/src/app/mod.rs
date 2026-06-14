mod contacts;
pub mod events;
mod files;
mod handlers;
mod moderation;
mod rooms;
mod sas_actor;
mod settings;
mod spawns;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use libp2p::{Multiaddr, PeerId};
use tokio::sync::{broadcast, Notify};
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
use crate::network::server::{ServerClient, ServerEvent};
use crate::network::transport::{self, TransportId, TransportProfile};
use crate::network::{self, NetworkHandle, NetworkMode};
use crate::storage::repo::{
    self, derive_room_id, AttachmentStatus, KnownPeer, RoomKind, StoredAttachment, StoredRoom,
    StoredRoomMember,
};
use crate::storage::{self, Db};

pub use self::events::{AppEvent, DiscoveredRoom};
use self::sas_actor::{SasActor, SasError, SasOutcome};

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

/// huddle 1.2.3: how long a quiet gap between two consecutive messages has to
/// be before the chat view starts a fresh, timestamped group (GUI) / draws a
/// time separator (TUI) instead of running them together. Kept short — a couple
/// of minutes — so a message sent even a few minutes after the last one shows
/// its own time rather than looking continuous. UTC throughout (matches logs).
pub const MESSAGE_GROUP_GAP_SECS: i64 = 2 * 60;

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
    /// huddle 1.3: for a hybrid post-quantum DM where WE are the initiator
    /// (lower fingerprint), the base64 ML-KEM-768 ciphertext we encapsulated
    /// to the partner. Re-published in every `MemberAnnounce` so the partner
    /// can decapsulate the same hybrid wrap key. `None` for group rooms, for
    /// classical DMs, and on the responder side (it never encapsulates). Held
    /// in memory only — it is deterministic and re-derived after a restart
    /// once the partner re-announces their ML-KEM key.
    dm_kem_ciphertext: Option<String>,
    /// huddle 1.3.1: `true` once this Direct room's wrap key is the **hybrid**
    /// (X25519 + ML-KEM-768) key. Gates the one-way classical→hybrid upgrade in
    /// `ensure_dm_key`: a classical-locked DM is upgraded to hybrid the moment
    /// the partner's post-quantum capability is observed, but a hybrid key is
    /// never downgraded. In-memory only; re-established from the persisted
    /// `room_members.mlkem_pubkey` pin after a restart. `false` for groups and
    /// classical DMs.
    dm_is_hybrid: bool,
    /// huddle 1.3.1: bounded retry counter for the ticker-driven
    /// `SessionKeyRequest` nudge that heals a DM whose hybrid handshake stalled
    /// (e.g. the initiator's single ciphertext-bearing announce was lost). Capped
    /// at `DM_KEY_RETRY_MAX` so we never spam an unreachable partner's mailbox;
    /// reset to 0 once the room reaches its desired keyed state.
    dm_key_retry: u8,
}

/// huddle 1.3.1: outcome of `ensure_dm_key` — tells the caller how to react.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DmKeyOutcome {
    /// We newly set (or upgraded to) the DM wrap key — re-broadcast our
    /// `MemberAnnounce` so the partner gets our wrapped session key (and, when
    /// we are the initiator, the KEM ciphertext).
    ReBroadcast,
    /// We are the responder, the partner is PQ-capable, but we don't yet have
    /// the KEM ciphertext — ask the initiator (via `SessionKeyRequest`) to
    /// re-announce it so we can decapsulate.
    RequestCiphertext,
    /// Nothing to do (already settled, can't derive yet, or not applicable).
    Noop,
}

/// huddle 1.3.1: which derivation `ensure_dm_key` should perform. Factored out
/// as a **pure** function so the security-critical decision (refuse classical
/// for a PQ-pinned peer; one-way classical→hybrid upgrade; never downgrade) is
/// directly unit-testable without standing up an `AppHandle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DmKeyAction {
    /// Derive a classical X25519 wrap key (partner has never shown PQ capability).
    Classical,
    /// We are the initiator: encapsulate a fresh ML-KEM secret → hybrid key + ct.
    HybridInitiator,
    /// We are the responder and hold the initiator's ciphertext: decapsulate → hybrid.
    HybridResponder,
    /// Responder, PQ-capable partner, but no ciphertext yet — ask for it.
    RequestCiphertext,
    /// Nothing to derive (settled hybrid, or steady classical with a non-PQ peer).
    Noop,
}

/// huddle 1.3.1: the pure DM-key decision. `partner_pq_capable` folds together
/// "this announce carried an ML-KEM key" and "we have a persisted pin", so this
/// is the single place the downgrade/upgrade policy lives:
///   * a settled hybrid DM is never touched (no downgrade);
///   * a PQ-capable partner always yields a hybrid action (classical is refused),
///     even if the DM is currently keyed classical (→ upgrade);
///   * a non-PQ partner yields classical only on first keying; once keyed it's a no-op.
fn plan_dm_key(
    already_keyed: bool,
    already_hybrid: bool,
    partner_pq_capable: bool,
    we_are_initiator: bool,
    have_ciphertext: bool,
) -> DmKeyAction {
    if already_keyed && already_hybrid {
        return DmKeyAction::Noop; // settled hybrid — final
    }
    if partner_pq_capable {
        // Hybrid only — never fall back to / stay on classical for a PQ peer.
        if we_are_initiator {
            DmKeyAction::HybridInitiator
        } else if have_ciphertext {
            DmKeyAction::HybridResponder
        } else {
            DmKeyAction::RequestCiphertext
        }
    } else if already_keyed {
        DmKeyAction::Noop // steady classical with a genuine non-PQ peer
    } else {
        DmKeyAction::Classical
    }
}

/// huddle 1.3.1: hard cap on ticker-driven `SessionKeyRequest` nudges for a
/// stalled DM handshake (~`DM_KEY_RETRY_MAX * ANNOUNCE_INTERVAL_SECS`). Bounds
/// mailbox impact for an offline partner; the partner's own re-announce on
/// reconnect remains the long-term healing path.
const DM_KEY_RETRY_MAX: u8 = 10;

/// huddle 1.3.1: minimum seconds between decrypt-miss `SessionKeyRequest`
/// heals per room — debounces a burst of undecryptable messages into one
/// request. The request makes peers re-broadcast their `MemberAnnounce`
/// (re-delivering the session key), so this is self-terminating: once we
/// receive the missing key, decrypts succeed and no more requests fire.
const KEY_REQUEST_COOLDOWN_SECS: i64 = 15;

/// huddle 2.0.2 (audit M-4): minimum seconds between MemberAnnounce *responses*
/// to inbound `SessionKeyRequest`s, per room. The request is unsigned and
/// unthrottled on the wire, so without this a storm makes every member re-emit a
/// full announce — an amplification/reflection DoS against the room and relay.
const ANNOUNCE_ON_REQUEST_COOLDOWN_SECS: i64 = 10;

impl Drop for ActiveRoom {
    /// huddle 1.3: wipe the DM/group **wrap key** (the classical or hybrid
    /// `passphrase_key` that unwraps Megolm session keys) when the room leaves
    /// memory, so the secret doesn't linger in a freed heap page or swap.
    /// Matches the project's `Zeroizing`-everything posture for derived keys.
    fn drop(&mut self) {
        if let Some(k) = self.passphrase_key.as_mut() {
            zeroize::Zeroize::zeroize(k);
        }
    }
}

const TYPING_TTL_SECS: i64 = 3;

/// TTL for a discovered room before it's considered stale (re-announcements
/// happen every 15 seconds; after 45s of silence we drop it).
const DISCOVERED_TTL_SECS: i64 = 45;
const ANNOUNCE_INTERVAL_SECS: u64 = 15;
/// huddle 2.0.3 (audit L-15 residual): hard ceiling on the in-memory
/// discovered-rooms map so a gossipsub flood of distinct room_ids can't grow it
/// without bound between the 45s TTL prunes. Eviction is stalest-first.
const MAX_DISCOVERED_ROOMS: usize = 1024;

/// huddle 2.0.3 (audit N-L2/L-4): minimum length for any passphrase we SET — a
/// master passphrase (setup / change / go-dark) or a room passphrase (create /
/// rotate). Enforced only at set time, never at derive/verify, so an existing
/// short passphrase still unlocks and a joiner can still enter a room whose
/// passphrase predates this floor. Argon2id raises a guess's cost but can't
/// rescue a trivially short secret — and a room's salt is broadcast in the clear,
/// so a weak room passphrase is directly offline-brute-forceable.
pub const MIN_PASSPHRASE_LEN: usize = 8;

fn validate_passphrase_len(p: &str) -> Result<()> {
    if p.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(HuddleError::Other(format!(
            "passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
        )));
    }
    Ok(())
}

// huddle 2.0.5 (WS2 foundations, increment #1): the SAS handshake state
// (`SasFlow`), the flow-map caps/TTL constants, and the verification state
// machine moved to `sas_actor::SasActor`. The `AppHandle` facade now delegates
// to it and applies the returned outcomes. See `crate::app::sas_actor`.

/// huddle 0.8: the canonical centralized server, reachable only as a Tor
/// v3 onion. Baked in so the client connects to the operator's relay by
/// default; override with the `--server <ws-url>` CLI flag, disable with
/// `--no-server`. Reached through the local Tor SOCKS5 proxy.
pub const DEFAULT_SERVER_URL: &str =
    "ws://huddleg2647kbrmngflqai23f4rrc7l5dnszz5lij76uhqzmkebx2mid.onion:80/ws";
/// huddle 1.1: the operator's **clearnet** door onto the SAME relay backend as
/// [`DEFAULT_SERVER_URL`], fronted by a cloudflared tunnel (valid TLS, no
/// domain of our own). Baked in so users who can't reach Tor still connect with
/// zero config. It sits LAST in [`default_fallback_order`], so a working onion
/// is always preferred and a Tor user never dials clearnet — this only lights
/// up when the onion is unreachable.
///
/// huddle 1.1.5: this is now a **stable** address — a free Cloudflare
/// `*.workers.dev` Worker that WS-proxies to the operator's relay. The Worker
/// reads the relay's current (rotating) `cloudflared` backend from KV, which the
/// VPS keeps fresh on every rotation, so this hostname never goes stale (unlike
/// the raw `*.trycloudflare.com` quick-tunnel URLs baked in 1.1.0–1.1.4). It
/// exists for users in regions where Tor itself is blocked. Still LAST in
/// [`default_fallback_order`], so a working onion is always preferred and a Tor
/// user never dials clearnet. Override per-client with `--clearnet-server`,
/// `clearnet_url` in config.toml, or Settings → Network; an explicit value
/// always wins over this default.
pub const DEFAULT_CLEARNET_URL: &str = "wss://huddle-ws-proxy.richer-richard.workers.dev/ws";
/// Local Tor SOCKS5 proxy used to dial `.onion` server URLs.
pub const DEFAULT_TOR_SOCKS: &str = "127.0.0.1:9050";

#[derive(Clone)]
pub struct AppHandle {
    identity: Arc<Identity>,
    network: NetworkHandle,
    /// huddle 2.0.0: set true by `shutdown()` so the relay-connection loop
    /// (`spawn_server_connection`) stops connecting/reconnecting and exits —
    /// otherwise it holds an `AppHandle` clone and keeps a live relay socket
    /// open after shutdown (a leak, and across an in-process restart it lets a
    /// stale instance race the new one on the shared on-disk DB).
    shutting_down: Arc<std::sync::atomic::AtomicBool>,
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
    ///
    /// huddle 2.0.0 (F5): behind a `Mutex` so `change_master_passphrase` can
    /// swap it in place after re-deriving it from the new passphrase — the
    /// AppHandle (and every clone) keeps working without a rebuild. Read via
    /// `persist_key()`; all RoomCrypto construction goes through that accessor.
    session_persist_key: Arc<Mutex<[u8; 32]>>,
    /// Phase G: the SAS verification subsystem — owns the in-flight handshake
    /// state. Extracted from this god-object in 2.0.5 (WS2 increment #1).
    sas: Arc<SasActor>,
    /// Phase F: ephemeral X25519 secrets the joiner is holding while
    /// they wait for the owner's `CodeJoinResponse`. Keyed by
    /// `(room_id, joiner_fp)` so multiple joiners in the same room can
    /// be in flight concurrently without trampling each other; and so
    /// the 30s timeout task (see `join_room_with_code`) can clean up
    /// its own entry by composite key without racing with peers.
    pending_code_secrets: Arc<Mutex<HashMap<(String, String), x25519_dalek::StaticSecret>>>,
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
    /// huddle 1.3.1: per-room cooldown (room_id → last unix) for the
    /// decrypt-miss `SessionKeyRequest` heal — a burst of undecryptable
    /// messages triggers at most one key request per `KEY_REQUEST_COOLDOWN_SECS`.
    key_request_cooldown: Arc<Mutex<HashMap<String, i64>>>,
    /// huddle 2.0.2 (audit M-4): per-room cooldown (room_id → last unix) for
    /// re-announcing in response to an inbound `SessionKeyRequest`, throttling
    /// the amplification/reflection vector.
    announce_on_request_cooldown: Arc<Mutex<HashMap<String, i64>>>,
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
    /// huddle 2.1.1: the live door order the relay reconnect loop reads at the
    /// top of every cycle. Seeded from the startup-resolved order;
    /// `set_transport_order` / `set_clearnet_relay` swap it and poke
    /// `relay_reconnect`, so a priority change applies immediately instead of
    /// only on the next launch.
    transport_order: Arc<Mutex<Vec<TransportId>>>,
    /// huddle 2.1.1: notified to make the relay loop drop the current socket
    /// and re-dial with the freshly-set `transport_order`.
    relay_reconnect: Arc<Notify>,
    /// huddle 1.1.4: the resolved Tor SOCKS5 proxy address (CLI/config →
    /// `DEFAULT_TOR_SOCKS`). Stored so privacy-sensitive clearnet fetches
    /// (the opt-in update check) can be routed through Tor instead of
    /// leaking the client's IP onto the clearnet.
    tor_socks: String,
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

/// huddle 1.2: whether a message typed into a room can actually leave this
/// device right now. The UIs query this to gate the composer instead of
/// optimistically echoing a message that silently reaches no one — the
/// "I typed but nothing happened" failure. Distinct from `RoomTransport`,
/// which is a pure status label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendReadiness {
    /// A live transport exists (a direct LAN link to a member, or the relay).
    /// The message will be delivered live, or — over the relay — reliably
    /// queued in the recipient's offline mailbox until they reconnect.
    Ready,
    /// The relay is configured but not connected yet (booting, reconnecting,
    /// or the Tor circuit is still coming up). Sending now would not leave the
    /// device, so the UI should hold the message and show "connecting".
    Connecting,
    /// No transport at all — the relay is disabled (`--no-server`) and there's
    /// no LAN link. Nothing typed here can reach the other party.
    Disconnected,
}

impl SendReadiness {
    /// True only when a send will actually go somewhere.
    pub fn can_send(self) -> bool {
        matches!(self, SendReadiness::Ready)
    }

    /// Short reason for the UI to show when the composer is gated.
    pub fn reason(self) -> &'static str {
        match self {
            SendReadiness::Ready => "",
            SendReadiness::Connecting => "connecting to relay — message held",
            SendReadiness::Disconnected => "offline — no relay and no LAN link",
        }
    }
}

/// Phase D follow-up: minimum seconds between two opportunistic
/// `host_addrs` dials to the same announcer fingerprint.
const HOST_ADDR_DIAL_BACKOFF_SECS: i64 = 300;

/// huddle 1.3.1: hard cap on the `host_addr_dial_attempts` map. Its key is the
/// unauthenticated `RoomAnnouncement.creator_fingerprint`, so a flood of
/// distinct fingerprints could otherwise grow it without bound (mirrors
/// `ROOM_SALT_CACHE`'s 4096 cap, populated in the same handler).
const HOST_ADDR_DIAL_ATTEMPTS_CAP: usize = 4096;

/// huddle 0.5: minimum ms between two `PeerIdentified`-triggered
/// re-broadcasts of our own `ProfileUpdate` to the same peer
/// fingerprint. Prevents storm-on-reconnect on flaky transports.
const PROFILE_REBROADCAST_FLOOR_MS: i64 = 60_000;

impl AppHandle {
    pub async fn start() -> Result<Self> {
        Self::start_with_options(
            NetworkMode::Server,
            0,
            None,
            Vec::new(),
            TransportConfig::default(),
        )
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
        Self::start_with_db_and_options(db, mode, port, session_persist_key, relays, transports)
            .await
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
        // Ensure rustls has a CryptoProvider before any transport door builds a
        // TLS config (the `wss://` clearnet relay). This is the innermost start
        // funnel — `start`, `start_with_options`, and `start_with_db` all route
        // here — so every consumer (GUI, TUI, tests) is covered. Idempotent;
        // see `crate::install_default_crypto_provider`.
        crate::install_default_crypto_provider();

        let identity = Self::load_or_create_identity(&db)?;
        let identity = Arc::new(identity);
        info!(fingerprint = %identity.fingerprint(), peer_id = %identity.peer_id(), mode = %mode.as_str(), port, relay_count = relays.len(), "identity loaded");

        let (net_event_tx, net_event_rx) = tokio::sync::mpsc::channel::<NetworkEvent>(256);
        // huddle 1.1.4: 1024 (was 256) gives a slow UI subscriber more
        // headroom before it lags and drops AppEvents. A lagging receiver
        // still recovers via authoritative resync (TUI grace-summary / GUI
        // ~1s refresh), so this is resilience, not correctness.
        let (app_event_tx, _) = broadcast::channel::<AppEvent>(1024);
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
            })
            // huddle 1.1: fall back to the operator's baked-in clearnet door
            // (`DEFAULT_CLEARNET_URL`) so a fresh client reaches the relay over
            // clearnet with zero config when Tor is unavailable. Gated on an
            // onion relay being configured: the real binaries always bake in
            // `DEFAULT_SERVER_URL`, while tests / libp2p-only embedders pass
            // `onion_url: None` (`TransportConfig::default`) and must NOT get a
            // network door they'd silently dial. Still tried only AFTER the
            // onion (see `default_fallback_order`); any explicit CLI / config /
            // saved-DB value above wins, and clearing the relay (empty DB
            // value) reverts to this default rather than to "no clearnet".
            .or_else(|| {
                transports
                    .onion_url
                    .as_ref()
                    .map(|_| DEFAULT_CLEARNET_URL.to_string())
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
                .map(|v| {
                    v.iter()
                        .filter_map(|s| TransportId::from_str(s))
                        .collect::<Vec<_>>()
                })
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

        // huddle 2.0.5 (WS2 increment #1): build the SAS actor from our identity
        // (fingerprint + ML-KEM ek, both stable) before `identity` is moved into
        // the struct below. The ek is now derived once and cached, vs. per-message.
        let sas = Arc::new(SasActor::new(
            identity.fingerprint().to_string(),
            identity.mlkem_public_bytes(),
        ));
        let handle = Self {
            identity,
            network,
            shutting_down: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            mode,
            active_rooms,
            discovered_rooms,
            restorable_rooms,
            connected_dial_addrs,
            file_manager,
            db,
            session_persist_key: Arc::new(Mutex::new(session_persist_key)),
            sas,
            pending_code_secrets: Arc::new(Mutex::new(HashMap::new())),
            pending_invite_dials: Arc::new(Mutex::new(HashMap::new())),
            nat_reachable_addrs: Arc::new(Mutex::new(HashSet::new())),
            relay_circuit_addrs: Arc::new(Mutex::new(HashSet::new())),
            host_addr_dial_attempts: Arc::new(Mutex::new(HashMap::new())),
            key_request_cooldown: Arc::new(Mutex::new(HashMap::new())),
            announce_on_request_cooldown: Arc::new(Mutex::new(HashMap::new())),
            last_profile_broadcast_at_ms: Arc::new(Mutex::new(HashMap::new())),
            pending_auto_dm_addrs: Arc::new(Mutex::new(HashSet::new())),
            app_event_tx,
            server_enabled: any_relay,
            aux_subscriptions: Arc::new(Mutex::new(HashSet::new())),
            active_transport: Arc::new(Mutex::new(None)),
            transport_profiles: transport_profiles.clone(),
            transport_order: Arc::new(Mutex::new(transport_order)),
            relay_reconnect: Arc::new(Notify::new()),
            tor_socks,
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
            let inbox = crate::network::protocol::inbox_room_id(handle.identity.fingerprint());
            handle.aux_subscriptions.lock().insert(inbox.clone());
            handle.network.subscribe_room(inbox).await;
        }
        // huddle 0.8/1.0: now that active rooms are loaded, open the
        // persistent relay connection (if any transport door is usable),
        // trying the doors in `transport_order`. Connecting after restore
        // means our `hello` carries the restored room ids + the inbox, so the
        // server registers our memberships and flushes any offline mailbox.
        if any_relay {
            handle.spawn_server_connection();
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
        // huddle 2.0.0 (F2): bound the content-replay seen-set by dropping rows
        // older than the retention window. Once-at-startup like the sweeps above
        // keeps it off the hot receive path; the FK cascade already clears a
        // room's rows when it's left/deleted, so this only reaps long-lived
        // sessions in still-active rooms.
        let replay_cutoff = now_unix().saturating_sub(repo::CONTENT_REPLAY_RETENTION_SECS);
        if let Err(e) = repo::gc_content_replay_seen(&handle.db, replay_cutoff) {
            warn!(%e, "failed to sweep content-replay seen-set");
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
        *self.active_transport.lock()
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
            let connected = self.connected_dial_addrs.lock().clone();
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

    /// huddle 1.2: can a message typed into `room_id` actually be delivered
    /// right now? Drives composer gating in both front-ends so we never show
    /// an optimistic local echo for a message that reached no one. A `Relay`
    /// or `LanDirect` transport means Ready (the relay mailboxes an offline
    /// partner, so it still counts). `Offline` resolves to `Connecting` when a
    /// relay is configured (it should come up shortly) or `Disconnected` when
    /// no relay is configured at all.
    pub fn room_send_readiness(&self, room_id: &str) -> SendReadiness {
        match self.room_transport(room_id) {
            RoomTransport::LanDirect | RoomTransport::Relay => SendReadiness::Ready,
            RoomTransport::Offline => {
                if self.server_enabled() {
                    SendReadiness::Connecting
                } else {
                    SendReadiness::Disconnected
                }
            }
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
    pub fn sign_invite(
        &self,
        invite: crate::invite::InviteLink,
    ) -> Result<crate::invite::InviteLink> {
        crate::invite::sign_invite(&self.identity, invite).map_err(Into::into)
    }

    pub fn discovered_rooms(&self) -> Vec<DiscoveredRoom> {
        let now = now_unix();
        let our_fp = self.identity.fingerprint().to_string();
        let mut by_id: HashMap<String, DiscoveredRoom> = self.discovered_rooms.lock().clone();

        // Merge in rooms we're currently in — gossipsub doesn't echo our
        // own announcements back to us, so without this our own hosted
        // rooms wouldn't appear in the lobby.
        for room in self.active_rooms.lock().values() {
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
        for (id, stored) in self.restorable_rooms.lock().iter() {
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
            if self.active_rooms.lock().contains_key(room_id) {
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
        let rooms = self.active_rooms.lock();
        let room = rooms.get(room_id)?;
        if room.info.kind != RoomKind::Direct {
            return None;
        }
        room.members.iter().find(|m| **m != our_fp).cloned()
    }

    pub fn active_room_ids(&self) -> Vec<String> {
        self.active_rooms.lock().keys().cloned().collect()
    }

    pub fn active_room_info(&self, room_id: &str) -> Option<StoredRoom> {
        self.active_rooms
            .lock()
            .get(room_id)
            .map(|r| r.info.clone())
    }

    pub fn room_members(&self, room_id: &str) -> Vec<String> {
        self.active_rooms
            .lock()
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
        // huddle 2.0.0 (F8): route through the FTS5 index. The repo helper
        // self-falls-back to the legacy LIKE scan on any FTS error or an empty
        // query, so this is strictly an upgrade (ranked, tokenized, prefix/
        // boolean-capable matching) with no loss of coverage.
        repo::search_room_messages_fts(&self.db, room_id, query, limit)
    }

    // -------------------------------------------------------------------
    // huddle 2.0.0 (F6): BIP39 seed-phrase export / import
    // -------------------------------------------------------------------

    /// huddle 2.0.0 (F6): export this identity's 32-byte Ed25519 seed as a
    /// 24-word BIP39 phrase. Gated on a master passphrase being set — the seed
    /// is the crown jewel, so we refuse to surface it for an unencrypted-DB
    /// session. The UI shows it once and re-entry-verifies via
    /// [`Self::verify_seed_reentry`].
    pub fn export_seed_phrase(&self) -> Result<String> {
        if !self.has_master_passphrase() {
            return Err(HuddleError::Other(
                "seed export requires a master passphrase to protect the exported phrase".into(),
            ));
        }
        Ok(crate::crypto::mnemonic::seed_to_phrase(
            &self.identity.seed(),
        ))
    }

    /// huddle 2.0.0 (F6): does `phrase` decode to OUR identity? Used by the
    /// export modal's re-entry step to confirm the user transcribed it
    /// correctly before they rely on it for recovery.
    pub fn verify_seed_reentry(&self, phrase: &str) -> Result<bool> {
        Ok(fingerprint_from_phrase(phrase)? == self.identity.fingerprint())
    }

    // -------------------------------------------------------------------
    // huddle 2.0.0 (F5): master passphrase change + at-rest re-key
    // -------------------------------------------------------------------

    /// Change the master passphrase, re-encrypting everything at rest.
    ///
    /// Verifies `current` against the live persist key (constant-time), derives
    /// the new master key + Megolm persist subkey from the new passphrase
    /// against the **existing** salt, re-encrypts every stored Megolm session
    /// pickle under the new subkey, `PRAGMA rekey`s the SQLCipher database to the
    /// new master key, swaps the in-memory persist key, and reloads the active
    /// rooms' `RoomCrypto`s so they continue under the new key. Emits
    /// [`AppEvent::PassphraseChanged`] on success.
    ///
    /// The salt is **never** rotated on a passphrase change (F5 CRITICAL fix).
    /// Argon2id over the same salt with a different passphrase already yields a
    /// different key, so a new salt buys nothing — but writing one would open an
    /// unrecoverable window: if the salt write failed *after* `PRAGMA rekey`
    /// committed, the on-disk salt would still derive the OLD key while the DB
    /// is now encrypted under the NEW one, permanently bricking the database.
    /// Keeping the salt fixed removes that failure window entirely; the only
    /// remaining commit point is the atomic `PRAGMA rekey` itself, so an aborted
    /// change always recovers with the old passphrase on the next launch.
    ///
    /// Concurrency (F5 HIGH fix): steps 3-6 run while the `active_rooms` lock is
    /// held, quiescing the message pipeline. Every Megolm persist goes through a
    /// `RoomCrypto` living inside `active_rooms`, so holding the guard for the
    /// whole rotation guarantees no concurrent decrypt/encrypt advances a session
    /// and writes it back under the old key while we re-encrypt the pickles —
    /// which would otherwise be silently clobbered with stale pre-advance state.
    pub async fn change_master_passphrase(&self, current: &str, new: &str) -> Result<()> {
        if !self.has_master_passphrase() {
            return Err(HuddleError::Other(
                "this session has no master passphrase to change \
                 (started with --no-master-passphrase)"
                    .into(),
            ));
        }
        // huddle 2.0.2 (audit L-4) / 2.0.3 (N-L2): floor the NEW passphrase. The
        // floor is applied only at set/change time (never at derive/verify), so an
        // existing short passphrase can still unlock — but new ones can't be
        // trivially weak. The at-rest key's strength is Argon2id-over-passphrase,
        // so a 1-char passphrase is brute-forceable regardless of KDF cost.
        validate_passphrase_len(new)?;
        // 1. Verify the current passphrase against the live persist key.
        let salt = storage::keychain::load_or_create_salt()?;
        let cur_master = storage::keychain::derive_master_key(current, &salt)?;
        let cur_subkey = storage::keychain::derive_subkey(&cur_master, b"megolm-persist");
        let old_persist = self.persist_key();
        if !ct_eq_32(&cur_subkey, &old_persist) {
            return Err(HuddleError::Other("incorrect current passphrase".into()));
        }
        // 2. Derive the new master key + persist subkey from the new passphrase
        //    against the EXISTING salt — we never rotate `keychain.salt` (see the
        //    doc comment): a different passphrase already yields a different key,
        //    and not writing a new salt removes the post-rekey salt-write failure
        //    window that could otherwise brick the database.
        let new_master = storage::keychain::derive_master_key(new, &salt)?;
        let new_persist = storage::keychain::derive_subkey(&new_master, b"megolm-persist");
        // 3-6. Hold `active_rooms` for the whole rotation so no concurrent
        //    decrypt/encrypt can advance a Megolm session and persist it under
        //    the OLD key mid-rekey (the F5 HIGH race). Every crypto persist path
        //    runs through a `RoomCrypto` inside this map, so the guard quiesces
        //    them all. Nothing in the section `.await`s, so holding the std
        //    Mutex across it is sound, and the lock order (active_rooms → db)
        //    matches every message handler — no deadlock.
        {
            let mut rooms = self.active_rooms.lock();
            // 3. Re-encrypt all Megolm session pickles old → new persist key, so
            //    they survive the master-key rekey AND decrypt under the new key.
            self.reencrypt_megolm_sessions(&old_persist, &new_persist)?;
            // 4. PRAGMA rekey the SQLCipher DB (atomic, sentinel-verified). This
            //    is now the single commit point of the whole rotation.
            {
                let conn = self.db.lock();
                storage::rekey_db(&conn, &new_master)?;
            }
            // 5. Swap the in-memory persist key and 6. reload the active rooms'
            //    cryptos under it — still inside the quiesce window so disk and
            //    in-memory session state stay consistent.
            *self.session_persist_key.lock() = new_persist;
            self.reload_active_room_cryptos_locked(&mut rooms, &new_persist);
        }
        let _ = self.app_event_tx.send(AppEvent::PassphraseChanged);
        info!("master passphrase changed and database re-keyed (salt unchanged)");
        Ok(())
    }

    /// F5 helper: re-encrypt every stored Megolm session pickle from `old_key`
    /// to `new_key` at the blob level (independent of SQLCipher). A row that
    /// can't be decoded under the old key is left untouched — `RoomCrypto::load`
    /// already tolerates and skips a single unreadable session.
    fn reencrypt_megolm_sessions(&self, old_key: &[u8; 32], new_key: &[u8; 32]) -> Result<()> {
        use vodozemac::megolm::{
            GroupSession, GroupSessionPickle, InboundGroupSession, InboundGroupSessionPickle,
        };
        for room in repo::list_rooms(&self.db)? {
            for s in repo::load_megolm_sessions_for_room(&self.db, &room.id)? {
                let data_str = match String::from_utf8(s.session_data.clone()) {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                let new_blob: Vec<u8> = if s.is_outbound {
                    let p =
                        GroupSessionPickle::from_encrypted(&data_str, old_key).map_err(|e| {
                            HuddleError::Other(format!("rekey: outbound pickle decrypt: {e}"))
                        })?;
                    GroupSession::from_pickle(p)
                        .pickle()
                        .encrypt(new_key)
                        .into_bytes()
                } else {
                    let p = InboundGroupSessionPickle::from_encrypted(&data_str, old_key).map_err(
                        |e| HuddleError::Other(format!("rekey: inbound pickle decrypt: {e}")),
                    )?;
                    InboundGroupSession::from_pickle(p)
                        .pickle()
                        .encrypt(new_key)
                        .into_bytes()
                };
                repo::save_megolm_session(
                    &self.db,
                    &repo::StoredMegolmSession {
                        room_id: s.room_id,
                        sender_fingerprint: s.sender_fingerprint,
                        session_id: s.session_id,
                        session_data: new_blob,
                        is_outbound: s.is_outbound,
                        created_at: s.created_at,
                    },
                )?;
            }
        }
        Ok(())
    }

    /// F5 helper: after a re-key, rebuild every active encrypted room's
    /// `RoomCrypto` from the (now new-key-encrypted) pickles so in-memory
    /// sessions keep persisting under the new key. Lossless — every session is
    /// already on disk.
    ///
    /// Takes the already-held `active_rooms` guard rather than re-locking,
    /// because `change_master_passphrase` holds it across the whole rotation to
    /// quiesce the message pipeline (the std Mutex is not reentrant).
    fn reload_active_room_cryptos_locked(
        &self,
        rooms: &mut HashMap<String, ActiveRoom>,
        new_key: &[u8; 32],
    ) {
        let our_fp = self.identity.fingerprint().to_string();
        for room in rooms.values_mut() {
            if !room.info.encrypted {
                continue;
            }
            match RoomCrypto::load(
                self.db.clone(),
                room.info.id.clone(),
                our_fp.clone(),
                *new_key,
            ) {
                Ok(Some(mut c)) => {
                    // F4: a rekey reload must not lose the epoch bookkeeping —
                    // rehydrate it so the rotation schedule keeps counting.
                    self.rehydrate_rotation_state(&mut c);
                    room.crypto = Some(c);
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(%e, room_id = %room.info.id, "F5: RoomCrypto reload after rekey failed")
                }
            }
        }
    }

    pub async fn shutdown(&self) {
        // huddle 2.0.0: stop the relay-connection loop (it holds a clone of us
        // and keeps a live socket open otherwise) BEFORE tearing down libp2p.
        // The flag halts reconnects; detaching the server drops the client so
        // its reader closes and the loop's `rx.recv()` returns None and exits.
        self.shutting_down
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.network.detach_server();
        self.network.shutdown().await;
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
                    mlkem_pubkey: None,
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
        // huddle 2.0.2 (audit M-10): a banned fingerprint is never an owner,
        // even if its `owner` role row hasn't been cleaned up yet. This closes
        // the "banned co-owner keeps full admin" hole at the authorization
        // gate (delete-any, ban-back, grant-owner, RoomSetting/TTL).
        if repo::is_member_banned(&self.db, room_id, fingerprint).unwrap_or(false) {
            return false;
        }
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
        self.persist_key() != [0u8; 32]
    }

    /// huddle 2.0.0 (F5): snapshot the at-rest Megolm persist key. Behind a
    /// `Mutex` since `change_master_passphrase` swaps it after a re-key; every
    /// read (RoomCrypto construction, passphrase verification) goes through here
    /// so a swap is observed atomically by all clones of the handle.
    fn persist_key(&self) -> [u8; 32] {
        *self.session_persist_key.lock()
    }

    /// Broadcast a "I'm typing" pulse to the given room. Caller is
    /// responsible for debouncing (don't fire more than every ~500ms).
    pub async fn broadcast_typing(&self, room_id: &str) {
        if !self.active_rooms.lock().contains_key(room_id) {
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
        let mut rooms = self.active_rooms.lock();
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
        // huddle 2.0.3 (audit N-L2): floor the new room passphrase on rotation
        // (subsumes the old non-empty check; the salt is broadcast in the clear).
        validate_passphrase_len(new_passphrase)?;
        let new_salt = passphrase::random_salt();
        let new_key = passphrase::derive_key(new_passphrase, &new_salt)?;

        let info = {
            let mut rooms = self.active_rooms.lock();
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
                self.persist_key(),
            )?;
            // F4: this is a fresh epoch (0/now) — persist it so the durable
            // counter doesn't keep the retired session's (possibly high) value
            // and wrongly trip a rotation on the next restart.
            self.persist_rotation_state(&new_crypto);
            room.crypto = Some(new_crypto);
            room.passphrase_key = Some(new_key);
            room.info.passphrase_salt = Some(new_salt.to_vec());
            room.info.clone()
        };

        // huddle 2.0.2 (audit M-4 follow-up): a rotation mints a fresh outbound
        // session, so a peer that accepts the rotation will (legitimately) send a
        // `SessionKeyRequest` to re-fetch our new key. Clear any in-flight
        // announce cooldown for this room so that request is served — the cooldown
        // only exists to collapse request *storms*, never to suppress a re-share
        // after our key actually changed.
        self.announce_on_request_cooldown.lock().remove(room_id);

        // Broadcast before persisting: peers learn about the rotation even
        // if we crash before the DB write lands, and our own restore path
        // can recover from the persisted Megolm session plus the announced
        // salt. Persisting first would risk a DB row that's ahead of what
        // any peer knows.
        let rot = RoomMessage::RotateRoomKey {
            rotator_fingerprint: self.identity.fingerprint().to_string(),
            new_salt: new_salt.to_vec(),
            // huddle 2.0.3 (audit N-M2): bind the room to this signed rotation.
            room_id: Some(room_id.to_string()),
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
            let mut rooms = self.active_rooms.lock();
            let room = rooms
                .get_mut(room_id)
                .ok_or_else(|| HuddleError::Other(format!("not in room {room_id}")))?;
            room.passphrase_key = Some(new_key);
            room.info.passphrase_salt = Some(new_salt.to_vec());
            room.info.clone()
        };
        // huddle 2.0.2 (audit M-4 follow-up): accepting a rotation means our key
        // state just changed, so clear our announce cooldown for this room — we
        // must serve peers' post-rotation re-share requests rather than throttle
        // them.
        self.announce_on_request_cooldown.lock().remove(room_id);
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
                // huddle 2.1.2 (audit FILES-1): a terminal OR already-complete row
                // means the transfer is done (cancelled, failed, ready, or saved).
                // Late/duplicate chunks — including unauthenticated injected ones —
                // must not resurrect it, nor (via the Err arm below) downgrade a
                // completed attachment back to Failed.
                if matches!(
                    a.status,
                    AttachmentStatus::Cancelled
                        | AttachmentStatus::Failed
                        | AttachmentStatus::Ready
                        | AttachmentStatus::Saved
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
                // huddle 2.1.2 (audit FILES-1): FileChunk is unsigned by design —
                // integrity comes from the SHA-256 assembly gate against `file_id`,
                // so any peer/relay can inject a chunk for a public file_id. A
                // rejected chunk (empty, oversize, index/total mismatch, …) must
                // therefore NOT fail the whole transfer: that let one injected junk
                // chunk cancel an in-flight transfer or downgrade a completed one to
                // Failed. Drop the bad chunk and leave the attachment state intact;
                // valid chunks from the real sender still drive it to completion (or
                // it times out / is re-offered).
                warn!(error = %e, %file_id, "dropping invalid file chunk (transfer state unchanged)");
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
        let short: String = full
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .take(8)
            .collect();
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
        let mut rooms = self.active_rooms.lock();
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
        let no_master = self.persist_key() == [0u8; 32];
        // huddle 2.0.3 (audit N-L2): when go-dark SETS the master passphrase for
        // the first time, floor it. When a master already exists this call only
        // verifies the existing one, so don't floor (an older short passphrase
        // must still be accepted to unlock).
        if no_master {
            validate_passphrase_len(master_passphrase)?;
        }
        if !no_master {
            let salt = storage::keychain::load_or_create_salt()?;
            let candidate_master = storage::keychain::derive_master_key(master_passphrase, &salt)?;
            let candidate_subkey =
                storage::keychain::derive_subkey(&candidate_master, b"megolm-persist");
            if !ct_eq_32(&candidate_subkey, &self.persist_key()) {
                return Err(HuddleError::Other("incorrect master passphrase".into()));
            }
        }

        let room_ids: Vec<String> = self.active_rooms.lock().keys().cloned().collect();
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

/// huddle 2.0.0 (F10): mint a stable, cross-peer message id — a random
/// UUID-v4-shaped string (`8-4-4-4-12` lowercase hex). huddle-core has no
/// `uuid` dependency, so we format 16 OS-random bytes with the v4 version +
/// RFC-4122 variant bits set; the collision probability is ~2^-122, matching
/// `uuid::Uuid::new_v4`. Minted by the sender when composing content so every
/// peer names the same logical message for reactions / edits / replies /
/// deletes.
fn new_client_msg_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// huddle 2.0.0 (F6): the fingerprint a 24-word BIP39 phrase decodes to,
/// without opening a session. Used to preview/verify an identity import (and by
/// [`AppHandle::verify_seed_reentry`]). Errors on an off-wordlist word, a bad
/// checksum, or the wrong word count.
pub fn fingerprint_from_phrase(phrase: &str) -> Result<String> {
    // `phrase_to_seed` already returns the seed in `Zeroizing`, so hand it
    // straight to `from_seed` — no second wrapper, no bare-array copy (F6).
    let seed = crate::crypto::mnemonic::phrase_to_seed(phrase)?;
    let id = Identity::from_seed(seed)?;
    Ok(id.fingerprint().to_string())
}

/// huddle 2.0.0 (F6): rebuild an [`Identity`] from a 24-word BIP39 phrase — the
/// fresh-install recovery path the TUI/GUI call before a session opens. The
/// restored identity is byte-for-byte the original (same fingerprint, PeerId,
/// and ML-KEM keypair).
pub fn import_identity_from_phrase(phrase: &str) -> Result<Identity> {
    let seed = crate::crypto::mnemonic::phrase_to_seed(phrase)?;
    Identity::from_seed(seed)
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

/// huddle 1.2.1: length of a connect code (chars), matching the relay's
/// `CONNECT_TOKEN_LEN`.
pub const CONNECT_CODE_LEN: usize = 8;
/// Crockford base32 alphabet (no I/L/O/U) — matches the relay's generator.
const CONNECT_CODE_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// huddle 1.2.1: canonicalize a typed connect code (uppercase, strip spaces /
/// dashes) and validate it's exactly `CONNECT_CODE_LEN` Crockford-base32
/// chars. Returns `None` for anything that isn't a well-formed code — so the
/// UIs can tell a connect code apart from an HD-ID (24 hex) or a username, and
/// route "add by …" input to the right path.
pub fn normalize_connect_code(input: &str) -> Option<String> {
    let up: String = input
        .trim()
        .to_ascii_uppercase()
        .chars()
        .filter(|c| *c != '-' && *c != ' ')
        .collect();
    if up.len() == CONNECT_CODE_LEN && up.bytes().all(|b| CONNECT_CODE_ALPHABET.contains(&b)) {
        Some(up)
    } else {
        None
    }
}

/// huddle 1.2.5: best-effort POSIX `~` expansion for a user-typed file path,
/// shared by the TUI and GUI "attach by path" entries so they behave
/// identically. Only the exact `~` and a leading `~/` are expanded to `$HOME`;
/// anything else (including `~user`, which we don't resolve) is left literal so
/// a bad path surfaces verbatim in the error. `$HOME` unset → no expansion.
pub fn expand_tilde(input: &str) -> PathBuf {
    expand_tilde_with(input, std::env::var("HOME").ok().as_deref())
}

/// Testable core of [`expand_tilde`] with an explicit home dir.
fn expand_tilde_with(input: &str, home: Option<&str>) -> PathBuf {
    if let Some(h) = home {
        if input == "~" {
            return PathBuf::from(h);
        }
        if let Some(rest) = input.strip_prefix("~/") {
            return PathBuf::from(h).join(rest);
        }
    }
    PathBuf::from(input)
}

#[cfg(test)]
mod attach_path_tests {
    use super::expand_tilde_with;
    use std::path::PathBuf;

    #[test]
    fn tilde_expansion_matches_posix_basics() {
        let home = Some("/home/alice");
        assert_eq!(expand_tilde_with("~", home), PathBuf::from("/home/alice"));
        assert_eq!(
            expand_tilde_with("~/docs/f.txt", home),
            PathBuf::from("/home/alice/docs/f.txt")
        );
        // Absolute + relative paths pass through untouched.
        assert_eq!(
            expand_tilde_with("/etc/hosts", home),
            PathBuf::from("/etc/hosts")
        );
        assert_eq!(expand_tilde_with("rel/f", home), PathBuf::from("rel/f"));
        // `~user` is NOT resolved — left literal so the error shows what was typed
        // (no `$HOME`+username gluing like the old TUI path did).
        assert_eq!(expand_tilde_with("~bob/f", home), PathBuf::from("~bob/f"));
        // No $HOME → no expansion.
        assert_eq!(expand_tilde_with("~/f", None), PathBuf::from("~/f"));
    }
}

#[cfg(test)]
mod content_id_tests {
    //! huddle 2.0.0 (F10/F6): pure-helper invariants for the cross-peer message
    //! id and the BIP39 identity import — exercised without an `AppHandle`.
    use super::{fingerprint_from_phrase, import_identity_from_phrase, new_client_msg_id};
    use crate::crypto::mnemonic::seed_to_phrase;
    use crate::identity::Identity;

    #[test]
    fn client_msg_id_is_uuid_v4_shaped_and_unique() {
        let a = new_client_msg_id();
        let b = new_client_msg_id();
        assert_ne!(a, b, "two minted ids must differ");
        // 8-4-4-4-12 lowercase-hex layout.
        let parts: Vec<&str> = a.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(a.chars().all(|c| c == '-' || c.is_ascii_hexdigit()));
        // Version nibble (first char of group 3) is '4'; variant nibble (first
        // char of group 4) is one of 8/9/a/b.
        assert_eq!(&parts[2][..1], "4");
        assert!(matches!(&parts[3][..1], "8" | "9" | "a" | "b"));
    }

    #[test]
    fn fingerprint_from_phrase_matches_identity_and_import_round_trips() {
        // F6: a phrase decodes to the same fingerprint the identity reports, and
        // a full re-import reproduces the identity byte-for-byte.
        let id = Identity::generate().unwrap();
        let phrase = seed_to_phrase(&id.seed());
        assert_eq!(fingerprint_from_phrase(&phrase).unwrap(), id.fingerprint());
        let restored = import_identity_from_phrase(&phrase).unwrap();
        assert_eq!(restored.fingerprint(), id.fingerprint());
        assert_eq!(restored.mlkem_public_bytes(), id.mlkem_public_bytes());
    }

    #[test]
    fn fingerprint_from_phrase_rejects_garbage() {
        assert!(fingerprint_from_phrase("not a valid bip39 phrase at all").is_err());
    }
}

#[cfg(test)]
mod dm_key_plan_tests {
    //! huddle 1.3.1: the post-quantum downgrade/upgrade policy is concentrated
    //! in the pure `plan_dm_key`. These tests pin the security-critical
    //! invariants without needing an `AppHandle`.
    use super::{plan_dm_key, DmKeyAction};

    #[test]
    fn settled_hybrid_is_never_touched() {
        // Once hybrid, no input can produce a re-derivation/downgrade.
        for &pq in &[true, false] {
            for &init in &[true, false] {
                for &ct in &[true, false] {
                    assert_eq!(
                        plan_dm_key(true, true, pq, init, ct),
                        DmKeyAction::Noop,
                        "settled hybrid must stay Noop (pq={pq}, init={init}, ct={ct})"
                    );
                }
            }
        }
    }

    #[test]
    fn pq_capable_partner_never_yields_classical() {
        // The core anti-downgrade invariant: a PQ-capable partner (announce ek
        // or persisted pin) must NEVER produce a classical derivation, in any
        // key state — including when currently keyed classical (→ upgrade).
        for &keyed in &[true, false] {
            // already_hybrid=true is covered above; here the DM is at most classical.
            for &init in &[true, false] {
                for &ct in &[true, false] {
                    let a = plan_dm_key(keyed, false, true, init, ct);
                    assert_ne!(a, DmKeyAction::Classical, "PQ peer must not go classical");
                    assert_ne!(
                        a,
                        DmKeyAction::Noop,
                        "PQ peer must act (derive/upgrade/request)"
                    );
                }
            }
        }
    }

    #[test]
    fn fresh_pq_handshake_roles() {
        // Not keyed yet, partner PQ-capable.
        assert_eq!(
            plan_dm_key(false, false, true, true, false),
            DmKeyAction::HybridInitiator,
            "initiator encapsulates even without a ciphertext"
        );
        assert_eq!(
            plan_dm_key(false, false, true, false, true),
            DmKeyAction::HybridResponder,
            "responder with the ciphertext decapsulates"
        );
        assert_eq!(
            plan_dm_key(false, false, true, false, false),
            DmKeyAction::RequestCiphertext,
            "responder without the ciphertext asks for it"
        );
    }

    #[test]
    fn classical_locked_upgrades_when_partner_is_pq() {
        // Split-brain / replay heal: a classical-locked DM upgrades to hybrid
        // the moment the partner's PQ capability is observed.
        assert_eq!(
            plan_dm_key(true, false, true, true, false),
            DmKeyAction::HybridInitiator,
            "classical-locked initiator upgrades"
        );
        assert_eq!(
            plan_dm_key(true, false, true, false, true),
            DmKeyAction::HybridResponder,
            "classical-locked responder upgrades once it has the ciphertext"
        );
        assert_eq!(
            plan_dm_key(true, false, true, false, false),
            DmKeyAction::RequestCiphertext,
            "classical-locked responder asks for the ciphertext to upgrade"
        );
    }

    #[test]
    fn genuine_pre_1_3_peer_uses_classical_once_then_settles() {
        // Non-PQ partner: classical on first keying, then steady (no churn).
        assert_eq!(
            plan_dm_key(false, false, false, true, false),
            DmKeyAction::Classical,
            "non-PQ partner, not keyed → classical"
        );
        assert_eq!(
            plan_dm_key(false, false, false, false, false),
            DmKeyAction::Classical
        );
        assert_eq!(
            plan_dm_key(true, false, false, true, false),
            DmKeyAction::Noop,
            "non-PQ partner already classical-keyed → no-op (no rederivation)"
        );
    }
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

/// huddle 1.1.4: keep `ROOM_SALT_CACHE` bounded. A long-lived client that
/// observes many room announcements could otherwise grow it without limit.
/// Salts are cheaply re-learned from the next announcement, so evicting an
/// arbitrary entry once the cap is reached is harmless.
const ROOM_SALT_CACHE_CAP: usize = 4096;

fn remember_room_salt(room_id: &str, salt: Vec<u8>) {
    let mut cache = ROOM_SALT_CACHE.lock();
    if !cache.contains_key(room_id) && cache.len() >= ROOM_SALT_CACHE_CAP {
        if let Some(k) = cache.keys().next().cloned() {
            cache.remove(&k);
        }
    }
    cache.insert(room_id.to_string(), salt);
}

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
        let circuit =
            address_preference("/ip4/1.2.3.4/tcp/4001/p2p/12D3Koo/p2p-circuit/p2p/12D3KooXYZ");
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
