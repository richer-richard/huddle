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
use crate::network::server::{ServerClient, ServerEvent};
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

/// huddle 1.3.1: bound the in-memory `sas_flows` map. Inbound `SasInit`
/// inserts an entry keyed by the initiator-chosen `tx_id`, so without a sweep
/// an authenticated peer streaming fresh tx_ids could grow it without limit.
/// Abandoned flows are reaped after this TTL, a global hard cap bounds total
/// memory, and a per-peer sub-cap stops one peer from starving everyone else.
///
/// huddle 1.3.3: the TTL is anchored to ~code-visible time, not flow start, so a
/// slow out-of-band comparison won't reap a live handshake — a real SAS stalls on
/// humans reading emoji/decimal to each other over voice, which can take minutes.
/// The initiator's flow is refreshed when the `SasResponse` arrives (moving its
/// clock off "SasInit sent" and onto "both keys known"); the responder's flow is
/// created at the same instant it displays the code, so its clock already starts
/// there and needs no refresh. The cap, not a tight TTL, is the real memory
/// bound, so 15 min is safe.
const SAS_FLOW_TTL_SECS: i64 = 900;
const SAS_FLOWS_CAP: usize = 256;
/// huddle 1.3.3: per-partner sub-cap. `sas_flows` is one global map keyed by the
/// attacker-chosen `tx_id`, so without this a single authenticated co-member
/// could fill all `SAS_FLOWS_CAP` slots with distinct tx_ids and block every
/// other peer's SAS verification node-wide until the TTL sweep. Capping in-flight
/// flows per partner fingerprint confines a flooder to its own share.
const SAS_FLOWS_PER_PEER: usize = 8;

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
    /// huddle 1.3.1: unix insert time, so the discovered-room pruner can reap
    /// abandoned flows (TTL) and bound this otherwise-unbounded map.
    created_at: i64,
    /// huddle 2.0.0 (F1): `true` iff we bound the partner's ML-KEM
    /// encapsulation key into this SAS code (the partner is post-quantum
    /// capable and we held their ek when we derived the code). Carried into
    /// `add_verified_peer(.., pq_capable = …)` on success so the durable
    /// `verified_peers.pq_capable` anchor records that this peer was verified
    /// PQ-capable — `ensure_dm_key` then refuses any later classical-only DM
    /// fallback for them, defeating a post-verification relay downgrade.
    partner_pq_capable: bool,
}

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
    /// Phase G: active SAS verifications. Keyed by tx_id (the random
    /// 16-byte salt picked by the initiator + base64'd).
    sas_flows: Arc<Mutex<HashMap<String, SasFlow>>>,
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
            sas_flows: Arc::new(Mutex::new(HashMap::new())),
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
            handle
                .aux_subscriptions
                .lock()
                .unwrap()
                .insert(inbox.clone());
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
        crate::invite::sign_invite(&self.identity, invite)
    }

    pub fn discovered_rooms(&self) -> Vec<DiscoveredRoom> {
        let now = now_unix();
        let our_fp = self.identity.fingerprint().to_string();
        let mut by_id: HashMap<String, DiscoveredRoom> =
            self.discovered_rooms.lock().unwrap().clone();

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
            if self.active_rooms.lock().unwrap().contains_key(room_id) {
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
        room.members.iter().find(|m| **m != our_fp).cloned()
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
        // huddle 2.0.0 (F8): route through the FTS5 index. The repo helper
        // self-falls-back to the legacy LIKE scan on any FTS error or an empty
        // query, so this is strictly an upgrade (ranked, tokenized, prefix/
        // boolean-capable matching) with no loss of coverage.
        repo::search_room_messages_fts(&self.db, room_id, query, limit)
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
        // huddle 2.0.3 (audit N-L2): floor the room passphrase at creation — its
        // Argon2id salt rides the cleartext RoomAnnouncement, so a weak one is
        // directly offline-brute-forceable to break the room's confidentiality.
        if let Some(p) = passphrase {
            validate_passphrase_len(p)?;
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
                self.persist_key(),
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
                mlkem_pubkey: None, // our own row; we pin partners, not ourselves
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
                dm_kem_ciphertext: None,
                dm_is_hybrid: false,
                dm_key_retry: 0,
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
        // huddle 1.2: ensure relay traffic for this DM is delivered straight
        // to the partner's fingerprint (works even before they subscribe).
        self.network
            .register_dm(room_id.clone(), partner_fingerprint.to_string());

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
            return self
                .bootstrap_direct_room(&room_id, partner_fingerprint)
                .await;
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
                mlkem_pubkey: None, // our own row
            },
        )?;

        // huddle 1.3: the DM wrap key is derived lazily in the `MemberAnnounce`
        // handler (`ensure_dm_key`), not here. We must first see the partner's
        // announce to learn whether they are post-quantum capable (whether they
        // publish an ML-KEM key) and, if we are the responder, to receive the
        // KEM ciphertext — so committing to a key now would risk locking in
        // classical and desyncing from a hybrid partner. Start with no key; the
        // partner's first announcement populates it.
        let passphrase_key: Option<[u8; KEY_LEN]> = None;

        // Always create our outbound Megolm session so we can encrypt
        // *something* the moment the key materializes. RoomCrypto
        // works the same as it does for group rooms — the only
        // difference is where `passphrase_key` comes from.
        let crypto = Some(RoomCrypto::new_for_room(
            self.db.clone(),
            room_id.clone(),
            our_fp.clone(),
            self.persist_key(),
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
                dm_kem_ciphertext: None,
                dm_is_hybrid: false,
                dm_key_retry: 0,
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

    /// huddle 1.3 / hardened in 1.3.1: (re)derive the DM wrap key for a Direct
    /// room from a partner `MemberAnnounce`, choosing the **hybrid**
    /// (X25519 + ML-KEM-768) path when the partner is post-quantum capable,
    /// else the classical X25519 path.
    ///
    /// ## Post-quantum capability pinning (1.3.1)
    /// A peer is "PQ-capable" if their ML-KEM key is present **on this announce
    /// or persisted** (`room_members.mlkem_pubkey`, set the first time we ever
    /// saw it in a signed announce). Once pinned, we **refuse the classical
    /// fallback** for that peer — so an untrusted relay cannot replay a captured
    /// pre-1.3 (classical-only, validly-signed) announce to force a
    /// quantum-unsafe downgrade, and the pin survives restarts even though the
    /// in-memory wrap key does not.
    ///
    /// ## Lock-in, one-way upgrade, never downgrade
    /// The first key derived is locked in. We **never** downgrade hybrid →
    /// classical. We **do** perform a one-way classical → hybrid **upgrade**:
    /// if a DM was locked classical (partner looked pre-1.3, or a replayed
    /// classical announce won the race) and we later observe the partner's PQ
    /// capability, we re-derive the hybrid key and **rotate our outbound Megolm
    /// session** (`rotate_outbound`) so the session key previously shared
    /// wrapped under the classical key is retired — closing the HNDL window the
    /// classical phase opened. This also heals a rollout split-brain without a
    /// restart.
    ///
    /// The lower-fingerprint peer is the **initiator** (encapsulates a fresh KEM
    /// secret and ships the ciphertext); the higher-fingerprint peer is the
    /// **responder** (decapsulates it) and asks for that ciphertext
    /// (`RequestCiphertext`) rather than falling back to a classical key.
    ///
    /// ## Residual (documented, not fully closable without a wire/out-of-band change)
    /// On a peer we have **never** pinned (true first contact, or the one-time
    /// 1.3.0→1.3.1 window before the partner re-announces), a relay that both
    /// replays a captured pre-1.3 announce **and** suppresses every genuine
    /// hybrid announce can still force an initial classical lock. The only bound
    /// on it is the upgrade+rotate above (the moment any genuine hybrid announce
    /// gets through); the bounded `SessionKeyRequest` retry does NOT cover this
    /// state (a classical-keyed room with an un-pinned partner is not nudged, and
    /// classical traffic decrypts fine so the decrypt-miss heal never fires). A
    /// real fix needs an out-of-band capability anchor (e.g. binding PQ
    /// capability into SAS).
    ///
    /// ## Concurrency
    /// In libp2p (`--mode mdns|direct`) builds on the multi-threaded runtime,
    /// `process_network_event` — and thus this fn's single call site — is driven
    /// by TWO concurrent tasks: the gossipsub loop (`spawn_event_processor`) and
    /// the relay loop (`spawn_server_connection`). Because the relay mirrors the
    /// same DM traffic, two `ensure_dm_key` calls for one Direct room CAN run
    /// concurrently. Race-freedom does NOT come from single-threading; it comes
    /// from the Phase-2 commit re-reading the LIVE `(passphrase_key,
    /// dm_is_hybrid)` under the lock plus the strictly monotonic
    /// `is_first || is_upgrade` rule (upgrade is classical→hybrid only). Every
    /// interleaving converges to hybrid with no downgrade and at most one
    /// `rotate_outbound` — so do not weaken the commit re-check.

    /// huddle 2.0.0 (F1): the partner's pinned ML-KEM-768 encapsulation key
    /// bytes (decoded from the durable `room_members.mlkem_pubkey` pin), or
    /// `None` if we've never observed it. Bound into the SAS transcript so a
    /// verified peer's post-quantum capability becomes part of the out-of-band
    /// trust anchor — see [`crate::crypto::sas::derive_sas_code`]. A malformed
    /// (wrong-length) pin is treated as absent.
    fn partner_mlkem_ek_bytes(&self, fingerprint: &str) -> Option<Vec<u8>> {
        let b64 = repo::lookup_peer_mlkem_pubkey(&self.db, fingerprint)
            .ok()
            .flatten()?;
        let bytes = B64.decode(&b64).ok()?;
        if bytes.len() == crate::crypto::pqc::MLKEM_EK_LEN {
            Some(bytes)
        } else {
            None
        }
    }

    fn ensure_dm_key(
        &self,
        room_id: &str,
        partner_fp: &str,
        partner_ed_b64: Option<&str>,
        partner_mlkem_b64: Option<&str>,
        ciphertext_b64: Option<&str>,
    ) -> DmKeyOutcome {
        // Phase 1: snapshot current key state.
        let (already_keyed, already_hybrid) = {
            let rooms = self.active_rooms.lock().unwrap();
            match rooms.get(room_id) {
                Some(r) => (r.passphrase_key.is_some(), r.dm_is_hybrid),
                None => return DmKeyOutcome::Noop,
            }
        };
        // The partner's Ed25519 pubkey is required for either path.
        let partner_ed = match partner_ed_b64 {
            Some(b64) => match B64.decode(b64).ok() {
                Some(b) if b.len() == 32 => {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&b);
                    a
                }
                _ => return DmKeyOutcome::Noop,
            },
            None => return DmKeyOutcome::Noop,
        };

        // PQ capability is sticky: this announce's ML-KEM key OR a previously
        // pinned one (persisted in room_members). Prefer the (freshly signed)
        // announce value; fall back to the durable pin.
        let stored_ek = repo::lookup_peer_mlkem_pubkey(&self.db, partner_fp)
            .ok()
            .flatten();
        let ek_b64: Option<String> = partner_mlkem_b64.map(|s| s.to_string()).or(stored_ek);
        let have_mlkem_ek = ek_b64.is_some();
        // huddle 2.0.0 (F1): the SAS verified-peer anchor is the THIRD capability
        // source, and the strongest — it survives a relay stripping both the live
        // announce key and the room_members pin. Folding it into
        // `partner_pq_capable` makes `plan_dm_key` refuse a classical fallback for
        // a peer we once SAS-verified as PQ-capable: with no ek available the plan
        // yields a hybrid action that can't derive (→ Noop, wait for a genuine
        // hybrid announce) rather than locking in a quantum-unsafe classical key.
        // `get_verified_peer_pq_capable` is fail-secure (reports `true` on a DB
        // error), so `.unwrap_or(true)` keeps the same loud-fail-over-silent-
        // downgrade posture. This is exactly `dm::must_refuse_classical_fallback`.
        let verified_pq_capable =
            repo::get_verified_peer_pq_capable(&self.db, partner_fp).unwrap_or(true);
        let partner_pq_capable = have_mlkem_ek || verified_pq_capable;
        debug_assert_eq!(
            crate::crypto::dm::must_refuse_classical_fallback(partner_pq_capable, have_mlkem_ek),
            partner_pq_capable && !have_mlkem_ek,
            "F1 downgrade guard must agree with the folded capability inputs"
        );
        let we_are_initiator = self.identity.fingerprint() < partner_fp;

        // The whole downgrade/upgrade policy lives in this pure decision.
        let action = plan_dm_key(
            already_keyed,
            already_hybrid,
            partner_pq_capable,
            we_are_initiator,
            ciphertext_b64.is_some(),
        );
        match action {
            DmKeyAction::Noop => return DmKeyOutcome::Noop,
            DmKeyAction::RequestCiphertext => return DmKeyOutcome::RequestCiphertext,
            DmKeyAction::Classical
            | DmKeyAction::HybridInitiator
            | DmKeyAction::HybridResponder => {}
        }

        // huddle 1.1.4: wipe our copy of the identity secret on drop.
        let our_seed = zeroize::Zeroizing::new(self.identity.secret_bytes());

        // Derive (no lock held), per the chosen action. `is_hybrid` records
        // which key we built so the commit can enforce never-downgrade.
        let (key, ct_b64, is_hybrid): ([u8; KEY_LEN], Option<String>, bool) = match action {
            DmKeyAction::HybridInitiator | DmKeyAction::HybridResponder => {
                // PQ-capable partner → hybrid ONLY; classical is refused.
                let ek = match ek_b64.as_deref().and_then(|s| B64.decode(s).ok()) {
                    Some(b) if b.len() == crate::crypto::pqc::MLKEM_EK_LEN => b,
                    _ => {
                        warn!(%partner_fp, "DM hybrid: malformed ML-KEM pubkey");
                        return DmKeyOutcome::Noop;
                    }
                };
                if let DmKeyAction::HybridInitiator = action {
                    match crate::crypto::dm::derive_dm_key_hybrid_initiator(
                        &our_seed,
                        &partner_ed,
                        &ek,
                        room_id,
                    ) {
                        Ok((key, ct)) => (key, Some(B64.encode(ct)), true),
                        Err(e) => {
                            warn!(%e, %partner_fp, "DM hybrid initiator derivation failed");
                            return DmKeyOutcome::Noop;
                        }
                    }
                } else {
                    // Responder: decode the initiator's ciphertext and decapsulate.
                    let ct = match ciphertext_b64.and_then(|c| B64.decode(c).ok()) {
                        Some(b) => b,
                        None => {
                            warn!(%partner_fp, "DM hybrid: malformed ML-KEM ciphertext");
                            return DmKeyOutcome::Noop;
                        }
                    };
                    match crate::crypto::dm::derive_dm_key_hybrid_responder(
                        &self.identity.pq_keypair(),
                        &our_seed,
                        &partner_ed,
                        &ct,
                        room_id,
                    ) {
                        Ok(key) => (key, None, true),
                        Err(e) => {
                            warn!(%e, %partner_fp, "DM hybrid responder derivation failed");
                            return DmKeyOutcome::Noop;
                        }
                    }
                }
            }
            DmKeyAction::Classical => {
                match crate::crypto::dm::derive_dm_key(&our_seed, &partner_ed, room_id) {
                    Ok(key) => (key, None, false),
                    Err(e) => {
                        warn!(%e, %partner_fp, "DM classical derivation failed");
                        return DmKeyOutcome::Noop;
                    }
                }
            }
            // Noop / RequestCiphertext already returned above.
            DmKeyAction::Noop | DmKeyAction::RequestCiphertext => unreachable!(),
        };

        // Phase 2: commit under the lock, re-checking the LIVE state.
        let mut rooms = self.active_rooms.lock().unwrap();
        let room = match rooms.get_mut(room_id) {
            Some(r) => r,
            None => return DmKeyOutcome::Noop,
        };
        let live_keyed = room.passphrase_key.is_some();
        let live_hybrid = room.dm_is_hybrid;
        if live_keyed && live_hybrid {
            return DmKeyOutcome::Noop; // raced to hybrid
        }
        let is_first = !live_keyed;
        // Upgrade ONLY classical → hybrid; never the reverse.
        let is_upgrade = live_keyed && is_hybrid && !live_hybrid;
        if is_first || is_upgrade {
            room.passphrase_key = Some(key);
            room.dm_is_hybrid = is_hybrid;
            if ct_b64.is_some() {
                room.dm_kem_ciphertext = ct_b64;
            }
            if is_upgrade {
                // Retire the classically-wrapped outbound session key (HNDL).
                if let Some(c) = room.crypto.as_mut() {
                    if let Err(e) = c.rotate_outbound() {
                        warn!(%e, %room_id, "DM classical→hybrid upgrade: outbound rotate failed");
                    } else {
                        // F4: this rotation reset the epoch (0/now); persist it so
                        // the new epoch's schedule survives a restart.
                        self.persist_rotation_state(c);
                    }
                }
                info!(%room_id, %partner_fp, "DM upgraded classical→hybrid (post-quantum)");
            }
            DmKeyOutcome::ReBroadcast
        } else {
            DmKeyOutcome::Noop
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
        // huddle 1.2: re-register direct-delivery routing for this restored DM
        // so its relay traffic addresses the partner by fingerprint.
        self.network
            .register_dm(room_id.to_string(), partner_fingerprint.to_string());
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
            // huddle 1.3: derive the DM wrap key lazily in the `MemberAnnounce`
            // handler once the partner re-announces (revealing PQ capability +,
            // for the responder, the KEM ciphertext). On restart the persisted
            // Megolm sessions already decrypt history; the wrap key is only
            // needed to process the partner's *next* session-key announce, which
            // re-arrives on reconnect.
            let pk: Option<[u8; KEY_LEN]> = None;
            // huddle 0.7.11: bubble up the error instead of .expect. The
            // inbound-DM auto-bootstrap path spawns this on its own task;
            // a transient DB write failure used to panic the task and
            // silently kill all subsequent DM bootstraps.
            let c = match RoomCrypto::load(
                self.db.clone(),
                room_id.to_string(),
                our_fp.clone(),
                self.persist_key(),
            )? {
                Some(mut c) => {
                    // F4: continue the rotation schedule from where it left off
                    // rather than resetting the counter to zero on this restart.
                    self.rehydrate_rotation_state(&mut c);
                    Some(c)
                }
                None => Some(RoomCrypto::new_for_room(
                    self.db.clone(),
                    room_id.to_string(),
                    our_fp.clone(),
                    self.persist_key(),
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
                dm_kem_ciphertext: None,
                dm_is_hybrid: false,
                dm_key_retry: 0,
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
                self.persist_key(),
            )?;
            Some(match existing {
                Some(mut c) => {
                    // F4: resume the rotation schedule across this restart/re-join
                    // instead of restarting the counter from zero.
                    self.rehydrate_rotation_state(&mut c);
                    c
                }
                None => RoomCrypto::new_for_room(
                    self.db.clone(),
                    room_id.to_string(),
                    our_fp,
                    self.persist_key(),
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
                dm_kem_ciphertext: None,
                dm_is_hybrid: false,
                dm_key_retry: 0,
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
                    dm_kem_ciphertext: None,
                    dm_is_hybrid: false,
                    dm_key_retry: 0,
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
            // huddle 2.0.3 (audit N-M2): bind the room to this signed leave.
            room_id: Some(room_id.to_string()),
        };
        let dispatched =
            match crate::crypto::sign_message(&self.identity, &leave_msg).and_then(|env| {
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

    /// Send a top-level message to a room. huddle 2.0.0 (F10): mints a stable
    /// `client_msg_id` so the message can later be reacted to / edited / deleted
    /// / replied to across peers.
    pub async fn send_room_message(&self, room_id: &str, body: &str) -> Result<()> {
        self.send_room_message_inner(room_id, body, None).await
    }

    /// huddle 2.0.0 (F10): send a reply to an existing message. `reply_to` is the
    /// `client_msg_id` of the message being replied to (the target may itself be
    /// a pre-2.0 message with no id or a since-deleted one — the UI degrades to a
    /// plain message then). Otherwise identical to [`send_room_message`].
    pub async fn send_reply(&self, room_id: &str, body: &str, reply_to: &str) -> Result<()> {
        self.send_room_message_inner(room_id, body, Some(reply_to))
            .await
    }

    /// Shared send path for top-level messages and replies. Mints the
    /// `client_msg_id`, encrypts (or not), publishes, persists with the id +
    /// `reply_to`, and — huddle 2.0.0 (F4) — rotates the outbound Megolm epoch
    /// after the configured message/age threshold, re-sharing the fresh session
    /// key via a `MemberAnnounce`.
    async fn send_room_message_inner(
        &self,
        room_id: &str,
        body: &str,
        reply_to: Option<&str>,
    ) -> Result<()> {
        let our_fp = self.identity.fingerprint().to_string();
        let client_msg_id = new_client_msg_id();
        // F4: read the rotation policy before taking the active_rooms lock (it
        // touches the DB) so we never nest the DB lock under active_rooms.
        let policy = self.megolm_rotation_policy();
        let (msg, needs_rotation) = {
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
                // F4: the message we're about to send used `session_id` (the
                // current epoch). Decide rotation AFTER the encrypt so the
                // counter includes this message; rotate the outbound session
                // in-place (sync) and re-announce the fresh key below, after we
                // publish this message under the old session the peers can decrypt.
                let needs_rotation = policy.is_enabled() && crypto.should_rotate(&policy);
                let msg = RoomMessage::Encrypted {
                    sender_fingerprint: our_fp.clone(),
                    session_id,
                    ciphertext_b64: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &ct_bytes,
                    ),
                    client_msg_id: Some(client_msg_id.clone()),
                    reply_to: reply_to.map(|s| s.to_string()),
                };
                if needs_rotation {
                    if let Err(e) = crypto.rotate_outbound() {
                        // Non-fatal: the message still goes out on the old epoch;
                        // we just didn't advance. The time/count trigger will fire
                        // again on the next send or heartbeat.
                        warn!(%e, %room_id, "F4: scheduled Megolm rotation failed");
                    }
                }
                // F4: persist the (possibly post-rotation) epoch bookkeeping so
                // the count/age schedule survives a restart instead of resetting
                // to zero. This is the after-each-encrypt save the policy relies
                // on; rehydrated via `rehydrate_rotation_state` after load.
                self.persist_rotation_state(crypto);
                (msg, needs_rotation)
            } else {
                // Plaintext rooms have no Megolm session to rotate.
                let msg = RoomMessage::Plain {
                    sender_fingerprint: our_fp.clone(),
                    body: body.to_string(),
                    client_msg_id: Some(client_msg_id.clone()),
                    reply_to: reply_to.map(|s| s.to_string()),
                };
                (msg, false)
            }
        };

        let bytes = encode_wire(&msg)?;
        self.network
            .publish_room_message(room_id.to_string(), bytes)
            .await;

        // F4: share the post-rotation session key. Done AFTER the message above
        // so peers receive (old-session message, then new-session announce) in
        // order — the rotation is forward-only, so they keep the old inbound
        // session to decrypt the message we just sent.
        if needs_rotation {
            if let Err(e) = self.broadcast_member_announce(room_id).await {
                warn!(%e, %room_id, "F4: post-rotation MemberAnnounce failed");
            } else {
                info!(%room_id, "F4: rotated outbound Megolm epoch and re-announced");
            }
        }

        let now = now_unix();
        let msg_id = repo::insert_room_message(
            &self.db,
            room_id,
            &our_fp,
            "out",
            body,
            now,
            Some(client_msg_id.as_str()),
            reply_to,
        )?;
        repo::update_room_last_active(&self.db, room_id, now)?;

        let _ = self.app_event_tx.send(AppEvent::MessageSent {
            room_id: room_id.to_string(),
            body: body.to_string(),
            message_id: msg_id,
        });

        Ok(())
    }

    /// huddle 2.0.0 (F4): the scheduled forward-only Megolm rotation policy,
    /// read from `app_settings` (`megolm_rotation_max_messages`,
    /// `megolm_rotation_max_hours`) and defaulting to the blueprint's 1000
    /// messages / 24 hours when unset or unparsable. A `0` for either bound
    /// disables that trigger; both `0` disables scheduled rotation entirely
    /// (pre-2.0.0 behaviour).
    fn megolm_rotation_policy(&self) -> crate::crypto::megolm::RotationPolicy {
        use crate::crypto::megolm::RotationPolicy;
        let max_messages = repo::get_setting(&self.db, "megolm_rotation_max_messages")
            .ok()
            .flatten()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(RotationPolicy::DEFAULT_MAX_MESSAGES);
        let max_hours = repo::get_setting(&self.db, "megolm_rotation_max_hours")
            .ok()
            .flatten()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(RotationPolicy::DEFAULT_MAX_HOURS);
        RotationPolicy::from_messages_and_hours(max_messages, max_hours)
    }

    /// huddle 2.0.0 (F4): persist a room's live outbound epoch bookkeeping
    /// (`messages_since_rotation`, `last_rotation_at`) to the durable
    /// `room_megolm_rotation_state` table. Called after each encrypt and after
    /// every rotation so the scheduled-rotation timing survives a restart
    /// (paired with `rehydrate_rotation_state` at the `RoomCrypto::load` sites).
    /// Best-effort: a failed write only means the counter falls back to its
    /// last persisted value next launch — it never blocks sending.
    fn persist_rotation_state(&self, crypto: &RoomCrypto) {
        if let Err(e) = repo::set_megolm_rotation_state(
            &self.db,
            crypto.room_id(),
            crypto.our_fingerprint(),
            crypto.messages_since_rotation(),
            crypto.last_rotation_at(),
        ) {
            warn!(%e, room_id = %crypto.room_id(), "F4: persist Megolm rotation state failed");
        }
    }

    /// huddle 2.0.0 (F4): rehydrate a freshly-`load`ed `RoomCrypto`'s epoch
    /// bookkeeping from `room_megolm_rotation_state`. `RoomCrypto::load` only
    /// restores the Megolm ratchet, so without this the message counter and
    /// epoch start reset to 0/now every launch and the rotation schedule never
    /// converges across restarts (a room most of the way to its message cap
    /// would start counting from zero again). No-op when no row exists yet (a
    /// never-sent room keeps the fresh 0/now baseline).
    fn rehydrate_rotation_state(&self, crypto: &mut RoomCrypto) {
        match repo::get_megolm_rotation_state(&self.db, crypto.room_id(), crypto.our_fingerprint())
        {
            Ok(Some((count, at))) => crypto.restore_rotation_state(count, at),
            Ok(None) => {}
            Err(e) => {
                warn!(%e, room_id = %crypto.room_id(), "F4: restore Megolm rotation state failed")
            }
        }
    }

    /// huddle 2.0.0 (F4): the current scheduled-rotation config as
    /// `(max_messages, max_hours)` for Settings → Encryption to display.
    pub fn megolm_rotation_config(&self) -> (u32, i64) {
        let p = self.megolm_rotation_policy();
        (p.max_messages, p.max_age_secs / 3600)
    }

    /// huddle 2.0.0 (F4): set the message-count rotation threshold (0 disables
    /// the count trigger). Persisted to `app_settings`.
    pub fn set_megolm_rotation_max_messages(&self, n: u32) -> Result<()> {
        repo::set_setting(&self.db, "megolm_rotation_max_messages", &n.to_string())
    }

    /// huddle 2.0.0 (F4): set the age rotation threshold in hours (0 disables
    /// the time trigger). Persisted to `app_settings`.
    pub fn set_megolm_rotation_max_hours(&self, hours: i64) -> Result<()> {
        repo::set_setting(
            &self.db,
            "megolm_rotation_max_hours",
            &hours.max(0).to_string(),
        )
    }

    // -------------------------------------------------------------------
    // huddle 2.0.0 (F10): reactions, edits, deletes
    // -------------------------------------------------------------------

    /// All reactions currently stored for a room (oldest first), for the UI to
    /// group by `target_client_msg_id` into per-emoji counts.
    pub fn room_reactions(&self, room_id: &str) -> Vec<repo::StoredReaction> {
        repo::list_room_reactions(&self.db, room_id).unwrap_or_default()
    }

    /// huddle 2.0.0 (F10): react to a message. `removed = false` adds the emoji,
    /// `true` toggles it off. Signs + broadcasts a `Reaction` and applies it
    /// locally so our own badge updates immediately. `target_msg_id` is the
    /// message's `client_msg_id`.
    pub async fn send_reaction(
        &self,
        room_id: &str,
        target_msg_id: &str,
        emoji: &str,
        removed: bool,
    ) -> Result<()> {
        let our_fp = self.identity.fingerprint().to_string();
        // huddle 2.0.0 (F10): only react to a message we actually hold in this
        // room. Without this guard a stray `client_msg_id` would store an
        // orphan reaction locally and broadcast a signed `Reaction` that every
        // peer drops anyway — inbound reactions are validated the same way (see
        // the `RoomMessage::Reaction` handler). Mirrors `edit_message`.
        repo::find_message_by_client_id(&self.db, room_id, target_msg_id)?
            .ok_or_else(|| HuddleError::Other("reaction target message not found".into()))?;
        let msg = RoomMessage::Reaction {
            sender_fingerprint: our_fp.clone(),
            target_msg_id: target_msg_id.to_string(),
            emoji: emoji.to_string(),
            removed,
        };
        let env = crate::crypto::sign_message(&self.identity, &msg)?;
        let bytes = crate::network::protocol::encode_wire_signed(&env)?;
        self.network
            .publish_room_message(room_id.to_string(), bytes)
            .await;
        if removed {
            repo::remove_reaction(&self.db, room_id, target_msg_id, &our_fp, emoji)?;
        } else {
            repo::add_reaction(&self.db, room_id, target_msg_id, &our_fp, emoji, now_unix())?;
        }
        let _ = self.app_event_tx.send(AppEvent::ReactionAdded {
            room_id: room_id.to_string(),
            message_id: target_msg_id.to_string(),
            sender_fingerprint: our_fp,
            emoji: emoji.to_string(),
            removed,
        });
        Ok(())
    }

    /// huddle 2.0.0 (F10): edit the body of a message we sent (or, as a room
    /// owner, anyone's). For encrypted rooms the new body is re-encrypted under
    /// our outbound Megolm session; for plaintext rooms it rides in the clear.
    /// Applied locally + broadcast as a signed `Edit` (last-write-wins).
    pub async fn edit_message(
        &self,
        room_id: &str,
        target_msg_id: &str,
        new_body: &str,
    ) -> Result<()> {
        let our_fp = self.identity.fingerprint().to_string();
        let target = repo::find_message_by_client_id(&self.db, room_id, target_msg_id)?
            .ok_or_else(|| HuddleError::Other("edit target message not found".into()))?;
        if target.sender_fingerprint != our_fp && !self.we_are_owner(room_id) {
            return Err(HuddleError::Other(
                "not authorized to edit this message (not the sender or a room owner)".into(),
            ));
        }
        let encrypted = self
            .active_room_info(room_id)
            .map(|r| r.encrypted)
            .unwrap_or(false);
        let (new_ciphertext_b64, session_id, new_body_field) = if encrypted {
            let mut rooms = self.active_rooms.lock().unwrap();
            let room = rooms
                .get_mut(room_id)
                .ok_or_else(|| HuddleError::Other(format!("not in room {room_id}")))?;
            let crypto = room
                .crypto
                .as_mut()
                .ok_or_else(|| HuddleError::Session("encrypted room missing crypto".into()))?;
            // huddle 2.0.0 (F10): carry the exact session we encrypt under so the
            // receiver decrypts the edit like an `Encrypted` body — no in-memory
            // "last inbound session" guess (which broke across rotation/restart).
            let (session_id, ct) = crypto.encrypt(new_body.as_bytes())?;
            (B64.encode(&ct), session_id, None)
        } else {
            (String::new(), String::new(), Some(new_body.to_string()))
        };
        let msg = RoomMessage::Edit {
            sender_fingerprint: our_fp.clone(),
            target_msg_id: target_msg_id.to_string(),
            new_ciphertext_b64,
            session_id,
            new_body: new_body_field,
        };
        let env = crate::crypto::sign_message(&self.identity, &msg)?;
        let bytes = crate::network::protocol::encode_wire_signed(&env)?;
        self.network
            .publish_room_message(room_id.to_string(), bytes)
            .await;
        repo::apply_message_edit(&self.db, room_id, target_msg_id, new_body, now_unix_ms())?;
        let _ = self.app_event_tx.send(AppEvent::MessageEdited {
            room_id: room_id.to_string(),
            message_id: target_msg_id.to_string(),
            editor_fingerprint: our_fp,
            new_body: new_body.to_string(),
        });
        Ok(())
    }

    /// huddle 2.0.0 (F10): delete (tombstone) a message we sent (or, as a room
    /// owner, anyone's). Broadcast as a signed `Delete`; the body is blanked
    /// everywhere and rendered as `[deleted]`.
    pub async fn delete_message(&self, room_id: &str, target_msg_id: &str) -> Result<()> {
        let our_fp = self.identity.fingerprint().to_string();
        let target = repo::find_message_by_client_id(&self.db, room_id, target_msg_id)?
            .ok_or_else(|| HuddleError::Other("delete target message not found".into()))?;
        if target.sender_fingerprint != our_fp && !self.we_are_owner(room_id) {
            return Err(HuddleError::Other(
                "not authorized to delete this message (not the sender or a room owner)".into(),
            ));
        }
        let msg = RoomMessage::Delete {
            sender_fingerprint: our_fp.clone(),
            target_msg_id: target_msg_id.to_string(),
        };
        let env = crate::crypto::sign_message(&self.identity, &msg)?;
        let bytes = crate::network::protocol::encode_wire_signed(&env)?;
        self.network
            .publish_room_message(room_id.to_string(), bytes)
            .await;
        repo::mark_message_deleted(&self.db, room_id, target_msg_id, now_unix_ms())?;
        let _ = self.app_event_tx.send(AppEvent::MessageDeleted {
            room_id: room_id.to_string(),
            message_id: target_msg_id.to_string(),
            deleter_fingerprint: our_fp,
        });
        Ok(())
    }

    // -------------------------------------------------------------------
    // huddle 2.0.0 (F9): disappearing messages — per-room TTL
    // -------------------------------------------------------------------

    /// The room's disappearing-messages TTL in seconds, or `None` when OFF.
    pub fn room_disappearing_ttl(&self, room_id: &str) -> Option<u32> {
        repo::get_room_disappearing_ttl(&self.db, room_id)
            .ok()
            .flatten()
    }

    /// huddle 2.0.0 (F9): set (or clear, with `None`) the room's
    /// disappearing-messages TTL. Persists locally, then broadcasts a signed
    /// `RoomSetting` so other members adopt it. Honest receivers apply it only
    /// when we're the room creator or an owner; the pruner then auto-deletes
    /// expired messages locally on every peer.
    pub async fn set_room_disappearing_ttl(
        &self,
        room_id: &str,
        ttl_secs: Option<u32>,
    ) -> Result<()> {
        repo::set_room_disappearing_ttl(&self.db, room_id, ttl_secs)?;
        let our_fp = self.identity.fingerprint().to_string();
        let msg = RoomMessage::RoomSetting {
            sender_fingerprint: our_fp,
            disappearing_ttl_secs: ttl_secs.map(u64::from).unwrap_or(0),
            // huddle 2.0.3 (audit N-M2): bind the room so the signed setting
            // can't be replayed onto another room's topic by a hostile relay.
            room_id: Some(room_id.to_string()),
        };
        let env = crate::crypto::sign_message(&self.identity, &msg)?;
        let bytes = crate::network::protocol::encode_wire_signed(&env)?;
        self.network
            .publish_room_message(room_id.to_string(), bytes)
            .await;
        let _ = self.app_event_tx.send(AppEvent::RoomTtlChanged {
            room_id: room_id.to_string(),
            ttl_secs,
        });
        Ok(())
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
            let mut rooms = self.active_rooms.lock().unwrap();
            // 3. Re-encrypt all Megolm session pickles old → new persist key, so
            //    they survive the master-key rekey AND decrypt under the new key.
            self.reencrypt_megolm_sessions(&old_persist, &new_persist)?;
            // 4. PRAGMA rekey the SQLCipher DB (atomic, sentinel-verified). This
            //    is now the single commit point of the whole rotation.
            {
                let conn = self.db.lock().unwrap();
                storage::rekey_db(&conn, &new_master)?;
            }
            // 5. Swap the in-memory persist key and 6. reload the active rooms'
            //    cryptos under it — still inside the quiesce window so disk and
            //    in-memory session state stay consistent.
            *self.session_persist_key.lock().unwrap() = new_persist;
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
            remember_room_salt(&room.id, salt);
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
        // huddle 1.2: route this contact's DM relay traffic by fingerprint
        // (direct delivery), not by room-membership fan-out — so DMs reach
        // them reliably even before both sides have subscribed the DM room.
        self.network
            .register_dm(dm_room_id.clone(), fingerprint.to_string());
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
        // huddle 1.2: deliver the request STRAIGHT to the target's fingerprint
        // over the relay (live, or queued in their mailbox if offline), tagged
        // with their inbox id so their client files it as a contact request.
        // This no longer depends on the target having an active inbox
        // subscription on the relay, and also rides libp2p gossipsub on the
        // inbox topic for LAN delivery.
        self.network
            .publish_direct(target_fingerprint.to_string(), inbox, bytes)
            .await;
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

    /// huddle 1.2.1: ask the relay to mint a short-lived **connect code** bound
    /// to our identity, so a peer can add/DM us by typing the code instead of
    /// our full HD-ID. The code (and its expiry) arrive asynchronously as
    /// `AppEvent::ConnectCodeCreated`. Errors immediately if the relay isn't
    /// connected (codes are a relay feature — there's no one to mint them).
    pub fn create_connect_code(&self) -> Result<()> {
        if !self.network.create_connect_token() {
            return Err(HuddleError::Network(
                "not connected to the relay — can't create a connect code".into(),
            ));
        }
        Ok(())
    }

    /// huddle 1.2.1: redeem a connect code someone shared. The relay resolves
    /// it to their identity and we send them a contact request (which opens a
    /// DM once they accept). Progress arrives as `AppEvent::ConnectCodeRedeemed`
    /// / `ConnectCodeFailed`. Errors immediately for a malformed code or when
    /// the relay isn't connected.
    pub fn redeem_connect_code(&self, code: &str) -> Result<()> {
        let norm = normalize_connect_code(code)
            .ok_or_else(|| HuddleError::Other("that doesn't look like a connect code".into()))?;
        if !self.network.redeem_connect_token(&norm) {
            return Err(HuddleError::Network(
                "not connected to the relay — can't redeem a connect code".into(),
            ));
        }
        Ok(())
    }

    /// huddle 1.2.1: the relay resolved a connect code we redeemed. Validate the
    /// resolution, then send the owner a contact request (which opens a DM when
    /// they accept). Emits `ConnectCodeRedeemed` on success, `ConnectCodeFailed`
    /// otherwise.
    async fn on_connect_code_resolved(
        &self,
        fingerprint: Option<String>,
        pubkey_b64: Option<String>,
    ) {
        let our_fp = self.identity.fingerprint().to_string();
        let fp = match fingerprint {
            Some(fp) if !fp.is_empty() => fp,
            _ => {
                let _ = self.app_event_tx.send(AppEvent::ConnectCodeFailed {
                    reason: "invalid or expired connect code".into(),
                });
                return;
            }
        };
        if fp == our_fp {
            let _ = self.app_event_tx.send(AppEvent::ConnectCodeFailed {
                reason: "that's your own connect code".into(),
            });
            return;
        }
        // Integrity check: if the relay also returned the owner's pubkey, it
        // MUST hash to the fingerprint it claims — else the mapping is bogus
        // (a buggy or hostile relay). The real identity proof still comes from
        // the owner's signed reply; this just rejects an obviously-wrong map.
        if let Some(pk_b64) = pubkey_b64.as_deref() {
            if let Some(pk) = B64
                .decode(pk_b64)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            {
                if crate::identity::compute_fingerprint(&pk) != fp {
                    let _ = self.app_event_tx.send(AppEvent::ConnectCodeFailed {
                        reason: "connect code resolved to a mismatched identity".into(),
                    });
                    return;
                }
            }
        }
        match self.send_contact_request(&fp, None).await {
            Ok(()) => {
                let _ = self
                    .app_event_tx
                    .send(AppEvent::ConnectCodeRedeemed { fingerprint: fp });
            }
            Err(e) => {
                let _ = self.app_event_tx.send(AppEvent::ConnectCodeFailed {
                    reason: format!("couldn't send the request: {e}"),
                });
            }
        }
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
                ROOM_SALT_CACHE.lock().unwrap().get(room_id).cloned()
            })
    }

    async fn announce_room_now(&self, info: &StoredRoom, member_count: u32) {
        let owner_fingerprints = repo::list_room_owners(&self.db, &info.id).unwrap_or_default();
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
        let (wrapped, is_direct, dm_ct) = {
            let mut rooms = self.active_rooms.lock().unwrap();
            let room = rooms
                .get_mut(room_id)
                .ok_or_else(|| HuddleError::Other("not in room".into()))?;
            let is_direct = room.info.kind == RoomKind::Direct;
            // huddle 1.3: the KEM ciphertext we (as DM initiator) encapsulated,
            // re-published every announce so the responder can decapsulate the
            // same hybrid wrap key. `None` for groups, classical DMs, responders.
            let dm_ct = room.dm_kem_ciphertext.clone();
            let wrapped = if room.info.encrypted {
                let crypto = room.crypto.as_mut().unwrap();
                let session_key = crypto.our_session_key_b64();
                match room.passphrase_key.as_ref() {
                    Some(passphrase_key) => {
                        Some(passphrase::wrap(session_key.as_bytes(), passphrase_key)?)
                    }
                    None if is_direct => {
                        // huddle 0.7.1: DM-specific path — partner's
                        // pubkey hasn't been observed yet, so we can't
                        // derive the wrap key. Send announce without
                        // a wrapped key — it carries our Ed25519 +
                        // ML-KEM pubkeys, which let the partner derive
                        // the key on their side. They'll respond with
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
            };
            (wrapped, is_direct, dm_ct)
        };
        let display_name = repo::get_display_name(&self.db).unwrap_or(None);
        // huddle 1.3: advertise our ML-KEM-768 encapsulation key on Direct-room
        // announces (only — group rooms stay byte-identical) so the partner can
        // run the hybrid post-quantum DM key agreement. Its presence is also how
        // the partner detects our PQ capability. The ciphertext is set only when
        // we are the initiator (lower fingerprint) and have encapsulated.
        let (sender_mlkem_pubkey, mlkem_ciphertext) = if is_direct {
            (Some(B64.encode(self.identity.mlkem_public_bytes())), dm_ct)
        } else {
            (None, None)
        };
        let msg = RoomMessage::MemberAnnounce {
            sender_fingerprint: our_fp,
            wrapped_session_key: wrapped,
            display_name,
            sender_ed25519_pubkey: Some(B64.encode(self.identity.public_bytes())),
            sender_mlkem_pubkey,
            mlkem_ciphertext,
        };
        // huddle 0.7.11: MemberAnnounce is now signed end-to-end. On the send
        // path the inner `sender_ed25519_pubkey` equals the envelope's pubkey by
        // construction (both are our identity key), and the receiver pins
        // whatever pubkey the announce carries. The pin is made safe not by
        // ignoring the inner field but by the receiver's `signer ==
        // sender_fingerprint` gate, which lets a peer write only its own row.
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
    /// huddle 1.2: every room id whose membership must be asserted on the
    /// relay — active rooms, rooms parked as `restorable` (encrypted groups /
    /// keyless DMs awaiting a passphrase or the partner's pubkey), and the aux
    /// subscriptions (our own contact inbox). Used both to build the Hello
    /// room set and to re-subscribe after each (re)connect, so the relay knows
    /// we belong to a room even before we can decrypt it — otherwise its
    /// fan-out skips us and group messages silently never arrive.
    fn relay_membership_ids(&self) -> Vec<String> {
        let mut set: HashSet<String> = self.active_rooms.lock().unwrap().keys().cloned().collect();
        set.extend(self.restorable_rooms.lock().unwrap().keys().cloned());
        set.extend(self.aux_subscriptions.lock().unwrap().iter().cloned());
        set.into_iter().collect()
    }

    fn spawn_server_connection(&self, order: Vec<TransportId>) {
        let handle = self.clone();
        tokio::spawn(async move {
            let mut backoff = 1u64;
            loop {
                // huddle 2.0.0: once shutdown() trips the flag, stop reconnecting
                // and let this task end (it holds the only live relay socket and
                // an AppHandle clone — leaving it running leaks both and, across
                // an in-process restart, races the new instance on the shared DB).
                if handle
                    .shutting_down
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    handle.network.detach_server();
                    return;
                }
                // huddle 1.0: the Hello room set is every active chat room
                // PLUS our aux subscriptions (the contact inbox), so the relay
                // re-registers inbox membership on every reconnect and flushes
                // any queued contact requests.
                let rooms: Vec<String> = handle.relay_membership_ids();

                // Try each door in order until one connects. Unavailable
                // doors (no URL / wrong build) are skipped.
                let mut connected: Option<(
                    ServerClient,
                    tokio::sync::mpsc::UnboundedReceiver<ServerEvent>,
                    TransportId,
                )> = None;
                for id in &order {
                    let (url, dial) = match handle.transport_profiles.iter().find(|p| p.id == *id) {
                        Some(p) if p.available() => {
                            (p.url.clone().unwrap(), p.dial.clone().unwrap())
                        }
                        _ => continue,
                    };
                    match ServerClient::connect(&url, &dial, handle.identity.clone(), rooms.clone())
                        .await
                    {
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
                    // huddle 1.2: re-assert membership for every active room
                    // over the freshly attached connection. Hello carried the
                    // room snapshot taken before we connected, so a room
                    // created/joined during the connect-handshake window would
                    // otherwise stay unknown to the relay until the next
                    // reconnect — silently breaking group fan-out for it. The
                    // relay's add_membership is idempotent, so re-subscribing is
                    // free. (DM rooms route by fingerprint and don't depend on
                    // this, but re-subscribing them is harmless.)
                    for rid in handle.relay_membership_ids() {
                        handle.network.subscribe_room(rid).await;
                    }
                    while let Some(ev) = rx.recv().await {
                        match ev {
                            ServerEvent::Message {
                                room,
                                payload,
                                mailbox_id,
                                ..
                            } => {
                                // huddle 2.0.0 (F7) + 2.0.2 (audit M-2): at-least-
                                // once relay delivery. `process_relay_message`
                                // dispatches the message and returns whether it was
                                // durably handled. We ACK the mailbox row (so the
                                // relay may delete its copy) ONLY when it was — an
                                // `Encrypted` body whose Megolm session key hasn't
                                // arrived returns false and is left in the mailbox
                                // for redelivery rather than ACKed-then-lost.
                                // `mailbox_id` is `Some` only for an offline-mailbox
                                // delivery from a 2.0+ relay; live fan-out and
                                // pre-2.0 relays leave it `None`. The relay's 24h
                                // sweep is the backstop.
                                let ack_ok = handle.process_relay_message(room, payload).await;
                                if ack_ok {
                                    if let Some(id) = mailbox_id {
                                        let _ = handle.network.send_mailbox_ack(id);
                                    }
                                }
                            }
                            ServerEvent::Ready | ServerEvent::Sent { .. } => {}
                            ServerEvent::ConnectToken { token, ttl_secs } => {
                                // huddle 1.2.1: relay minted our connect code.
                                let expires_at = now_unix() + ttl_secs as i64;
                                let _ = handle.app_event_tx.send(AppEvent::ConnectCodeCreated {
                                    code: token,
                                    expires_at,
                                });
                            }
                            ServerEvent::ConnectTokenResolved {
                                fingerprint,
                                pubkey_b64,
                            } => {
                                handle
                                    .on_connect_code_resolved(fingerprint, pubkey_b64)
                                    .await;
                            }
                            ServerEvent::Disconnected => break,
                        }
                    }
                    handle.network.detach_server();
                    *handle.active_transport.lock().unwrap() = None;
                    warn!("relay connection closed; reconnecting");
                } else {
                    warn!("all relay doors failed; will retry");
                }
                // huddle 2.0.0: exit promptly on shutdown rather than sleeping
                // the backoff and looping back to reconnect.
                if handle
                    .shutting_down
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    handle.network.detach_server();
                    return;
                }
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(30);
            }
        });
    }

    fn spawn_announcement_ticker(&self) {
        let handle = self.clone();
        tokio::spawn(async move {
            let our_fp = handle.identity.fingerprint().to_string();
            let mut interval = tokio::time::interval(Duration::from_secs(ANNOUNCE_INTERVAL_SECS));
            interval.tick().await; // skip the immediate tick
            loop {
                interval.tick().await;
                // huddle 2.0.2 (audit M-3): stop the heartbeat once shutdown
                // has begun, so we don't keep reading/writing the DB or
                // publishing announces during/after the rekey + close window.
                if handle
                    .shutting_down
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    return;
                }
                // huddle 1.3.1: alongside the room re-announce, find Direct rooms
                // whose hybrid handshake hasn't converged (no wrap key yet, or
                // keyed classical while the partner is PQ-capable = upgrade
                // pending) and, while they still have retry budget, emit a
                // bounded `SessionKeyRequest` nudge. This heals a stalled
                // handshake (e.g. the initiator's single ciphertext-bearing
                // announce was lost) without a periodic full MemberAnnounce; the
                // hard cap keeps an unreachable partner's mailbox from filling.
                // huddle 2.0.0 (F4): read the scheduled-rotation policy once per
                // tick (outside the active_rooms lock — it touches the DB). The
                // heartbeat is what fires the *time*-based trigger for rooms that
                // aren't actively sending; the send path covers the count trigger.
                let rotation_policy = handle.megolm_rotation_policy();
                let (snapshot, dm_nudges, rotated): (
                    Vec<(StoredRoom, u32)>,
                    Vec<String>,
                    Vec<String>,
                ) = {
                    let mut active = handle.active_rooms.lock().unwrap();
                    let snap: Vec<(StoredRoom, u32)> = active
                        .values()
                        .map(|r| (r.info.clone(), r.members.len() as u32))
                        .collect();
                    let mut nudges = Vec::new();
                    let mut rotated = Vec::new();
                    for room in active.values_mut() {
                        // F4: scheduled forward-only Megolm rotation for any keyed
                        // encrypted room (groups + DMs). Rotate in-place (sync)
                        // and re-announce the fresh key after the lock. Only keyed
                        // rooms rotate — an unkeyed DM has nothing to share yet.
                        if room.info.encrypted
                            && room.passphrase_key.is_some()
                            && rotation_policy.is_enabled()
                        {
                            if let Some(c) = room.crypto.as_mut() {
                                if c.should_rotate(&rotation_policy) {
                                    match c.rotate_outbound() {
                                        Ok(()) => {
                                            // F4: persist the reset (0/now) epoch so
                                            // the schedule doesn't re-arm from
                                            // scratch after a restart.
                                            handle.persist_rotation_state(c);
                                            rotated.push(room.info.id.clone());
                                        }
                                        Err(e) => warn!(
                                            %e, room_id = %room.info.id,
                                            "F4: scheduled Megolm rotation failed in heartbeat"
                                        ),
                                    }
                                }
                            }
                        }
                        if room.info.kind != RoomKind::Direct || !room.info.encrypted {
                            continue;
                        }
                        let keyed = room.passphrase_key.is_some();
                        let partner = room.members.iter().find(|m| m.as_str() != our_fp).cloned();
                        let pq_capable = match &partner {
                            Some(p) => repo::lookup_peer_mlkem_pubkey(&handle.db, p)
                                .ok()
                                .flatten()
                                .is_some(),
                            None => false,
                        };
                        // Converged = hybrid keyed, or classical keyed with a
                        // genuinely non-PQ partner. Anything else needs a nudge.
                        let needs_nudge = !keyed || (!room.dm_is_hybrid && pq_capable);
                        if needs_nudge {
                            if room.dm_key_retry < DM_KEY_RETRY_MAX {
                                room.dm_key_retry = room.dm_key_retry.saturating_add(1);
                                nudges.push(room.info.id.clone());
                            }
                        } else {
                            room.dm_key_retry = 0;
                        }
                    }
                    (snap, nudges, rotated)
                };
                for (info, member_count) in snapshot {
                    handle.announce_room_now(&info, member_count).await;
                }
                // F4: re-share each rotated room's fresh session key.
                for rid in rotated {
                    if let Err(e) = handle.broadcast_member_announce(&rid).await {
                        warn!(%e, room_id = %rid, "F4: post-rotation MemberAnnounce failed");
                    } else {
                        info!(room_id = %rid, "F4: rotated outbound Megolm epoch (heartbeat) and re-announced");
                    }
                }
                for rid in dm_nudges {
                    let req = RoomMessage::SessionKeyRequest {
                        requester_fingerprint: our_fp.clone(),
                    };
                    if let Ok(bytes) = encode_wire(&req) {
                        handle.network.publish_room_message(rid, bytes).await;
                    }
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
                // huddle 2.0.2 (audit M-3): honor shutdown in the pruner too.
                if handle
                    .shutting_down
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    return;
                }
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
                // huddle 1.3.1: reap abandoned SAS flows so an inbound-SasInit
                // flood (or just unfinished handshakes) can't grow sas_flows
                // without bound. Finalized flows are already removed promptly.
                // huddle 1.3.3: `created_at` is refreshed on progress, so this is
                // an idle-since-last-activity TTL — a slow but live handshake survives.
                {
                    let mut flows = handle.sas_flows.lock().unwrap();
                    flows.retain(|_, f| now - f.created_at <= SAS_FLOW_TTL_SECS);
                }
                // huddle 2.0.0 (F9): disappearing-messages sweep. Physically
                // delete every message past its room's TTL, against our own
                // clock (best-effort + local). F2 interaction: a deleted
                // message's `content_replay_seen` row survives, so a replayed
                // copy of an expired message is still dropped as a replay and can
                // never be resurrected into the chat. Emit a coarse refresh nudge
                // when anything was removed so the open room re-fetches history.
                match repo::delete_expired_messages(&handle.db, now) {
                    Ok(removed) if removed > 0 => {
                        debug!(removed, "F9: pruned expired messages");
                        let _ = handle
                            .app_event_tx
                            .send(AppEvent::MessagesExpired { count: removed });
                    }
                    Ok(_) => {}
                    Err(e) => warn!(%e, "F9: expired-message sweep failed"),
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
                    remember_room_salt(&ann.room_id, salt.clone());
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
                        // huddle 1.3.1: creator_fingerprint is unauthenticated, so
                        // drop entries past the backoff window (they no longer
                        // suppress a dial) and hard-cap inserts to bound a flood of
                        // distinct fingerprints from growing the map without limit.
                        attempts.retain(|_fp, last| now - *last < HOST_ADDR_DIAL_BACKOFF_SECS);
                        match attempts.get(&ann.creator_fingerprint).copied() {
                            Some(last) if now - last < HOST_ADDR_DIAL_BACKOFF_SECS => false,
                            _ => {
                                if attempts.len() < HOST_ADDR_DIAL_ATTEMPTS_CAP {
                                    attempts.insert(ann.creator_fingerprint.clone(), now);
                                    true
                                } else {
                                    // huddle 1.3.3: at cap we cannot record this
                                    // attempt, so dialing here would bypass the
                                    // per-fingerprint backoff entirely — every later
                                    // announce for an unrecordable fingerprint would
                                    // re-dial its (unauthenticated) host_addrs. An
                                    // attacker can keep the map saturated with bogus
                                    // creator_fingerprints, so refuse the dial rather
                                    // than amplify it into an outbound-connection
                                    // storm against an attacker-chosen address.
                                    // Legit saturation (4096 distinct live announcers
                                    // within the 300s backoff window) is implausible.
                                    false
                                }
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
                    if repo::is_peer_blocked(&self.db, &ann.creator_fingerprint).unwrap_or(false) {
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
                {
                    let mut map = self.discovered_rooms.lock().unwrap();
                    // huddle 2.0.3 (audit L-15 residual): cap the map so a flood
                    // of distinct group room_ids can't grow it without bound
                    // between TTL prunes; evict the stalest entry to make room.
                    if !map.contains_key(&ann.room_id) && map.len() >= MAX_DISCOVERED_ROOMS {
                        if let Some(stale) = map
                            .iter()
                            .min_by_key(|(_, r)| r.last_seen)
                            .map(|(k, _)| k.clone())
                        {
                            map.remove(&stale);
                        }
                    }
                    map.insert(ann.room_id.clone(), discovered.clone());
                }
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
                let (msg, verified_signer, signed_at_ms) = match wire {
                    WireMessage::Plain(m) => (m, None, None),
                    WireMessage::Signed(env) => {
                        let claimed_pubkey = env.ed25519_pubkey_b64.clone();
                        // huddle 2.0.2 (audit M-6): the signature binds this
                        // timestamp, so it's a clock the relay can't forge.
                        let signed_at = env.signed_at_ms;
                        match crate::crypto::verify_signed(&env) {
                            Ok((m, fp)) => {
                                // Defense in depth: if we've persisted
                                // a pubkey for this fingerprint in this
                                // room before, the envelope's pubkey
                                // MUST match it. A different pubkey for
                                // the same fingerprint means identity
                                // drift — TOFU violation — drop.
                                match repo::get_member_ed25519_pubkey(&self.db, &room_id, &fp) {
                                    Ok(Some(known)) if known != claimed_pubkey => {
                                        // huddle 2.0.0 (F3): surface the drift
                                        // instead of silently dropping. The
                                        // offending message is STILL dropped (we
                                        // never trust the new key implicitly); the
                                        // UI prompts the user to re-verify (SAS),
                                        // accept the new key, or block the peer.
                                        warn!(
                                            %fp, %room_id,
                                            "pubkey mismatch vs stored; emitting SafetyNumberChanged and dropping signed message"
                                        );
                                        let display_name =
                                            repo::lookup_display_name(&self.db, &fp).ok().flatten();
                                        let _ =
                                            self.app_event_tx.send(AppEvent::SafetyNumberChanged {
                                                room_id: room_id.clone(),
                                                fingerprint: fp.clone(),
                                                old_pubkey_b64: known,
                                                new_pubkey_b64: claimed_pubkey.clone(),
                                                display_name,
                                            });
                                        return;
                                    }
                                    _ => {}
                                }
                                (m, Some(fp), Some(signed_at))
                            }
                            Err(e) => {
                                warn!(%e, fp = %env.fingerprint, "signed envelope verify failed");
                                return;
                            }
                        }
                    }
                };
                self.handle_room_message(&room_id, msg, verified_signer, signed_at_ms)
                    .await;
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
            NetworkEvent::PeerIdentified {
                peer_id,
                fingerprint,
            } => {
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
                        // huddle 1.3.4: evict entries older than the rebroadcast
                        // floor so this map can't grow without bound as distinct
                        // peer fingerprints churn through (e.g. an attacker
                        // cycling Ed25519 identities). Anything older than the
                        // floor would re-broadcast anyway, so dropping it is free.
                        last.retain(|_fp, t| now_ms - *t < PROFILE_REBROADCAST_FLOOR_MS);
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
                            if let Ok(bytes) = crate::network::protocol::encode_wire_signed(&env) {
                                let rooms: Vec<String> =
                                    self.active_rooms.lock().unwrap().keys().cloned().collect();
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
                    let tail: String = s
                        .chars()
                        .rev()
                        .take(8)
                        .collect::<String>()
                        .chars()
                        .rev()
                        .collect();
                    let _ = self
                        .app_event_tx
                        .send(AppEvent::DcutrSucceeded { peer_label: tail });
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
                let global_verified_only = repo::get_setting(&self.db, "verified_only_inbound")
                    .ok()
                    .flatten()
                    .map(|v| v == "1")
                    .unwrap_or(false);
                if global_verified_only {
                    let is_verified = repo::is_globally_verified(&self.db, &fingerprint)
                        .unwrap_or(false)
                        || repo::is_fingerprint_trusted(&self.db, &fingerprint).unwrap_or(false);
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
    ///
    /// INVARIANT (huddle 1.1.4): never hold a `std::sync::Mutex` guard
    /// (`active_rooms`, `sas_flows`, the DB) across an `.await`. Always
    /// scope the guard in its own block or `drop()` it before awaiting —
    /// see the DM-key path below. This is also enforced mechanically:
    /// this fn runs inside a `Send` task, so a `!Send` `MutexGuard` held
    /// across `.await` would fail to compile.
    /// huddle 2.0.2 (audit M-2): can we currently decrypt an `Encrypted` body
    /// tagged with `session_id` from `sender`? Returns false when the room,
    /// its crypto, or the inbound session isn't present yet.
    fn can_decrypt(&self, room_id: &str, sender: &str, session_id: &str) -> bool {
        self.active_rooms
            .lock()
            .unwrap()
            .get(room_id)
            .and_then(|r| r.crypto.as_ref())
            .map(|c| c.has_inbound_session(sender, session_id))
            .unwrap_or(false)
    }

    /// huddle 2.0.3 (audit N-M3): whether a mailbox-delivered signed affordance
    /// (`Edit`/`Delete`/`Reaction`) can be durably applied right now — i.e. its
    /// target message is already present. The handlers drop an affordance whose
    /// target hasn't arrived yet; if we ACK such a drop, a relay that reorders
    /// the mailbox (affordance before its target) permanently suppresses the
    /// edit/deletion/retraction. Non-affordances (and envelopes that don't
    /// verify) return `true` so the normal ACK proceeds.
    fn relay_affordance_resolved(
        &self,
        room_id: &str,
        env: &crate::network::protocol::SignedRoomMessage,
    ) -> bool {
        let Ok((msg, _signer)) = crate::crypto::verify_signed(env) else {
            return true;
        };
        let target = match &msg {
            RoomMessage::Edit { target_msg_id, .. }
            | RoomMessage::Delete { target_msg_id, .. }
            | RoomMessage::Reaction { target_msg_id, .. } => target_msg_id,
            _ => return true,
        };
        matches!(
            repo::find_message_by_client_id(&self.db, room_id, target),
            Ok(Some(_))
        )
    }

    /// huddle 2.0.2 (audit M-2): process a mailbox-delivered relay message and
    /// report whether the caller may ACK it (let the relay delete its copy). An
    /// `Encrypted` body we can't decrypt yet (its Megolm session key hasn't
    /// arrived) is still dispatched — which triggers a `SessionKeyRequest` heal —
    /// but is NOT ACKed, so the relay keeps the only copy for redelivery instead
    /// of dropping it. The relay's 24h sweep remains the backstop.
    async fn process_relay_message(&self, room_id: String, payload: Vec<u8>) -> bool {
        let ack_ok = match serde_json::from_slice::<WireMessage>(&payload) {
            Ok(WireMessage::Plain(RoomMessage::Encrypted {
                ref sender_fingerprint,
                ref session_id,
                ..
            })) => self.can_decrypt(&room_id, sender_fingerprint, session_id),
            // huddle 2.0.3 (audit N-M3): don't ACK a signed Edit/Delete/Reaction
            // whose target hasn't arrived — leave it for the relay to redeliver.
            Ok(WireMessage::Signed(ref env)) => self.relay_affordance_resolved(&room_id, env),
            _ => true,
        };
        self.process_network_event(NetworkEvent::RoomMessageReceived {
            room_id,
            payload,
            from_peer: PeerId::random(),
        })
        .await;
        ack_ok
    }

    async fn handle_room_message(
        &self,
        room_id: &str,
        msg: RoomMessage,
        verified_signer: Option<String>,
        // huddle 2.0.2 (audit M-6): the signature-bound send time (Some for a
        // verified Signed envelope), used as the authenticated last-write-wins
        // clock for edits so a relay can't revert content by reordering.
        signed_at_ms: Option<i64>,
    ) {
        let our_fp = self.identity.fingerprint().to_string();
        // huddle 1.2: lazily re-activate a known DM that isn't currently in
        // active_rooms before dispatching. Otherwise the first inbound message
        // or MemberAnnounce (which carries the session key!) for a DM that was
        // parked as `restorable` (partner pubkey unknown at restore) or simply
        // closed this session is silently dropped by the per-arm
        // `active_rooms.get(room_id) -> None => return` guards — and the DM
        // appears dead. Only DM rooms that ALREADY exist on disk with a known
        // partner are auto-activated here; group rooms (which need a
        // passphrase) and unknown rooms are left untouched.
        {
            let known_inactive = !self.active_rooms.lock().unwrap().contains_key(room_id);
            if known_inactive {
                if let Ok(Some(info)) = repo::get_room(&self.db, room_id) {
                    if info.kind == RoomKind::Direct {
                        let partner = repo::list_room_members(&self.db, room_id)
                            .ok()
                            .into_iter()
                            .flatten()
                            .map(|m| m.fingerprint)
                            .find(|fp| *fp != our_fp);
                        if let Some(partner_fp) = partner {
                            if let Err(e) = self.bootstrap_direct_room(room_id, &partner_fp).await {
                                debug!(%e, %room_id, "lazy DM re-activation on inbound failed");
                            }
                        }
                    }
                }
            }
        }
        match msg {
            RoomMessage::MemberAnnounce {
                sender_fingerprint,
                wrapped_session_key,
                display_name,
                sender_ed25519_pubkey,
                sender_mlkem_pubkey,
                mlkem_ciphertext,
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
                // messages. The hijack is closed by the `signer ==
                // sender_fingerprint` check below: a peer can only write its
                // OWN room_members row. The inner `sender_ed25519_pubkey` is
                // still persisted as the TOFU pin (below) and used for DM key
                // derivation; for honest peers it equals the envelope pubkey,
                // and a peer that sets inner != envelope only poisons its own
                // pin and is then locked out by the TOFU check on its future
                // signed messages.
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
                if repo::is_member_banned(&self.db, room_id, &sender_fingerprint).unwrap_or(false) {
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
                            if let Ok(bytes) = crate::network::protocol::encode_wire_signed(&env) {
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
                            // huddle 1.3.1: persist the partner's ML-KEM key
                            // (Direct announces only) as the durable
                            // post-quantum-capability pin. COALESCE-preserved,
                            // so a later announce that omits it can't erase the
                            // pin and a relay can't replay an old classical
                            // announce to downgrade us. `None` for groups.
                            mlkem_pubkey: sender_mlkem_pubkey.clone(),
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

                // huddle 1.3 / 1.3.1: for Direct rooms, (re)derive the DM wrap
                // key now — hybrid (X25519 + ML-KEM-768) when the partner is
                // post-quantum capable (announce or persisted pin), else
                // classical X25519. The partner's pubkey(s) and — when we are
                // the responder — the KEM ciphertext arrive in *this*
                // MemberAnnounce, so we compute the key before the unwrap path
                // runs. `ensure_dm_key` is idempotent, pins PQ capability, and
                // performs the one-way classical→hybrid upgrade.
                let is_direct_room = matches!(
                    self.active_rooms
                        .lock()
                        .unwrap()
                        .get(room_id)
                        .map(|r| r.info.kind),
                    Some(RoomKind::Direct)
                );
                if is_direct_room {
                    match self.ensure_dm_key(
                        room_id,
                        &sender_fingerprint,
                        sender_ed25519_pubkey.as_deref(),
                        sender_mlkem_pubkey.as_deref(),
                        mlkem_ciphertext.as_deref(),
                    ) {
                        DmKeyOutcome::ReBroadcast => {
                            // We just established (or upgraded) the DM wrap key —
                            // re-broadcast our MemberAnnounce so the partner gets
                            // our wrapped session key (and, if we are the
                            // initiator, the KEM ciphertext). Fire-and-forget.
                            let app = self.clone();
                            let rid = room_id.to_string();
                            tokio::spawn(async move {
                                if let Err(e) = app.broadcast_member_announce(&rid).await {
                                    warn!(%e, "re-broadcast DM announce after key derivation");
                                }
                            });
                        }
                        DmKeyOutcome::RequestCiphertext => {
                            // We are the responder and lack the KEM ciphertext —
                            // ask the initiator to re-announce it (its
                            // SessionKeyRequest handler re-broadcasts a full
                            // MemberAnnounce carrying the ciphertext). huddle 1.3.1:
                            // debounce per room (shared `key_request_cooldown`, like
                            // the decrypt-miss heal) so a stalled handshake's
                            // ciphertext-less re-announces can't drive an
                            // un-throttled request↔announce ping-pong; the bounded
                            // ticker nudge still guarantees convergence.
                            let now = now_unix();
                            let due = {
                                let mut cd = self.key_request_cooldown.lock().unwrap();
                                // huddle 1.3.4: evict entries older than the
                                // cooldown so this map stays bounded as room ids
                                // churn; anything older than the window is "due"
                                // anyway, so dropping it changes no behavior.
                                cd.retain(|_room, t| now - *t < KEY_REQUEST_COOLDOWN_SECS);
                                let last = cd.get(room_id).copied().unwrap_or(0);
                                if now - last >= KEY_REQUEST_COOLDOWN_SECS {
                                    cd.insert(room_id.to_string(), now);
                                    true
                                } else {
                                    false
                                }
                            };
                            if due {
                                let app = self.clone();
                                let rid = room_id.to_string();
                                let our = our_fp.clone();
                                tokio::spawn(async move {
                                    let req = RoomMessage::SessionKeyRequest {
                                        requester_fingerprint: our,
                                    };
                                    if let Ok(bytes) = encode_wire(&req) {
                                        app.network.publish_room_message(rid, bytes).await;
                                    }
                                });
                            }
                        }
                        DmKeyOutcome::Noop => {}
                    }
                }

                if need_inbound {
                    let wrapped = wrapped_session_key.unwrap();
                    let result = {
                        let mut rooms = self.active_rooms.lock().unwrap();
                        // huddle 1.3.1: the active_rooms lock was released after
                        // `need_inbound` was computed, so the room may have been
                        // concurrently removed (e.g. a UI-thread `leave_room`)
                        // before we re-acquire here. Guard like every sibling arm
                        // instead of `.unwrap()` so a concurrent leave can't panic
                        // (and permanently halt) the inbound message pipeline.
                        let room = match rooms.get_mut(room_id) {
                            Some(r) => r,
                            None => return,
                        };
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
                // huddle 2.0.2 (audit M-4): rate-limit our re-announce so an
                // unsigned SessionKeyRequest storm can't make us (and every other
                // member) flood the room with full MemberAnnounces. At most one
                // response per room per ANNOUNCE_ON_REQUEST_COOLDOWN_SECS; a genuine
                // joiner is still served on the next tick / their own re-announce.
                {
                    let now = now_unix();
                    let mut cd = self.announce_on_request_cooldown.lock().unwrap();
                    if now - cd.get(room_id).copied().unwrap_or(0)
                        < ANNOUNCE_ON_REQUEST_COOLDOWN_SECS
                    {
                        return;
                    }
                    cd.insert(room_id.to_string(), now);
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
                client_msg_id,
                reply_to,
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
                if repo::is_member_banned(&self.db, room_id, &sender_fingerprint).unwrap_or(false) {
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
                    Ok((pt, message_index)) => {
                        // huddle 2.0.0 (F2): content-layer replay protection.
                        // The Megolm message_index uniquely names this ciphertext
                        // within (room, sender, session), so a durable seen-set
                        // lets us silently drop a wire-level replay of an
                        // already-processed content message — even across
                        // restarts or a cross-transport re-broadcast. ONLY
                        // content is deduped; control arms above/below skip this
                        // so legitimate recurring re-announces keep working.
                        match repo::check_content_replay_seen(
                            &self.db,
                            room_id,
                            &sender_fingerprint,
                            &session_id,
                            message_index,
                        ) {
                            Ok(true) => {
                                debug!(
                                    %sender_fingerprint, %room_id, %session_id, message_index,
                                    "dropping replayed Encrypted content"
                                );
                                return;
                            }
                            Ok(false) => {}
                            Err(e) => {
                                // Fail OPEN on a seen-set query error: a rare
                                // duplicate is preferable to silently dropping a
                                // genuine message because the DB hiccuped.
                                warn!(%e, "content replay check failed; processing message");
                            }
                        }
                        let body = String::from_utf8_lossy(&pt).to_string();
                        let sent_at = now_unix();
                        // Record BEFORE the insert so the seen-set is authoritative
                        // even if a later step fails; INSERT OR IGNORE on the
                        // composite PK keeps this idempotent under any race.
                        if let Err(e) = repo::record_content_seen(
                            &self.db,
                            room_id,
                            &sender_fingerprint,
                            &session_id,
                            message_index,
                            sent_at,
                        ) {
                            // A genuine DB error here (a constraint hit is INSERT OR
                            // IGNORE's silent no-op and returns Ok, not Err) means this
                            // index isn't durably marked seen, so a later resend could
                            // pass check_content_replay_seen again. We deliberately do
                            // NOT drop the message — fail-open, matching the seen-set
                            // *check* above — because the partial UNIQUE index on
                            // room_messages now makes the duplicate insert an idempotent
                            // no-op, so the worst case is a redundant AppEvent, not a
                            // duplicate row. Surface it instead of swallowing with let _.
                            warn!(
                                %e, %room_id, %sender_fingerprint, %session_id, message_index,
                                "F2: failed to record content-replay seen-set entry; \
                                 relying on room_messages dedup to stay idempotent"
                            );
                        }
                        let _ = repo::insert_room_message(
                            &self.db,
                            room_id,
                            &sender_fingerprint,
                            "in",
                            &body,
                            sent_at,
                            client_msg_id.as_deref(),
                            reply_to.as_deref(),
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
                        // huddle 1.3.1: a *missing inbound session* (as opposed to a
                        // genuine decryption error) means the sender is encrypting
                        // under a session key we never received — a late join, a key
                        // rotation, or (new in 1.3.1) a classical→hybrid upgrade that
                        // rotated the sender's outbound session and whose single
                        // re-announce was lost. Ask for keys: the `SessionKeyRequest`
                        // makes peers re-broadcast their `MemberAnnounce`, which
                        // re-delivers the current session key. Debounced per room so a
                        // burst of undecryptable messages sends at most one request,
                        // and self-terminating (decrypts succeed once the key lands).
                        if e.to_string()
                            .contains(crate::crypto::megolm::MISSING_INBOUND_SESSION_ERR)
                        {
                            let now = now_unix();
                            let due = {
                                let mut cd = self.key_request_cooldown.lock().unwrap();
                                // huddle 1.3.4: evict entries older than the
                                // cooldown so this map stays bounded as room ids
                                // churn; anything older than the window is "due"
                                // anyway, so dropping it changes no behavior.
                                cd.retain(|_room, t| now - *t < KEY_REQUEST_COOLDOWN_SECS);
                                let last = cd.get(room_id).copied().unwrap_or(0);
                                if now - last >= KEY_REQUEST_COOLDOWN_SECS {
                                    cd.insert(room_id.to_string(), now);
                                    true
                                } else {
                                    false
                                }
                            };
                            if due {
                                let app = self.clone();
                                let rid = room_id.to_string();
                                let our = our_fp.clone();
                                tokio::spawn(async move {
                                    let req = RoomMessage::SessionKeyRequest {
                                        requester_fingerprint: our,
                                    };
                                    if let Ok(bytes) = encode_wire(&req) {
                                        app.network.publish_room_message(rid, bytes).await;
                                    }
                                });
                            }
                        }
                    }
                }
            }
            RoomMessage::Plain {
                sender_fingerprint,
                body,
                client_msg_id,
                reply_to,
            } => {
                if sender_fingerprint == our_fp {
                    return;
                }
                // huddle 2.0.2 (audit H-1): an encrypted room must only ever
                // carry `Encrypted` (Megolm-authenticated) content. A `Plain`
                // message here is unauthenticated — its `sender_fingerprint` is
                // attacker-controlled — so any node that learns the (discoverable)
                // room id could otherwise inject a forged message attributed to a
                // trusted member, rendered indistinguishably from real traffic.
                // Drop unsigned plaintext in encrypted rooms.
                if repo::get_room(&self.db, room_id)
                    .ok()
                    .flatten()
                    .map(|r| r.encrypted)
                    .unwrap_or(false)
                {
                    warn!(%sender_fingerprint, %room_id, "dropping unsigned Plain in an encrypted room (anti-spoof)");
                    return;
                }
                if repo::is_member_banned(&self.db, room_id, &sender_fingerprint).unwrap_or(false) {
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
                    client_msg_id.as_deref(),
                    reply_to.as_deref(),
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
                if repo::is_member_banned(&self.db, room_id, &sender_fingerprint).unwrap_or(false) {
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
                room_id: announced_room_id,
            } => {
                // huddle 2.0.3 (audit N-M2): a signed message that names its room
                // must match the topic it arrived on, else a hostile relay
                // replayed it cross-room.
                if let Some(rid) = &announced_room_id {
                    if rid != room_id {
                        warn!(%room_id, announced = %rid, "RotateRoomKey room mismatch; dropping cross-room replay");
                        return;
                    }
                }
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
            RoomMessage::MemberLeave {
                sender_fingerprint,
                room_id: announced_room_id,
            } => {
                // huddle 2.0.3 (audit N-M2): drop a signed leave replayed onto a
                // different room's topic.
                if let Some(rid) = &announced_room_id {
                    if rid != room_id {
                        warn!(%room_id, announced = %rid, "MemberLeave room mismatch; dropping cross-room replay");
                        return;
                    }
                }
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
                if repo::is_member_banned(&self.db, room_id, &sender_fingerprint).unwrap_or(false) {
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
                if repo::is_member_banned(&self.db, room_id, &sender_fingerprint).unwrap_or(false) {
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
                // huddle 2.0.2 (audit M-10): demote the banned target out of the
                // `owner` role so they drop from `owner_fingerprints` announcements
                // and can never regain admin by un-ban races. (is_owner also now
                // excludes banned fps, so this is defense-in-depth + clean state.)
                if let Err(e) = repo::revoke_owner_role(&self.db, room_id, &target_fingerprint) {
                    warn!(%e, "BanMember: revoke_owner_role failed");
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
                let their_pub = match crate::crypto::sas::parse_pubkey(&ephemeral_x25519_pubkey_b64)
                {
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
                // huddle 1.3.1: bound sas_flows against an inbound SasInit flood
                // (the tx_id key is attacker-chosen). Drop new flows once at cap;
                // existing tx_ids still progress, and the TTL sweep reaps stale ones.
                // huddle 1.3.3: also enforce a per-partner sub-cap so one peer
                // streaming distinct tx_ids can't fill the global pool and starve
                // everyone else's SAS verification node-wide.
                {
                    let flows = self.sas_flows.lock().unwrap();
                    if !flows.contains_key(&tx_id) {
                        if flows.len() >= SAS_FLOWS_CAP {
                            warn!(%tx_id, "sas_flows at global cap; dropping inbound SasInit");
                            return;
                        }
                        let from_peer = flows
                            .values()
                            .filter(|f| f.partner_fingerprint == signer)
                            .count();
                        if from_peer >= SAS_FLOWS_PER_PEER {
                            warn!(%signer, "sas_flows per-peer cap; dropping inbound SasInit");
                            return;
                        }
                    }
                }
                let (_, our_secret, our_pub) = crate::crypto::sas::new_session();
                // huddle 2.0.0 (F1): bind the initiator's ML-KEM ek (if we hold
                // their pin) into the transcript so their PQ capability is part of
                // the OOB-compared code. A relay that strips it from one side
                // drives that side to `None`, diverging the codes — the downgrade
                // is then caught by the human comparison.
                let partner_ek = self.partner_mlkem_ek_bytes(&signer);
                let partner_pq_capable = partner_ek.is_some();
                // huddle 2.0.0 (F1 fix): bind BOTH eks (sorted-canonical) so the
                // two peers — who hold the keys in opposite roles — derive the
                // same code. Gating stays on the partner's ek inside sas_info.
                let our_ek = self.identity.mlkem_public_bytes();
                let sas_code = match crate::crypto::sas::derive_sas_code(
                    &our_secret,
                    &their_pub,
                    &tx_id_bytes,
                    Some(&our_ek),
                    partner_ek.as_deref(),
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(%e, "SasInit: rejecting non-contributory ephemeral; dropping");
                        return;
                    }
                };
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
                        created_at: now_unix(),
                        partner_pq_capable,
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
                let their_pub = match crate::crypto::sas::parse_pubkey(&ephemeral_x25519_pubkey_b64)
                {
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
                // huddle 2.0.0 (F1): bind the responder's ML-KEM ek (if pinned)
                // into the transcript, symmetric with the responder's SasInit
                // binding — both sides must hold each other's ek for the codes to
                // agree. Looked up outside the `sas_flows` lock (no DB access
                // while the flows mutex is held).
                let partner_ek = self.partner_mlkem_ek_bytes(&signer);
                let partner_pq_capable = partner_ek.is_some();
                // huddle 2.0.0 (F1 fix): our own ek, fetched outside the
                // sas_flows lock; bound symmetrically with the partner's (see
                // the SasInit handler).
                let our_ek = self.identity.mlkem_public_bytes();
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
                    let code = match crate::crypto::sas::derive_sas_code(
                        &flow.our_secret,
                        &their_pub,
                        &tx_id_bytes,
                        Some(&our_ek),
                        partner_ek.as_deref(),
                    ) {
                        Ok(c) => c,
                        Err(e) => {
                            warn!(%e, "SasResponse: rejecting non-contributory ephemeral; dropping");
                            return;
                        }
                    };
                    flow.sas_code = Some(code.clone());
                    // huddle 2.0.0 (F1): record whether this code bound the
                    // partner's ML-KEM ek, so `finish_sas` persists the durable
                    // `verified_peers.pq_capable` anchor.
                    flow.partner_pq_capable = partner_pq_capable;
                    // huddle 1.3.3: refresh the TTL clock on real progress so the
                    // reaper measures idle-since-last-activity, not age-since-start
                    // — a live handshake mid out-of-band comparison won't be reaped.
                    flow.created_at = now_unix();
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
                    room.issued_codes
                        .retain(|(c, exp)| !(c == &code && *exp > now));
                    let matched = room.issued_codes.len() < original_len;
                    if !matched {
                        info!(%joiner_fp, "CodeJoinRequest: code invalid or expired; ignoring");
                        return;
                    }
                    let crypto = room.crypto.as_ref().unwrap();
                    (true, crypto.our_session_id(), crypto.our_session_key_b64())
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
                        if let Err(e) = crypto.add_inbound_session(&owner_fp, &session_key_str) {
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
                // huddle 2.0.3 (audit N-L1): JoinRefused MUST be owner-signed
                // (protocol.rs must-be-signed list), but the receiver previously
                // surfaced the attacker-controlled `reason` from *any* sender —
                // including an unsigned `Plain` — which is an attacker-controlled
                // phishing toast. Require a verified signature (kills the
                // anonymous spoof), and enforce room-owner authority when we know
                // the room's owners; if we don't yet (a refused first-contact),
                // a valid signature at least makes the reason attributable.
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!(%room_id, "dropping unsigned JoinRefused");
                        return;
                    }
                };
                let owners = self.room_owners(room_id);
                if !owners.is_empty() && !owners.iter().any(|o| o == &signer) {
                    warn!(%signer, %room_id, "JoinRefused from non-owner; dropping");
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
                    let _ = repo::delete_pending_contact_request(&self.db, &requester_fingerprint);
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
            // huddle 2.0.0 (F10): add/remove an emoji reaction on another peer's
            // message. Must be signed by the reactor; the target must exist in
            // THIS room (so a stray UUID from another room can't seed a phantom
            // reaction). Idempotent at the repo layer.
            RoomMessage::Reaction {
                sender_fingerprint,
                target_msg_id,
                emoji,
                removed,
            } => {
                if sender_fingerprint == our_fp {
                    return;
                }
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!("dropping unsigned Reaction");
                        return;
                    }
                };
                if signer != sender_fingerprint {
                    warn!(%signer, %sender_fingerprint, "Reaction signer mismatch; dropping");
                    return;
                }
                if repo::is_member_banned(&self.db, room_id, &sender_fingerprint).unwrap_or(false) {
                    return;
                }
                match repo::find_message_by_client_id(&self.db, room_id, &target_msg_id) {
                    Ok(Some(_)) => {}
                    _ => {
                        debug!(%target_msg_id, %room_id, "Reaction target unknown in room; dropping");
                        return;
                    }
                }
                let res = if removed {
                    repo::remove_reaction(
                        &self.db,
                        room_id,
                        &target_msg_id,
                        &sender_fingerprint,
                        &emoji,
                    )
                } else {
                    repo::add_reaction(
                        &self.db,
                        room_id,
                        &target_msg_id,
                        &sender_fingerprint,
                        &emoji,
                        now_unix(),
                    )
                };
                if let Err(e) = res {
                    warn!(%e, "applying inbound reaction failed");
                    return;
                }
                let _ = self.app_event_tx.send(AppEvent::ReactionAdded {
                    room_id: room_id.to_string(),
                    message_id: target_msg_id,
                    sender_fingerprint,
                    emoji,
                    removed,
                });
            }
            // huddle 2.0.0 (F10): edit a message body, last-write-wins. Applied
            // only when the signer is the original sender OR a current room owner
            // (moderation). For encrypted rooms the new body rides as a fresh
            // Megolm ciphertext decrypted against the session the editor carries
            // in `session_id` (exactly like `Encrypted`); for plaintext rooms it
            // rides as `new_body`.
            RoomMessage::Edit {
                sender_fingerprint,
                target_msg_id,
                new_ciphertext_b64,
                session_id,
                new_body,
            } => {
                if sender_fingerprint == our_fp {
                    return;
                }
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!("dropping unsigned Edit");
                        return;
                    }
                };
                if signer != sender_fingerprint {
                    return;
                }
                if repo::is_member_banned(&self.db, room_id, &sender_fingerprint).unwrap_or(false) {
                    return;
                }
                let target =
                    match repo::find_message_by_client_id(&self.db, room_id, &target_msg_id) {
                        Ok(Some(m)) => m,
                        _ => {
                            debug!(%target_msg_id, %room_id, "Edit target unknown; dropping");
                            return;
                        }
                    };
                if target.sender_fingerprint != signer && !self.is_owner(room_id, &signer) {
                    warn!(%signer, %target_msg_id, "Edit not authorized (not sender or owner); dropping");
                    return;
                }
                // Resolve the replacement plaintext.
                let new_plaintext = match new_body {
                    Some(b) => b,
                    None => {
                        // Encrypted room: decrypt the fresh ciphertext against the
                        // session the editor carried in `session_id` — exactly like
                        // an `Encrypted` body. No in-memory "last inbound session"
                        // cache, so this still works after a Megolm rotation, across
                        // a restart, from a second device, or when the edit is the
                        // first message we see on that session.
                        let ct = match B64.decode(&new_ciphertext_b64) {
                            Ok(c) => c,
                            Err(e) => {
                                warn!(%e, "Edit: bad ciphertext base64; dropping");
                                return;
                            }
                        };
                        if session_id.is_empty() {
                            // A pre-session-id edit (e.g. an old 2.0.0-dev peer):
                            // we can't know which session it was encrypted under,
                            // so drop it gracefully rather than guess.
                            debug!(%room_id, %sender_fingerprint, "Edit: missing session_id; dropping");
                            return;
                        }
                        let dec = {
                            let mut rooms = self.active_rooms.lock().unwrap();
                            let room = match rooms.get_mut(room_id) {
                                Some(r) => r,
                                None => return,
                            };
                            let crypto = match room.crypto.as_mut() {
                                Some(c) => c,
                                None => return,
                            };
                            crypto.decrypt(&sender_fingerprint, &session_id, &ct)
                        };
                        match dec {
                            Ok((pt, _)) => String::from_utf8_lossy(&pt).to_string(),
                            Err(e) => {
                                debug!(%e, "Edit: decrypt of new body failed; dropping");
                                return;
                            }
                        }
                    }
                };
                match repo::apply_message_edit(
                    &self.db,
                    room_id,
                    &target_msg_id,
                    &new_plaintext,
                    // huddle 2.0.2 (audit M-6): LWW on the signature-bound send
                    // time, not the receiver clock — a relay can no longer revert
                    // an edit by reordering/replaying signed envelopes.
                    signed_at_ms.unwrap_or_else(now_unix_ms),
                ) {
                    Ok(true) => {
                        let _ = self.app_event_tx.send(AppEvent::MessageEdited {
                            room_id: room_id.to_string(),
                            message_id: target_msg_id,
                            editor_fingerprint: signer,
                            new_body: new_plaintext,
                        });
                    }
                    Ok(false) => {
                        debug!(%target_msg_id, "Edit ignored (stale timestamp or deleted)");
                    }
                    Err(e) => warn!(%e, "apply_message_edit failed"),
                }
            }
            // huddle 2.0.0 (F10): tombstone a message. Applied only when the
            // signer is the original sender OR a current room owner. Idempotent.
            RoomMessage::Delete {
                sender_fingerprint,
                target_msg_id,
            } => {
                if sender_fingerprint == our_fp {
                    return;
                }
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!("dropping unsigned Delete");
                        return;
                    }
                };
                if signer != sender_fingerprint {
                    return;
                }
                // huddle 2.0.2 (audit L-22): mirror the banned-member filter that
                // every other content arm has — a banned peer (incl. a demoted
                // co-owner, see M-10) must not be able to tombstone messages.
                if repo::is_member_banned(&self.db, room_id, &signer).unwrap_or(false) {
                    debug!(%signer, %room_id, "dropping Delete from banned peer");
                    return;
                }
                let target =
                    match repo::find_message_by_client_id(&self.db, room_id, &target_msg_id) {
                        Ok(Some(m)) => m,
                        _ => {
                            debug!(%target_msg_id, %room_id, "Delete target unknown; dropping");
                            return;
                        }
                    };
                if target.sender_fingerprint != signer && !self.is_owner(room_id, &signer) {
                    warn!(%signer, %target_msg_id, "Delete not authorized (not sender or owner); dropping");
                    return;
                }
                match repo::mark_message_deleted(&self.db, room_id, &target_msg_id, now_unix_ms()) {
                    Ok(true) => {
                        let _ = self.app_event_tx.send(AppEvent::MessageDeleted {
                            room_id: room_id.to_string(),
                            message_id: target_msg_id,
                            deleter_fingerprint: signer,
                        });
                    }
                    Ok(false) => {}
                    Err(e) => warn!(%e, "mark_message_deleted failed"),
                }
            }
            // huddle 2.0.0 (F9): a signed disappearing-messages TTL update.
            // Applied only when the signer is the room creator or a current owner.
            RoomMessage::RoomSetting {
                sender_fingerprint,
                disappearing_ttl_secs,
                room_id: announced_room_id,
            } => {
                // huddle 2.0.3 (audit N-M2): drop a signed RoomSetting replayed
                // onto a different room's topic by a hostile relay.
                if let Some(rid) = &announced_room_id {
                    if rid != room_id {
                        warn!(%room_id, announced = %rid, "RoomSetting room mismatch; dropping cross-room replay");
                        return;
                    }
                }
                if sender_fingerprint == our_fp {
                    return;
                }
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!("dropping unsigned RoomSetting");
                        return;
                    }
                };
                if signer != sender_fingerprint {
                    return;
                }
                // huddle 2.0.3 (audit N-M6): a banned principal — including the
                // room creator, who bypasses the `is_owner` ban-exclusion via the
                // `is_creator` shortcut below — must not be able to force a
                // (retroactive, history-purging) disappearing-TTL change.
                if repo::is_member_banned(&self.db, room_id, &signer).unwrap_or(false) {
                    warn!(%signer, %room_id, "RoomSetting from banned member; dropping");
                    return;
                }
                let is_creator = repo::get_room(&self.db, room_id)
                    .ok()
                    .flatten()
                    .map(|r| r.creator_fingerprint == signer)
                    .unwrap_or(false);
                if !is_creator && !self.is_owner(room_id, &signer) {
                    warn!(%signer, %room_id, "RoomSetting from non-owner; dropping");
                    return;
                }
                let ttl = if disappearing_ttl_secs == 0 {
                    None
                } else {
                    Some(disappearing_ttl_secs.min(u32::MAX as u64) as u32)
                };
                if let Err(e) = repo::set_room_disappearing_ttl(&self.db, room_id, ttl) {
                    warn!(%e, %room_id, "set_room_disappearing_ttl failed");
                    return;
                }
                info!(%room_id, ?ttl, "F9: applied inbound disappearing-messages TTL");
                let _ = self.app_event_tx.send(AppEvent::RoomTtlChanged {
                    room_id: room_id.to_string(),
                    ttl_secs: ttl,
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
                (
                    true,
                    Some(meta.megolm_session_id.clone()),
                    Some(meta),
                    ciphertext,
                )
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
            cache_path: Some(
                self.file_manager
                    .cache_path(&file_id)
                    .to_string_lossy()
                    .into(),
            ),
            saved_path: Some(original_path.to_string_lossy().into()),
            error: None,
            encrypted: room_encrypted,
            wrapped_key: encrypted_meta_opt
                .as_ref()
                .map(|m| m.wrapped_key_b64.clone()),
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
                self.decrypt_attachment(room_id, &attachment.sender_fingerprint, &cached, &meta)?
            } else {
                cached
            }
        };
        let saved = self
            .file_manager
            .write_to_downloads(&attachment.name, &plaintext)?;
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
        let path = attachment.saved_path.ok_or_else(|| {
            HuddleError::Other("not saved yet — press Enter to save first".into())
        })?;
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
        *self.session_persist_key.lock().unwrap()
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
        repo::set_setting(
            &self.db,
            "verified_only_inbound",
            if on { "1" } else { "0" },
        )
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

    /// Persisted attach-mode toggle (desktop GUI). When true, the GUI's
    /// "Attach" button opens a manual file-path text entry instead of the
    /// native OS file dialog (rfd) — useful when the native picker is
    /// unavailable (headless / remote display) or simply not wanted. The TUI
    /// is unaffected (it always uses its in-terminal picker + path entry).
    /// Default **OFF** (use the native dialog).
    pub fn attach_via_path(&self) -> bool {
        repo::get_setting(&self.db, "attach_via_path")
            .unwrap_or(None)
            .map(|v| v == "1")
            .unwrap_or(false)
    }

    pub fn set_attach_via_path(&self, on: bool) -> Result<()> {
        repo::set_setting(&self.db, "attach_via_path", if on { "1" } else { "0" })
    }

    /// huddle 1.1.3: the persisted theme — `"system"` (default; the GUI follows
    /// the OS light/dark setting), `"dark"`, or `"light"`. The desktop GUI reads
    /// this to pick its egui visuals. huddle 1.1.4: the TUI now honors it too
    /// (`"dark"`/`"light"`; `"system"` resolves to Dark there). Unset resolves to
    /// `"system"`; installs that already persisted `"dark"`/`"light"` keep them.
    pub fn theme(&self) -> String {
        repo::get_setting(&self.db, "theme")
            .ok()
            .flatten()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "system".to_string())
    }

    /// huddle 1.1.4: the resolved Tor SOCKS5 proxy address (e.g.
    /// `127.0.0.1:9050`). Lets privacy-sensitive clearnet fetches (the
    /// opt-in update check) tunnel through Tor rather than leak the IP.
    pub fn tor_socks(&self) -> &str {
        &self.tor_socks
    }

    pub fn set_theme(&self, theme: &str) -> Result<()> {
        repo::set_setting(&self.db, "theme", theme)
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
            return Err(HuddleError::Other("only an owner can grant owner".into()));
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
    pub async fn kick_member(&self, room_id: &str, target_fingerprint: &str) -> Result<String> {
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
    pub async fn join_room_with_code(&self, room_id: &str, code: &str) -> Result<()> {
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
                    self.persist_key(),
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
                dm_kem_ciphertext: None,
                dm_is_hybrid: false,
                dm_key_retry: 0,
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
                created_at: now_unix(),
                // huddle 2.0.0 (F1): set true once the SasResponse arrives and we
                // bind the responder's ML-KEM ek into the derived code.
                partner_pq_capable: false,
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
            // huddle 1.3.4: never confirm a SAS before the code has actually
            // been derived from the partner's ephemeral key. The initiator's
            // flow starts with `sas_code = None` and only gets a code once the
            // SasResponse arrives; an alternate codepath (e.g. a TUI keypress
            // not gated on the handshake stage) could otherwise send
            // SasConfirm{matched:true} while `sas_code` is still None — i.e. the
            // user confirmed a match they never saw, defeating the whole
            // out-of-band-comparison MITM defense.
            if flow.sas_code.is_none() {
                return Err(HuddleError::Other(
                    "SAS code not computed yet — wait for the partner's response \
                     before confirming a match"
                        .into(),
                ));
            }
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
        // huddle 2.0.0 (F1): read whether this SAS bound the partner's ML-KEM ek
        // BEFORE removing the flow, then persist it as the durable
        // `verified_peers.pq_capable` anchor. The flag is sticky-once-true in
        // `add_verified_peer`, so a later classical (group) re-verification of an
        // already-PQ-verified peer can never clear it.
        let partner_pq_capable = self
            .sas_flows
            .lock()
            .unwrap()
            .get(tx_id)
            .map(|f| f.partner_pq_capable)
            .unwrap_or(false);
        repo::add_verified_peer(
            &self.db,
            partner_fingerprint,
            now_unix(),
            partner_pq_capable,
        )?;
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
        // huddle 2.0.3 (audit N-L2): floor the new room passphrase on rotation
        // (subsumes the old non-empty check; the salt is broadcast in the clear).
        validate_passphrase_len(new_passphrase)?;
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
        self.announce_on_request_cooldown
            .lock()
            .unwrap()
            .remove(room_id);

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
            let mut rooms = self.active_rooms.lock().unwrap();
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
        self.announce_on_request_cooldown
            .lock()
            .unwrap()
            .remove(room_id);
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

        let room_ids: Vec<String> = self.active_rooms.lock().unwrap().keys().cloned().collect();
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
    let mut cache = ROOM_SALT_CACHE.lock().unwrap();
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
