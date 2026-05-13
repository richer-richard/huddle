# Huddle Roadmap: Phases 2-5

This document describes the evolution of Huddle from a same-LAN chat
tool into a cross-network, production-grade decentralized messenger.

Phase 1 (current) establishes the foundation: mDNS discovery, E2EE via
vodozemac Olm sessions, SQLite persistence, and a ratatui TUI. All
subsequent phases build on `huddle-core`'s `AppHandle` abstraction.

---

## Phase 2 - Going Beyond Local LAN

### The Bootstrap Problem

"Decentralized chat across the internet without servers" is
theoretically possible but practically requires SOME bootstrap
infrastructure. The options:

**a) Hardcoded IPFS/libp2p public bootstrap nodes (recommended first)**
- Use Protocol Labs' public bootstrap nodes for Kademlia DHT peer
  discovery. Free, well-maintained, globally distributed.
- Trade-off: depends on Protocol Labs' infrastructure. If their
  bootstrap nodes go down, new peer discovery fails (existing
  connections continue).
- Implementation: add bootstrap node addresses to `config.rs`, dial
  them on startup.

**b) User-deployed bootstrap node on a VPS (~$5/mo)**
- Run a minimal `huddle-relay` binary on a VPS that participates in
  the DHT and acts as a relay for NAT traversal.
- Trade-off: costs money, requires ops, but gives full control.
- Good as a secondary option or for private deployments.

**c) Tor hidden services per identity**
- Each Huddle identity runs a Tor hidden service. Discovery via
  out-of-band sharing of .onion addresses.
- Trade-off: no bootstrap deploy needed, strong privacy, but depends
  on Tor directory authorities and has high latency (~2-5s per message).

**d) Reference implementations**
- **Briar:** Tor-based. Each device runs a hidden service. Discovery
  is QR code + contact exchange only. No DHT.
- **Berty:** libp2p + IPFS. Uses public IPFS bootstrap + custom
  rendezvous nodes. Closest to our architecture.
- **I2P:** Reseed servers bootstrap the network. Fully encrypted
  overlay. High complexity.

### Implementation Plan

**Kademlia DHT in `huddle-core`:**
- Modify: `crates/huddle-core/src/network/behavior.rs`
  - Add `kademlia: libp2p::kad::Behaviour` to `HuddleBehavior`
  - Add `HuddleBehaviorEvent::Kademlia(kad::Event)` variant
- Modify: `crates/huddle-core/src/network/mod.rs`
  - Handle Kademlia events (routing table updates, query results)
  - Bootstrap on startup: dial bootstrap nodes, run `kad.bootstrap()`
  - Register our PeerId in the DHT for discoverability
- Modify: `crates/huddle-core/src/config.rs`
  - Add `bootstrap_nodes: Vec<Multiaddr>` to config
  - Default to IPFS public bootstrap list
- New: `crates/huddle-core/src/network/discovery.rs`
  - Unified discovery abstraction: mDNS (LAN) + Kademlia (WAN)
  - Emit the same `PeerDiscovered` events regardless of source

**NAT Traversal:**
- Add libp2p `dcutr` (Direct Connection Upgrade through Relay) behavior
- Requires at least one relay peer reachable from both clients
- Add `relay: libp2p::relay::Behaviour` to `HuddleBehavior`
- AutoNAT for detecting NAT status

**Tauri Desktop Shell:**
- Modify: `crates/huddle-tauri/src/main.rs`
  - Tauri command handlers wrapping `AppHandle` methods
  - `#[tauri::command] async fn send_message(...)` etc.
- New: `crates/huddle-tauri/ui/` (React + TypeScript)
  - Same three-pane layout as TUI but desktop-grade
  - Real-time updates via Tauri events (AppEvent -> frontend)
- The Tauri shell is largely glue: `AppHandle` does all the work.

**Command surface for Tauri:**
```
tauri::command send_message(peer_id: String, body: String)
tauri::command initiate_session(peer_id: String)
tauri::command get_messages(peer_id: String, limit: i64) -> Vec<Message>
tauri::command list_peers() -> Vec<Peer>
tauri::command get_identity() -> Identity { fingerprint, peer_id }
tauri::event app_event -> AppEvent (streamed to frontend)
```

### Cross-Network Testing

Without a VPS, you can test Kademlia locally by running 3+ nodes
on different ports with `--listen /ip4/127.0.0.1/tcp/<port>`.
True cross-network testing requires at least one node with a public IP
or a relay node on a VPS.

---

## Phase 3 - Robustness

**Connection Retry with Exponential Backoff:**
- Modify: `crates/huddle-core/src/network/mod.rs`
  - On `ConnectionClosed`, schedule retry with backoff (1s, 2s, 4s, ...)
  - Cap at 60s. Reset backoff on successful connection.

**Message Resend on Reconnect:**
- New: `crates/huddle-core/src/storage/outbox.rs`
  - `outbox` table: messages sent but not yet ACK'd
  - On reconnect, resend all unACK'd messages for that peer
- Modify: `crates/huddle-core/src/storage/schema.rs`
  - Add outbox migration

**Protocol Versioning:**
- Modify: `crates/huddle-core/src/network/protocol.rs`
  - Add `version: u8` field to `HuddleRequest` envelope
  - Protocol negotiation via libp2p identify (check agent_version)
  - Graceful handling of version mismatches

**Wire Format Optimization:**
- Replace `serde_json` with `bincode` or `prost` (protobuf) in
  `HuddleCodec`
- Keep JSON as a debug fallback behind a feature flag
- Significant bandwidth reduction for encrypted message payloads

**Pre-key Replenishment:**
- Modify: `crates/huddle-core/src/session/mod.rs`
  - Track one-time key count. When below threshold (e.g., 5 remaining),
    generate a new batch and persist.
  - vodozemac one-time keys are finite; without replenishment, new
    sessions fail after keys are exhausted.

---

## Phase 4 - Offline & At-Rest Security

**Store-and-Forward via Volunteer Relays:**
- New: `crates/huddle-core/src/relay/mod.rs`
  - Peers can opt in to store encrypted messages for offline peers
  - DHT slot keyed by SHA-256(recipient_fingerprint), 7-day TTL
  - When peer comes online, queries their own DHT slot
  - Messages are already E2EE, so relays see only ciphertext
- Modify: `crates/huddle-core/src/network/mod.rs`
  - On send failure (peer offline), store in relay DHT
  - On startup, check own DHT slot for pending messages

**SQLCipher with User Passphrase:**
- Replace `rusqlite` with `rusqlite` + SQLCipher feature
- Modify: `crates/huddle-core/src/storage/mod.rs`
  - Passphrase prompt on launch (passed in from frontend)
  - Derive encryption key via Argon2id (from passphrase + salt)
  - `PRAGMA key = 'derived-key';` on database open
- Migration path: one-time export from unencrypted DB, reimport into
  encrypted DB. Or keep both and prompt user to migrate.

**Vodozemac Serialization Key Rotation:**
- Modify: `crates/huddle-core/src/session/store.rs`
  - Replace hardcoded `SERIALIZATION_KEY` with key derived from
    user passphrase (same Argon2id derivation as SQLCipher key,
    different salt)
  - On first encrypted launch, re-serialize all existing sessions
    with the new key

---

## Phase 5 - Groups & UX

**Group Chat via MLS (RFC 9420):**
- Dependency: `openmls` crate
- New: `crates/huddle-core/src/group/mod.rs`
  - Group state management (members, epoch, tree)
  - Welcome message handling for new members
  - Commit/Proposal flow for membership changes
- New: `crates/huddle-core/src/group/store.rs`
  - `groups` table: group_id, name, mls_state, created_at
  - `group_members` table: group_id, peer_id, role
  - `group_messages` table: same schema as messages but with group_id
- Modify: `crates/huddle-core/src/network/protocol.rs`
  - New message types: `GroupMessage`, `GroupWelcome`, `GroupCommit`

**Alternative considered: Sender Keys**
- Simpler than MLS. WhatsApp used this pre-MLS.
- Each sender has one ratchet; all group members decrypt with it.
- O(N) key distribution per sender (vs O(log N) for MLS tree).
- O(N^2) total bandwidth for N senders.
- Easier to implement but doesn't scale past ~50 members.
- MLS (via openmls) is the better long-term choice.

**QR Code Identity Exchange:**
- New: `crates/huddle-core/src/identity/qr.rs`
  - Encode fingerprint + connection info as QR payload
  - Decode scanned QR to add peer manually
- Integrate with camera access (Tauri: via plugin, TUI: skip)

**Contact Verification UX:**
- New: `crates/huddle-tui/src/ui/verify.rs`
  - Side-by-side fingerprint display
  - Numeric safety-number comparison (Signal-style)
  - "Verified" badge after comparison
- Modify: `crates/huddle-core/src/storage/repo.rs`
  - Add `verified: bool` to peers table

**Media Attachments:**
- Modify: `crates/huddle-core/src/network/protocol.rs`
  - New message type: `FileChunk { file_id, chunk_index, total, data }`
  - Chunked transfer over the existing protocol
- New: `crates/huddle-core/src/media/mod.rs`
  - File chunking, reassembly, progress tracking
  - Store metadata in `files` table

**Typing Indicators:**
- Best-effort ephemeral messages (not persisted)
- New protocol message: `TypingStatus { is_typing: bool }`
- Send on keystroke, cancel after 5s of inactivity

**Delivery and Read Receipts:**
- Extend `HuddleResponse::Ack` with receipt types
- New: `DeliveryReceipt`, `ReadReceipt` message types
- Update `messages` table with `read_at` column

---

## How to Resume

### Phase 2
- **Start with:** `crates/huddle-core/src/network/behavior.rs` (add
  Kademlia behavior) and `crates/huddle-core/src/config.rs` (add
  bootstrap config)
- **Tests to add:** multi-node DHT bootstrap test, NAT traversal test
  with relay
- **Verify:** `cargo test --workspace`, then test with 3 nodes on
  different ports
- **Cross-network testing:** requires at least one publicly reachable
  node or a VPS with `huddle-relay`

### Phase 3
- **Start with:** `crates/huddle-core/src/network/mod.rs` (add retry
  logic) and `crates/huddle-core/src/storage/outbox.rs` (new)
- **Tests to add:** retry on disconnect, outbox resend, protocol
  version negotiation
- **Verify:** kill and restart a node mid-conversation; messages
  should resume

### Phase 4
- **Start with:** `crates/huddle-core/src/storage/mod.rs` (SQLCipher
  migration) and `crates/huddle-core/src/session/store.rs` (key
  rotation)
- **Tests to add:** encrypted DB round-trip, passphrase change,
  store-and-forward relay test
- **Verify:** database file is encrypted on disk (`file huddle.db`
  should not show "SQLite"), serialized sessions survive key rotation

### Phase 5
- **Start with:** `crates/huddle-core/src/group/mod.rs` (new module)
  and the `openmls` crate integration
- **Tests to add:** group creation, member add/remove, group message
  delivery, MLS epoch advancement
- **Verify:** 3+ node group chat works, member removal prevents
  further decryption
- **Setup:** at least 3 nodes for meaningful group testing
