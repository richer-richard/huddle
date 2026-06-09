# huddle — Roadmap beyond 2.0.0

*Companion to the forward-looking engineering brief. 2.0.0 shipped the
"cheap-but-real" layer — the foundation-independent features that close named
gaps without reshaping the architecture. This document is the **sequenced plan
for the heavy, multi-release work** that 2.0.0 deliberately did not attempt,
with the dependency structure that decides the order.*

---

## What 2.0.0 shipped (for context)

Security/crypto: PQ-capability binding into SAS + invites + the verified-peers
store (F1), content-layer replay protection (F2), scheduled Megolm epoch
rotation (F4), master-passphrase change + at-rest SQLCipher rekey (F5),
safety-number-change alarm (F3). Recovery: BIP39 mnemonic seed export/import
(F6). Reliability: at-least-once relay ACKs (F7). Product: FTS5 local search
(F8), disappearing messages (F9), reactions/replies/edits/deletes (F10).
Engineering: workspace version inheritance, proptest + cargo-fuzz scaffolding,
relay Prometheus `/metrics`, cargo-deny gate (F11–F14).

None of those reshaped huddle's two prized properties — **statelessness**
(re-derive everything from one seed; no per-conversation state) and
**dumb-relay simplicity** (the server is a base64 mover). Everything below
spends one or both, deliberately, and is therefore sequenced rather than rushed.

---

## The hidden shared foundation

Four of the most-wanted capabilities are secretly the *same* investment:

- **MLS groups** need an ordered, per-group delivery service (commits must be
  totally ordered).
- **At-least-once → exactly-once-ish** and durable history need durable, acked
  mailbox rows (2.0.0's F7 is the first step).
- **Multi-device** needs a replayable event journal.
- **Relay horizontal scaling** needs pluggable durable storage.

All four are faces of one move: **from "lossy broadcast + best-effort mailbox +
one SQLite mutex" to "append-only logs with per-consumer cursors, behind a
storage trait."** Build this first and the ambitious features land on prepared
ground instead of forcing a second rewrite.

The other unlock is the **core refactor**: decompose `app/mod.rs` (the ~6.8k-line
shared-mutable `AppHandle`) into an **actor model** (one owning task per room /
relay-connection / swarm, message-passing, no shared lock) behind a **typed
`Command` enum**. This dissolves the hand-rolled race guards (`ensure_dm_key`),
makes commands rate-limitable and loggable, and is the seam that makes mobile
FFI clean.

---

## Sequenced plan

### Phase F1 — Foundations (do first)
1. **Typed command layer + actor decomposition of `huddle-core`.** Extract one
   subsystem at a time (files → SAS → DM keying → rooms) behind the stable
   `AppHandle` surface so the TUI/GUI don't change. *Spends: nothing yet —
   pure internal shape. Unlocks: everything below.*
2. **Durable, append-only event journal with per-consumer cursors** to replace
   the lossy `broadcast::channel`. Removes the "resync-as-correctness" hack,
   guarantees security prompts are never dropped, and is the multi-device
   backbone. *Spends: storage + discipline.*
3. **Ordered/durable relay delivery service** — per-room append/sequence point +
   pluggable storage trait (SQLite default, optional Postgres/FoundationDB).
   Simultaneously delivers MLS's ordering need and the scaling seam.
   *Spends: dumb-relay simplicity (the relay grows a per-room log).*

### Phase F2 — Reach
4. **Mobile (iOS/Android) via `uniffi`** over the now-FFI-friendly core, with
   **sealed/low-metadata push** (opaque APNs/FCM wakeup; client fetches the
   real ciphertext on wake). Biggest user-base multiplier. *Depends on the
   typed command layer.*
5. **Headless daemon (`huddled`) + scriptable API** (local socket / gRPC) for
   bots, automations, a long-lived per-user onion mailbox, and an *optional*
   loudly-disclaimed Matrix bridge.
6. **WASM web client** (clearly labeled as a weaker-metadata convenience tier —
   the browser can't use Tor).

### Phase F3 — Heavy crypto (lands on the ordered-log + actor foundation)
7. **DM Double Ratchet (PQ3-style):** seed a Double Ratchet from the existing
   hybrid X25519+ML-KEM-768 root key → forward secrecy + post-compromise
   security, with periodic PQ re-seed. Keep Megolm decrypting *historical* DM
   rooms; cut *new* DM epochs to the ratchet (no bulk ciphertext migration).
   *Spends: DM statelessness (durable per-DM ratchet + skipped-key cache for the
   store-and-forward mailbox).*
8. **MLS groups (RFC 9420) via OpenMLS / mls-rs**, run for *new* rooms behind a
   capability flag; Megolm rooms live out their lives. TreeKEM gives FS + PCS and
   **cryptographically-enforced removal** (a kick becomes an epoch change, not an
   honest-client convention). Carries PQ via `draft-ietf-mls-pq-ciphersuites`.
   *Depends on the ordered delivery service (F1.3). Largest single item.*
9. **Hybrid PQ authentication: composite Ed25519 + ML-DSA-65** on the
   authority/identity envelopes (announces, invites) — *not* per-chat-line
   (≈3.3 KB sigs). Keep Ed25519 as the second lock (the RustCrypto PQ crates are
   unaudited; a real ML-DSA verify bug shipped and was caught Jan 2026). Derive
   the ML-DSA key from the same seed (no new on-disk material).
10. **Metadata-blinding suite:** sealed sender (encrypt sender identity inside
    the payload), per-epoch blinded rotating room/recipient tags
    (`HKDF(shared_room_secret, epoch)`), size-bucket padding + optional
    cover-traffic, and an opt-in **per-user Tor-onion mailbox** (Cwtch/Ricochet
    model). *Spends: dumb-relay simplicity hardest — the relay becomes a
    sealed-envelope router; composes with MLS welcome messages and sealed sender.*

### Phase F4 — Real-time
11. **E2EE voice/video calls:** signaling over the existing signed envelopes /
    `SendDirect`, media keys from the hybrid DM / MLS group keys, media over
    WebRTC/SRTP. Honest disclosure: calls need the LAN/direct or a clearnet TURN
    path (Tor latency is hostile to real-time), so the metadata posture is weaker
    — label it. Cheap first step that delivers most everyday value:
    **asynchronous voice messages** through the (overhauled) file pipeline.

### Cross-cutting, schedulable any time
- **Key transparency** (IETF keytrans) as an *optional* anchor — verifiability,
  not discovery; tree head gossiped via invites/SAS.
- **File-transfer overhaul:** content-addressed BLAKE3 block tree, disk-backed,
  resumable, dedup; optional relay blob store (ciphertext, own TTL) for large
  offline transfers. (2.0.0 hardened the existing transfer; this replaces it.)
- **Recovery depth:** encrypted DB backup/export (prereq for multi-device),
  Shamir social recovery, hardware-backed seed storage (Secure Enclave / TPM /
  YubiKey).
- **Relay anti-abuse:** proof-of-work (hashcash) on contact requests / connect
  codes + per-connection token buckets (cheap self-minted identities make
  per-account limits weak).
- **Relay federation / redundancy:** invites carry multiple relay URLs; mailboxes
  replicate or are tried in order (availability + censorship resistance).
- **Multi-device:** per-device subkey cross-signed by the identity key; device
  linking via the existing SAS/QR flow; history sync via the event journal (F1.2)
  + encrypted backup. *Spends: single-device statelessness hardest.*
- **Test/CI:** `MemoryTransport` for the logic-level libp2p tests + `cargo-nextest`
  to retire the `--test-threads=1` requirement; sign release binaries (sigstore)
  + publish an SBOM.

---

## The cost ledger (keep honest)

| Capability | Spends |
|---|---|
| Double Ratchet, multi-device | **statelessness** → durable, syncable ratchet/device state |
| MLS, metadata blinding | **dumb-relay simplicity** → ordered, sealed-envelope router |
| PQ authentication, richer features | **wire compactness + audit surface** |

None of these are reasons not to proceed — they're reasons to proceed
*deliberately*, keeping the simple defaults (single-binary SQLite relay,
classical fast path, single device) available alongside the powerful options,
exactly the layered, opt-in posture huddle already uses for transports and Arti.
