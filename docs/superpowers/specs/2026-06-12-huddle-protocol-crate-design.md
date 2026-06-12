# Design: extract the `huddle-protocol` crate (WS1.1)

*Status: **proposed — awaiting review.** Part of `docs/ROADMAP-ecosystem-importance.md`,
workstream WS1 (protocol + substrate). This is the foundation step: it unblocks the PQ/MLS
wire additions (WS2) and the mobile FFI boundary (WS3), and it is the "spec as code" a second
implementation would target.*

## Goal

Extract huddle's **pure wire format and crypto constructions** into a new standalone crate,
`huddle-protocol`, depending only on RustCrypto-family crates — no `tokio`, `libp2p`,
`rusqlite`, `vodozemac`, `arti`, or any runtime. Both the client (`huddle-core`) and the relay
(`huddle-server`) depend on it, so "what it means to speak huddle" lives in exactly one place.

## Non-goals

- **No wire-format change.** Pure refactor; every byte on the wire and on disk stays identical
  (proven by golden vectors — see Testing).
- **No app/API churn.** `huddle-core` re-exports the moved items at their current paths, so the
  TUI, GUI, and `AppHandle` compile unchanged.
- **Not the `AppHandle` actor refactor** (that's WS1.3, separate). This lifts out only the leaf
  wire+crypto modules, which today have no runtime coupling.
- **Not publishing to crates.io yet.** `huddle-protocol` stays a path-only workspace member
  until the protocol doc (WS1.2) is written; publishing is a later, deliberate step.

## Why this first

1. It is **the spec, as code.** A second implementation targets this crate's types; the
   protocol doc (WS1.2) is written *from* it.
2. **The seam already exists and is being worked around.** `huddle-server` open-codes
   `compute_fingerprint` and Ed25519 challenge verification (`crates/huddle-server/src/main.rs`)
   with a comment that it does so "rather than pulled from huddle-core so the relay stays
   independent of the client's heavy libp2p / vodozemac graph." A lean `huddle-protocol` is
   exactly the missing shared dependency that removes that duplication.
3. It is **low-risk and verifiable** — the moved code is pure (input bytes → output bytes), so
   correctness is provable by re-running the existing crypto/property tests plus byte-for-byte
   wire golden vectors.

## What moves (verified inventory)

Each item below imports only bucket-(a) crates (serde + RustCrypto family) or other moved
modules — confirmed by reading the `use` statements of every module.

| Source (in `huddle-core`) | Contents | Verdict |
|---|---|---|
| `network/protocol.rs` | `WireMessage`, `SignedRoomMessage`, `RoomAnnouncement`, `RoomMessage` (23 variants), `encode_wire*` | move as-is |
| `crypto/mod.rs` | `sign_message{,_at}`, `verify_signed{,_at}`, `signed_bytes`, `SIGNED_ENVELOPE_WINDOW_MS` | move as-is |
| `crypto/pqc.rs` | ML-KEM-768: `PqKeypair`, `encapsulate_deterministic`, `combine_hybrid`, length consts | move as-is |
| `crypto/dm.rs` | classical + hybrid DM key agreement, `must_refuse_classical_fallback` | move as-is |
| `crypto/sas.rs` | SAS transcript/code derivation, `SAS_EMOJI`, ephemeral session | move as-is |
| `crypto/passphrase.rs` | Argon2id `derive_key*`, ChaCha20-Poly1305 `wrap`/`unwrap` | move as-is |
| `crypto/mnemonic.rs` | BIP-39 `seed_to_phrase` / `phrase_to_seed` | move as-is |
| `crypto/megolm.rs` → `RotationPolicy` only | pure rotation policy (not `RoomCrypto`) | move the policy; leave `RoomCrypto` |
| `invite.rs` | `InviteLink`, `InviteRoom`, `sign_invite`, `encode`/`decode`, `signable_bytes` | move as-is |
| `storage/repo.rs` → `RoomKind` | pure `Direct`/`Group` enum (used by `RoomAnnouncement`) | move; re-export from `storage::repo` |
| `files/encryption.rs` → `EncryptedFileMeta` | pure 4-string wire struct (used by `FileOffer`) | move the *type* only |
| relay `ClientMsg`/`ServerMsg` | duplicated in `network/server.rs` **and** `huddle-server/src/main.rs` | unify into one shared definition (below) |

## What stays in `huddle-core`

- **`RoomCrypto`** (Megolm group sessions + SQLCipher persistence) — the only *entangled*
  crypto: every method touches `self.db` / `repo::*`. Keeps `vodozemac` a core-only dependency.
- **`encrypt_file` / `decrypt_file`** — they take `&mut RoomCrypto`. Only their
  `EncryptedFileMeta` result type moves.
- **The libp2p half of `Identity`** — see the split below.
- All `network/`, `storage/`, `app/`, `config/`, runtime `files/` code.

## The `identity.rs` split (the one non-trivial move)

`Identity` mixes pure crypto with libp2p (`PeerId`, `Keypair`). Split into:

- **`huddle_protocol::identity::IdentityKeys`** — owns the Ed25519 `SigningKey` + precomputed
  fingerprint + derived ML-KEM keypair. Methods: `generate`, `from_secret_bytes`, `from_seed`,
  `seed`, `secret_bytes`, `public_bytes`, `sign`, `fingerprint`, `pq_keypair`,
  `mlkem_public_bytes`. Plus free fns `compute_fingerprint`, `safety_code`, `relay_auth_msg`,
  and `RELAY_AUTH_DOMAIN`. Deps: ed25519-dalek, sha2, zeroize, hex (+ the moved `pqc`).
- **`huddle_core::identity::Identity`** — a thin wrapper holding `IdentityKeys` + the libp2p
  `Keypair` / `PeerId` derived from the same seed. Delegates the pure methods (`fingerprint()`,
  `sign()`, `seed()`, …) to `IdentityKeys`, and keeps `peer_id()` / `keypair()`. The public
  type name and methods are unchanged, so existing `huddle_core::identity::Identity` callers
  don't move.

Standard "pure value type + runtime wrapper" pattern; keeps the entire app surface stable.

## Unifying the relay `ClientMsg` / `ServerMsg`

Today the two enums are duplicated with *opposite* derives (client side: `ClientMsg:
Serialize`, `ServerMsg: Deserialize`; server side: the reverse). Three small drifts exist, all
benign supersets:

- `Hello` carries `#[serde(default)]` on `pubkey_b64 / signature_b64 / rooms / acks` on the
  server (to accept pre-1.1.4 clients) — keep the defaults in the unified type.
- `ServerMsg::Ready { fingerprint }` (server emits) vs. unit `Ready` (client ignores it) —
  unify to `Ready { fingerprint: String }`; the client simply doesn't read the field.
  *Wire-identical*: the server already sends the object form and the client already tolerates
  it.
- `ServerMsg::ConnectTokenResolved { token, … }` — server echoes `token`; unify with
  `#[serde(default)]` so the client need neither send nor read it.

Unified definition in `huddle_protocol::relay`: both enums `#[derive(Serialize, Deserialize)]`;
each side uses the direction it needs. **Constraint: the unified types must serialize
byte-identically to today's output** — locked by golden vectors captured *before* the move.
The server then drops its open-coded `compute_fingerprint` / `verify_client_auth` and calls the
shared `huddle_protocol::identity` functions.

## Backward-compatibility invariants (non-negotiable)

- **Wire bytes unchanged.** Every `#[serde(default, skip_serializing_if = …)]` attribute moves
  verbatim — they are what keep new optional fields off the wire when unset (1.x↔2.x compat).
- **`verify_signed` still verifies the raw payload bytes *before* deserializing,** so the
  signature check is independent of struct shape (adding fields never breaks an old receiver).
- **On-disk SQLCipher format unchanged** — `RoomKind` / `EncryptedFileMeta` keep identical
  serde representations; only their *definition site* moves. `storage::repo` re-exports
  `RoomKind` so existing `repo::RoomKind` paths resolve.
- **Additive-only,** per the project's standing wire policy: this change renames no field and
  removes no variant.

## Re-export strategy (zero app churn)

`huddle-core` keeps its module paths as re-export shims:

- `huddle_core::network::protocol` → `pub use huddle_protocol::protocol::*;`
- `huddle_core::crypto` → `pub use huddle_protocol::crypto::*;` **plus** the local
  `megolm` / `RoomCrypto` items that stay.
- `huddle_core::invite` → `pub use huddle_protocol::invite::*;`
- `huddle_core::identity` → keeps `Identity` (the wrapper) + `pub use
  huddle_protocol::identity::{compute_fingerprint, safety_code, relay_auth_msg, …};`

Result: every existing `use huddle_core::…` in the TUI / GUI / app keeps compiling.

## Migration sequence

1. Capture **golden wire vectors** first: serialize a representative `WireMessage` /
   `SignedRoomMessage` / each relay message / `InviteLink` to bytes from the current tree; commit
   them as test fixtures.
2. Create `crates/huddle-protocol` (workspace member, path dep, bucket-(a) deps only).
3. Move the pure modules (protocol, crypto leaves, invite, mnemonic, pqc, dm, sas, passphrase,
   `RotationPolicy`, `RoomKind`, `EncryptedFileMeta`, `IdentityKeys`) + their unit/property
   tests.
4. Add the unified `relay` module; point `huddle-core::network::server` at it.
5. Rewire `huddle-core`: re-export shims; `Identity` wrapper over `IdentityKeys`; `RoomCrypto`
   / `encrypt_file` reference the moved `EncryptedFileMeta`.
6. Rewire `huddle-server`: depend on `huddle-protocol`; delete open-coded `compute_fingerprint`
   / `verify_client_auth`; use the shared relay types.
7. Green the gauntlet + golden vectors + a `cargo tree` check proving `huddle-protocol` pulls no
   libp2p / tokio / rusqlite / vodozemac.

## Testing

- **Golden vectors** — byte-for-byte equality of every wire type before/after. The core safety
  net; nothing ships if a vector changes.
- **Full gauntlet** per `CLAUDE.local.md`: `--lib`, hybrid_dm, properties (deterministic);
  roundtrip, client; app_over_server + integration (serial, `--test-threads=1`); `cargo fmt
  --all --check`; `cargo clippy --workspace --all-targets`; `cargo deny check`.
- **Leanness invariant** — assert in CI that `cargo tree -p huddle-protocol` contains none of
  {libp2p, tokio, rusqlite, vodozemac, arti, rustls}, so the boundary can't silently regress.
- **Server-graph check** — `huddle-server`'s auth path no longer needs `huddle-core`.

## Risks & mitigations

- **Hidden runtime coupling surfaces mid-move** → the three mappers found none in the leaf
  modules; if one appears, leave that item in core and record it (the boundary is a per-module
  verdict, already established).
- **Relay-message unification changes a byte** → golden vectors from step 1 catch it before it
  ships; the three drifts are documented supersets.
- **`RoomKind` move ripples through `storage`** → re-export from `storage::repo`; it's a
  four-line pure enum.
- **Churn in `huddle-core` internal `crate::` paths** → mechanical; the compiler enumerates
  every site.

## Open questions (for review)

1. **Crate name** — `huddle-protocol` (proposed) vs. `huddle-wire` vs. `huddle-types`.
   "Protocol" reads best for the spec-as-code framing.
2. **Publish now or later?** Recommend path-only until the protocol doc (WS1.2) lands, then
   publish `huddle-protocol` 0.1 to crates.io as the first externally-consumable artifact.
3. **Trait seam for `RoomCrypto` now or in WS2?** Recommend defer — keep this change a pure
   move so MLS slots in cleanly during WS2 rather than muddying the extraction.
