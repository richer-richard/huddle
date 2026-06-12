# Design: MLS group messaging rollout (WS2-b)

*Status: **wire defined + sequenced.** The MLS message wire is now in
`huddle-protocol` (additive, shipped); this spec is the plan for the engine
integration, app adoption, and PQ ciphersuites — the genuinely multi-release part
that the foundations program (durable journal, per-room ordered delivery)
deliberately unblocked.*

## Why MLS, and why now it's tractable

MLS (RFC 9420) gives a group the three properties Megolm doesn't: **forward
secrecy + post-compromise security** (TreeKEM re-keys every epoch) and
**cryptographically-enforced removal** (a kick is an epoch change the removed
member can't follow, not an honest-client convention). It is also the IETF
standard, and it is where **post-quantum group messaging** is being standardized
(`draft-ietf-mls-pq-ciphersuites`) — so adopting MLS is how huddle reaches "fully
post-quantum messaging, groups included."

MLS needs one thing Megolm doesn't: **a total order on group commits** (every
member must apply add/remove/update commits in the same sequence). huddle 2.0.8
shipped exactly that — the relay's per-room `seq`. The durable event journal
(2.0.7) gives the replayable history MLS state + multi-device want. So the
foundations are in place.

## What shipped here (the wire)

Four additive `RoomMessage` variants in `huddle-protocol` (PROTOCOL.md §11),
carrying opaque TLS-serialized MLS objects so the protocol crate stays
runtime-free:

- `MlsKeyPackage` — a member publishes its `KeyPackage` so others can add it.
- `MlsWelcome` *(signed, directed)* — hands a new member the group secrets.
- `MlsCommit` *(signed)* — advances the epoch; applied in per-room `seq` order.
- `MlsApplication` — an MLS-encrypted chat message under the current epoch key.

All additive: a pre-2.1 peer drops the unknown variant gracefully, so MLS and
classical Megolm rooms coexist.

## The rollout (sequenced)

### Phase 1 — the engine, behind a `mls` cargo feature
Add `openmls` (0.7) + `openmls_rust_crypto` (provider) + `openmls_basic_credential`
to `huddle-core` under a **default-off `mls` feature** (the same opt-in posture as
`arti`, so the default build stays lean). A `crypto/mls.rs` module wraps it:
derive the MLS `SignatureKeyPair` + `KeyPackage` from the identity, create a
group, add/remove members (→ `Commit` + `Welcome`), process a commit, and
encrypt/decrypt application messages. MLS group state persists in SQLCipher via an
`openmls_traits::StorageProvider` backed by the existing DB. Unit-tested
(two-member add + message round-trip; remove + epoch change).

### Phase 2 — app adoption behind a room capability
A room opts into MLS at creation (a capability flag carried in the room
announcement / invite — **not** a new `RoomKind` variant, which would break old
peers' string deserialization). For MLS rooms, `AppHandle` routes through the MLS
engine instead of `RoomCrypto`/Megolm: publish `MlsKeyPackage` on join, the
adder sends `MlsWelcome` + `MlsCommit`, members apply commits **in `seq` order**
(buffer out-of-order commits until the gap fills), and chat rides
`MlsApplication`. Megolm rooms are untouched.

### Phase 3 — post-quantum ciphersuite
Move MLS rooms to a hybrid PQ ciphersuite as `draft-ietf-mls-pq-ciphersuites`
stabilizes in openmls (X-Wing / ML-KEM KEM + the existing Ed25519+ML-DSA auth from
WS2-a). This is the headline: **PQ-secure groups**, the gap Megolm leaves.

## Cost ledger (honest)

- **Spends dumb-relay simplicity** only as already paid — the relay orders by
  `seq` but still routes opaque blobs and never decrypts.
- **Spends wire compactness + audit surface** — MLS commits/welcomes are larger
  than Megolm key shares, and openmls is a substantial dependency (hence the
  default-off feature).
- **Keeps the simple default** — classical Megolm rooms remain the default and are
  byte-unaffected; MLS is opt-in per room, exactly the layered posture huddle uses
  for transports, Arti, and PQ-DM.

## Status

Wire: **done** (2.1.0, additive, tested). Engine + adoption + PQ ciphersuite:
sequenced as Phases 1–3 above, each its own gauntlet-green PR — the foundations
they need (ordered delivery, durable journal) are shipped.
