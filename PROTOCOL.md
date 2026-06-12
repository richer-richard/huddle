# The Huddle Protocol

*Version 1 (huddle 2.0.4). This document specifies the wire format and
cryptographic constructions of huddle precisely enough to build a second,
interoperable implementation. The normative source is the
[`huddle-protocol`](crates/huddle-protocol) crate — a runtime-free Rust crate
holding exactly the types and functions described here; where prose and code
disagree, the code wins, and that is a spec bug to be fixed.*

This is a companion to [`SECURITY.md`](SECURITY.md) (the threat model and
posture) and [`docs/ROADMAP-ecosystem-importance.md`](docs/ROADMAP-ecosystem-importance.md)
(why this spec exists). Keywords **MUST**, **MUST NOT**, **SHOULD**, **MAY**
are used in the RFC 2119 sense.

---

## 1. Overview

Huddle is an end-to-end-encrypted group and direct messaging protocol with three
layered concerns:

1. **Identity** — a self-certifying Ed25519 keypair; no accounts, no phone
   numbers, no central directory. Everything (the libp2p PeerId, the post-quantum
   ML-KEM keypair, every DM key) deterministically re-derives from one 32-byte
   seed.
2. **The E2EE message layer** — opaque ciphertext carried in a signed envelope.
   Group rooms use a Megolm group ratchet; direct messages derive a key by a
   hybrid post-quantum agreement. Authenticity is an application-layer Ed25519
   signature, independent of transport.
3. **Transport** — interchangeable "doors" (Tor onion, raw clearnet WebSocket,
   TLS WebSocket) onto a **zero-knowledge relay** that routes opaque blobs by an
   opaque room id and a peer-to-peer libp2p mesh. A relay never holds keys and
   never decrypts; doors are interoperable, so peers on different transports
   share the same rooms.

The relay and the mesh are interchangeable delivery substrates: the *same* signed,
encrypted bytes are published on both. A conforming implementation MAY support any
subset of transports; the message and crypto layers are transport-independent.

### 1.1 Primitives

| Purpose | Primitive |
|---|---|
| Identity / authenticity | Ed25519 (`ed25519-dalek`, `verify_strict`) |
| Classical DM key agreement | X25519 ECDH (`x25519-dalek`) |
| Post-quantum DM key agreement | ML-KEM-768 / FIPS 203 (`ml-kem`), hybrid with X25519 |
| Group message encryption | Megolm (`vodozemac`) |
| Symmetric AEAD (files, key-wrap) | ChaCha20-Poly1305 |
| Key derivation | HKDF-SHA-256 |
| Passphrase stretching | Argon2id (m = 65536 KiB, t = 3, p = 4) |
| Hashing | SHA-256 (identity, transcripts), SHA-512 (X25519 clamp) |
| Seed backup | BIP-39 (24 words) |

All multi-byte integers in signed transcripts are **big-endian**. All binary
fields on the JSON wire are **standard base64** (`STANDARD`) unless noted as
base64url.

---

## 2. Identity & fingerprints

An identity is an Ed25519 keypair. The 32-byte secret seed is the sole root
secret.

- **Fingerprint** — `SHA-256(ed25519_pubkey)[0..12]`, hex-encoded (24 hex chars),
  grouped into six dash-separated quads: `xxxx-xxxx-xxxx-xxxx-xxxx-xxxx` (96 bits).
  Displayed with an `HD-` brand prefix in UIs. Function: `compute_fingerprint`.
- **Safety code** — `SHA-256(ed25519_pubkey)[0..6]`, hex uppercased,
  `SAFE-XXXX-XXXX-XXXX`. Display-only shorthand. Function: `safety_code`.
- **ML-KEM-768 keypair** — derived deterministically from the Ed25519 seed:
  `HKDF-SHA256(salt = "huddle-mlkem-768-seed-v1", IKM = ed25519_seed)` expanded to
  the 64-byte ML-KEM seed, then `MlKem768::from_seed`. The 1184-byte encapsulation
  (public) key is `MLKEM_EK_LEN`; the ciphertext is `MLKEM_CT_LEN` = 1088; shared
  secrets are `SS_LEN` = 32. No ML-KEM key material is ever stored — it is
  recomputed on demand.
- **BIP-39** — the 32-byte seed encodes to a 24-word English mnemonic and back;
  this is the entire backup/restore of an identity.

A receiver MUST, before trusting any signed message, re-derive the fingerprint
from the envelope's pubkey and reject the message if it does not equal the
asserted fingerprint (§3.2). This binds the claimed identity string to the key.

---

## 3. The wire envelope

Every byte exchanged on a room topic (over relay or mesh) is a JSON `WireMessage`:

```
WireMessage = { "type": "plain",  "data": <RoomMessage> }   // unsigned
            | { "type": "signed", "data": <SignedRoomMessage> }
```

(`#[serde(tag="type", content="data", rename_all="snake_case")]`.)

`RoomMessage` is an **externally-tagged** enum — `{ "<Variant>": { …fields } }`
with PascalCase variant names (§4). New optional fields use
`#[serde(default, skip_serializing_if = "Option::is_none")]` so they are absent on
the wire when unset; this is the **sole** backward-compatibility mechanism
(§9) and MUST be preserved exactly.

### 3.1 SignedRoomMessage

```
SignedRoomMessage = {
  "fingerprint":        String,   // asserted sender fingerprint
  "ed25519_pubkey_b64": String,   // base64 of the 32-byte signer pubkey
  "payload_b64":        String,   // base64 of the RoomMessage JSON
  "signature_b64":      String,   // base64 of the 64-byte Ed25519 signature
  "signed_at_ms":       i64       // epoch-ms at signing (serde default 0)
}
```

The signature is computed over the **canonical signed bytes**:

```
signed_bytes(payload, signed_at_ms) =
    payload || "|huddle-signed-v1|" || be64(signed_at_ms)
```

where `payload` is the raw `RoomMessage` JSON (the bytes that `payload_b64`
decodes to) and `be64` is the 8-byte big-endian encoding. Putting the timestamp
inside the signed bytes makes the freshness check (below) signature-bound: a
replayer cannot rewrite the timestamp without invalidating the signature.

### 3.2 Verification (`verify_signed`)

A receiver MUST perform, in order:

1. `signed_at_ms != 0` (zero is the legacy/forgery sentinel) — else reject.
2. Decode the pubkey; it MUST be 32 bytes. Compute `derived_fp =
   compute_fingerprint(pubkey)`; it MUST equal `fingerprint` — else reject.
3. Decode `payload` and the 64-byte signature. Verify with Ed25519
   **`verify_strict`** (rejects low-order / mixed-order keys) over
   `signed_bytes(payload, signed_at_ms)` — else reject.
4. Deserialize `payload` as a `RoomMessage`.
5. **Freshness window** (applied *after* step 3 so the message type is known):
   if the type is window-bound, `|now_ms − signed_at_ms|` MUST be ≤
   `SIGNED_ENVELOPE_WINDOW_MS` = 300000 (±5 min) — else reject.

   **Exempt** from the window (they ride the offline mailbox and may arrive days
   later; their replay protection is idempotency + the signature):
   `ContactRequest`, `MemberAnnounce`, `SessionKeyRequest`.

On success the verified `(RoomMessage, fingerprint)` is returned. Callers MUST
additionally check the fingerprint is authorized for the action (e.g. a current
owner for `BanMember` — §4.3).

Messages whose authenticity matters MUST be sent as `signed`. In an **encrypted**
room a conforming client MUST reject `plain` messages outright (a node that learns
a room id could otherwise inject a forged attributed message).

---

## 4. RoomMessage catalog

Fields shown are the wire-significant ones; `#[serde(default)]` /
`skip_serializing_if` attributes are part of the contract (§9). "Signed" = MUST be
carried in a `SignedRoomMessage`.

### 4.1 Membership & keying

- **`MemberAnnounce`** *(signed; window-exempt)* — `sender_fingerprint`,
  `wrapped_session_key?` (passphrase-wrapped Megolm session key for encrypted
  rooms; §5.1), `display_name?`, `sender_ed25519_pubkey?` (so members learn the
  signer's key), `sender_mlkem_pubkey?` + `mlkem_ciphertext?` (Direct rooms only;
  §5.2). Presence of `sender_mlkem_pubkey` signals post-quantum capability.
- **`SessionKeyRequest`** *(signed; window-exempt)* — `requester_fingerprint`.
  Asks existing members to re-share the room key (rate-limited by senders).
- **`MemberLeave`** *(signed)* — `sender_fingerprint`, `room_id?`. Signer MUST
  equal the leaving fingerprint. `room_id` (when present) MUST match the topic
  (anti cross-room replay).
- **`RotateRoomKey`** *(signed)* — `rotator_fingerprint`, `new_salt`, `room_id?`.
  Announces a new passphrase salt after a kick/rotation.

### 4.2 Content

- **`Plain`** — `sender_fingerprint`, `body`, `client_msg_id?`, `reply_to?`
  (cleartext payload; only valid in non-encrypted rooms).
- **`Encrypted`** — `sender_fingerprint`, `session_id`, `ciphertext_b64`,
  `client_msg_id?`, `reply_to?` (Megolm ciphertext; §5.1).
- **`Reaction` / `Edit` / `Delete`** *(signed)* — keyed to a sender-minted stable
  `client_msg_id` (a random ULID inside the encrypted body). `Edit`/`Delete` apply
  only when the signer equals the original author; last-write-wins by the
  signature-bound timestamp. Best-effort among honest clients.
- **`FileOffer` / `FileChunk`** — content-addressed file transfer (§5.4).
- **`Typing`** — `sender_fingerprint` (ephemeral, unsigned, cosmetic).
- **`ProfileUpdate`** *(signed)* — `sender_fingerprint`, `username`, `updated_at`
  (last-write-wins display name).
- **`RoomSetting`** *(signed)* — `sender_fingerprint`, `disappearing_ttl_secs`,
  `room_id?`. Signer MUST be creator/owner and not banned.

### 4.3 Authority & verification (all signed)

- **`OwnerGrant`** — `room_id`, `target_fingerprint`. Signer MUST be a current
  owner.
- **`BanMember`** — `room_id`, `target_fingerprint`. Signer MUST be an owner; a
  ban strips the target's owner role and is followed by an immediate
  `RotateRoomKey` (cryptographic eviction; §5.1).
- **`JoinRefused`** — `room_id`, `target_fingerprint`, `reason`. Owner-authenticated.
- **`CodeJoinRequest` / `CodeJoinResponse`** — single-use join-code flow (§5.3).
- **`SasInit` / `SasResponse` / `SasConfirm`** — SAS verification handshake (§5.5).
- **`ContactRequest`** *(window-exempt)* — `requester_fingerprint`, `display_name?`,
  `note?`, `sender_ed25519_pubkey?` (first-contact friend request via the inbox).

A conforming honest client enforces the authority rules above; the protocol is
**honest-client** at the membership layer (soft moderation), with the
cryptographic teeth being key rotation (§5.1) — see SECURITY.md and the documented
residual `N-M1` (§8).

---

## 5. Cryptographic constructions

### 5.1 Group rooms (Megolm)

Each member runs one **outbound** Megolm session per room and holds an **inbound**
session per peer. `Encrypted.ciphertext_b64` is the Megolm ciphertext;
`session_id` identifies the sender's outbound session. A receiver MUST NOT regress
an inbound session to an earlier ratchet index (anti-suppression).

**Passphrase-keyed delivery.** For a room with a passphrase, a member wraps its
Megolm session key and broadcasts it in `MemberAnnounce.wrapped_session_key`:

```
key   = Argon2id(passphrase, salt; m=65536 KiB, t=3, p=4) -> 32 bytes
wrap  = base64( nonce[12] || ChaCha20-Poly1305(key, nonce, session_key_b64) )
```

(`SALT_LEN`=16, `KEY_LEN`=32, `NONCE_LEN`=12.) **Forward-only epoch rotation:** the
outbound session rotates on a schedule and on membership change, bounding the
exposure of any one key. A kick rotates the key and re-wraps it to the remaining
members only — the banned member keeps receiving bytes it can no longer decrypt.

### 5.2 Direct messages (hybrid post-quantum agreement)

A DM "room" between two identities derives a 32-byte wrap key non-interactively
from long-term keys, bound to the canonical room id.

**Classical path** (`derive_dm_key`): each side maps its Ed25519 key to X25519 —
secret via `SHA-512(seed)[0..32]` with RFC 7748 clamping, public via the
Edwards→Montgomery birational map — performs X25519 ECDH (with a contributory /
small-order check), then:

```
dm_key = HKDF-SHA256(salt = "huddle-dm-key-v1\0",
                     IKM  = x25519_shared,
                     info = canonical_room_id)            -> 32 bytes
```

**Hybrid path** (huddle ≥ 1.3, when both peers publish an ML-KEM key). The
initiator derives a *deterministic* encapsulation message
`m = HKDF-SHA256(salt = "huddle-dm-mlkem-encaps-v1", IKM = our_seed,
info = partner_ek || room_id)`, computes `(ct, ss_mlkem) = ML-KEM.Encaps(partner_ek;
m)` (deterministic — same inputs reproduce the exact ciphertext), and ships `ct` in
`MemberAnnounce.mlkem_ciphertext`. Both sides combine:

```
dm_key = HKDF-SHA256(salt = "huddle-hybrid-kem-v1",
                     IKM  = x25519_shared || ss_mlkem,
                     info = ct || canonical_room_id)       -> 32 bytes
```

The key is secure as long as *either* X25519 or ML-KEM holds (this is the standard
concatenation-KEM combiner — the same shape as Signal's PQXDH). The derived
`dm_key` then plays the role of the passphrase key in §5.1 to wrap Megolm session
keys.

**Downgrade resistance.** ML-KEM public keys ride inside the *signed*
`MemberAnnounce`, so a relay cannot strip them without breaking the signature. A
peer's post-quantum capability is pinned on first sight; thereafter a client MUST
refuse the classical fallback for that peer (`must_refuse_classical_fallback`),
defeating a replay of a captured classical-only announce.

### 5.3 Join codes

An owner mints a single-use code. The joiner generates an ephemeral X25519 keypair
and sends a signed `CodeJoinRequest { room_id, joiner_x25519_pubkey_b64, code }`;
the owner replies with a signed `CodeJoinResponse` wrapping the room's session key
under an ECDH-derived key. Code-joined members are read-only (they lack the
passphrase and cannot wrap keys for newer joiners).

### 5.4 File transfer

A file is encrypted once under a fresh ChaCha20-Poly1305 key; that key is
Megolm-wrapped:

```
EncryptedFileMeta = {
  "megolm_session_id": String,   // session that wrapped the file key
  "wrapped_key_b64":   String,
  "nonce_b64":         String,
  "content_hash":      String    // hex SHA-256 of plaintext, bound as AEAD AAD
}
```

`content_hash` is the AEAD associated data, so the `(key, nonce, ciphertext)`
triple cannot be replayed against different content; it is also verified after
decryption. The body is split into chunks carried in `FileChunk` messages
following a `FileOffer` that carries the `EncryptedFileMeta`.

### 5.5 SAS verification

Two peers each generate an ephemeral X25519 keypair and a 16-byte transaction id
(`TX_ID_LEN`), exchange pubkeys in signed envelopes (`SasInit`/`SasResponse`), and
derive a short authentication string from the ephemeral ECDH secret:

```
okm = HKDF-SHA256(salt = tx_id, IKM = ecdh_shared, info = sas_info)  -> 11 bytes
```

The first 6 bytes yield seven 6-bit indices, **rejection-sampled** (label
`"huddle-sas-v1-rs"`) into `0..49` to pick from a frozen 49-entry word table; the
last 5 bytes yield three 13-bit values + 1000 → three 4-digit decimal groups
(the MSC 2241 *shape*; the word table is huddle's own and does **not**
interoperate with Matrix SAS). `sas_info` binds post-quantum capability:

```
sas_info = "huddle-sas-v1"                                    // neither side PQ
         | "huddle-sas-pqbind-v1" || SHA-256( sort(ek_a, ek_b) )  // both PQ
```

Byte-sorting the two ML-KEM keys makes the binding symmetric, so honest peers
derive the same code while a relay that strips one side's key makes the codes
diverge (downgrade detection). Peers compare the code out-of-band and confirm with
a signed `SasConfirm`; a match pins the partner's identity key (TOFU) as verified.

---

## 6. Invites

An invite is `huddle://invite#<base64url(JSON)>` of an `InviteLink`:

```
InviteLink = {
  "v": u32,                       // 1 unsigned · 2 signed · 3 +relay_url · 4 +mlkem_ek
  "host_multiaddr": String,       // libp2p dial target, WITH /p2p/<peer-id>
  "fingerprint": String,
  "room": InviteRoom?,            // optional auto-join room summary
  "creator_pubkey_b64": String?,  // v≥2
  "signed_at_ms": i64,            // v≥2 (skip when 0)
  "signature_b64": String?,       // v≥2: Ed25519 over signable_bytes()
  "relay_url": String?,           // v≥3: wss:// or ws:// (covered by signature)
  "mlkem_ek_b64": String?         // v≥4: inviter ML-KEM key (PQ capability commit)
}
```

`signable_bytes()` is a deterministic transcript: header `"huddle-invite-v2|"`
(classical) or `"huddle-invite-v4|"` (when an ML-KEM key is present), then
`host_multiaddr | fingerprint | be64(signed_at_ms) |`, then the room block (or
`no-room`), then an optional `|relay|<url>` tail and `|mlkem-ek|<key>` tail. Tails
are appended only when present, so classical invites are byte-identical to v2/v3
and verify across versions. Owner lists are sorted before signing and re-sorted
before verifying.

A verifier MUST: re-derive the fingerprint from `creator_pubkey_b64` and check it
matches; `verify_strict` the signature over the reconstructed `signable_bytes()`;
reject invites older than 24 h or future-dated. **Anti-downgrade:** a `v=1` invite
that carries *any* signature field MUST be rejected (a genuine legacy v1 never
does), so a signed invite cannot be stripped to `v=1` to skip verification.

---

## 7. Relay & transport

### 7.1 The doors model

A relay is reachable through one or more **doors**, each a different
anti-censorship trade-off, all fronting the *same* mailbox + room fan-out:

- **Tor v3 onion** (most private; the default) — via a local SOCKS5 proxy or
  in-process Arti.
- **Clearnet `ws://`** to a raw IP (fast; exposes the client IP + WS metadata to
  on-path observers, never the plaintext).
- **TLS `wss://`** (e.g. a cloudflared tunnel) using the system trust store.

A client tries doors **most-private-first** and falls through on failure. Because
all doors terminate at one server process sharing one set of rooms, a Tor client
and a clearnet client are in the *same* room — cross-transport interoperability is
a property of the design, not a bridge.

### 7.2 Zero-knowledge routing

The relay treats every payload as an opaque base64 blob, routed by a cleartext
`room` tag (an opaque id it never interprets) or a recipient `fingerprint`. It
holds no keys and performs no decryption. What it *can* observe is metadata: room
ids, member fingerprints, and timing (the onion door hides client IPs).

### 7.3 Control protocol

Client→relay (`ClientMsg`) and relay→client (`ServerMsg`) are JSON, tagged
`{"type": "<snake_case>", …}`:

```
ClientMsg: hello{fingerprint,pubkey_b64,signature_b64,rooms,acks}
           subscribe{room} · unsubscribe{room}
           publish{room,id,payload_b64}
           send_direct{to,room,id,payload_b64}
           create_connect_token · redeem_connect_token{token}
           fetch · ack{mailbox_id} · ping
ServerMsg: challenge{nonce_b64} · ready{fingerprint}
           message{room,id,payload_b64,mailbox_id?}
           sent{id,delivered,queued}
           connect_token{token,ttl_secs}
           connect_token_resolved{token,fingerprint?,pubkey_b64?}
           pong · error{message}
```

The optional fields (`mailbox_id`, the `hello` auth fields) use `serde(default)` /
`skip_serializing_if`, so old and new clients/relays interoperate byte-compatibly.

### 7.4 Authentication

On connect the relay sends `challenge{nonce_b64}` (a 32-byte nonce). The client
answers with `hello`, signing:

```
relay_auth_msg(nonce) = "huddle-relay-auth-v1" || nonce
```

The relay verifies the Ed25519 signature (`verify_strict`) against `pubkey_b64`,
checks `compute_fingerprint(pubkey) == fingerprint`, and pins that server-derived
fingerprint to the connection (the client-claimed string is never trusted for
routing). The distinct domain tag keeps a relay-auth signature from ever being
mistaken for a `SignedRoomMessage`. *(Residual `N-M4`: this proof is not bound to a
specific relay identity — §8.)*

### 7.5 Mailbox & delivery

`publish` fans a message out to the room's currently-connected members and queues
it for offline ones; `send_direct` delivers to a specific fingerprint's
connections or its per-fingerprint mailbox. A capable client sets `acks: true`; the
relay then tags each mailbox delivery with a `mailbox_id` and keeps the row until
the client `ack`s durable receipt (**at-least-once** delivery). Pre-2.0 clients
that never ack get classical delete-on-deliver. Queued ciphertext past a TTL is
GC'd.

---

## 8. Threat model summary

Full treatment in [`SECURITY.md`](SECURITY.md). In brief, against a malicious
peer, a malicious/coerced relay, and a network/LAN attacker:

- **Content confidentiality & integrity** hold E2E: the relay sees only
  ciphertext; signatures are verified before content is acted on; encrypted rooms
  reject unsigned injection.
- **Post-quantum**: DM key agreement is hybrid (harvest-now-decrypt-later
  resistant); Megolm content and ChaCha20-Poly1305 files are symmetric (already
  PQ); identity/authority signatures remain classical Ed25519 (forging needs a
  *live* quantum computer, not a recording).
- **Documented residuals** (deferred, see the roadmap): `N-M1` relay membership is
  self-asserted (anyone who learns a room id can subscribe to its ciphertext +
  metadata; the zero-knowledge routing that enables cross-transport chat is the
  same property — the real fix is a per-room capability token); `N-M4` relay
  `Hello` auth is not channel-bound to a server identity. Metadata (room ids,
  fingerprints, timing) is visible to the relay by design at this layer.

At-rest confidentiality relies on the local SQLCipher database key (Argon2id from
the master passphrase); message bodies are plaintext under that key.

---

## 9. Versioning & compatibility

There is **no in-band version negotiation**. Compatibility is maintained by an
**additive-only** discipline:

- New fields are optional with `#[serde(default, skip_serializing_if = …)]`, so
  they are absent on the wire when unset and ignored by older peers.
- New enum variants are dropped gracefully by older peers (unknown tag → ignored).
- Renaming, removing, or retyping an existing field or variant is **forbidden**
  without an explicit version scheme.
- `verify_signed` validates the raw payload bytes *before* deserializing, so
  adding fields never breaks an older receiver's signature check.

This is what lets every 1.x / 2.x huddle interoperate. The wire bytes of the types
above are frozen; the conformance vectors (`crates/huddle-protocol/tests/wire_compat.rs`)
pin the load-bearing behavior (variant tags, snake_case, omit-when-none).

---

## 10. Conformance

A second implementation is conforming if it:

1. Produces and accepts the `WireMessage` / `SignedRoomMessage` / `RoomMessage`
   encodings of §3–4 byte-for-byte (validate against `wire_compat.rs`).
2. Implements `verify_signed` (§3.2) including the freshness window and its
   exemptions.
3. Derives identity, fingerprints, DM keys (classical and hybrid), SAS codes, and
   passphrase wraps using the exact domain-separation tags and parameters in §2,
   §5 — these are the interop-critical constants.
4. Speaks the relay control protocol and auth handshake of §7 (if it uses the
   relay transport).

The `huddle-protocol` crate is published on crates.io and MAY be used directly as
the reference implementation of all of the above.

---

*Changes to this document and to `huddle-protocol` are coordinated: a wire change
is a protocol-version event, not a patch. File issues against the
[repository](https://github.com/richer-richard/huddle).*
