# Security

This document describes huddle's security model as of **1.3.3**: what is
protected, how, and — just as importantly — what is *not*. Read the
"Known limitations / by-design tradeoffs" section before trusting huddle
with anything that matters.

## Posture

huddle is **end-to-end encrypted**: the relay (and any LAN peer that
isn't a participant) only ever sees opaque ciphertext plus routing
metadata, never plaintext and never keys. Group rooms use per-sender
Megolm sessions, direct messages use an X25519+HKDF key derived from
both parties' long-term identities, every authority-bearing control
message is an Ed25519-signed envelope, and the local database is
encrypted at rest with SQLCipher under an Argon2id-stretched master
passphrase. **That said, huddle is a learning project, not
production-audited chat.** The protocol has had self-review passes and
the crypto primitives are standard (vodozemac Megolm, ed25519-dalek,
x25519-dalek, ChaCha20-Poly1305, Argon2id, HKDF-SHA256), but it has
**not** had an independent third-party security audit and threat-modelling
work is ongoing. Do not rely on it for high-stakes secrets without your
own careful review.

## What's encrypted vs. what's plaintext

### Encrypted (end-to-end, keys never leave the clients)

- **Group rooms** — vodozemac **Megolm** group sessions (one outbound
  session per sender). For passphrase rooms the session key is wrapped
  with ChaCha20-Poly1305 under an **Argon2id**-derived key
  (m=64 MiB, t=3, p=4) bound to a per-room salt; for code-join rooms it
  is wrapped under an ECDH-derived key between owner and joiner.
- **Direct messages** — a 32-byte room key. Since **1.3.0** this is a
  **hybrid post-quantum** key when both peers are on 1.3+: a classical
  **X25519 ECDH** secret (between the two parties' long-term Ed25519
  identities, converted to Montgomery form) and an **ML-KEM-768** (FIPS
  203) encapsulated secret are concatenated and run through **HKDF-SHA256**,
  bound to the canonical DM room id and the KEM ciphertext. The key is
  secure as long as *either* primitive holds, so recorded DMs resist a
  future quantum computer (see "1.3 changes" and "harvest-now-decrypt-later"
  below). Against a pre-1.3 peer it transparently falls back to the
  classical X25519-only key. Either way both peers derive the same key and
  message payloads are then Megolm-encrypted as in group rooms.
- **File attachments** in encrypted rooms — bytes are
  ChaCha20-Poly1305-encrypted under a fresh per-file key that is itself
  Megolm-wrapped in the file offer.
- **Control / authority messages** — `OwnerGrant`, `BanMember`,
  `RotateRoomKey`, the SAS handshake, `CodeJoinRequest/Response`,
  `MemberLeave`, `MemberAnnounce`, `FileOffer`, `ProfileUpdate`, and
  friends ride inside an **Ed25519 `SignedRoomMessage` envelope**. The
  verifier re-derives the sender's fingerprint from the signing pubkey,
  uses `verify_strict` (rejecting low-/mixed-order keys), and rejects
  envelopes whose signature-bound timestamp falls outside a ±5-minute
  window (anti-replay).
- **At rest** — the local SQLite database is **SQLCipher**-encrypted.
  The `PRAGMA key` is your master passphrase stretched with Argon2id
  against a per-installation salt (`keychain.salt`); an HKDF subkey is
  used for Megolm session persistence.

### Plaintext / observable

- **The relay sees only room ids and opaque ciphertext.** huddle-server
  treats every wire payload as an opaque base64 blob, routes by the
  cleartext `room` id, and never decrypts. What it *can* observe is
  **metadata**: room ids, member fingerprints, message timing and sizes,
  and (on a clearnet door) client IP. The onion door hides client IPs;
  blinding the room/recipient identifiers is deferred work.
- **The relay's own SQLite DB is not encrypted at rest** — but it is
  **keyless**: it holds only ciphertext payloads plus routing metadata
  (memberships, per-recipient mailbox rows), never any decryption key.
  Compromising the relay host yields metadata and ciphertext, not
  message contents.
- **Public (unencrypted) rooms** carry cleartext payloads by design.
  Use an encrypted room for anything sensitive.

## Identity, trust, and verification

- **Identity** is an **Ed25519** keypair generated on first launch and
  stored under your platform data directory. Its 96-bit fingerprint is
  rendered as a branded `HD-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` id.
- **TOFU pinning.** The first time you see a peer's signed
  `MemberAnnounce` / `ProfileUpdate`, their Ed25519 pubkey is pinned to
  their fingerprint. Because authority messages are signed and the
  fingerprint is *re-derived from the signing key*, nobody can later
  claim an existing fingerprint with a different key, and a username
  cannot be spoofed by stuffing a string into a packet.
- **SAS verification** (Matrix MSC 2241-aligned). Both peers run a
  short-authentication-string exchange: each generates an ephemeral
  X25519 keypair, exchanges pubkeys inside signed envelopes, performs
  ECDH, and derives a 7-word + decimal code via HKDF with rejection
  sampling (uniform over the symbol table). The peers compare the code
  out-of-band (call / in person); a MITM who substitutes an ephemeral
  key produces a different code on each side, so the comparison catches
  it. On match the fingerprint is marked verified, and an optional
  "reject inbound from unverified" mode gates strangers.

## 1.1.4 hardening

- **Enforced relay client authentication (Ed25519 challenge–response).**
  A client no longer simply asserts a fingerprint in its `Hello`. The
  relay issues a random challenge nonce; the client signs it with its
  Ed25519 identity key and returns the signature, which the relay
  verifies against the pubkey-derived fingerprint before binding the
  socket to that identity. This stops an attacker from registering under
  someone else's fingerprint to siphon their mailbox or impersonate them
  on the routing layer. (End-to-end encryption already prevented reading
  message *contents* without keys; this closes the metadata/impersonation
  gap at the relay.)
- **X25519 contributory (small-order) checks.** Both the DM key
  agreement (`crypto::dm`) and the SAS handshake (`crypto::sas`) now
  reject a non-contributory shared secret via `was_contributory()`. An
  attacker who injects one of the small-order Montgomery points as a
  "pubkey" can no longer force a predictable low-order shared secret;
  two honest peers always produce a contributory secret, so this never
  rejects a legitimate exchange.
- **Safer mailbox delivery.** The relay now deletes a queued message only
  after delivering it (peek → deliver → delete-delivered) over a bounded
  outbound queue, closing the window where a socket drop mid-drain could
  silently lose or double-deliver ciphertext. It also enforces a pre-auth
  handshake timeout and pins the proven fingerprint to the connection so a
  second `Hello` can't re-bind the socket to another identity's mailbox.
- **Update check routed over Tor.** The opt-in once-per-24h crates.io
  version poll is sent through the local Tor SOCKS proxy (or skipped when
  Tor is unavailable) instead of leaking a direct clearnet request that
  could correlate "this IP runs huddle" to an on-path observer.
- **Key zeroization.** Argon2id-derived passphrase keys, the extracted
  X25519 scalar in DM derivation, and other short-lived secret buffers
  are held in `Zeroizing` wrappers so they are overwritten on drop rather
  than lingering in a stale heap page or swap.

## 1.2 changes

- **Fingerprint-addressed relay delivery (`SendDirect`).** 1:1 DMs and
  friend requests are delivered to a recipient *fingerprint* (live to its
  connections, or queued in its per-fingerprint mailbox), independent of room
  membership. The security posture is unchanged: the relay still only sees
  opaque ciphertext plus the same routing metadata (sender/recipient
  fingerprints, room/inbox ids, timing) it already saw for membership fan-out —
  it never decrypts. The recipient still proves their identity at the relay via
  the 1.1.4 challenge–response before any mailbox is drained to them.
- **Replay window made store-and-forward-aware.** The ±5-minute wall-clock
  window on signed envelopes (anti-replay) is now applied *after* signature
  verification and is **not** enforced for store-and-forward control messages
  (`ContactRequest`, `MemberAnnounce`, `SessionKeyRequest`). Those legitimately
  sit in the offline mailbox for hours/days, so a wall-clock window would drop
  valid first-contact requests and first key exchanges. The Ed25519 signature
  still proves the sender's identity, and re-applying these messages is
  idempotent (re-adding a known member / re-showing a pending request is a
  no-op). Every other signed type keeps the strict window. The one replay that
  is **not** a no-op is a captured pre-1.3 (classical-only) `MemberAnnounce`
  replayed to force a post-quantum downgrade — see "1.3 changes → Downgrade
  resistance" below, where the PQ-capability pin neutralizes it for any peer
  whose ML-KEM key has ever been observed (with a documented first-contact
  residual).
- **Connect codes carry no authority (1.2.1).** A connect code is a short
  (40-bit, 5-minute) handle the relay maps to an identity *only* so a peer can
  look up your fingerprint and send you a contact request — which you still
  accept. Redeeming a code grants nothing else; the code is never persisted and
  expires fast, bounding any enumeration. The redeeming client verifies the
  pubkey the relay returns hashes to the fingerprint it claims, and the real
  identity proof remains the owner's *signed* contact-request/announce, so a
  misbehaving relay can't substitute an identity undetected.

## 1.3 changes — post-quantum hybrid DM key agreement

- **Hybrid X25519 + ML-KEM-768 DM keys.** The direct-message wrap key is now
  derived from two independent shared secrets — a classical **X25519 ECDH** and
  a post-quantum **ML-KEM-768** (FIPS 203, RustCrypto `ml-kem`) encapsulation —
  combined with **HKDF-SHA256**:
  `HKDF(salt = "huddle-hybrid-kem-v1"; ikm = ss_x25519 ‖ ss_mlkem; info = kem_ct ‖ room_id)`.
  Because both secrets feed the same KDF as input keying material, the output is
  a secure key if **either** primitive is unbroken, and it is never weaker than
  the previous classical-only key. This is the construction Signal standardized
  as PQXDH, scoped to huddle's static DM model.
- **What this defends: "harvest now, decrypt later".** A well-resourced
  adversary can record E2E ciphertext today and decrypt it years later once a
  cryptographically-relevant quantum computer can break X25519 (via Shor's
  algorithm). The ML-KEM half removes that: recovering the DM key would *also*
  require breaking ML-KEM (a lattice problem with no known quantum break). The
  symmetric message cipher (Megolm = AES-256 + HMAC-SHA-256) and file cipher
  (ChaCha20-Poly1305) were already quantum-resistant — only the *key agreement*
  was classical, and that is the gap this closes.
- **Deterministic keypair, zero migration.** Each identity's ML-KEM keypair is
  derived from its existing Ed25519 seed via a domain-separated HKDF
  (`PqKeypair::from_identity_seed`, which expands the seed and then hands the
  64-byte result to ml-kem's `DecapsulationKey::from_seed`), so every pre-1.3
  identity gains a post-quantum key with no new on-disk material and no
  migration. The public encapsulation key is published
  in `MemberAnnounce`; peers cannot compute it from the Ed25519 *public* key
  alone, so it must be exchanged (it does not weaken the identity).
- **Deterministic encapsulation, no per-DM state.** The lower-fingerprint peer
  is the **initiator**: it encapsulates a secret to the responder's ML-KEM key
  using a message `m = HKDF(initiator_seed; partner_ek ‖ room_id)` and ships the
  ciphertext in its signed announce; the higher-fingerprint peer decapsulates.
  Seeding `m` from the initiator's long-term secret makes the ciphertext
  reproducible (so no per-DM secret has to be stored) **without** weakening the
  post-quantum guarantee: `m` is unknown to anyone lacking the initiator's seed,
  so a quantum attacker who later recovers the X25519 secret still cannot
  reconstruct the ML-KEM secret (that needs `m` or the responder's private key).
- **Downgrade resistance (hardened in 1.3.1).** The ML-KEM public key and
  ciphertext travel *inside* the Ed25519-**signed** `MemberAnnounce` envelope, so
  a malicious relay cannot *strip* them to force a classical downgrade without
  invalidating the signature. But a captured pre-1.3 (classical-only) announce is
  itself validly signed and — like all `MemberAnnounce`es — exempt from the
  replay window, so a relay could *replay* it to push a peer onto the classical
  path. 1.3.1 closes that with **PQ-capability pinning**: the first time we see a
  peer's ML-KEM key in a signed announce we persist it (`room_members.mlkem_pubkey`),
  and from then on we **refuse the classical fallback** for that peer — a replayed
  classical announce is ignored. The pin survives restarts (the in-memory wrap key
  does not), and a DM that was momentarily keyed classical (rollout timing, or a
  replay that won an initial race) is **upgraded** to hybrid the moment any
  capability is observed; the upgrade also **rotates our outbound Megolm session**,
  retiring the session key that had been shared wrapped under the classical key.
  Rotation is **forward-only**: every message sent *after* the upgrade uses a key
  never exposed classically, but any messages already sent during the transient
  classical window were encrypted under the retired session and **remain
  HNDL-exposed** — rotation cannot retroactively protect them (it bounds the
  exposure to that window, it does not erase it). The decision is one-way:
  classical→hybrid only, never the reverse.
  - **Residual (documented).** On a peer we have *never* pinned — true first
    contact, or the one-time 1.3.0→1.3.1 window before they re-announce — a relay
    that both replays a captured classical announce **and** suppresses every
    genuine hybrid announce can still force an initial classical lock. The only
    bound on this state is that the upgrade+rotate fires the instant any genuine
    hybrid announce gets through (a peer already keyed classical against an
    un-pinned partner can still decrypt that partner's classical traffic, so the
    decrypt-miss key-request heal does not probe it; capability is only ever
    learned from a `MemberAnnounce` that carries the ML-KEM key). It is not
    eliminable without an out-of-band capability anchor — binding PQ capability
    into SAS / the verified-peers store is the planned real fix.
  - A *malicious endpoint* (the peer you are actually talking to) can still
    withhold its own ML-KEM key to keep the DM classical, but that only weakens
    that peer's own traffic. A deliberate same-identity 1.3→pre-1.3 binary
    downgrade is refused (fail-closed) rather than silently accepted.
- **Not changed (and why):** identity and message authenticity still use
  classical **Ed25519** signatures, and Megolm's own per-message signing is
  unchanged. Forging a signature requires a quantum computer operating *at the
  time of the attack* — it is not a "harvest now" threat — and replacing the
  identity scheme would break the relay auth, fingerprints, TOFU pinning, and
  the connect-code system. Post-quantum *signatures* (ML-DSA / SLH-DSA) are a
  possible future step but are out of scope for the harvest-now-decrypt-later
  fix. Group-room key delivery under a passphrase is already post-quantum
  (Argon2id + ChaCha20-Poly1305 are symmetric); the ECDH-wrapped code-join path
  remains classical for now.

## Known limitations / by-design tradeoffs

These are honest, deliberate tradeoffs — not oversights:

- **No master passphrase ⇒ plaintext at rest.** Running with
  `--no-master-passphrase` opens an **unencrypted** local database (the
  unlock screen is skipped). This is intended for testing/convenience;
  in that mode anyone with disk access reads your messages and keys.
- **`kick_member` is advisory on unencrypted rooms.** A kick broadcasts a
  signed `BanMember` and immediately rotates the room key, so the banned
  peer can't decrypt future *encrypted* traffic — that key rotation is
  the cryptographic enforcement. On a public/unencrypted room there is no
  key to rotate, so the ban is honest-client-enforced only; it is not a
  hard network quarantine.
- **No forward secrecy yet.** DM and group room keys derive from
  long-term identity material (and persist), so a future identity-key
  compromise can unlock historical session keys for that party (Megolm
  message keys still ratchet, but the wrap key does not). This is
  orthogonal to the 1.3 post-quantum work: the hybrid DM key is stronger
  against a *future quantum computer* but is still derived from long-term
  keys, so it provides no forward secrecy against an *identity-seed*
  compromise — and because the ML-KEM keypair is derived from that same
  seed, a seed compromise exposes exactly what it did before, no more.
  Per-DM ephemeral ratchets (Double Ratchet-style) and DB rekey are on the
  roadmap — see "Current limitations" in the README.
- **Broadcast-event drop under load.** Internal event channels are
  bounded; under a heavy burst an event can be dropped. This is mitigated
  by resync (re-reading authoritative state) rather than guaranteed
  delivery of every transient event.
- **The clearnet door is a fallback, not the primary path.** Since 1.1.5 the
  baked-in clearnet default is a **stable** `*.workers.dev` proxy that
  forwards to the operator's relay, so a URL embedded in an old invite no
  longer goes stale. **The Tor onion is the canonical, preferred address;**
  the clearnet door is tried only after the onion and exists for users in
  regions where Tor itself is blocked. A *self-hosted* `*.trycloudflare.com`
  quick-tunnel relay still rotates its hostname on each `cloudflared`
  restart — use a named tunnel or a real domain for a stable self-hosted URL.
- **Settings apply on next launch.** Several network-affecting toggles
  (LAN mDNS on/off, transport selection) take effect on the next launch
  rather than mid-session, to avoid a costly live behaviour rebuild.
- **SAS table is not yet interop-tested** against other MSC 2241 clients;
  both ends must run a compatible huddle version.

## Reporting a vulnerability

Please report security issues on GitHub: open a **private security
advisory** at <https://github.com/richer-richard/huddle/security/advisories/new>
(preferred), or a regular issue at
<https://github.com/richer-richard/huddle/issues> for non-sensitive
reports. Include the version (`huddle doctor` / `huddle-gui doctor`),
your platform, and reproduction steps. Because huddle is a learning
project maintained on a best-effort basis, please allow reasonable time
for a fix before any public disclosure.
