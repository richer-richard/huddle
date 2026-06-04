# Security

This document describes huddle's security model as of **1.2.2**: what is
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
- **Direct messages** — a 32-byte room key derived by **X25519 ECDH**
  between the two parties' long-term Ed25519 identities (converted to
  Montgomery form), expanded with **HKDF-SHA256** and bound to the
  canonical DM room id via the `info` parameter. Both peers derive the
  same key with no shared passphrase and no extra round trip. Message
  payloads are then Megolm-encrypted as in group rooms.
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
  no-op), so dropping the window for them does not enable a meaningful replay.
  Every other signed type keeps the strict window.
- **Connect codes carry no authority (1.2.1).** A connect code is a short
  (40-bit, 5-minute) handle the relay maps to an identity *only* so a peer can
  look up your fingerprint and send you a contact request — which you still
  accept. Redeeming a code grants nothing else; the code is never persisted and
  expires fast, bounding any enumeration. The redeeming client verifies the
  pubkey the relay returns hashes to the fingerprint it claims, and the real
  identity proof remains the owner's *signed* contact-request/announce, so a
  misbehaving relay can't substitute an identity undetected.

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
  message keys still ratchet, but the wrap key does not). Per-DM
  ephemeral ratchets (Double Ratchet-style) and DB rekey are on the
  roadmap — see "Current limitations" in the README.
- **Broadcast-event drop under load.** Internal event channels are
  bounded; under a heavy burst an event can be dropped. This is mitigated
  by resync (re-reading authoritative state) rather than guaranteed
  delivery of every transient event.
- **The free clearnet hostname rotates.** The baked-in
  `*.trycloudflare.com` quick-tunnel door gets a new hostname whenever
  cloudflared restarts, so a relay URL embedded in an old invite can go
  stale. **The Tor onion is the canonical, stable address;** the clearnet
  door is tried only after the onion and is a convenience for users who
  can't reach Tor. Use a named tunnel or a real domain for a stable
  clearnet URL.
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
