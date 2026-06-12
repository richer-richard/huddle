# huddle — the path from "a chat app" to ecosystem infrastructure

*This is the **importance** layer. `ROADMAP-2.0-and-beyond.md` and
`BRAINSTORM-future-functionality.md` answer "what should huddle build next" — they make
huddle a better chat app. This document answers a different question: **how does huddle stop
being one secure-messenger-among-many and become something the ecosystem depends on, cites,
or can't ignore.** The two compose — the feature roadmaps are the body, this is the spine.*

---

## The thesis

Feature breadth does not make open-source software important. Calls, MLS, multi-device,
reactions — every one makes huddle a stronger competitor to Signal, Matrix, SimpleX, Briar,
and Cwtch, all of which have orders of magnitude more resources. "A better also-ran" is still
an also-ran.

Software becomes *important* by being one of three things:

1. **Depended upon** — other projects build *on* it. (libsignal is embedded in WhatsApp;
   OpenMLS and libp2p are infrastructure others assemble from.)
2. **First or best at one specific thing** — it owns a capability or idea the field cites.
   (The Signal Protocol. The Matrix spec. WireGuard's whole-design-fits-in-your-head
   simplicity.)
3. **Trusted** — analyzed, audited, formally modeled, so people stake real risk on it.

huddle today is none of these — and the README says so out loud: *"a learning project, not
production-audited chat."* That sentence is the ceiling. This roadmap is how we lift it.

---

## What huddle uniquely has to build on

Three properties are genuinely differentiated and load-bearing for everything below:

- **Transport-agnostic, zero-knowledge relay + the "doors" model.** One `huddle-server`
  process is simultaneously a Tor onion, a raw clearnet IP, and a Cloudflare-fronted `wss`,
  all sharing one mailbox + room fan-out — so a Tor user and a clearnet user sit *in the same
  room*, and the relay routes by opaque `room_id` and learns nothing. Briar/Cwtch are
  Tor-only; SimpleX/Session run bespoke networks; Signal/Matrix do not do graceful
  most-private-first transport *interop* at all. **Nobody else has this.** It is the wedge.
- **Stateless, seed-derived identity.** PeerId, ML-KEM key, and DM keys all re-derive from one
  BIP-39 seed; no per-conversation state on the happy path. Elegant and rare.
- **Real hybrid post-quantum DMs** (X25519 + ML-KEM-768) with downgrade resistance pinned into
  SAS and invites. Signal-PQXDH-class — almost no small project has actually shipped it.

---

## The program

Four workstreams, sequenced by dependency, not by excitement.

### WS1 — Protocol + substrate *(the spine; do first)*

Make huddle a *thing other people can build on*, not just an app you run.

1. **Extract a standalone `huddle-protocol` crate** — the pure wire format + crypto
   constructions, depending only on RustCrypto-family crates (no tokio / libp2p / sqlite /
   vodozemac). This is **the spec, as code**: one place that defines what "speaking huddle"
   means, that a second implementation (in any language) can target, and that the relay shares
   instead of *hand-duplicating* it. (`huddle-server` currently open-codes
   `compute_fingerprint` + Ed25519 challenge verification to dodge the client's heavy graph —
   proof the seam is real and missing.) *First concrete step:
   `docs/superpowers/specs/2026-06-12-huddle-protocol-crate-design.md`.*
2. **Write "The Huddle Protocol" as a versioned, citable document** — wire format, the
   signed-envelope + Megolm constructions, the hybrid-PQ DM agreement, the transport-door /
   zero-knowledge-relay model, and the threat model. A spec turns "an app" into "a standard."
3. **Carve `huddle-core` behind a documented SDK boundary.** Today the surface is the
   ~6.8k-line `AppHandle` god-object — embeddable by nobody. The actor / typed-command refactor
   already sequenced in `ROADMAP-2.0-and-beyond.md` (Phase F1) is the same work; do it in
   service of an *embeddable* core.
4. **Make the relay a reusable primitive,** and land the deferred authz that makes it credible
   infrastructure rather than a toy: per-room capability tokens for membership (`N-M1`) and
   channel-bound relay auth (`N-M4`), both already on the deferred-security backlog.

*Spends: nothing in step 1 (pure internal reshape, byte-identical wire); dumb-relay
simplicity in step 4.* *Unlocks: WS2's clean wire additions, WS3's mobile FFI, and the entire
"depended-upon" thesis.*

### WS2 — Post-quantum everywhere + MLS groups *(the flag)*

huddle is PQ on DMs only; the group ratchet (Megolm) and the authority signatures (Ed25519)
are classical. **Post-quantum *group* messaging is the live research frontier** — MLS
(RFC 9420) is mid-standardizing PQ ciphersuites (`draft-ietf-mls-pq-ciphersuites`) and almost
nobody has shipped it.

- **Adopt MLS for new rooms** (via OpenMLS or `mls-rs`), behind a capability flag; Megolm
  rooms live out their lives. TreeKEM brings forward secrecy, post-compromise security, and
  *cryptographically-enforced* removal (a kick becomes an epoch change, not an honest-client
  convention — closing the soft-ownership gap the README documents today).
- **Carry PQ through MLS's PQ ciphersuites,** so the group layer becomes hybrid-PQ — closing
  the gap that leaves group history classically exposed today.
- **Hybrid PQ authentication** (composite Ed25519 + ML-DSA-65) on the identity / authority
  envelopes (announces, invites) — *not* per-line (~3.3 KB signatures). Keep Ed25519 as the
  second lock; the RustCrypto PQ crates are young (a real ML-DSA verify bug shipped and was
  caught in Jan 2026). Derive the ML-DSA key from the same seed — no new on-disk material.

Outcome huddle can credibly claim: **fully hybrid-post-quantum messaging, groups included —
before the field.** That is a citable first. *Depends on: WS1 (these are wire additions;
define them in the protocol crate). Spends: wire compactness + audit surface.*

### WS3 — Distribution + a wedge audience

Importance is also adoption — the Briar/Cwtch path.

- **Pick the users huddle is *uniquely* right for:** people on censored or hostile networks who
  need Tor↔clearnet↔Cloudflare interop, no phone number, and no account. huddle's doors model
  is *the* differentiator for exactly this audience; lead with it.
- **Mobile (iOS / Android) via `uniffi`** over the now-FFI-clean core (depends on WS1's SDK
  boundary) — the single biggest user-base multiplier, with sealed / low-metadata push.
- **Reproducible, signed cross-platform packaging** (Linux AppImage/.deb, Windows MSI, the
  existing macOS flow), with checksums + SBOM + sigstore, so a security tool's users can verify
  what they run.
- **Community surface:** the protocol spec (WS1) + a conformance test-vector set is what lets a
  *second* implementer show up — which is how an app becomes an ecosystem.

### WS4 — Assurance *(continuous; gates the rest)*

- **Self-audit continuously** — the multi-agent adversarial scan discipline already used for
  2.0.1 → 2.0.3, run against each new surface (the protocol-crate boundary first). Findings
  tracked internally, never shipped as a public vuln roadmap.
- **Plan, but don't yet commission, an external audit + a formal-methods model**
  (ProVerif / Tamarin of the key agreement). This is what finally deletes the README's ceiling
  — but it lands *after* WS1/WS2 settle the protocol, so it analyzes a stable target. Sequence
  it; don't rush it.

---

## Sequencing & dependency structure

```
WS1  protocol crate → spec → SDK seam → relay authz
  ├── unblocks → WS2  (PQ + MLS: wire additions defined in the protocol crate)
  ├── unblocks → WS3  (mobile FFI needs the clean core boundary)
  └── analyzed by → WS4 (audit a stable protocol, not a moving one)
WS4 runs continuously alongside everything; the *external* audit waits for WS1 + WS2.
```

WS1 is the gate. Everything compounds off a clean protocol boundary; doing WS2/WS3 first would
mean building on the `AppHandle` tangle and paying for it twice.

---

## The cost ledger (kept honest)

| Workstream | Spends |
|---|---|
| `huddle-protocol` extraction (WS1.1) | nothing — pure internal reshape, byte-identical wire |
| relay-as-primitive + capability tokens (WS1.4) | **dumb-relay simplicity** → the relay grows per-room authz |
| MLS + PQ everywhere (WS2) | **wire compactness + audit surface** → bigger envelopes, younger crypto |
| mobile + multi-device (WS3) | **single-device statelessness** → syncable state |

None are reasons not to proceed — they are reasons to proceed *deliberately*, keeping the
simple defaults (single-binary SQLite relay, classical fast path, single device) available
alongside the powerful options, exactly the layered, opt-in posture huddle already uses for
transports and Arti.

---

## Relationship to the existing docs

- `ROADMAP-2.0-and-beyond.md` — the heavy *feature* sequence (MLS, Double Ratchet, metadata
  blinding, multi-device, calls). WS2 absorbs and re-frames its crypto items around the
  protocol crate; the rest stays valid.
- `BRAINSTORM-future-functionality.md` — the feature catalogue across six lenses. Still the
  menu; this doc is the reason to cook.
- `ROADMAP-forward-secrecy-and-rekey.md` — coordinate every rekey-adjacent item (MLS removal,
  member-removal rekey) with it.

---

*Nearest concrete work: the `huddle-protocol` crate extraction (WS1.1). Design spec:
`docs/superpowers/specs/2026-06-12-huddle-protocol-crate-design.md`.*
