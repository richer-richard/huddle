# huddle 2.0.1 — Security Vulnerability Scan & Code Critique

**Target:** huddle workspace @ `2.0.1` (commit `c030de1`)
**Scope:** Exhaustive vulnerability scan + harsh code critique. CI/CD & infrastructure
were explicitly **out of scope** (owned by a separate effort).
**Method:** 21 specialized auditors (16 security + 5 code-critique) read the 2.0.1 tree;
every security finding was put through 3 independent adversarial skeptics
(exploitability / correctness / already-mitigated lenses) and only survives on a
majority vote. Code-quality findings went through a single judge.

## ⚠️ Run integrity note

The multi-agent run was interrupted by an account session-limit partway through the
**Verify** and **Synthesize** phases. As a result:

- All **21 finder agents completed**; **99 raw findings** were produced.
- The two report-synthesis agents **died on the limit** (no auto-generated report).
- **31 findings were dropped only because their verifier hit the limit** — *not*
  because they were refuted.

This report was assembled by recovering the journaled agent outputs from disk and
**manually completing the failed verifiers' and synthesizers' work** — reading the
cited code by hand to adjudicate each orphaned finding. Provenance is marked per
finding:

- `✓ 3/3` / `✓ 2/3` — confirmed by the workflow's adversarial skeptic vote.
- `⚒ manual` — recovered from a verifier that timed out, then adjudicated by hand
  against the source (code citations inline).

---

## Executive summary

| Severity | Security | Code critique |
|---|---|---|
| **Critical** | 0 | 0 |
| **High** | 2 | 2 |
| **Medium** | 11 | 11 |
| **Low** | 27 | 6 |
| **Info** | 1 | — |
| **Total** | **41** | **19** |

**Top-line take.** No memory-unsafety (`unsafe` count is zero — good) and the core
cryptographic primitives are sound: the Megolm ratchet doesn't reuse outbound keys
after rotation, pickles are authenticated, the X25519+ML-KEM hybrid combiner binds
**both** secrets, and **the 2.0.1 headline fix — symmetric SAS post-quantum
capability binding — holds up under audit** (see §1.x). The 2.0.1 advisory triage in
`.cargo/audit.toml` was **verified accurate** (see Appendix A).

The real exposure is at the **trust boundaries above the crypto**: an **unauthenticated
`Plain`-message sender-spoof into encrypted rooms** (HIGH), a wide-open **relay with no
rate-limiting or global mailbox cap** (HIGH), and a cluster of **at-least-once /
replay / ordering** weaknesses (edits, reactions, deletes, mailbox ACKs) that a
malicious or compromised relay can weaponize for **targeted, silent message
loss/suppression**. Memory-hygiene is inconsistent: the BIP39/seed hardening (F6)
is incomplete on the everyday DB load path.

---

## Part 1 — Security Vulnerabilities

### HIGH

#### H-1 · Unsigned `Plain` messages are accepted into encrypted rooms → sender spoofing  ⚒ manual
**`crates/huddle-core/src/app/mod.rs:4885-4917` (handler); `:4022-4069` (dispatch); `crates/huddle-core/src/network/protocol.rs:100-111`**

`WireMessage::Plain` dispatches with `verified_signer = None` straight into
`handle_room_message` (mod.rs:4023). The `RoomMessage::Plain` arm then inserts the
message and emits `MessageReceived` attributed **solely to the attacker-supplied
`sender_fingerprint`**, with no signature check and no guard on whether the room is
encrypted. Only `self`/banned-sender filters apply.

**Impact:** Any node that learns a room's id (group room_ids are broadcast in
cleartext on `ROOMS_TOPIC`; a DM room_id is derivable from the two fingerprints) can
publish a `Plain` message to `huddle-room-<id>` spoofing **any** non-banned member.
Honest clients in an **encrypted** room render it identically to authenticated Megolm
traffic — there is no "unauthenticated" badge and the message-list query doesn't
filter on encryption. This breaks sender authenticity, the core promise of an E2EE
messenger (put words in a trusted contact's mouth; social-engineering). The in-code
comment at mod.rs:4726-4731 only reasons about *unencrypted* rooms — the
encrypted-room case is an oversight.
*Caveat (why HIGH not Critical):* injected content is attacker-authored plaintext;
no key compromise and no confidentiality break of real messages.

**Fix:** In `handle_room_message`, reject `Plain` (and other unsigned content arms)
when the room is encrypted — encrypted rooms must only accept `Encrypted`. Equivalently,
require a verified signer for any content-bearing arm in an encrypted room.

#### H-2 · Unbounded mailbox disk-fill via `SendDirect` (no global cap, no rate limit)  ✓ 3/3
**`crates/huddle-server/src/main.rs:883-943` (SendDirect), `:1274-1288` (enqueue/trim)**

An Ed25519 keypair is free to mint, so a single authenticated socket can loop
`SendDirect{ to: <fabricated fp>, payload_b64: <256 KiB> }` as fast as the link
allows — 500 rows per fake recipient, no throttle anywhere in `handle_client_msg`. The
per-fingerprint cap (`MAX_MAILBOX_PER_FP`) doesn't bound the **number** of recipient
fingerprints. Fills the host disk, bloats the single `huddle-server.db`, and since all
DB ops share one `Mutex<Connection>` (main.rs:293), eventually wedges the relay
offline. The unbounded `memberships` growth finding (L-x) compounds it.

**Fix:** Global mailbox ceiling (total rows and/or bytes) enforced in `enqueue()`;
per-connection token-bucket rate limit covering `Publish`+`SendDirect`; require the
recipient fingerprint to be registered/seen (or sharply lower the per-unknown-recipient
cap) before allocating mailbox space.

### MEDIUM

#### M-1 · `add_inbound_session` blindly replaces sessions → permanent message loss / relay-assisted suppression  ✓ 3/3
**`crates/huddle-core/src/crypto/megolm.rs:207-233`**

`add_inbound_session` does `InboundGroupSession::new` + `INSERT OR REPLACE` instead of
vodozemac's compare/merge. A later `MemberAnnounce` re-anchors the inbound session
**forward**, so any earlier ciphertext (index < new anchor) becomes undecryptable
forever. **Censorship primitive:** a malicious relay withholds ciphertext N, induces a
re-announce that pushes victims' anchor past N, then the message is permanently
undecryptable even if later delivered — looking like a key bug, not a dropped message.
A single late joiner's heal request re-anchors *all* members forward.
**Fix:** use vodozemac's session compare/merge (keep the lowest known index); never
replace an inbound session with one at a higher first-known-index.

#### M-2 · F7 mailbox ACK sent regardless of whether the message decrypted/persisted  ⚒ manual
**`crates/huddle-core/src/app/mod.rs:3596-3615`**

`process_network_event(...).await` returns `()` — no success signal — then the ACK is
sent unconditionally (`send_mailbox_ack(id)`, mod.rs:3614). An `Encrypted` message that
arrives from the mailbox **before** its Megolm session key (a normal race) hits the
`Encrypted` arm, fails to decrypt, and is dropped without persisting — but is still
ACKed, so the relay deletes its only copy. **Net: permanent message loss**, defeating
F7's at-least-once guarantee. The optimistic comment at 3603-3611 ("persists
synchronously before it returns") is false for the undecryptable case.
**Fix:** make `process_network_event` (or the Encrypted/Plain handlers) return a
persisted/decrypted result and ACK only on success; leave undecryptable messages in
the mailbox for retry; rely on the relay's 24h sweep as the backstop, not the eager ACK.

#### M-3 · `shutdown()` is incomplete — announcement ticker & pruner keep running with live DB writes  ⚒ manual
**`crates/huddle-core/src/app/mod.rs:2603-2610` (shutdown), `:3658` (ticker), `:3767` (pruner)**

`shutdown()` sets `shutting_down` and the **relay loop** honors it (mod.rs:3645-3651),
but `spawn_announcement_ticker` (3658) and `spawn_discovered_room_pruner` (3767) never
check the flag (grep confirms no reference past 3646). They keep ticking — reading the
DB, calling `broadcast_member_announce`, publishing — after `shutdown()`. During the F5
rekey window or a GUI in-process restart this races live DB access against
close/rekey (same class as the previously-fixed restart regression).
**Fix:** check `shutting_down` at the top of both loop bodies and return; or hold
`JoinHandle`s and `abort()` them in `shutdown()`.

#### M-4 · Unauthenticated `SessionKeyRequest` is an unthrottled reflection/amplification DoS  ✓ 3/3
**`crates/huddle-core/src/network/protocol.rs:218-220`; `network/mod.rs:973-982`; `app/mod.rs:4704-4714`, `:3414-3485`**

`SessionKeyRequest` is **absent from the MUST-be-signed list** (protocol.rs:42-67) and
the handler re-broadcasts a full `MemberAnnounce` (wrapped session key, pubkeys, ML-KEM
material) with no rate-limit or dedup. An attacker spams `SessionKeyRequest` on a room
topic and every member floods the topic with announces — amplification against the whole
room and the relay mailbox.
**Fix:** rate-limit/cooldown per (room, requester); coalesce announce responses; consider
requiring the requester to be a known member.

#### M-5 · Megolm inbound re-anchor (group) — see M-1; plus F5 non-atomic rekey  ✓ 2/3
**`crates/huddle-core/src/app/mod.rs:2495-2563`; `storage/mod.rs:68-80`; `storage/repo.rs:571-587`**

`change_master_passphrase` re-encrypts Megolm pickles row-by-row (one autocommit
`INSERT OR REPLACE` each) and runs the SQLCipher `PRAGMA rekey` **non-atomically**, with
no rollback on partial failure. A crash/error mid-rekey can leave pickles written under a
mix of old/new keys → unreadable sessions (message loss).
**Fix:** wrap the pickle re-encryption + key rotation in a single transaction (or a
staged write-new-then-swap), and verify-before-commit.

#### M-6 · Edits use receiver-local clock for last-write-wins → relay can revert content  ✓ 3/3
**`crates/huddle-core/src/app/mod.rs:5744-5844` (apply uses `now_unix_ms()` at 5824); dispatch `:4022-4068` drops `signed_at_ms`; `storage/repo.rs:1168-1185`**

The `Edit` is signed and carries `signed_at_ms`, but the apply path uses the **receiver's**
wall clock for LWW and discards the signed timestamp. A relay that reorders/replays a
signed `Edit` can make an older edit win → revert a message to attacker-chosen prior
content, fully attributable to the real author.
**Fix:** order edits by the signed `signed_at_ms` (tie-break on a deterministic id), not
receiver-local time; reject edits older than the currently-applied one.

#### M-7 · Accepting an invite silently demotes Tor below clearnet and adopts an unvalidated relay URL  ✓ 2/3
**`crates/huddle-core/src/app/mod.rs:6354-6372` (`set_clearnet_relay`); callers `crates/huddle/src/app.rs:4653`, `crates/huddle-gui/src/app.rs:1249`; `network/transport.rs:221-251`**

Accepting an invite calls `set_clearnet_relay` with the invite's relay URL — no
validation, no user consent — and globally reorders transport so clearnet outranks Tor.
A hostile invite **deanonymizes** a Tor-preferring user and pins them to an
attacker-controlled relay (metadata capture). See also M-9 (v1 unsigned invite).
**Fix:** validate the URL; never let an invite lower the transport-privacy floor without
explicit user confirmation; scope an invite's relay to that room, don't make it global.

#### M-8 · Unbounded reassembly-map growth via tiny `FileChunk`s → remote OOM  ✓ 3/3
**`crates/huddle-core/src/files/mod.rs:227-237`, `:295-340`; reachable `app/mod.rs:5043-5064`, `:7164-7206`**

`accept_chunk` accounts only bytes, not the number of in-flight reassembly buffers, and a
peer can open unlimited partial transfers with empty/tiny chunks → unbounded memory.
**Fix:** cap concurrent in-flight reassemblies per peer and total; evict stale partials;
require `FileOffer` (signed) before allocating a reassembly buffer (ties to L-x).

#### M-9 · v1 unsigned invite pins an attacker-controlled clearnet relay (deanonymization)  ✓ 3/3
**`crates/huddle-core/src/invite.rs:244-265`; adopt `crates/huddle/src/app.rs:4653`, `crates/huddle-gui/src/app.rs:1249`; TUI modal `crates/huddle/src/ui/modal.rs:1686-1740`**

The v1 invite branch is unsigned and unvalidated; the relay it carries is adopted
globally with no warning in the TUI accept modal. Overlaps M-7; called out separately
because the v1 format itself provides no integrity.
**Fix:** deprecate/refuse unsigned v1 invites for relay-pinning; require a signed invite
to set any transport; show the relay/onion the invite pins before acceptance.

#### M-10 · Banning never strips the `owner` role → banned co-owner keeps full admin  ✓ 3/3
**`crates/huddle-core/src/app/mod.rs:5095-5138` (BanMember), `:6220-6225` (is_owner), `:6850-6858`; `storage/repo.rs:442-467`, `:431-437`**

`BanMember` records a ban but doesn't remove the target's `owner` role. A banned co-owner
still passes `is_owner`, so they can delete-any, ban back, grant-owner, and set hostile
disappearing TTLs — the ban is cosmetic against owners.
**Fix:** on ban, revoke roles (delete from owners) atomically with the ban insert; have
`is_owner` exclude banned fingerprints.

#### M-11 · Single global DB mutex with unenforced `active_rooms → db` lock ordering  ⚒ manual
**`crates/huddle-core/src/storage/mod.rs` (`Arc<Mutex<Connection>>`); `app/mod.rs` (many `active_rooms.lock()` then `db` access)**

All storage funnels through one `Mutex<Connection>`; meanwhile `active_rooms` is a second
mutex frequently held across DB calls. The ordering is convention-only. Combined with the
many `.lock().unwrap()` sites, a single poisoned lock (from any panic under the lock)
becomes a process-wide DoS, and the global DB mutex serializes all I/O (scaling ceiling).
**Fix:** document & enforce a lock hierarchy; avoid holding `active_rooms` across DB
calls; consider a connection pool / `parking_lot` non-poisoning mutexes; replace
`.unwrap()` on locks with recovery.

### LOW  *(condensed — file:line and one-line impact each)*

| # | Finding | Location | Note |
|---|---|---|---|
| L-1 | F4 scheduled rotation re-wraps under the **unchanged** room passphrase → documented anti-harvest benefit not delivered for groups | `crypto/megolm.rs:341-351`; `app/mod.rs:3429-3432` | ✓1/1 |
| L-2 | Content-replay set GC'd after 90d but inbound sessions kept forever → old ciphertexts replay as fresh after the window | `storage/repo.rs:720,780-787`; `app/mod.rs:4768-4789` | ✓1/1 |
| L-3 | First-contact PQ downgrade: capability **absence** is unauthenticated → announce-suppression + classical-replay forces classical-only | `app/mod.rs:229-253,1472-1514`; `crypto/dm.rs:178-180` | ✓2/3 (documented residual) |
| L-4 | No minimum length / strength floor on master or room passphrase | `app/mod.rs:2468`; `crypto/passphrase.rs:37-57`; `keychain.rs:162-174` | ✓1/1 |
| L-5 | Crown-jewel seed materialized **un-zeroized** on the everyday DB load/save path (F6 incomplete) | `app/mod.rs:3371-3379`; `identity.rs:66-68`; `repo.rs:35-42` | ✓1/1 |
| L-6 | Decrypted Megolm session key returned as bare `Vec<u8>` → lands in un-zeroized `String`s | `crypto/passphrase.rs:74-87`; `app/mod.rs:4688-4692,5478-5486` | ✓1/1 |
| L-7 | Derived DM/room wrap keys deref'd out of `Zeroizing` into bare `Copy` arrays | `crypto/dm.rs:84-87,133,150`; `passphrase.rs:42`; `app/mod.rs:1521,5407,5475` | ✓1/1 |
| L-8 | Raw ML-KEM shared secret + 64-byte seed copied out of non-zeroizing temporaries | `crypto/pqc.rs:92-93,122,153` | ✓1/1 |
| L-9 | BIP39 recovery phrase persists in un-zeroized `String`/`Mnemonic` during decode; `bip39` dep lacks `zeroize` feature | `crypto/mnemonic.rs:28-31,46,55`; `Cargo.toml:87` | ✓1/1 |
| L-10 | At-rest master key, HKDF subkey, and `PRAGMA key/rekey` SQL strings never zeroized | `keychain.rs:162-186`; `storage/mod.rs:25,69`; `app/mod.rs` | ✓1/1 |
| L-11 | Data dir + encrypted DB + `keychain.salt` created with default (world-readable 0644) perms | `config.rs:205-207`; `storage/mod.rs:23`; `keychain.rs:130-148` | ✓1/1 |
| L-12 | No per-room cap on `room_messages`/`content_replay_seen` inserts → a member grows peers' DB/FTS unbounded | `storage/repo.rs:879-919,752-774` | ✓1/1 |
| L-13 | `save_identity` uses `INSERT OR REPLACE` on the single-row identity table → a re-call wipes `display_name`/`onboarding_seen` | `storage/repo.rs:35-42` | ✓1/1 |
| L-14 | Relay-client outbound queue unbounded after Hello → hostile/slow relay can OOM the client | `network/server.rs:214,311,320-365` | ✓2/3 |
| L-15 | `RoomAnnouncement` on the global topic has no per-field caps and no ingest rate-limit/dedup | `protocol.rs:127-171`; `network/mod.rs:961-972`; `app/mod.rs:3860-4002` | ✓1/1 |
| L-16 | Unauthenticated `/metrics` leaks live activity metadata (online users, msg volume, backlog) | `huddle-server/src/main.rs:485-531,460` | ✓2/3 |
| L-17 | Unbounded `memberships` growth (1000 rooms/Hello, repeatable, never GC'd) | `huddle-server/src/main.rs:779-786,1260-1266` | ✓1/1 |
| L-18 | Reactions have no ordering or replay dedup → reorder/replay flips reaction state | `app/mod.rs:5678-5737`; `storage/repo.rs:1091-1136` | ✓1/1 |
| L-19 | No swarm connection limits; unbounded peer-tracking maps in the libp2p task | `network/mod.rs:381-418,476-556,716-717,774-789` | ✓1/1 |
| L-20 | Pinned-cert `wss` path is dead code; baked-in clearnet relay is **not** cert-pinned | `network/server.rs:267-271`; `transport.rs:230,234`; `app/mod.rs:363` | ✓1/1 |
| L-21 | Integer underflow in invite freshness check on attacker-controlled `signed_at_ms` (`now - signed_at_ms`) | `invite.rs:351` | ✓1/1 |
| L-22 | `Delete` receive handler omits the banned-member filter present on every other content arm | `app/mod.rs:5847-5887` | ✓3/3 |
| L-23 | `Edit`/`Delete` mutate by `(room, client_msg_id)` without sender scope, while identity is `(room, sender, client_msg_id)` | `storage/repo.rs:1176-1230`; `schema.rs:362-364` | ✓1/1 |
| L-24 | F9 disappearing TTL is **retroactive** and physically purges all members' history, no floor, no per-message snapshot | `storage/repo.rs:1053-1066`; `app/mod.rs:5890-5930,3796-3812` | ✓1/1 |
| L-25 | Unauthenticated `FileChunk` injection enables targeted file-transfer DoS (no `FileOffer` gate) | `app/mod.rs` file-chunk path | ⚒ manual (ties M-8) |
| L-26 | Network metadata (peer multiaddrs, relay/onion URLs, fingerprints) written in cleartext to `huddle-gui.log` beside the encrypted DB | `crates/huddle-gui/src/main.rs:62-73` | ⚒ manual |
| L-27 | Latent poisoned-`Mutex` DoS: crypto `unwrap` under `active_rooms` relies on an unguarded cross-function invariant | `app/mod.rs` | ⚒ manual (ties M-11) |

### INFO

- **I-1 · F3 "safety number changed" alarm is effectively unreachable for real identity-key changes** ✓1/1 — `app/mod.rs:4034-4059`; `identity.rs:135-144`. The drift check fires on pubkey mismatch *for a fingerprint*, but the fingerprint is derived from the pubkey, so a changed key is a changed fingerprint → it presents as a new peer, not a drift alarm. The F3 UX path is largely dead for the threat it targets. (Borderline LOW; kept INFO pending a repro.)

---

## Part 2 — Code Critique (harsh)

### Architecture — the load-bearing debt

- **H-C1 · `AppHandle` is an 8,013-line god-object.** ⚒ manual — `app/mod.rs`. Crypto
  orchestration + network + storage + file transfer + the SAS state machine + UI-event
  fan-out all live on one struct with ~150 methods. It is the *only* public seam and it
  leaks internal storage-row and libp2p types across the boundary. This is the single
  biggest maintainability and security-review liability in the repo: every audit has to
  reason about one mutable object touched from many tasks (hence the `shutting_down`
  atomic patch, M-3, M-11). **Mandate a split:** `Identity`, `GroupCrypto`, `DmCrypto`,
  `Transport`, `Store`, `FileTransfer`, `Verification` as separate modules behind traits,
  with `AppHandle` reduced to a thin orchestrator.

- **H-C2 · The 2.0.1 headline security fix has zero regression test.** ⚒ manual —
  `tests/integration.rs`, `crypto/sas.rs`. The asymmetric-SAS PQ-capability-binding bug
  that *justified the entire 2.0.1 release* has no protocol/app-level test proving the
  attack is now rejected. A future refactor can silently reintroduce it. This is the most
  important missing test in the suite.

- **M-C1 · No trait/abstraction seams → the roadmap forces a rewrite.** ⚒ manual.
  Group crypto, DM key-agreement, storage, and transport are concrete types wired through
  `AppHandle`. Swapping Megolm for MLS, or adding a Double Ratchet, means rewriting the
  ~1,500-line message handler. There is nowhere to inject an alternative ratchet.

- **M-C2 · Identity is single-device by construction.** ⚒ manual — `identity.rs`. One
  Ed25519 seed is the sole root for all keys, and sessions are keyed by fingerprint with
  **no device dimension**. Multi-device (on the roadmap) cannot be added without reworking
  identity, session keying, the wire types, and the schema simultaneously.

- **M-C3 · DM key-agreement exposes only static, non-ratcheting derivations.** ⚒ manual —
  `crypto/dm.rs`. No per-DM session object → nowhere to add Double-Ratchet / DM forward
  secrecy without rewriting the app's wrap path. (DMs currently lack the per-message FS
  that the group path gets from Megolm.)

- **M-C4 · Wire protocol has no negotiated version.** ⚒ manual — `network/protocol.rs`.
  "Additive serde" only covers *optional fields*; any unknown envelope/message **variant**
  hard-fails to parse and is silently dropped (dispatch returns on `from_slice` error,
  mod.rs:4017). There is no version handshake, so 1.x↔2.x compatibility is untestable and
  a future breaking change has no graceful-degradation path. (No `cargo-semver-checks`
  either — but that's the CI effort's domain.)

- **M-C5 · Error taxonomy collapses crypto/auth failures into stringly-typed variants.**
  ⚒ manual — `error.rs` (27 lines). Every cryptographic/auth failure becomes
  `Session(String)` or `Other(String)`; a consumer that must distinguish "decrypt failed"
  from "transport failed" can only substring-match the `Display` text. **L-C1:** `Storage(#[from] rusqlite::Error)` leaks the SQLCipher backend across the public API,
  coupling every consumer to rusqlite. Introduce typed, matchable error variants
  (esp. an `Auth`/`Decrypt`/`Verify` family) and wrap the storage error.

### GUI — immediate-mode performance & a security-relevant modal bug

- **M-C6 · Peer edit/reaction spam → unbounded synchronous SQLite reloads on the egui UI
  thread (remote freeze).** ⚒ manual — `huddle-gui/src/model.rs`, `panes/chat.rs`. Remote
  input drives blocking DB reloads + per-frame whole-room re-sort/re-index/re-clone
  (reactions O(messages×reactions)). A malicious peer can freeze the GUI client — a
  remote DoS that also belongs in Part 1. **M-C7:** all `AppHandle` reads block the egui
  main thread; the 1 s tick re-pulls ~15 snapshots + every open room + attachments and
  runs FTS inline.
- **M-C8 · Modal queue evicts the OLDEST entry** ⚒ manual — `model.rs`. A flood of
  peer-raised modals can silently drop a **security alert** (TOFU key-change / forged
  invite). Security-relevant: combine with H-1/M-7 to suppress the very warning that would
  catch the attack. Evict newest-low-priority, never a security modal.
- **M-C9 · Master/room passphrases held & cloned in plain `String` (not `Zeroizing`)** in
  the GUI app/modal state ⚒ manual — `huddle-gui/src/app.rs`, and the TUI equivalent below
  (mirrors core L-4/L-6 hygiene gaps).
- **L-C2** SAS initiator modal can stick on "Waiting" if `SasCodeReady` races `ReqOk::TxId`
  (`model.rs`). **L-C3** `RestartApp` spawns a second process before the first releases the
  SQLCipher DB → lock contention/corruption risk (`app.rs`).

### TUI — confirmed quality issues  ✓ (judge-verified)

- **M-C10 · Master/room passphrases and the exported BIP39 seed sit in un-zeroized TUI
  modal/prompt state** — `huddle/src/app.rs`. Same crown-jewel-in-cleartext class as L-5/L-9.
- **L-C4 · `block`/`unblock`/`forget` peer errors are swallowed while the UI reports
  success** — `huddle/src/app.rs`. A failed block silently leaves the peer un-blocked.
- **L-C5 · SAS verification modal renders a `[c]ancel` affordance that does nothing** —
  `huddle/src/ui/modal.rs`. Users believe they cancelled a verification they didn't.
- **L-C6 · Ctrl+C inside text-input modals types a literal `c` into passphrase/seed
  fields** instead of cancelling — `huddle/src/input.rs`. Corrupts secret entry.

### Test suite — happy-path heavy, adversarial-light

268 test fns but the **negative/attack** properties are largely untested. Top gaps
(⚒ manual, recovered from the failed `judge:testing` agents):

- **The 2.0.1 SAS PQ-binding fix** (H-C2 above) — no regression test.
- **F2 content-replay** is untested at the layer where the defense runs (`app/mod.rs`).
- **The kick-rotates-key forward-secrecy test silently no-ops when mDNS is blocked**
  (`tests/integration.rs`) — it can pass without exercising the property.
- **The hottest untrusted parser** (inbound signed-envelope verify) and the **server
  `ClientMsg` handler** are **unfuzzed** (only 3 fuzz targets exist).
- **No forward-migration test** from a populated old-schema DB; the new `UNIQUE`-index
  migration is an untested startup-bricking footgun (`storage/mod.rs`, `schema.rs`).
- **Relay DoS/resource-limit defenses are entirely untested** (`huddle-server`).
- **F3 TOFU key-drift detection has no test** (and per I-1 may be dead).

The fact that the libp2p integration tests must run **serially** (flaky under parallel)
is itself a smell that real port/mDNS races are being papered over rather than isolated.

---

## Appendix A — Dependency-advisory triage: verified accurate

The 2.0.1 `.cargo/audit.toml` / `deny.toml` triage was checked against the code, not
just re-flagged:

| Advisory | Crate / path | Triage claim | Verdict |
|---|---|---|---|
| RUSTSEC-2026-0119 (O(n²) name-compression DoS) | hickory-proto via libp2p-mdns | LAN-scoped, mDNS opt-in, no upstream fix (libp2p-mdns pins hickory ^0.25) | **Accepted** — reachable only on the opt-in LAN path; relay/onion is default |
| RUSTSEC-2026-0118 (NSEC3 unbounded loop DoS) | hickory-proto via libp2p-mdns/-dns | same LAN/opt-in scope, no fix | **Accepted** |
| RUSTSEC-2023-0071 (rsa Marvin timing) | rsa via arti/tor-llcrypto | arti is feature-gated **default-off**; huddle does no RSA decryption | **Accepted** — not in shipped default builds |

Plus `cargo audit` unmaintained warnings (`proc-macro-error2`, `paste`, `bincode`) — deep
transitive, low priority. **Recommendation:** keep the `ignore` list under review on every
dependency bump; track libp2p for a hickory ≥0.26.1 bump to retire the two DoS items.

## Appendix B — Method, provenance & what was de-prioritized

- 99 raw findings → **39 confirmed by adversarial vote** before the session-limit
  interruption; **60 rejected** (refuted by ≥2 skeptics — plausible-but-wrong claims
  filtered out, e.g. several "downgrade" and "nonce-reuse" claims that the code already
  guards). **31 were orphaned by verifier timeouts** and adjudicated by hand here; the
  security-critical ones (H-1, M-2, M-3, M-11, L-25/26/27) were confirmed by direct code
  reading with citations, and the architecture/test critiques were confirmed against
  established repo facts.
- Zero `unsafe` blocks in the workspace (verified) — no memory-safety surface to audit.
- Items the skeptics **rejected** (not in this report) included claims of HKDF combiner
  weakness, ML-KEM decapsulation oracle leakage, SQL injection in the FTS path, and
  SAS emoji bias — each refuted by reading the actual implementation.

### Suggested fix order (highest leverage first)
1. **H-1** (reject `Plain`/unsigned content in encrypted rooms) — small, closes a
   sender-authenticity hole.
2. **H-2 / M-4 / M-1 / M-6** relay-weaponizable integrity bugs (rate-limit + global cap;
   sign/throttle `SessionKeyRequest`; compare/merge inbound sessions; sign-timestamp LWW).
3. **M-2 / M-3** delivery & lifecycle correctness (ACK-after-persist; honor shutdown).
4. **M-10 / L-22 / L-24** authorization correctness (strip owner on ban; ban-filter on
   `Delete`; disappearing-TTL floor + non-retroactive).
5. The **zeroization sweep** (L-5..L-11, M-C9/M-C10) and **H-C2** (regression-test the
   2.0.1 fix) before further crypto work.

*Generated by recovering and manually completing an interrupted 21-agent audit run
(`wf_6276efd1-832`) against huddle 2.0.1.*
