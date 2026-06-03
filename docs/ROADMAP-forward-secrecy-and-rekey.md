# ROADMAP — Forward secrecy, DB re-key, and retention/GC

Status: design / not yet implemented. This document specifies three deferred
hardening items for huddle. Each section is written to be picked up directly by
an implementer: it cites the exact files and functions that exist today, names
the new functions/columns/messages to add, and lists the migration and test
work. File/line references are against the tree at the time of writing
(`crates/huddle-core` and `crates/huddle-server`).

Cross-cutting conventions used below:
- "Megolm" = `vodozemac::megolm` group sessions wrapped by
  `crate::crypto::megolm::RoomCrypto`.
- "persist key" = the 32-byte HKDF subkey under which session pickles are
  encrypted at rest (`RoomCrypto.persist_key`, derived in
  `app::Huddle::start_with_options` via
  `storage::keychain::derive_subkey(mk, b"megolm-persist")`).
- "master key" = the 32-byte Argon2id output of
  `storage::keychain::derive_master_key`, used both as the SQLCipher
  `PRAGMA key` (`storage::open_db`) and as HKDF input material for the persist
  key.
- Wire messages live in `crate::network::protocol::RoomMessage`; signed
  envelopes go through `crypto::sign_message` / `crypto::verify_signed`.

---

## 1. Forward secrecy at the room-key layer

### 1.1 Problem statement

Two distinct weaknesses, both meaning that compromising a key *now* exposes
traffic from the *past* (no forward secrecy) and/or the *future* after a
membership change (no post-compromise security):

1. **Group rooms (Megolm).** A member's outbound Megolm session is created once
   (`RoomCrypto::new_for_room`) and only ever replaced on an explicit
   passphrase rotation or a ban (`app::Huddle::rotate_room`). When a member
   simply leaves, or is removed without a passphrase rotation, every remaining
   member keeps using the *same* outbound session, and the departed member
   still holds the `InboundGroupSession` they were given at join time. That
   inbound session ratchets forward deterministically, so the departed member
   can decrypt every subsequent message any sender produces from that
   un-rotated session. Rotation is also coarse: it is tied to a *human* passphrase
   change, not to the membership event.

2. **DMs.** The 1-1 DM key is a pure function of the two long-term Ed25519
   identities and the room id (`crypto::dm::derive_dm_key`): `HKDF(X25519-DH(our
   seed, partner pubkey), info = room_id)`. It is fully deterministic and never
   changes for the life of the contact. Compromise of either party's identity
   seed at any future time re-derives the *single* DM key and decrypts the
   entire DM history (all of it is encrypted under one Megolm session seeded
   from that one key). There is zero forward secrecy and zero
   post-compromise security for DMs.

### 1.2 Current behavior (exact files/functions)

- `crates/huddle-core/src/crypto/megolm.rs`
  - `RoomCrypto::new_for_room` (~L43): one `GroupSession::new` per room, persisted.
  - `RoomCrypto::encrypt` (~L124): advances and persists the outbound ratchet; never rotates.
  - `RoomCrypto::add_inbound_session` (~L169): installs a peer's `SessionKey` as an `InboundGroupSession`; once installed it is never revoked.
  - `RoomCrypto::our_session_key_b64` (~L198): exports the *current* outbound session key (the thing handed to joiners).
- `crates/huddle-core/src/app/mod.rs`
  - `rotate_room` (~L5039): the ONLY place a fresh outbound session is minted post-join. Derives a new Argon2id `passphrase_key` from a new salt, replaces `room.crypto` with a brand-new `RoomCrypto`, broadcasts a signed `RoomMessage::RotateRoomKey { rotator_fingerprint, new_salt }`, then re-`broadcast_member_announce`.
  - `accept_rotation` (~L5101): peers derive the new `passphrase_key` from the announced salt and emit a `SessionKeyRequest`.
  - `RotateRoomKey` receive arm (~L3344): verifies the signer == claimed rotator, then surfaces `AppEvent::RotationRequested` to the UI (rotation is operator-driven, not automatic).
  - Ban path: `rotate_room` is invoked after a ban (search `RotateRoomKey`/ban around L4624) — the only membership event that triggers a rekey, and only because a human/owner action drives it.
- DM key: `crates/huddle-core/src/crypto/dm.rs::derive_dm_key` (whole file). One static key per pair, forever.
- Key distribution primitive: `RoomMessage::MemberAnnounce { wrapped_session_key: Option<String>, .. }` (`network/protocol.rs` ~L169) carries `passphrase::wrap(our_session_key, room_passphrase_key)`. `SessionKeyRequest` (~L190) asks existing members to re-announce. This is the transport we reuse for epoch distribution.

### 1.3 Proposed design

#### A. Epoch-based Megolm rotation on membership change

Introduce an explicit, monotonically increasing **epoch** per room. Every
outbound Megolm session is bound to an epoch; a membership *removal* (leave,
ban, kick) bumps the epoch and forces every remaining member to mint a fresh
outbound session and redistribute it only to the *current* roster.

1. **Epoch state.**
   - New column `rooms.key_epoch INTEGER NOT NULL DEFAULT 0` (migration, §1.5).
   - New column `room_megolm_sessions.epoch INTEGER NOT NULL DEFAULT 0` so a
     session pickle records which epoch it belongs to. Outbound sessions from a
     superseded epoch are deleted after a grace window; inbound sessions from a
     superseded epoch are *retained read-only* (so history written in the old
     epoch is still decryptable locally) but never re-keyed forward.
   - Extend `StoredMegolmSession` (`storage::repo`) and
     `RoomCrypto` with an `epoch: u64` field; thread it through
     `new_for_room` / `load` / `persist_outbound` / `save_megolm_session`.

2. **Rotation trigger.** Add `app::Huddle::rotate_for_membership_change(room_id,
   reason)` invoked from the existing membership-removal sites:
   - the `MemberLeave` receive arm (`app/mod.rs` ~L3375, where we currently
     just `room.members.remove`),
   - the ban path (already rotates — switch it to the epoch path),
   - kick/own-leave cleanup.
   Membership *additions* do NOT bump the epoch (a joiner legitimately receives
   the current session); only removals do. This keeps "join then read backward"
   working while guaranteeing a departed member cannot read forward.

3. **New outbound session, scoped distribution.**
   `rotate_for_membership_change` mints `RoomCrypto::rotate_outbound()` (new
   method: replaces `self.outbound` with `GroupSession::new(...)`, increments
   the in-memory epoch, persists with the new epoch, schedules the old outbound
   pickle for deletion). It then distributes the new `our_session_key_b64()`
   **only to the current roster**.
   - Reuse `MemberAnnounce.wrapped_session_key`, but stop wrapping the group
     session under a *room-wide passphrase key* (which a departed member still
     knows). Instead wrap it **per recipient** under the pairwise DM key
     (`derive_dm_key(our seed, recipient pubkey, dm_room_id)`), so a removed
     member — who is no longer a recipient — receives nothing decryptable. Add
     `RoomMessage::EpochKeyShare { room_id, epoch, recipient_fingerprint,
     wrapped_session_key_b64 }` (signed). The passphrase-wrapped form stays
     only for the *initial bulk join* of brand-new encrypted rooms; all
     post-join rekeys go per-recipient.

4. **Receive arm.** New `EpochKeyShare` handler: if `recipient_fingerprint ==
   our_fp` and `epoch > our stored room epoch`, unwrap with our DM key for the
   sender, `add_inbound_session`, and advance `rooms.key_epoch`. Messages tagged
   with a stale epoch are still decryptable (old inbound sessions retained);
   messages we *send* always use the newest epoch's outbound session.

5. **Message epoch tag.** Add an `epoch` field to the per-message envelope
   (where `session_id` already travels) so a receiver picks the right inbound
   session deterministically and so we can detect "sender is behind" and re-emit
   an `EpochKeyShare`.

This gives **post-compromise security on removal** (departed member is cut off
from all future traffic) while preserving local readback of history. It does
*not* claim per-message forward secrecy within an epoch — Megolm is a forward
ratchet, not a double ratchet — but it bounds exposure to a single epoch.

#### B. Ratcheting / ephemeral-DH for DMs

Replace the single static DM key with a forward-secret scheme. Two options,
recommended in order:

- **Preferred — adopt a double-ratchet for DMs** by promoting DMs off the
  shared-Megolm path onto `vodozemac::olm` (already a dependency family),
  which gives a Signal-style Double Ratchet (DH ratchet + symmetric chain
  ratchet) with both forward secrecy and post-compromise security. The static
  `derive_dm_key` output becomes only the *bootstrap* shared secret used to
  establish the first Olm session (X3DH-lite: long-term identity + an ephemeral
  prekey exchanged in the first two `MemberAnnounce`s). Each DM message then
  carries a ratchet header; compromise of the identity seed no longer unlocks
  past messages because per-message keys are deleted after use.

- **Lighter-weight fallback — ephemeral-DH epochs for DMs.** Keep Megolm but
  add an ephemeral X25519 keypair per side, rotated on a schedule (every N
  messages or T hours). The DM "room key" becomes `HKDF(static_dh ||
  ephemeral_dh, info = room_id||epoch)`; each side advertises a new ephemeral
  pubkey in a signed `RoomMessage::DmRatchetStep { epoch, ephemeral_pubkey_b64 }`
  and discards the previous ephemeral secret. This yields forward secrecy at
  epoch granularity without a full double-ratchet implementation. It is strictly
  weaker than option 1 (no per-message PCS) but a much smaller change and reuses
  the epoch machinery from §A.

Whichever is chosen, `derive_dm_key`'s salt is already versioned
(`b"huddle-dm-key-v1\0"`); bump to `-v2` for the bootstrap derivation so a v1
and v2 client can't silently disagree on key material.

### 1.4 Affected code

- `crypto/megolm.rs`: add `epoch` field + `rotate_outbound()`; thread epoch through persist/load.
- `crypto/dm.rs`: add bootstrap derivation (`-v2` salt) and, for option A, the Olm session setup helpers; for option B, the `HKDF(static||ephemeral)` path.
- `network/protocol.rs`: add `EpochKeyShare`, an `epoch` field on the message envelope, and (option A) Olm prekey fields on `MemberAnnounce`, or (option B) `DmRatchetStep`.
- `app/mod.rs`: `rotate_for_membership_change`; call it from `MemberLeave` (~L3375), ban, kick, leave; new receive arms; epoch-aware send path in the encrypt routine; replace the room-wide-passphrase wrap on post-join rekeys with per-recipient DM-key wrap.
- `storage/schema.rs` + `storage/repo.rs`: new columns + epoch in `StoredMegolmSession`; pruning of superseded outbound sessions.

### 1.5 Migration / compat concerns

- Schema: append `ALTER TABLE rooms ADD COLUMN key_epoch INTEGER NOT NULL DEFAULT 0;` and `ALTER TABLE room_megolm_sessions ADD COLUMN epoch INTEGER NOT NULL DEFAULT 0;` to `schema::MIGRATIONS` (append-only — never reorder; see `run_migrations`). Existing rows back-fill to epoch 0, which is correct: everything pre-upgrade is "epoch 0".
- Wire compat: `EpochKeyShare` / `DmRatchetStep` / the new envelope `epoch` field are additive. A new client talking to an old client must fall back to the legacy un-epoched behavior when the peer never advertises an epoch. Gate on a capability bit in `MemberAnnounce` (e.g. an `epoch_capable: bool`, defaulting false via serde) so mixed-version rooms degrade gracefully rather than dropping messages.
- DM v1→v2: a v2 client opening an existing DM with a v1 peer must keep deriving the v1 static key until both ends signal v2 (capability bit), then perform a one-time bootstrap to the ratchet. Historic v1 messages stay decryptable under the retained v1 key.
- Departed-member readback: by design, after a removal the departed member loses future access. Make sure their *own* locally-stored history (inbound sessions from before the epoch bump) is retained so their UI doesn't blank out past conversations.

### 1.6 Test plan

- Unit (`crypto/megolm.rs`): `rotate_outbound` produces a new `session_id`/epoch; old inbound sessions still decrypt old ciphertext; new ciphertext only decrypts with the new session.
- Unit (`crypto/dm.rs`): ratchet/ephemeral step advances key; a key captured at epoch N cannot decrypt epoch N+1 ciphertext (forward secrecy assertion); commutativity preserved across a step.
- Integration (`app`): three-member room, member C leaves → assert A's post-leave message is decryptable by B but NOT by a `RoomCrypto` reconstructed from C's retained inbound session (i.e. C is cut off). Assert A/B's history written before the leave is still readable.
- Mixed-version: old-client (no epoch capability) ⇄ new-client round-trip still delivers messages.
- Property/fuzz: random interleavings of join/leave/rotate never wedge the epoch cursor (monotonic, no gaps that strand a member without a current session).

---

## 2. Full DB re-key on master-passphrase change

### 2.1 Problem statement

There is no implemented "change my master passphrase" path. The master key is
established once at launch and used as both the SQLCipher `PRAGMA key` and the
HKDF input for the Megolm persist key. A user who wants to rotate their
passphrase has no safe operation: a naive re-derive would (a) leave the
SQLCipher database still encrypted under the *old* key (so the new passphrase
wouldn't open it next launch), (b) leave every Megolm session pickle wrapped
under the *old* persist subkey (unreadable after rekey), and (c) leave old key
material resident in memory because nothing is zeroized.

### 2.2 Current behavior (exact files/functions)

- `crates/huddle-core/src/storage/keychain.rs`
  - `derive_master_key` (~L53): Argon2id(passphrase, keychain salt) → 32-byte master key.
  - `derive_subkey` (~L71): HKDF(master) → persist subkey.
  - `load_or_create_salt` (~L33): persists `keychain.salt` once; a rekey that changes the salt would orphan the old DB.
- `crates/huddle-core/src/storage/mod.rs`
  - `open_db` (~L22): runs `PRAGMA key = "x'<hex>'"` once at open, with a sentinel `SELECT count(*) FROM sqlite_master` to detect a wrong key. There is no `PRAGMA rekey`.
- `crates/huddle-core/src/app/mod.rs`
  - `start_with_options` (~L400): derives `session_persist_key` from the master key, opens the DB, then **drops the master key** — `Huddle` only retains the *subkey* (`session_persist_key`, struct field ~L230), not the master key. So even a rekey routine cannot re-derive subkeys without re-prompting for the current passphrase.
  - `go_dark` (~L5346): the existing pattern for "verify the master passphrase" (re-derive subkey, `ct_eq_32` against the in-memory one). Reuse this verification shape.
  - There is **no** `set_master_passphrase` / `change_master_passphrase` anywhere (confirmed: only `has_master_passphrase`, `rotate_room`, `go_dark`, `generate_join_passphrase` exist). This item is net-new.
- Zeroization today: `crypto::passphrase::derive_key_zeroizing` and `crypto::dm` wipe *short-lived* derivations, but `session_persist_key: [u8; 32]` on `Huddle`, the `passphrase_key: Option<[u8;32]>` on each `ActiveRoom`, and the master key in `start_with_options` are plain arrays with no `Drop`/zeroize.

### 2.3 Proposed design

Add `app::Huddle::change_master_passphrase(current: &str, new: &str) -> Result<()>`
performing an atomic three-part rekey:

1. **Verify current.** Re-derive `current` against `load_or_create_salt()` and
   `ct_eq_32` the resulting subkey against `self.session_persist_key`, exactly
   as `go_dark` does. Reject on mismatch before touching anything.

2. **SQLCipher PRAGMA rekey.** Derive the new master key. Because the keychain
   salt feeds the master KDF, decide salt policy:
   - Keep the salt stable (simplest) so only the passphrase changes the key; OR
   - Rotate the salt too (stronger) by writing a *new* salt file only after the
     DB rekey + persist re-wrap both succeed.
   Then on the live connection run:
   ```sql
   PRAGMA rekey = "x'<new_master_key_hex>'";
   ```
   `PRAGMA rekey` re-encrypts every page in place; it must run on the same open
   connection (`Db = Arc<Mutex<Connection>>`) while holding the lock, and
   should be wrapped so WAL is checkpointed first (`PRAGMA wal_checkpoint(TRUNCATE)`)
   to avoid a rekey racing the WAL. Verify with the same sentinel query
   `open_db` uses.

3. **Re-wrap persisted material under the new persist subkey.** The Megolm
   session pickles are encrypted with `derive_subkey(master, b"megolm-persist")`,
   which changes when the master key changes. For every room and every stored
   session: decrypt the pickle with the *old* persist key
   (`GroupSessionPickle::from_encrypted` / `InboundGroupSessionPickle::from_encrypted`),
   re-encrypt with the *new* persist key (`.pickle().encrypt(new_key)`), and
   `save_megolm_session` the result. Add a `RoomCrypto::rewrap(old, new)` helper
   and/or a `storage::repo::rewrap_all_megolm_sessions(db, old, new)` batch that
   does this inside a single SQL transaction so a crash can't leave a mix of
   old- and new-wrapped rows. Any session whose pickle won't decrypt under the
   old key is logged and skipped (same resilience policy as `RoomCrypto::load`).

4. **Atomicity / ordering.** Sequence: checkpoint WAL → re-wrap all session
   pickles in a tx (still under old persist key for SQLCipher, but the *pickle*
   inner crypto changes) → `PRAGMA rekey` the file → write the new salt (if
   rotating) → swap `self.session_persist_key` and any cached room
   `passphrase_key`s to the new subkey in memory. If `PRAGMA rekey` fails after
   the re-wrap, the re-wrapped pickles are encrypted under the new persist key
   but the file is still encrypted under the old SQLCipher key — recoverable by
   retrying the rekey. Document this recovery path; the dangerous direction
   (rekey succeeds, re-wrap fails) is avoided by ordering re-wrap *before*
   rekey.

5. **Zeroization.** Convert in-memory long-lived key material to zeroize-on-drop:
   - Change `Huddle.session_persist_key: [u8;32]` → `Zeroizing<[u8;32]>` (or a
     newtype that derives `ZeroizeOnDrop`). `Copy` must be dropped, so audit the
     few read sites (they all pass `self.session_persist_key` by value into
     `RoomCrypto::new_for_room`/`load`; change those to `*` / clone-into-array).
   - Same for `ActiveRoom.passphrase_key`.
   - In `change_master_passphrase` and `start_with_options`, hold the master key
     in `Zeroizing<[u8;32]>` and explicitly drop the old subkey after the swap.
   - Add `ZeroizeOnDrop` to any new struct that stashes a master key.

### 2.4 Affected code

- `storage/mod.rs`: add `rekey_db(conn, new_master_key)` (checkpoint + `PRAGMA rekey` + sentinel).
- `storage/keychain.rs`: optional `rotate_salt()` that writes a new `keychain.salt` atomically (temp file + rename).
- `storage/repo.rs`: `rewrap_all_megolm_sessions(db, old_persist, new_persist)` in one tx.
- `crypto/megolm.rs`: `RoomCrypto::rewrap(old, new)` (or rely on the repo batch + reload).
- `app/mod.rs`: `change_master_passphrase`; convert `session_persist_key`/`passphrase_key` to zeroizing types; thread the master key (or a re-derivable handle) so subkeys can be recomputed.
- TUI/GUI: a Settings action calling `change_master_passphrase` (out of scope here but note the call site).

### 2.5 Migration / compat concerns

- No schema migration needed — this is a runtime operation. But it touches every
  `room_megolm_sessions` row, so it must tolerate the resilience cases
  `RoomCrypto::load` already handles (corrupt/undecryptable pickles skipped, not fatal).
- `--no-master-passphrase` mode (`session_persist_key == [0u8;32]`, DB
  unencrypted): `change_master_passphrase` should refuse, or offer a separate
  "enable encryption" path that runs `PRAGMA rekey` from no-key to a key. Treat
  enabling encryption as a distinct, clearly-labeled operation.
- Backward compat: a DB rekeyed by a new client simply requires the new
  passphrase at next launch; the on-disk format is unchanged (still SQLCipher).
  An older client binary opening it still works as long as the user types the
  new passphrase.
- Crash safety: document that an interrupted rekey is recoverable by re-running
  with the current (old) passphrase, because re-wrap precedes rekey.

### 2.6 Test plan

- Unit (`storage`): open encrypted DB, write a row, `rekey_db` to a new key,
  reopen with the new key → row present; reopen with the old key → sentinel
  fails with the "wrong master passphrase" error.
- Unit (`repo`): seed N Megolm sessions under persist key A, `rewrap_all` to B,
  reload with B → all sessions restore; reload with A → all skipped (warned).
- Integration (`app`): `change_master_passphrase(good, new)` → drop `Huddle` →
  restart with `new` → rooms + sessions decrypt and a previously-sent message
  still decrypts. `change_master_passphrase(wrong, new)` → `Err`, DB untouched.
- Crash injection: simulate failure after re-wrap but before `PRAGMA rekey`
  (return early) → assert re-running with the *old* passphrase recovers.
- Zeroization: a focused test (or `#[cfg(test)]` hook) asserting the old
  subkey buffer is zeroed after the swap (e.g. compare against a captured copy
  by Drop instrumentation).

---

## 3. Age-based retention / GC

### 3.1 Problem statement

Nothing prunes by age. On the client, `room_messages` and `room_attachments`
grow without bound (and attachment cache files on disk with them). On the relay
(`huddle-server`), the `mailbox` is drained on flush but **`memberships` is
never deleted** and per-fingerprint mailbox rows are only trimmed by *count*
(newest 500), never by *age* — a fingerprint that never reconnects keeps 500
rows forever, and stale memberships accumulate indefinitely. This is a
privacy and disk-growth problem: an attacker who later compromises the device or
relay recovers arbitrarily old data that the user reasonably believed was
ephemeral.

### 3.2 Current behavior (exact files/functions)

- Client, `crates/huddle-core/src/storage/repo.rs`
  - `insert_room_message` (~L581), `get_room_messages` (~L633), `search_room_messages` (~L601): unbounded by age.
  - `upsert_attachment` (~L1307), `list_room_attachments` (~L1398), `delete_attachment` (~L1445): delete is manual/per-file only. No sweep.
  - Schema (`storage/schema.rs`): `room_messages.sent_at`, `room_attachments.created_at` exist (good — the timestamps we need are already there). `idx_room_messages_room` is on `(room_id, sent_at)`.
- Client, `app/mod.rs`: the only existing age-based cleanup is the friend/contact-request TTL sweeps (`PENDING_FRIEND_REQUEST_TTL_SECS`, 3 days) referenced in `schema.rs` around the `pending_friend_requests` table — a good template for the GC sweep shape.
- Relay, `crates/huddle-server/src/main.rs`
  - `migrate` (~L400): `memberships` + `mailbox` (with `created_at`).
  - `enqueue` (~L434): trims `mailbox` to `MAX_MAILBOX_PER_FP` (=500, count-based) per recipient.
  - `take_mailbox` (~L450): drains then `DELETE FROM mailbox WHERE fingerprint = ?` — only on a successful flush; offline recipients never get pruned by age.
  - `memberships`: `add_membership` only ever `INSERT OR IGNORE`; the single `DELETE` is the explicit leave path (~L299). No GC.

### 3.3 Proposed design

Configurable retention with conservative, privacy-preserving defaults. Prefer
**disabled-by-default destructive deletion** with clearly documented opt-in
windows, so an upgrade never silently eats a user's history.

**Client.**
- Config (`crate::config`, persisted in `config.toml`): `message_retention_days:
  Option<u32>` (None = keep forever, the default), `attachment_retention_days:
  Option<u32>` (None = forever), and `attachment_cache_max_bytes: Option<u64>`
  for a size cap on the on-disk cache. Surface in Settings.
- New repo functions:
  - `prune_room_messages_older_than(db, cutoff_unix) -> usize`
  - `prune_attachments_older_than(db, cutoff_unix) -> Vec<cache_path>` (returns
    cache paths so the caller can `wipe_file` them — reuse the zeroing wiper
    from `app::wipe_file`, factored into a shared util).
  - Run both inside one transaction per sweep.
- Scheduling: a single startup sweep plus a low-frequency background task (e.g.
  every 6 h) in `app`, modeled on the pending-request TTL sweep. Deleting a
  message must also delete dependent `room_attachments` (the FK is
  `ON DELETE CASCADE` from `rooms`, but messages→attachments is via
  `message_id` and not enforced — delete attachments explicitly by age too, and
  wipe their cache files).
- Safety: never prune the *current* outbound/inbound Megolm sessions or room
  rows — retention applies to `room_messages` / `room_attachments` payloads
  only, not key material. (Key GC for superseded epochs is handled by §1, with
  its own grace window.)

**Relay (`huddle-server`).**
- Add constants: `MAILBOX_TTL_SECS` (default e.g. 14 days) and
  `MEMBERSHIP_TTL_SECS` (default e.g. 30 days). Make them overridable via env
  vars read in `main` (the server already reads config from env-style args).
- Add `created_at`/`last_seen` to `memberships` (migration in `migrate`):
  `ALTER TABLE memberships ADD COLUMN last_seen INTEGER` is awkward with the
  existing composite PK, so instead add the column with a default and back-fill
  `now_unix()` on the next `add_membership` touch.
- Add a periodic sweeper task (spawned in `main`, runs hourly):
  - `DELETE FROM mailbox WHERE created_at < ?cutoff` (age cutoff = now −
    `MAILBOX_TTL_SECS`).
  - `DELETE FROM memberships WHERE last_seen < ?cutoff` (now −
    `MEMBERSHIP_TTL_SECS`), refreshing `last_seen` whenever a fingerprint
    re-announces in `handle_client_msg`.
- Keep the existing count-based `MAX_MAILBOX_PER_FP` trim as a complementary
  bound; the age sweep handles the "never reconnects" case the count trim misses.

### 3.4 Affected code

- Client: `config.rs` (new fields), `storage/repo.rs` (prune fns), `app/mod.rs` (startup + periodic sweep, shared `wipe_file` util), Settings UI (call sites).
- Relay: `huddle-server/src/main.rs` — `migrate` (add `last_seen` / `created_at`), `add_membership` (refresh `last_seen`), new `sweep_expired()` + a `tokio::spawn` loop in `main`, new TTL constants/env.

### 3.5 Migration / compat concerns

- Client schema: timestamps already exist; no migration strictly required for
  messages/attachments. If a `last_pruned_at` bookkeeping column is wanted, add
  it append-only to `MIGRATIONS`.
- Relay schema: adding `last_seen`/`created_at` to `memberships` is additive;
  `CREATE TABLE IF NOT EXISTS` in `migrate` won't alter an existing table, so
  use explicit `ALTER TABLE ... ADD COLUMN` guarded by a `PRAGMA table_info`
  check (the relay has no `user_version` migration framework — add a minimal one
  or do the idempotent column-exists check).
- Defaults: retention OFF by default on the client (no surprise data loss on
  upgrade). Relay TTLs ON by default (the relay is a transient queue, not an
  archive — but pick generous windows, 14/30 days, and make them env-tunable so
  the operator can extend).
- Irreversibility: deletion is permanent and attachment cache files are zeroed
  (`wipe_file`) before unlink. Document this prominently in Settings copy.

### 3.6 Test plan

- Unit (`repo`): insert messages with `sent_at` straddling a cutoff →
  `prune_room_messages_older_than` deletes only the older ones; returns count.
- Unit (`repo`): attachments older than cutoff are returned with their cache
  paths and removed from the table; a temp cache file passed through the wiper is
  zeroed then unlinked.
- Integration (`app`): seed old + new messages, run the sweep, assert old gone /
  new kept / key material untouched / room still loads.
- Relay: insert mailbox + membership rows with old `created_at`/`last_seen`, run
  `sweep_expired`, assert expired rows gone and fresh rows kept; re-announce
  refreshes `last_seen` so an active member is never swept.
- Config: retention=None (default) ⇒ sweep is a no-op (regression guard against
  accidental data loss).

---

## Suggested sequencing

1. Item 2 (DB re-key + zeroization) first — smallest blast radius, no wire
   changes, and it establishes the zeroizing-key-type plumbing the other items
   benefit from.
2. Item 3 (retention/GC) next — additive, no crypto changes, immediate privacy
   win on both client and relay.
3. Item 1 (forward secrecy) last and behind a capability flag — largest change,
   needs the epoch schema and a mixed-version migration story; ship the Megolm
   epoch rotation (§1.3.A) before the DM ratchet (§1.3.B).
