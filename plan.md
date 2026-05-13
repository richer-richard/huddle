# Huddle Roadmap

Phase 1 (current) ships a LAN-only TUI chat client built around
**rooms**: anyone can start one, others on the network see and join
it, and rooms can be public or encrypted. Mesh-based gossipsub
broadcasts; rooms survive their original creator leaving. Megolm
group sessions for encryption, with session keys wrapped by an
Argon2id-derived passphrase key.

What's documented here is what comes next, in priority order.

---

## Phase 2 — Media attachments (images, audio, video, files)

The fundamental challenge: terminals can't render videos and can only
sometimes render images. So the design is **transfer-first**, with
optional inline preview when the terminal supports it.

### Wire protocol

A new gossipsub message type sent over the existing per-room topic:

```rust
RoomMessage::FileOffer {
    sender_fingerprint: String,
    file_id: String,        // SHA-256 hash of the content
    name: String,
    size_bytes: u64,
    mime: Option<String>,
    // For encrypted rooms: the file key (32 bytes) is wrapped with
    // the same Megolm session as text messages.
    encrypted_meta: Option<EncryptedFileMeta>,
}

RoomMessage::FileChunk {
    sender_fingerprint: String,
    file_id: String,
    chunk_index: u32,
    total_chunks: u32,
    // 64 KiB chunks
    data: Vec<u8>,   // base64 in JSON
}
```

Chunked over gossipsub. For Phase 2 we'll use a 1 MiB hard limit per
file to stay within gossipsub's reasonable message budget; larger
files defer to Phase 3 (dedicated libp2p streams via the
`request-response` protocol or raw streams).

### Files to add

- `crates/huddle-core/src/files/mod.rs` — `FileManager`: track
  outbound + inbound transfers, reassemble chunks, persist to disk
- `crates/huddle-core/src/files/encryption.rs` — wrap a file key with
  the room's Megolm session before sharing; encrypt the file with
  ChaCha20-Poly1305 (separate from message encryption to keep the
  Megolm ratchet from advancing on every chunk)
- `crates/huddle-core/src/storage/repo.rs` — new `room_attachments`
  table: (id, room_id, message_id, name, mime, size, local_path,
  status [pending/complete/failed])
- `crates/huddle-tui/src/ui/attach_modal.rs` — file picker modal
  triggered by `^A` in a room
- `crates/huddle-tui/src/ui/room.rs` — render file references as
  `[file  filename.ext  4.2 MB  ████░░  47%]` with `^O` to open the
  focused message's attachment via the system default opener
  (`open` on macOS, `xdg-open` on Linux)

### Storage

Files are saved to `<data_dir>/files/<room_id>/<file_id>__<name>` —
keeping the original name (after sanitization) for `open` to pick
the right app.

### Optional inline preview (later)

The `ratatui-image` crate detects Kitty/Sixel/iTerm2 graphics
protocols and renders inline. Defer until file transfer is solid.
Audio/video stay external — `open` does the right thing.

### Effort

~800-1000 lines split across core + TUI. About 4-5 commits.

---

## Phase 3 — Member rotation / removal

Right now anyone with a passphrase keeps the Megolm session key
forever. There's no way to "kick" someone or to ensure past members
can't decrypt new messages.

### Approach

When the room creator (or, in mesh mode, any current member)
initiates a rotation:

1. All current members generate fresh outbound Megolm sessions
2. New session keys are wrapped with a NEW passphrase (or rotated
   key) and broadcast
3. Old sessions are retained only for decrypting historic messages

### Files

- `crates/huddle-core/src/room/rotation.rs` — orchestrate rotation
  events
- `crates/huddle-core/src/network/protocol.rs` — new `RotateRoomKey`
  RoomMessage variant
- `crates/huddle-tui/src/ui/modal.rs` — rotation confirmation modal,
  triggered by a new key binding (`^R` in a room)

### Effort

~300 lines. One commit.

---

## Phase 4 — At-rest security & key derivation

- Replace `rusqlite` with SQLCipher (feature-flagged in `rusqlite`)
- On launch, prompt for a master passphrase (or use a config flag for
  testing)
- Derive the DB encryption key via Argon2id (same library, different
  salt from room passphrases)
- Use the same derived material to replace the hardcoded
  `SESSION_PERSIST_KEY` in `crypto/megolm.rs`

### Files

- `crates/huddle-core/src/storage/mod.rs` — `open_db` accepts a
  master key
- `crates/huddle-core/src/storage/keychain.rs` — derive + cache the
  master key
- `crates/huddle-tui/src/ui/master_passphrase.rs` — startup modal
  for entering the master passphrase

### Migration

Drop & recreate the DB if the user can't provide their old
passphrase — Phase 1 data is ephemeral anyway.

### Effort

~400 lines. One commit.

---

## Phase 5 — Contact verification

The "are you really 8a13-a3e0?" UX:

- New `^V` modal in a room with side-by-side fingerprint comparison
- After verification, mark the peer as verified in the SQLite
  `room_members` table
- Show a small "verified" badge next to verified members in the
  member list

Real safety relies on out-of-band verification (read fingerprints
aloud, scan a QR code in person, compare hashes via a different
channel). We just provide the UX; the user does the verification.

### Files

- `crates/huddle-core/src/storage/repo.rs` — `verified BOOL` column
  on `room_members`
- `crates/huddle-tui/src/ui/modal.rs` — `render_verify_modal`
- `crates/huddle-tui/src/input.rs` — `^V` binding in room view

### Effort

~250 lines. One commit.

---

## Phase 6 — Quality-of-life

Smaller items, grouped:

- **Typing indicators** — ephemeral `RoomMessage::Typing` broadcast,
  TTL 3s, shown in the member list area
- **Message search** — `^F` modal that searches `room_messages` for
  the current room
- **Mute / notifications** — per-room toggle, terminal bell on
  mention (`@my-fingerprint` substring) when muted
- **QR-code identity exchange** — `qrcode` crate + ANSI block chars,
  render your fingerprint as a QR for phone-to-laptop verification
- **Display names** — let users pick a display name per identity;
  share via `MemberAnnounce`
- **Room history scroll-to-top** — `g/G` bindings vim-style

### Effort

~600 lines total. Independent items, can be picked one at a time.

---

## Explicitly out of scope (for the foreseeable future)

- **Cross-network discovery** — no DHT, no Tor, no I2P, no
  centralized bootstrap. Same-LAN is the design.
- **Group calls / voice** — terminal doesn't help much here.
- **Federated/server mode** — there is no server.
- **Mobile / web frontends** — `huddle-core` could in principle be
  used elsewhere but it's not a goal.

---

## How to resume

Each phase is self-contained. To pick one up:

1. Read this section + the spec section for that phase
2. Start with the listed files-to-add
3. Add tests next to each new module (the existing tests in
   `crypto/`, `storage/`, and `app/` are the model)
4. Verify with `cargo test --workspace` + the integration test in
   `crates/huddle-core/tests/integration.rs`
5. Manually test on two machines per `MANUAL_TESTING.md`

The architectural boundary is `huddle-core::app::AppHandle` — every
new feature should expose itself as a method on `AppHandle` plus an
`AppEvent` variant. The TUI consumes these and is the one place
where UX choices live.
