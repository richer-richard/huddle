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

### The file card (placeholder UX)

Attachments don't render as raw pixels in the terminal. They appear
in the chat history as a **focusable file card** — a multi-line
block that's visually unmistakable as "not text", with explicit
controls in its bottom row:

```
  10:42  8a13  ┌─[file] design-mockup.png · 4.2 MB · png ───────────┐
              │  ████████████████░░░░░░░░░  74%  · downloading      │
              │  [Enter] save to Downloads   [o] open   [c] cancel  │
              └─────────────────────────────────────────────────────┘
```

Four visual states, distinguished by border color and the right-hand
status word:

- **offered** — peer announced the file; chunks not fetched yet.
  Status: `offered · [Enter] to download`. Border: DarkGray.
- **downloading** — chunks arriving. Status: `NN% · downloading`;
  the progress bar fills. Border: Yellow.
- **ready** — all chunks received, SHA-256 verified. Status:
  `ready · [Enter] save to Downloads`, then after first save
  `saved to ~/Downloads/…` and the primary action becomes `[o] open`.
  Border: Green.
- **failed** — hash mismatch or chunks didn't recover. Status:
  `failed · [r] to retry`. Border: Red.

Focused state overrides border color with Cyan and bolds the action
hints in the bottom row, so users always see which card the next
keystroke targets.

#### Navigation

The room view gains a second focus mode for cards. While the input
is blurred (`Esc` from the input bar), `Tab` cycles focus among
visible file cards; `j`/`k` (or arrows) step between them. The hint
bar at the bottom of the screen swaps to show the focused card's
available actions.

| Key      | Action                                                       |
|----------|--------------------------------------------------------------|
| `Enter`  | Offered → start download. Ready → save to Downloads.         |
| `o`      | Open the saved file via the system opener.                   |
| `c`      | Cancel an in-flight download (partial chunks discarded).     |
| `r`      | Retry a failed transfer.                                     |
| `s`      | Save again with a fresh `-N` filename suffix.                |
| `Esc`    | Return focus to the input bar.                               |

**Mouse clicks** on a card's rendered area act as `Enter`.
Implemented by enabling `crossterm::event::EnableMouseCapture` at
startup and hit-testing the cached `Rect` of each rendered card on
`MouseEvent::Down(Left)`. Keyboard nav remains the source of truth;
the mouse is purely additive, so the app stays usable over SSH /
without mouse support.

#### Where files land

Two paths on the receiving side, kept distinct on purpose:

- **Cache** — chunks accumulate at
  `<data_dir>/files/cache/<file_id>.part`, renamed to `<file_id>`
  once the SHA-256 matches. The cache is the durable record of the
  transfer; if the user saves twice (or restarts), saves are copies
  from cache. Cache survives restarts so cards reappear in state
  `ready` next time the room is opened.
- **Downloads** — on `Enter` from a ready card, the cached file is
  copied to the platform's Downloads directory via
  `dirs::download_dir()` (`~/Downloads` on macOS/Linux,
  `%USERPROFILE%\Downloads` on Windows). The original (sanitized)
  filename is used; on collision the file gets a `-1`, `-2`, …
  suffix before the extension. The card stores the resolved path so
  `[o] open` knows what to launch.

### Files to add

- `crates/huddle-core/src/files/mod.rs` — `FileManager`: track
  outbound + inbound transfers, reassemble chunks, verify SHA-256,
  expose `save_to_downloads(file_id)` and `open_saved(file_id)`
- `crates/huddle-core/src/files/encryption.rs` — wrap a file key with
  the room's Megolm session before sharing; encrypt the file with
  ChaCha20-Poly1305 (separate from message encryption to keep the
  Megolm ratchet from advancing on every chunk)
- `crates/huddle-core/src/storage/repo.rs` — new `room_attachments`
  table: `(id, room_id, message_id, sender_fingerprint, file_id,
  name, mime, size, status, cache_path, saved_path, created_at)`
- `crates/huddle/src/ui/file_card.rs` — render one card across its
  four states; return the rendered `Rect` for keyboard focus +
  mouse hit-testing
- `crates/huddle/src/ui/room.rs` — interleave file cards with text
  messages in the scroll buffer; track focused-card index; route
  card keys + mouse clicks to `AppHandle`
- `crates/huddle/src/ui/attach_modal.rs` — outbound file picker
  triggered by `^A`; navigate the local filesystem and pick a file
  to offer

### AppHandle additions

```rust
impl AppHandle {
    pub async fn send_file(&self, room_id: &str, path: &Path) -> Result<String>;
    pub async fn start_download(&self, room_id: &str, file_id: &str) -> Result<()>;
    pub async fn save_to_downloads(&self, file_id: &str) -> Result<PathBuf>;
    pub async fn cancel_transfer(&self, file_id: &str) -> Result<()>;
    pub fn open_saved(&self, file_id: &str) -> Result<()>;
}
```

New `AppEvent` variants: `FileOffered { room_id, file_id, name,
size, sender_fingerprint }`, `FileProgress { file_id, bytes_received,
total_bytes }`, `FileReady { file_id }`, `FileSaved { file_id, path }`,
`FileFailed { file_id, reason }`.

### Optional inline preview (later)

For image attachments, the card can render a thumbnail above its
status line when the terminal supports Kitty / Sixel / iTerm2
graphics protocols (via `ratatui-image`). Audio/video stay external
— the system opener does the right thing. This is *additive* to the
card; the card design above is the baseline that works in every
terminal.

### Effort

~1000-1200 lines split across core + TUI. About 5-6 commits.

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
- `crates/huddle/src/ui/modal.rs` — rotation confirmation modal,
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
- `crates/huddle/src/ui/master_passphrase.rs` — startup modal
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
- `crates/huddle/src/ui/modal.rs` — `render_verify_modal`
- `crates/huddle/src/input.rs` — `^V` binding in room view

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
