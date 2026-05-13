# Huddle

Decentralized, terminal-native chat rooms for your local network.

Open the TUI, browse rooms that other people on the same Wi-Fi are
hosting, or start one yourself. Rooms can be public (cleartext over
gossipsub) or encrypted (per-sender Megolm group sessions, session keys
wrapped with an Argon2id-derived passphrase key).

No servers, no accounts, no cloud, no internet required.

> **This is a learning project, not production-audited chat.**
> SQLCipher protects the database at rest under your master passphrase,
> Megolm sessions are persisted with an Argon2id-derived key, files use
> ChaCha20-Poly1305, and contact verification is available — but the
> protocol has not been audited and threat-modelling work is ongoing.
> Don't rely on it for real secrets without a careful review.

## Build

Requires Rust 1.75+ (edition 2021).

```bash
cargo build --release
./target/release/huddle
```

## How it works

1. **Launch** — your Ed25519 identity loads (or generates) from disk
   silently. The lobby appears. mDNS starts listening for room
   announcements on the LAN.
2. **Browse** — other huddles on the network broadcast their rooms via
   gossipsub on a global `huddle-rooms-v1` topic. You see them in the
   lobby with name, public/encrypted, member count, and host fingerprint.
3. **Start a room** — press `s`. Pick a name, choose public or
   encrypted (and a passphrase if encrypted). The lobby switches to
   the in-room view.
4. **Join a room** — navigate with `j/k`, press `Enter`. If it's
   encrypted, enter the passphrase. You'll be added to that room's
   gossipsub topic and start receiving messages.
5. **Chat** — type to send. Multiple rooms appear as tabs along the
   top; `^Tab` cycles, `1..9` jumps directly.
6. **Leave** — `^L` leaves the current room (broadcasts a leave
   notice); `^B` goes back to the lobby without leaving (useful for
   browsing while in a room).

## Lobby

```
+--------------------------------------------------------+
|   huddle                                               |
|   decentralized rooms                                  |
|                                                        |
|   you  745e-fe8a-ca21-8954-b0b4-016b                   |
|        listening on /ip4/10.3.64.113/tcp/56825         |
+--------------------------------------------------------+
|   rooms (3)                                            |
|                                                        |
|  >  lunch-talk        public      3 members   8a13     |
|     team-1on1         encrypted   2 members   c4f1     |
|     design-review     public      5 members   745e     |
|                                                        |
+--------------------------------------------------------+
|  [s] start  [j/Enter] join  [r] refresh  [?] help  [q] |
+--------------------------------------------------------+
```

## In a room

```
+--------------------------------------------------------+
| [1] lunch-talk  [2] secret-room E*                     |
+--------------------------------------------------------+
| #lunch-talk  public  3 members: 8a13 c4f1 you*         |
+--------------------------------------------------------+
|                                                        |
|  10:42  8a13    hey did you get the doc?               |
|  10:43  you     yeah just opening it now               |
|  10:43  c4f1    nice                                   |
|                                                        |
+--------------------------------------------------------+
| > _                                                    |
+--------------------------------------------------------+
| ^Tab next   / type   Esc back   ^L leave   ?  help     |
+--------------------------------------------------------+
```

## Key bindings

### Lobby
| Key             | Action                                  |
|-----------------|-----------------------------------------|
| `s`             | Start a new room                        |
| `d`             | Dial a peer by `ip:port`                |
| `i`             | Show your identity as a QR code         |
| `Enter`         | Join / reconnect the selected entry     |
| `Tab`           | Toggle focus rooms ↔ known peers        |
| `j/k` or arrows | Navigate                                |
| `r`             | Refresh / reconnect                     |
| `x`             | Forget the selected known peer          |
| `?`             | Help                                    |
| `q`             | Quit                                    |

### In a room
| Key       | Action                                       |
|-----------|----------------------------------------------|
| `/`       | Focus input (start typing)                   |
| `Enter`   | Send the typed message                       |
| `Alt+Enter` / `^J` | Insert a newline in the input        |
| `Esc`     | Blur input (or, if blurred, go to lobby)     |
| `^Tab`/`^N` | Next tab                                   |
| `^P`      | Previous tab                                 |
| `1`..`9`  | Jump to tab N                                |
| `^L`      | Leave the current room                       |
| `^B`      | Back to lobby (without leaving)              |
| `^A`      | Attach a file (opens local FS picker)        |
| `^R`      | Rotate the room key (encrypted rooms)        |
| `^V`      | Verify member fingerprints                   |
| `^F`      | Search this room's history                   |
| `^M`      | Mute / unmute this room                      |
| `f`       | Focus file cards (Tab/j/k between them)      |
| `g` / `G` | Scroll to top / bottom of history            |
| `?`       | Help                                         |
| `q`       | Quit (in-room, when input not focused)       |
| `Ctrl-C`  | Quit (always — confirms first)               |

### File-card focus mode (after pressing `f`)
| Key       | Action                                  |
|-----------|-----------------------------------------|
| `j/k`     | Navigate cards                          |
| `Enter`   | Save to Downloads (or wait if not ready) |
| `o`       | Open the saved file with system opener  |
| `c`       | Cancel an in-flight transfer            |
| `s`       | Save with a fresh `-N` suffix           |
| `Esc/f`   | Exit card focus                         |

## Architecture

```
huddle/
  huddle-core    library: rooms, crypto, network, storage
  huddle     terminal UI (the only frontend)
  huddle-tauri   stub (kept for future desktop shell)
```

**Networking** — libp2p with TCP+Noise+Yamux transport, mDNS for LAN
discovery, gossipsub for both global room advertisement and per-room
message broadcast. Mesh topology — every member of a room receives
every message; there's no "host" with special powers, and rooms
survive the original creator leaving (as long as someone else is in
them).

**Encryption (encrypted rooms)** — vodozemac Megolm group sessions, one
outbound session per peer. When you join a room, you send your session
key to everyone, encrypted with ChaCha20-Poly1305 under a key derived
from the passphrase via Argon2id. New joiners ask for keys via a
`SessionKeyRequest` broadcast; existing members re-broadcast their
session keys in response.

**Identity** — Ed25519 keypair stored under your platform's data
directory. Fingerprint format: six groups of four hex chars
(`a3b1-c2d4-e5f6-7890-1234-abcd`).

**Storage** — SQLCipher (rusqlite + bundled SQLCipher + vendored OpenSSL).
On launch you enter a master passphrase; it's stretched with Argon2id
against a per-installation salt and used as `PRAGMA key` to decrypt the
database, plus an HKDF subkey replaces the Phase-1 hardcoded Megolm
persistence key. Tables: `identity`, `rooms`, `room_members`,
`room_megolm_sessions`, `room_messages`, `room_attachments`,
`known_peers`. Pass `--no-master-passphrase` to fall back to an
unencrypted database for testing.

**File attachments** — `^A` opens a local file picker; selected files
are SHA-256-hashed, chunked into 64 KiB pieces, and broadcast over the
room's gossipsub topic with a `FileOffer` + N `FileChunk` messages. In
encrypted rooms the bytes are ChaCha20-Poly1305-encrypted with a fresh
file key that's Megolm-wrapped in the offer. Receivers see a focusable
file card in chat — press `f` to enter card mode, `j/k` to step, Enter
to save to your platform's Downloads folder, `o` to open with the
system opener. Phase 2 cap is 1 MiB per file.

## Operator notes

- The first launch creates `<data_dir>/keychain.salt`. Don't move or
  delete it without your passphrase backed up — the salt is not secret
  but losing it forces a re-derive that won't unlock the existing DB.
- `--no-master-passphrase` skips the prompt and opens an unencrypted
  DB. Use it only for testing.

## Current limitations

- LAN-only discovery by default. Cross-network use requires `^A` /
  manual dial to an `ip:port` (port-forwarded if you're across NATs).
  No DHT, no Tor.
- File transfer is capped at 1 MiB per file (Phase 2). Larger files
  defer to a dedicated libp2p stream protocol (Phase 3 in `plan.md`).
- Member rotation broadcasts a new key but doesn't kick old members
  for past messages — they can still decrypt history they have.
- Plain rooms are transport-encrypted by libp2p Noise but plaintext
  to every member of the room.
- mDNS may not work on some corporate / restricted networks.
- Contact verification is UX-only; the cryptographic check is the
  user's responsibility (compare fingerprints out-of-band).

## Testing

```bash
cargo test --workspace
```

Includes two-node integration tests for unencrypted and encrypted room
message exchange. See `MANUAL_TESTING.md` for the two-machine
checklist.

## Roadmap

See `plan.md` for: media attachments, contact verification, member
rotation/removal, key replenishment, SQLCipher at-rest encryption, and
more.

## Data directory

- **macOS:** `~/Library/Application Support/huddle/`
- **Linux:** `~/.local/share/huddle/`
- **Windows:** `%APPDATA%\huddle\`

## License

Licensed under either of

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([`LICENSE-MIT`](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
