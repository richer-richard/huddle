# Huddle

Decentralized, terminal-native chat rooms for your local network.

Open the TUI, browse rooms that other people on the same Wi-Fi are
hosting, or start one yourself. Rooms can be public (cleartext over
gossipsub) or encrypted (per-sender Megolm group sessions, session keys
wrapped with an Argon2id-derived passphrase key).

No servers, no accounts, no cloud, no internet required.

> **This is a learning project, not production-secure chat.**
> The vodozemac session serialization key is hardcoded, the SQLite
> database is unencrypted, and the protocol has not been audited.
> Do not use this for real secrets. See `plan.md` for the roadmap
> toward production security.

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
| Key      | Action                          |
|----------|---------------------------------|
| `s`      | Start a new room                |
| `j/Enter`| Join the selected room          |
| `j/k` or arrows | Navigate rooms list      |
| `r`      | Refresh discovered rooms        |
| `?`      | Help                            |
| `q`      | Quit                            |

### In a room
| Key       | Action                                |
|-----------|---------------------------------------|
| `/`       | Focus input (start typing)            |
| `Enter`   | Send the typed message                |
| `Esc`     | Blur input (or, if blurred, go to lobby) |
| `^Tab`/`^N` | Next tab                            |
| `^P`      | Previous tab                          |
| `1`..`9`  | Jump to tab N                         |
| `^L`      | Leave the current room                |
| `^B`      | Back to lobby (without leaving)       |
| `?`       | Help                                  |
| `q`       | Quit (in-room, when input not focused)|
| `Ctrl-C`  | Quit (always — confirms first)        |

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

**Storage** — SQLite (rusqlite, bundled). Schema: `identity`, `rooms`,
`room_members`, `room_megolm_sessions`, `room_messages`. Messages
persist across launches keyed by room ID.

## Current limitations

- LAN only — mDNS discovery doesn't cross routers. No internet relay,
  no Tor, no DHT. By design for this phase.
- No file/image/audio/video attachments yet.
- No contact verification UI (no safety-number flow).
- No member removal — anyone with the passphrase keeps the key
  forever. Removal requires rotation (not implemented).
- Vodozemac session pickling key is hardcoded.
- SQLite is unencrypted at rest.
- Plain rooms are visible to anyone in the room (transport-encrypted
  by libp2p Noise, but plaintext to room members).
- mDNS may not work on some corporate/restricted networks.

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

MIT
