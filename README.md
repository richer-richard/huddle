# Huddle

Decentralized, terminal-native chat rooms.

Open the TUI, browse rooms that other people on the same LAN are
hosting (or that you've reached by relay across the internet), or
start one yourself. Rooms can be public (cleartext over gossipsub) or
encrypted (per-sender Megolm group sessions, session keys wrapped with
an Argon2id-derived passphrase key).

No servers, no accounts, no cloud — by default, no internet required.
For peers across NATs, opt in to a Circuit Relay v2 host of your choice
via `--relay` or `config.toml`; AutoNAT v2 + DCUtR will hole-punch to
direct when possible.

> **This is a learning project, not production-audited chat.**
> SQLCipher protects the database at rest under your master passphrase,
> Megolm sessions are persisted with an Argon2id-derived key, file
> bytes use ChaCha20-Poly1305, and SAS contact verification ships in
> v0.3 — but the protocol has not been audited and threat-modelling
> work is ongoing. Don't rely on it for real secrets without a
> careful review.

## Build

Requires Rust 1.75+ (edition 2021).

```bash
cargo build --release
./target/release/huddle
```

## How it works (high level)

1. **Launch** — your Ed25519 identity loads (or generates) from disk
   silently. The lobby appears. mDNS starts listening for room
   announcements on the LAN. If you configured a relay (`--relay` or
   `config.toml`), huddle dials it and reserves a `/p2p-circuit` so
   peers across the internet can dial you.
2. **First launch only** — a 3-page onboarding card explains huddle's
   leaderless model (rooms outlive the creator), the master passphrase
   vs room passphrase distinction, and the new keybindings.
3. **Browse** — other huddles broadcast their rooms via gossipsub on a
   global `huddle-rooms-v1` topic. You see them in the lobby with
   name, public/encrypted, member count, host fingerprint, and (with
   internet reach) a reachability badge — `🌐 reachable`, `🏠 LAN
   only`, or `🔍 detecting…`.
4. **Start a room** — `s`. Pick a name, choose public or encrypted
   (and a passphrase if encrypted). You become the room's first
   *owner*; only owners can kick or grant moderation.
5. **Join a room** — `j/k`, `Enter`. Encrypted: enter the passphrase.
   Joined-via-code (see below): no passphrase prompt, but you become
   *read-only* (you can receive + send but can't onboard new
   members yourself).
6. **Inbound dial gate** — if someone you don't know dials you (Phase A),
   the TUI raises an Accept / Reject / Trust+Accept modal. The peer
   isn't added to your gossipsub mesh until you decide.
7. **Chat, verify, moderate** — see the key bindings below for SAS
   verification (`^V → s`), kick (`^K`), grant owner (`^G`), invite
   links (`^I`), join codes (`^J`/`c`), and verified-only-mode toggles
   (`,` global, `o` per room).

## Lobby

```
+--------------------------------------------------------+
|   huddle  ·  LAN (mDNS)                                |
|   decentralized rooms                                  |
|                                                        |
|   you  745e-fe8a-ca21-8954-b0b4-016b                   |
|        listening on /ip4/10.3.64.113/tcp/56825         |
|        🌐 reachable                                    |
+--------------------------------------------------------+
|   rooms (3)                                            |
|                                                        |
|  >  lunch-talk        public      3 members   8a13     |
|     team-1on1         encrypted   2 members   c4f1     |
|     design-review     public      5 members   745e     |
|                                                        |
+--------------------------------------------------------+
|  [s] start  [j/Enter] join  [I] invite  [v] paste     |
|  [,] settings  [d] dial  [r] refresh  [?] help  [q]   |
+--------------------------------------------------------+
```

## Key bindings

### Lobby
| Key                | Action                                  |
|--------------------|-----------------------------------------|
| `s`                | Start a new room                        |
| `d`                | Dial a peer by multiaddr or `ip:port`   |
| `i`                | Show your identity as a QR code         |
| `I` (Shift+I)      | Generate an invite link (peer-only)     |
| `v`                | Paste an invite link (`huddle://invite#…`) |
| `,`                | Settings (global verified-only, clear blocks) |
| `Enter`            | Join / reconnect the selected entry     |
| `Tab`              | Toggle focus rooms ↔ known peers        |
| `j/k` or arrows    | Navigate                                |
| `r`                | Refresh / reconnect                     |
| `x`                | Forget the selected known peer          |
| `?`                | Help                                    |
| `q`                | Quit                                    |

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
| `^A`      | Attach a file                                |
| `^R`      | Rotate the room key (encrypted rooms)        |
| `^V`      | Verify members — picker; `s` inside it starts SAS |
| `^K`      | Kick a member (owners only)                  |
| `^G`      | Grant owner role (owners only)               |
| `^I` (capital) | Generate an invite for this room        |
| `^J`      | Generate a single-use join code (owners only) |
| `c`       | Join a room with a code (from lobby join modal) |
| `o`       | Per-room verified-only-join toggle (owners)  |
| `B` (Shift+b) | List bans for this room (owners)         |
| `^F`      | Search this room's history                   |
| `^M`      | Mute / unmute this room                      |
| `f`       | Focus file cards (Tab/j/k between them)      |
| `g` / `G` | Scroll to top / bottom of history            |
| `?`       | Help                                         |
| `q`       | Quit (in-room, when input not focused)       |
| `Ctrl-C`  | Quit (always — confirms first)               |

## SAS verification

Both peers select each other in the Verify modal (`^V`), one presses
`s` to start. Each generates an ephemeral X25519 keypair, exchanges
pubkeys via signed envelopes, and derives a shared secret via ECDH.
HKDF produces a Matrix MSC 2241-aligned 7-emoji + three-4-digit-group
decimal code; both peers compare OOB (call/SMS/in-person) and press
`m` to match. A MITM substituting an ephemeral key gets a different
SAS code on each side — the OOB comparison catches it.

On match, the partner's fingerprint is marked verified (per-room +
global). With the global "verified-only inbound" toggle on (Settings,
`,`), unverified inbound dials auto-reject without prompting.

## Invite links

Press `^I` from a room (room-included invite) or `I` from the lobby
(peer-only invite). The TUI shows a `huddle://invite#<base64-JSON>`
URL plus a QR. The base64 JSON carries the host multiaddr (with
`/p2p/<peer-id>` so libp2p enforces the peer-id check on dial),
the human-display fingerprint, and an optional room summary.

Paste an invite from the lobby with `v`. The TUI confirms the
claimed fingerprint and dials. After dial, the post-dial
fingerprint check (added in 0.3.x) re-derives the peer's fingerprint
from their Ed25519 pubkey on Identify and disconnects if it doesn't
match the invite's claim — defense in depth, since libp2p's
`/p2p/<peer-id>` already enforces the cryptographic match.

If the invite includes an encrypted room, you're prompted for the
passphrase next.

## Owners, kick, ban

The room's creator is the first owner; owners can grant the role to
others (`^G`) or kick (`^K`). Kick = signed `BanMember` broadcast +
immediate `RotateRoomKey` with a freshly-generated passphrase
(displayed to the owner for OOB re-share with the remaining members).

The banned peer still receives gossipsub bytes but can't decrypt the
new outbound session key. Honest peers honour the ban (drop their
messages); cryptographic enforcement is the key rotation, not the
ban row itself. **Soft owner model — kick is not a hard network
quarantine.**

`B` (Shift+b) lists the bans for the current room.

## Internet reach

By default huddle uses LAN mDNS only. To accept dials across the
internet, register with a Circuit Relay v2 host:

```bash
huddle --relay /dns4/relay.example.com/tcp/4001/p2p/12D3Koo...
```

…or persist in `config.toml`:

```toml
# macOS:  ~/Library/Application Support/huddle/config.toml
# Linux:  ~/.config/huddle/config.toml
# Windows: %APPDATA%\huddle\config.toml
relays = [
  "/dns4/relay.example.com/tcp/4001/p2p/12D3Koo...",
]
```

CLI flags override the config file. No relays are configured by
default — you pick one explicitly. AutoNAT v2 probes test your
reachability against the connected peer pool; DCUtR attempts a
hole-punch upgrade to a direct connection whenever a relayed
connection forms. The lobby badge shows the current state
(`🌐 reachable` / `🏠 LAN only` / `🔍 detecting…`).

Room announcements optionally carry a `host_addrs` field with up to 4
of the announcer's reachable addresses (relay-circuit and
AutoNAT-confirmed external). Peers receiving an announcement they
have no direct connection for will opportunistically dial the first
listed address (rate-limited per announcer). This lets cross-internet
peers bootstrap without invite links.

## Join codes (read-only joiners)

Owners press `^J` in a room to generate a single-use, 10-minute
`XXXX-XXXX` code. The owner shares it OOB. The joiner picks "join
with code" (`c`) instead of passphrase in the join modal and types
the code. The joiner's TUI generates an ephemeral X25519 keypair,
broadcasts a signed `CodeJoinRequest`, and waits for the owner's
`CodeJoinResponse` (which wraps the room's session key under an
ECDH-derived key). If no response arrives within 30 s, the TUI
surfaces a timeout error — usually meaning the code was wrong or
expired.

Code-joined members are **read-only**: they can read and send, but
without the passphrase they can't wrap session keys for newer
joiners. The room tab renders `(read-only)` next to the name. To
upgrade, an owner can re-onboard them with the actual passphrase.

## Architecture

```
huddle/
  huddle-core    library: rooms, crypto, network, storage
  huddle         terminal UI (the only frontend)
  huddle-tauri   stub (kept for future desktop shell)
```

**Networking** — libp2p 0.56 with TCP+Noise+Yamux transport, mDNS for
LAN discovery, gossipsub for both global room advertisement and
per-room message broadcast, identify, ping, request-response,
Circuit Relay v2 client, AutoNAT v2 (client + server), DCUtR. Mesh
topology — every member of a room receives every message; there's no
"host" with special powers, and rooms survive the original creator
leaving (as long as someone else is in them). The owner role is
client-enforced state, not a network-level privilege.

**Encryption** — vodozemac Megolm group sessions (one outbound per
peer). When you join via passphrase, you wrap your session key with
ChaCha20-Poly1305 under an Argon2id key derived from
`(passphrase, salt)` and broadcast that for every existing member to
pick up. When you join via code, ECDH between owner and joiner gives
a wrap key that delivers only the owner's session — the joiner's own
outbound goes unwrapped.

**App-level signing** — every protocol message whose authenticity
matters (`OwnerGrant`, `BanMember`, `RotateRoomKey`, SAS handshake,
`CodeJoinRequest/Response`, `JoinRefused`) is wrapped in a
`SignedRoomMessage` Ed25519 envelope. Receivers verify the signature,
re-derive the fingerprint from the envelope's pubkey, and gate on
both `verified_signer.is_some()` and (where applicable) signer-is-owner.

**Identity** — Ed25519 keypair stored under your platform's data
directory. Fingerprint format: six groups of four hex chars
(`a3b1-c2d4-e5f6-7890-1234-abcd`).

**Storage** — SQLCipher (rusqlite + bundled SQLCipher + vendored
OpenSSL). On launch you enter a master passphrase; it's stretched
with Argon2id (m=64 MiB, t=3, p=4) against a per-installation salt
and used as `PRAGMA key`, plus an HKDF subkey replaces the older
hardcoded Megolm persistence key. Tables include `identity`,
`rooms`, `room_members` (with `role`, `ed25519_pubkey`),
`room_megolm_sessions`, `room_messages`, `room_attachments`,
`known_peers` (with `fingerprint`, `trusted`), `blocked_peers`,
`room_bans`, `verified_peers`, `app_settings`. Migrations are
additive only and tracked via `PRAGMA user_version`. Pass
`--no-master-passphrase` to fall back to an unencrypted database
for testing.

**File attachments** — `^A` opens a local file picker; selected files
are SHA-256-hashed, chunked into 64 KiB pieces, and broadcast over
the room's gossipsub topic with a `FileOffer` + N `FileChunk`
messages. In encrypted rooms the bytes are ChaCha20-Poly1305-encrypted
with a fresh file key that's Megolm-wrapped in the offer. Receivers
see a focusable file card in chat — press `f` to enter card mode,
`j/k` to step, Enter to save to your platform's Downloads folder.
Phase 2 cap is 1 MiB per file.

## Operator notes

- The first launch creates `<data_dir>/keychain.salt`. Don't move or
  delete it without your passphrase backed up — losing it forces a
  re-derive that won't unlock the existing DB.
- `--no-master-passphrase` opens an unencrypted DB. Testing only.
- `--relay <multiaddr>` (repeatable) registers a circuit-relay
  reservation. The relay's identify response is the cue to start
  listening on `<relay>/p2p-circuit`.
- `--no-relay` ignores any relays in `config.toml` for this run.

## Current limitations

- LAN-only by default. Cross-network use needs a configured relay
  (Phase D), an invite link with a public multiaddr, or a manual
  `d` dial to a port-forwarded `ip:port`.
- Code-joined members are read-only — they don't have the passphrase
  and can't onboard further members.
- Kick / ban are honest-client-enforced at the gossipsub layer; the
  cryptographic teeth come from the key rotation that follows.
- File transfer is capped at 1 MiB per file (Phase 2). Larger files
  defer to a dedicated libp2p stream protocol (planned).
- mDNS may not work on some corporate / restricted networks.
- Verified-only inbound mode trusts SAS-verified + previously-trusted
  fingerprints. Don't enable it before you've verified at least one
  peer you can re-bootstrap from.
- The SAS emoji table follows Matrix MSC 2241 for future cross-client
  compatibility but is not yet interop-tested against any other client.

## Testing

```bash
cargo test --workspace -- --test-threads=1
```

`--test-threads=1` keeps the mDNS-based integration tests from
fighting each other on a single host. The suite covers two-node
plain + encrypted round-trip, Phase A inbound-dial accept and reject,
Phase B kick-and-rotate (3-node), and Phase F code-join. See
`MANUAL_TESTING.md` for the two-machine checklist.

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
