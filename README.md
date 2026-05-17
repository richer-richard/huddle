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

### Global (any mode, no modal open)
| Key                | Action                                  |
|--------------------|-----------------------------------------|
| `?`                | Help — generated live from `input.rs`, scroll with `j/k` |
| `:` or `Ctrl+P`    | Command palette — fuzzy search every action |
| `Ctrl+H`           | Notification history (last 100 status events) |
| `Ctrl+C`           | Quit (confirms first)                   |

### Lobby
| Key                | Action                                  |
|--------------------|-----------------------------------------|
| `s`                | Start a new room                        |
| `a`                | Add friend by HD ID or username (races LAN / IP / relay) |
| `d`                | Dial a peer by multiaddr or `ip:port`   |
| `i`                | Show your identity as a QR code         |
| `I` (Shift+I)      | Generate an invite link (peer-only)     |
| `v`                | Paste an invite link (`huddle://invite#…`) |
| `,`                | Settings (username, verified-only, clear blocks, go dark, update check, what's new) |
| `R` (Shift+r)      | Mark every room read                    |
| `Enter`            | Join / reconnect the selected entry     |
| `Tab`              | Toggle focus rooms ↔ known peers        |
| `j/k` or arrows    | Navigate                                |
| `r`                | Refresh / reconnect                     |
| `x`                | Forget the selected known peer          |
| `q`                | Quit                                    |

### In a room
| Key       | Action                                       |
|-----------|----------------------------------------------|
| `/`       | Focus input (start typing)                   |
| `Enter`   | Send the typed message                       |
| `Alt+Enter` / `^J` | Insert a newline in the input        |
| `Esc`     | Blur input (or, if blurred, go to lobby)     |
| `^Tab`/`^N` | Next tab                                   |
| `^P`      | Previous tab (or command palette when input is blurred) |
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

### Settings modal
| Key | Action                                                   |
|-----|----------------------------------------------------------|
| `u` | Edit your username                                       |
| `U` (Shift+u) | Toggle the crates.io update check (opt-in)     |
| `v` / Space / Enter | Toggle "reject inbound from unverified"  |
| `c` | Clear blocked peers                                      |
| `w` | Replay onboarding (what's new)                           |
| `!` | Delete account (go dark) — two-factor confirm            |

## Username & ID display (huddle 0.5)

Every peer has a 96-bit fingerprint rendered as a branded
`HD-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` ID. Same security as before, just a
friendlier format. The lobby header shows yours.

Set an optional username from Settings (`,` → `u`). The username is
broadcast in a *signed* `ProfileUpdate` event — peers receiving it
verify the Ed25519 signature against the claimed fingerprint, so
nobody can spoof "alice" by stuffing a string into a packet. If you
clear the field (empty input), you broadcast as `[anonymous]`.

In chat, your message label shows the username (or `[anonymous]`).
SAS-verified peers also get a green `✓` next to their name in chat,
matching the existing badge in the room member list.

## Add friend by HD ID or username (huddle 0.5.1+)

Lobby `a` opens an add-friend modal that takes either:

- an `HD-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` ID (or the bare 24-hex form
  with/without dashes — normalized internally),
- or a username string (unique-match lookup in `peer_profiles`).

Resolution: huddle looks the fingerprint up across recent room
announcements (`creator_fingerprint` + `host_addrs`) and the persisted
`known_peers` table. Every candidate multiaddr is then handed to libp2p
as a single `DialOpts::peer_id().addresses()` call — the swarm **races
them in parallel** (huddle 0.5.2+) and the first to complete wins. The
client also pre-sorts by transport preference (RFC1918 LAN ip4 →
loopback → public ip4 → ip6 / dns → `/p2p-circuit`) so when latencies
are close the LAN slot starts first. mDNS-discovered peers don't need
this path at all — they show up in the lobby automatically.

The privacy trade-off worth knowing about: this works only for peers
you've **already seen on a shared gossipsub mesh** — same LAN, a relay
you both connect to, or a prior dial. There's deliberately no central
"add by ID" directory; cold-start strangers must pass an invite link
out-of-band first. Adding a directory (DHT, rendezvous server, central
service) would either centralize the architecture or leak lookup
metadata to bootstrap nodes — both fail the "trusted relay, absolute
privacy" goal huddle's built around.

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

## Go dark — irreversible account deletion (huddle 0.5)

Settings → `!` opens the **go dark** modal. Two-factor gate:

1. Your **master passphrase** (re-derived and constant-time compared
   to the in-memory SQLCipher subkey).
2. Type the literal phrase `DELETE EVERYTHING` in the second field.

On confirm, huddle:

- best-effort `MemberLeave`s every joined room (2-second cap so a
  flapping transport can't hang the wipe),
- shuts down the network task,
- zeroes-then-deletes `huddle.db`, `huddle.db-shm`, `huddle.db-wal`,
  `keychain.salt`, `huddle.log` (and any rotated logs), and
  `config.toml` from the data dir,
- removes the now-empty data dir, and
- shows a brief goodbye modal before exiting.

There is no recovery. Restarting huddle after a go-dark generates a
fresh identity from scratch.

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

## What's new in 0.7.1 — E2E DMs

Direct messages are now end-to-end encrypted on the room layer.

- New `crate::crypto::dm::derive_dm_key` derives a 32-byte room key
  from one side's Ed25519 secret seed and the other side's Ed25519
  public key via X25519 ECDH + HKDF-SHA256.
- `start_direct` creates DMs as `encrypted = true` with the
  ECDH-derived key as the Megolm wrap key. The "passphrase salt"
  slot stores the canonical room_id so re-bootstraps re-derive
  identically.
- When we don't yet have the partner's pubkey (e.g. fingerprint
  resolved from a QR / invite / username), the room is created with
  no wrap key. The next `MemberAnnounce` from the partner carries
  their pubkey; we derive the key lazily, then re-broadcast our own
  `MemberAnnounce` with the wrapped Megolm session key.
- Backward compatibility: DMs created against pre-0.7.1 peers stay
  in their original `encrypted=false` mode (the rooms table records
  it). New 0.7.1+ DMs are always E2E.

## What's new in 0.7 — TUI 2.0

`0.7.0` is a brand-new TUI built around a **sidebar + pane** layout
(Discord/Slack-style), with explicit separation of **Direct messages**
from **Group rooms**. The old `Screen::{Lobby, InRoom}` flat-screen
model and the tab-bar are retired.

### Sidebar sections

| Section          | What it shows                                            |
| ---------------- | -------------------------------------------------------- |
| Profile          | you: username, HD-ID, NAT badge, listen addresses        |
| Direct messages  | 1-1 DMs (`RoomKind::Direct`, 2-people-forever)           |
| Group rooms      | every multi-peer room, plus a Discover row for unjoined  |
| People           | known peers, verified peers, blocked peers in one block  |
| Activity         | status history + in-flight file transfers                |
| Settings         | global toggles + blocked-peer manager + go-dark          |

### Key bindings (huddle 0.7)

| Anywhere (sidebar focus or non-chat pane) | Action |
| ----------------------------------------- | ------ |
| `m`                                       | start a DM (Compose-DM modal) |
| `g`                                       | start a group room |
| `p`                                       | jump to People pane |
| `,`                                       | jump to Settings pane |
| `i`                                       | show QR / HD-ID |
| `Shift+I`                                 | generate invite link |
| `a`                                       | add friend by HD-ID / username |
| `v`                                       | paste an invite link |
| `c`                                       | join with code |
| `Tab` / `Shift+Tab`                       | jump between sidebar sections |
| `Space` / `←` / `→`                       | expand / collapse a section |
| `j` / `k`                                 | move sidebar cursor |
| `Enter`                                   | open the selected row |
| `Ctrl+P` / `:`                            | command palette |
| `Ctrl+H`                                  | notification quick-glance |
| `?`                                       | help |
| `R`                                       | mark all rooms read |
| `q` / `Ctrl+C`                            | quit |

| In a chat pane (DM or Group)              | Action |
| ----------------------------------------- | ------ |
| `/`                                       | focus the input |
| `Esc`                                     | blur input / focus sidebar |
| `Ctrl+V`                                  | SAS-verify partner |
| `Ctrl+F`                                  | search room history |
| `Ctrl+A`                                  | attach a file |
| `Ctrl+L`                                  | leave the room |
| `Ctrl+I` (group only)                     | toggle member margin |
| `Ctrl+K` / `Ctrl+G` (group + owner)       | kick / grant-owner |
| `Ctrl+R` (group + owner)                  | rotate room key |
| `Ctrl+J` (group + owner)                  | generate join code |
| `Ctrl+M` (group)                          | toggle mute |
| `Ctrl+O` (group + owner)                  | toggle verified-only-join |
| `Shift+B` (group + owner)                 | view bans |
| `Alt+Enter` / `Ctrl+J`                    | newline in input |

### Direct messages are 1-1 forever and end-to-end encrypted

`RoomKind::Direct` is persisted on the rooms table; the canonical
DM room ID is `sha256("huddle-dm-v1\0" || min(fp_a, fp_b) || "\0" ||
max(fp_a, fp_b))`. Both peers, regardless of who clicks `m` first,
derive the same room ID — `start_direct` is idempotent across both
peers and across reinstalls. A third member cannot join a DM
(`MemberAnnounce` past the 2-member cap is dropped locally), and
DM-kind announcements are filtered out of third parties' discovery
caches.

**End-to-end encryption (huddle 0.7.1+):** every DM uses a Megolm
group session whose wrap key comes from an Ed25519→X25519 ECDH
between the two parties' long-term identity keys, expanded with
HKDF-SHA256 bound to the canonical room_id. Both peers
independently derive the same 32-byte key without any shared
passphrase or out-of-band handshake — see
`crates/huddle-core/src/crypto/dm.rs`. The wrapped session key
travels in `MemberAnnounce` exactly like a group room's; the only
difference is where the wrap key came from.

The first `MemberAnnounce` carries each party's pubkey, which the
other side uses to derive the ECDH key. Once both keys are known,
session-key wrapping resumes the normal Megolm flow and all
subsequent traffic is E2E.

### Retired

- `Screen::{Lobby, InRoom}` binary — replaced by `Pane` enum.
- The tab-bar and numeric `1..9` tab jumps.
- `Ctrl+B` (back-to-lobby in chat) — `Esc` focuses sidebar instead.
- `LobbyFocus` (the two-list focus toggle) — sidebar focus model.
- The flat `discovered_rooms` list — split into DM / Group sections.

## What's new in 0.6 (UX overhaul)

`0.6.0` is a focused UX release. The protocol surface didn't change;
the TUI did.

- **Command palette** (`:` or `Ctrl+P`) — fuzzy-search every action.
  Drives discoverability without bloating the visible chrome. You no
  longer need to remember `a/d/i/,/c/I/v/!/u/o/^J/^I/^K/^G/^V` to find
  things.
- **Notification history** (`Ctrl+H`) — the last 100 status-bar
  messages, scrollable, with timestamps. Replaces the "goldfish"
  status bar where two events in quick succession overwrote each
  other.
- **Help is now generated from `input.rs`** — every keybinding is
  documented, scroll with `j/k`. Help is sectioned by context
  (Lobby / In a room / Card focus / etc.) and can never drift from
  the actual key map again.
- **Onboarding versioning** — the welcome card now re-fires only the
  "what's new in X.Y" page when you upgrade between versions. You can
  also replay it any time from `Settings → w`.
- **Pending-modal indicator** — when an async event (inbound dial,
  rotation, error) arrives behind another modal, the status bar shows
  `[N pending · Ctrl+H to view]` so it never silently disappears.
  Queue is FIFO and capped at 16.
- **Adaptive hint bar** — the bottom-of-screen hints rotate based on
  what's most likely to be useful next (empty lobby surfaces "add
  friend"; unread tab surfaces "join"; etc.).
- **Lobby header polish** — `huddle 0.6.0` version anchor, clock,
  live peer counter alongside the NAT reachability badge.
- **Scroll indicator + day separators in chat** — the message pane
  shows `N/M · live` (or `N/M · ↑ K above`) at the bottom border, and
  date dividers (`─── 2026-05-15 ───`) appear when conversations span
  days.
- **Unread counts in tabs** — `[2] room-name (3)` shows the actual
  count instead of a vague `*`. `R` (shift-r) in the lobby zeros every
  tab at once.
- **Opt-in update detection** — a tiny ureq-backed background task
  pings `https://crates.io/api/v1/crates/huddle` once per 24 h. If a
  newer version exists, a banner appears under the lobby header. OFF
  by default; toggle via `Settings → U` or the command palette.
- **`huddle doctor` CLI** — `huddle doctor` prints version, data
  paths, file sizes, and config without touching the network or
  asking for the master passphrase. Paste it into bug reports.

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
