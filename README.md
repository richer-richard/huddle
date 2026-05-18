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
   silently. The TUI opens on the **Welcome** pane with the sidebar
   on the left. mDNS starts listening for room announcements on the
   LAN. If you configured a relay (`--relay` or `config.toml`),
   huddle dials it and reserves a `/p2p-circuit` so peers across the
   internet can dial you.
2. **First launch only** — a versioned onboarding card explains
   huddle's leaderless model (rooms outlive the creator), the master
   passphrase vs room passphrase distinction, the sidebar layout, and
   the new keybindings.
3. **Direct messages** — press `m`, type a partner's HD-ID or
   username, hit `Enter`. The DM appears in the **Direct messages**
   section of the sidebar on both peers. DMs are end-to-end encrypted
   on the room layer via an ECDH derivation between the two parties'
   identity keys (huddle 0.7.1+).
4. **Group rooms** — press `g` to create a multi-peer room. Pick a
   name, choose public or encrypted (and a passphrase if encrypted).
   You become the room's first *owner*; only owners can kick, grant
   moderation, or rotate the room key. Discovered rooms you haven't
   joined appear under the **Discover** sub-row in the sidebar.
5. **Inbound dial gate** — if someone you don't know dials you, the
   TUI raises an Accept / Reject / Trust+Accept modal. The peer isn't
   added to your gossipsub mesh until you decide.
6. **Chat, verify, moderate** — see the [Key bindings](#key-bindings)
   tables for SAS verification (`Ctrl+V → s`), kick (`Ctrl+K`), grant
   owner (`Ctrl+G`), invite links (`Shift+I`), join codes (`Ctrl+J` /
   `c`), and verified-only-mode toggles (Settings pane, `o` per room).

## TUI layout

```
+----------------------------------------------------------------------+
| huddle 0.7.1  ·  745e-fe8a-…  ·  🌐 reachable          12:34 UTC     |
+------------------------+---------------------------------------------+
| ▾ Profile              | # general                                   |
|   alice  HD-AAAA-…  🌐 |   4 members · 🔒 encrypted                   |
| ▾ Direct messages  (2) |                                             |
|   ● bob       1m   (1) |   12:32  bob          hey                   |
|   ○ dave       offline |   12:33  carol  ✓     same here              |
| ▾ Group rooms      (1) |   12:34  you          looks good            |
|   # general  4  E      |                                             |
|   + Discover (2)       |                                             |
| ▾ People               |                                             |
|   eve  HD-EEEE-…  ✓    |   > _                                       |
| ▸ Activity             |                                             |
| ▸ Settings             |                                             |
+------------------------+---------------------------------------------+
| ?help  /type  ^V verify  ^F search  ^A attach  ^L leave  ^I members  |
+----------------------------------------------------------------------+
```

Six sidebar sections, top-to-bottom: **Profile** (you), **Direct
messages**, **Group rooms** (with a Discover row), **People** (known +
verified + blocked), **Activity** (status history + transfers),
**Settings** (toggles + go-dark). `j/k` moves the cursor; `Tab` /
`Shift+Tab` jumps between sections; `Space` / `→` / `←` toggles
expand. `Enter` opens the selection in the right-hand pane. `Esc`
focuses the sidebar from a chat pane.

## Key bindings

Single source of truth: `crates/huddle/src/keybindings.rs`. The Help
modal (`?`) renders the same table at runtime, so it can never drift
from the actual key map.

### Global (any pane, no modal open)
| Key                | Action                                  |
|--------------------|-----------------------------------------|
| `?`                | Help                                    |
| `:` or `Ctrl+P`    | Command palette — fuzzy search every action |
| `Ctrl+H`           | Notification history (last 100 status events) |
| `Shift+←` / `Shift+→`| Focus sidebar / pane (tmux-style)     |
| `Esc`              | Close modal / blur input / focus sidebar |
| `q` / `Ctrl+C`     | Quit (confirms first)                   |

> **About the focus-jump binding (huddle 0.7.3+):** `Shift+←` /
> `Shift+→` toggle keyboard focus between the sidebar and the pane,
> including while typing in chat input. Shift+arrows are unclaimed at
> OS and terminal level on macOS, Linux, and Windows — no Mission
> Control / Spaces conflict. (0.7.2 briefly used `Ctrl+←` / `Ctrl+→`
> but those collide with macOS's Move-between-Spaces shortcut.)

### Sidebar / non-chat panes
| Key                | Action                                  |
|--------------------|-----------------------------------------|
| `m`                | Start a DM (Compose-DM modal)           |
| `g`                | Start a group room                      |
| `p`                | Jump to the People pane                 |
| `,`                | Jump to the Settings pane               |
| `a`                | Add friend by HD ID or username         |
| `d`                | Dial a peer by multiaddr or `ip:port`   |
| `i`                | Show your identity as a QR code         |
| `Shift+I`          | Generate an invite link (peer-only, or room-scoped from a chat pane) |
| `v`                | Paste an invite link (`huddle://invite#…`) |
| `c`                | Join with code (when an encrypted group is selected) |
| `j` / `k` / arrows | Move sidebar cursor                     |
| `Tab` / `Shift+Tab`| Jump to next / prev sidebar section     |
| `Space` / `→` / `←`| Toggle section expand                   |
| `Enter`            | Open the selected row                   |
| `r`                | Refresh / reconnect (context-sensitive) |
| `x`                | Forget the selected peer                |
| `R` (Shift+r)      | Mark every room read                    |

### Chat pane (DM or Group)
| Key                       | Action                                |
|---------------------------|---------------------------------------|
| `/`                       | Focus input                           |
| `Enter`                   | Send                                  |
| `Alt+Enter` / `Ctrl+J`    | Newline in input                      |
| `Esc`                     | Blur input (or focus sidebar)         |
| `Ctrl+V`                  | Verify partner / member (SAS)         |
| `Ctrl+F`                  | Search this room's history            |
| `Ctrl+A`                  | Attach a file                         |
| `Ctrl+L`                  | Leave the room                        |
| `j` / `k`                 | Scroll messages (input blurred)       |
| `g` / `G`                 | Scroll to top / bottom                |
| `PageUp` / `PageDown`     | Scroll a page                         |
| `f`                       | Focus file cards (`j/k` steps)        |

### Group pane only
| Key                       | Action                                |
|---------------------------|---------------------------------------|
| `Ctrl+I`                  | Toggle the right-margin member list   |
| `Ctrl+K`                  | Kick a member (owners only)           |
| `Ctrl+G`                  | Grant owner role (owners only)        |
| `Ctrl+R`                  | Rotate the room key (owners only)     |
| `Ctrl+J`                  | Generate a single-use join code (owners) |
| `Ctrl+M`                  | Mute / unmute this room               |
| `Ctrl+O`                  | Per-room verified-only-join toggle    |
| `Shift+B`                 | List bans for this room (owners)      |

### Settings pane (or Settings modal)
| Key | Action                                                   |
|-----|----------------------------------------------------------|
| `V` | Toggle "reject inbound from unverified"                  |
| `U` | Toggle the crates.io update check (opt-in)               |
| `E` | Edit your username                                       |
| `W` | Replay onboarding (what's new)                           |
| `B` | Manage blocked peers                                     |
| `Alt+Shift+1` (Option+Shift+1 on macOS) | Delete account (go dark) — passphrase-gated |

## Username & ID display (huddle 0.5)

Every peer has a 96-bit fingerprint rendered as a branded
`HD-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` ID. Same security as before, just a
friendlier format. The Profile pane (sidebar's top section) shows yours.

Set an optional username from the Profile or Settings pane (`E`). The username is
broadcast in a *signed* `ProfileUpdate` event — peers receiving it
verify the Ed25519 signature against the claimed fingerprint, so
nobody can spoof "alice" by stuffing a string into a packet. If you
clear the field (empty input), you broadcast as `[anonymous]`.

In chat, your message label shows the username (or `[anonymous]`).
SAS-verified peers also get a green `✓` next to their name in chat,
matching the existing badge in the room member list.

## Add friend by HD ID or username (huddle 0.5.1+)

Press `a` from the sidebar to open the add-friend modal. Takes either:

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
this path at all — they show up in the sidebar's People section
automatically.

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
global). With the global "verified-only inbound" toggle on (Settings
pane, `V`), unverified inbound dials auto-reject without prompting.

## Invite links

Press `Shift+I` to generate an invite. From a chat pane the invite
includes the current room; from anywhere else it's peer-only. The TUI
shows a `huddle://invite#<base64-JSON>` URL plus a QR. The base64 JSON
carries the host multiaddr (with `/p2p/<peer-id>` so libp2p enforces
the peer-id check on dial), the human-display fingerprint, and an
optional room summary.

Paste an invite from the sidebar with `v`. The TUI confirms the
claimed fingerprint and dials. After dial, the post-dial
fingerprint check (added in 0.3.x) re-derives the peer's fingerprint
from their Ed25519 pubkey on Identify and disconnects if it doesn't
match the invite's claim — defense in depth, since libp2p's
`/p2p/<peer-id>` already enforces the cryptographic match.

If the invite includes an encrypted room, you're prompted for the
passphrase next.

## Owners, kick, ban

The room's creator is the first owner; owners can grant the role to
others (`Ctrl+G`) or kick (`Ctrl+K`). Kick = signed `BanMember` broadcast +
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
connection forms. The Profile pane / sidebar badge shows the current
state (`🌐 reachable` / `🏠 LAN only` / `🔍 detecting…`).

Room announcements optionally carry a `host_addrs` field with up to 4
of the announcer's reachable addresses (relay-circuit and
AutoNAT-confirmed external). Peers receiving an announcement they
have no direct connection for will opportunistically dial the first
listed address (rate-limited per announcer). This lets cross-internet
peers bootstrap without invite links.

## Join codes (read-only joiners)

Owners press `Ctrl+J` in a Group pane to generate a single-use,
10-minute `XXXX-XXXX` code. The owner shares it OOB. The joiner
selects the encrypted group in the sidebar and presses `c` to enter
the code. The joiner's TUI generates an ephemeral X25519 keypair,
broadcasts a signed `CodeJoinRequest`, and waits for the owner's
`CodeJoinResponse` (which wraps the room's session key under an
ECDH-derived key). If no response arrives within 30 s, the TUI
surfaces a timeout error — usually meaning the code was wrong or
expired.

Code-joined members are **read-only**: they can read and send, but
without the passphrase they can't wrap session keys for newer
joiners. The Group pane header renders `(read-only)` next to the
encryption marker. To upgrade, an owner can re-onboard them with the
actual passphrase.

## Go dark — irreversible account deletion (huddle 0.5)

Press `Alt+Shift+1` (the Option key on macOS — same physical key) from
anywhere — or use the labeled row on the Settings pane — to open the
**go dark** modal. Single-field gate (huddle 0.7.6+):

- If you have a **master passphrase**, that's the gate — re-derived
  via Argon2id and constant-time compared to the in-memory SQLCipher
  subkey. Wrong passphrase clears the field and shows an inline error.
- In `--no-master-passphrase` sessions (no key to compare against),
  type the literal phrase `DELETE EVERYTHING` (case sensitive) instead.

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
peer). For group rooms entered via passphrase, you wrap your session
key with ChaCha20-Poly1305 under an Argon2id key derived from
`(passphrase, salt)` and broadcast that for every existing member to
pick up. For group rooms entered via code, ECDH between owner and
joiner gives a wrap key that delivers only the owner's session — the
joiner's own outbound goes unwrapped. For DMs (huddle 0.7.1+), the
wrap key comes from an Ed25519→X25519 ECDH between the two parties'
identity keys, expanded with HKDF-SHA256 bound to the canonical room
ID — both peers independently derive the same 32-byte wrap key.

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
`rooms` (with `kind` ∈ {`direct`, `group`}), `room_members` (with
`role`, `ed25519_pubkey`), `room_megolm_sessions`, `room_messages`,
`room_attachments`, `known_peers` (with `fingerprint`, `trusted`),
`blocked_peers`, `room_bans`, `verified_peers`, `peer_profiles`
(self-declared usernames, signed at the wire layer), `app_settings`.
Migrations are additive only and tracked via `PRAGMA user_version`.
Pass `--no-master-passphrase` to fall back to an unencrypted database
for testing.

**File attachments** — `Ctrl+A` opens a local file picker; selected
files are SHA-256-hashed, chunked into 64 KiB pieces, and broadcast
over the room's gossipsub topic with a `FileOffer` + N `FileChunk`
messages. In encrypted rooms (DM or group) the bytes are
ChaCha20-Poly1305-encrypted with a fresh file key that's
Megolm-wrapped in the offer. Receivers see a focusable file card in
chat — press `f` to enter card mode, `j/k` to step, Enter to save to
your platform's Downloads folder. Phase 2 cap is 1 MiB per file.

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
- DM end-to-end encryption (huddle 0.7.1) re-derives the room wrap key
  from both peers' long-term Ed25519 identity keys via X25519 ECDH —
  it lacks forward secrecy at the room-key layer. A future identity-
  key compromise unlocks historical DM session keys between those
  two parties (Megolm message keys still ratchet, but the wrap key
  doesn't). Per-DM ephemeral ratchets (Double Ratchet-style) are a
  candidate follow-up.

## What's new in 0.7.6 — Go Dark single-field flow

A user report surfaced that the 0.5-era two-field Go Dark modal looked
like it "didn't work" even after typing `DELETE EVERYTHING`. Root cause
was UX, not logic: the modal required filling **both** a master
passphrase field AND a typed `DELETE EVERYTHING` field, with `Tab` to
switch between them. Default focus was the passphrase, so typing
`DELETE EVERYTHING` straight away put the phrase into the wrong field
and the validation error rendered at the bottom of an already-tall red
modal — easy to miss.

- **Single field, mode-aware.** Sessions with a master passphrase now
  use the passphrase directly as the gate (the natural strong secret
  the user already knows — Argon2id-derived, constant-time compared).
  `--no-master-passphrase` sessions keep the typed `DELETE EVERYTHING`
  phrase as their only available gate, since they have no key to
  compare against.
- **Loud error feedback.** Wrong attempts now render `✗ <reason>` with
  a bold red banner directly above the Enter/Esc hint bar, instead of
  being buried at the bottom of the modal. The input field also clears
  on failure so the next attempt starts fresh.
- **No more `Tab`.** Removed `GoDarkNextField` action and the
  `KeyCode::Tab` mapping inside the Go Dark modal arm — single field
  means nothing to switch to.
- **New accessor** `AppHandle::has_master_passphrase() -> bool` so the
  TUI can pick the right gate at modal-open time without leaking the
  in-memory subkey.

## What's new in 0.7.5 — notifier hardening

Self-review of 0.7.4 surfaced four follow-up items. All landed in 0.7.5:

- **Conservative initial focus state.** 0.7.4 defaulted `focused = true`,
  which suppressed notifications if huddle launched in a terminal that
  was already in the background (no `FocusGained` event ever fired).
  0.7.5 treats "no focus event observed yet" as **unfocused** — false
  positives (one extra notification) only.
- **Sliding catch-up grace.** The 5-second post-launch summary window
  now extends by 2s on every inbound message during the window, capped
  at a hard 30s ceiling from start. Slow gossipsub backlogs are
  correctly batched into one summary instead of leaking into
  per-message alerts.
- **Notification rate-limit.** A 2-second cooldown coalesces bursts:
  the first notification in a burst fires immediately with full
  detail (room / sender / preview); within the next 2s, additional
  notifications are counted and a single "N more new messages" summary
  fires when the window closes. Prevents process / thread spam for
  busy rooms.
- **ASCII chord labels.** `⌥⇧1` keycap glyphs were dropped in favor
  of `Alt+Shift+1` (and `Option+Shift+1 on macOS` callouts where it
  helps) — fonts render the Unicode keycaps too inconsistently
  across terminals. The Mac runtime behavior is unchanged (the
  `⁄` glyph and the `ALT|SHIFT+!` event both still trigger Go Dark).

## What's new in 0.7.4 — desktop notifications + safer go-dark chord

- **Desktop notifications when the terminal isn't focused.** Every
  inbound message fires a native notification (`osascript` on macOS,
  `notify-send` on Linux, PowerShell BalloonTip on Windows — no extra
  dependency) when crossterm reports the terminal as unfocused.
  Notifications include the room name, sender display name, and a
  trimmed message preview. When the terminal IS focused, no
  notification is sent — the message is already on screen and the
  unread badge does the work.
- **Catch-up summary on startup.** When huddle reopens, messages
  received during a 5-second catch-up window are batched into ONE
  notification: `huddle · N new messages while you were away`. After
  the window closes, real-time notifications kick in.
- **Focus reporting via crossterm `EnableFocusChange`.** Supported by
  iTerm2, Terminal.app, Alacritty, Kitty, wezterm, Windows Terminal,
  and GNOME Terminal. On a terminal that doesn't emit
  `FocusGained` / `FocusLost`, the app stays in "focused = true" mode
  and never fires per-message notifications — graceful degradation.
- **Go dark rebound to `Alt+Shift+1`** (Option+Shift+1 on macOS). Plain
  `!` was just Shift+1 — one accidental keystroke could open the
  destructive flow. The Mac chord works out of the box on Terminal.app
  via the unicode glyph `⁄` that Option+Shift+1 produces, AND via the
  `ALT|SHIFT+!` event that Alt-as-Meta terminals emit. On Linux/Windows
  the same Alt+Shift+1 chord is uncontested.
- **First-time macOS notification permission prompt.** macOS will ask
  to allow Script Editor (or Terminal) to send notifications the first
  time huddle fires one. Click Allow once and you're set.

## What's new in 0.7.3 — UX polish round 2

- **Focus-jump rebound to `Shift+←` / `Shift+→`.** 0.7.2's `Ctrl+←` /
  `Ctrl+→` collided with macOS Mission Control's Move-between-Spaces
  shortcut (and `Cmd+←` / `Cmd+→` is Terminal/iTerm2 tab-switching,
  ruling that out too). Shift+arrows are unclaimed everywhere.
- **Sidebar cursor is visible again.** The previous bg-only highlight
  on the selected row used `Color::Rgb(40, 40, 60)` which is
  near-indistinguishable from default terminal bg on Terminal.app.
  Selected rows now recolor every span's foreground to **yellow**
  (warn) when the sidebar is focused, dim text when not — readable
  on every dark theme.
- **2-col gutter between sidebar and pane.** Panes with `Borders::NONE`
  (Welcome, Profile) used to render text flush against the sidebar
  separator line. The outer layout now inserts a 2-column gap before
  the pane rect, so every pane has visible breathing room.
- **Settings pane keybindings actually fire.** The pane displays
  `V verified-only / U update check / E username / W replay
  onboarding / ! go dark` — but 0.7.0–0.7.2 only dispatched those
  inside the Settings *modal*, leaving the pane rows inert. They now
  fire from the pane itself.
- **`!` (go dark) is global.** Previously only available from the
  Settings modal; now reachable from any non-chat pane. The modal's
  two-factor passphrase + "DELETE EVERYTHING" confirm protects
  against accidental triggers.

## What's new in 0.7.2 — UX polish

- **`Ctrl+←` / `Ctrl+→` focus jump** between sidebar and pane (works
  from any context, including while typing in chat input). One
  keystroke instead of `Esc` → `Tab`. macOS users may need to disable
  Mission Control's Move-left/right-a-space shortcut (System Settings
  → Keyboard → Keyboard Shortcuts → Mission Control). When focus
  jumps to a chat pane, the input is auto-activated so you can type
  immediately.
- **Settings pane padding fix.** The value column was jammed flush
  against the label column when a label was exactly 24 chars wide
  (`update check (crates.io)on` rendered with no gap). Labels now pad
  to 28 chars, guaranteeing visible whitespace before every value.
- **Sidebar focus border** continues to highlight which region owns
  the keystrokes (already shipped in 0.7; surfaced more clearly with
  the new focus-jump bindings).

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

`0.7.0` rewrote the TUI around a **sidebar + pane** layout
(Discord/Slack-style), with explicit separation of **Direct messages**
from **Group rooms**. The legacy `Screen::{Lobby, InRoom}` flat-screen
model and the tab-bar were retired.

See [TUI layout](#tui-layout) and [Key bindings](#key-bindings) for
the current state. Notable shipped items:

- New `RoomKind::{Direct, Group}` persisted on the rooms table;
  `RoomAnnouncement.kind` (serde-default for back-compat) tags every
  wire announcement so 0.7 peers can split DMs from groups.
- Canonical DM room IDs: `sha256("huddle-dm-v1\0" || min(fp_a, fp_b)
  || "\0" || max(fp_a, fp_b))` — both peers, regardless of who
  presses `m` first, derive identical IDs. `start_direct` is
  idempotent across both peers and reinstalls.
- DM-visibility filter at honest 0.7+ consumers: Direct
  announcements addressed to anyone else are dropped, so a DM never
  leaks past the two participants' sidebars.
- 2-member cap enforced locally on `RoomKind::Direct` rooms.
- New panes: Profile, People (known + verified + blocked sublists),
  Activity (status history + transfers), Settings (toggles, blocked
  peers, go-dark).
- New `Modal::ComposeDm` with inline autocomplete from
  `known_peers` + `peer_profiles`; falls back to `AddFriend`
  semantics on unrecognized input — no modal-on-modal.
- Centralized `Theme` module so colors live in one place.

**Retired in 0.7**: `Screen::{Lobby, InRoom}`, the tab-bar, numeric
`1..9` tab jumps, `Ctrl+B` (back-to-lobby in chat — `Esc` focuses
sidebar instead), `LobbyFocus` (replaced by `SidebarFocus`), the flat
`discovered_rooms` list (now split into DM / Group sections).

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
