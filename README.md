# Huddle

End-to-end-encrypted chat rooms over Tor — as a native desktop app
(`huddle-gui`, egui/eframe) or a terminal UI (`huddle`). Both drive the same
core, identity, and relay.

Open either client, start a room or paste an invite, and chat. Rooms can be
public (cleartext payloads) or encrypted (per-sender Megolm group
sessions, session keys wrapped with an Argon2id-derived passphrase
key). Either way the transport is end-to-end: the relay only ever sees
ciphertext.

**huddle 1.0 runs LAN discovery and the relay together by default — no
mode switch.** Friends on the same network connect directly over libp2p
(mDNS); everyone else is reached through a self-hostable relay
(`crates/huddle-server`). Each message rides whichever path reaches the
peer, and the per-chat header shows which (`via lan` / `via relay`). The
relay is a dumb encrypted router + offline mailbox — it never holds keys
and never decrypts.

**The relay has several "doors", each a different anti-censorship
tradeoff** (run `huddle transports` to see them): a Tor v3 **onion** via
your system Tor (most private, the default); the same onion via a private
**obfs4/WebTunnel bridge** (for networks that block Tor); an in-process
**Arti** onion (with `--features arti`); and **clearnet** `ws://`/`wss://`
straight to a raw IP (fast, for VPN users or where Tor is fully blocked —
the relay sees your IP, but messages stay end-to-end encrypted). The same
`huddle-server` process can be exposed as an onion **and** on a public IP
at once, so all doors share one set of rooms + mailboxes. Pick a door with
`--transport <id>`, set an order with `--transport-order`, or point at a
clearnet relay with `--clearnet-server ws://<ip>:<port>/ws`.

As of **1.1**, huddle also ships with the operator's **clearnet relay baked
in** (a cloudflared `wss://` tunnel onto the very same rooms + mailboxes), so
a client that can't reach Tor connects with zero config. It's tried only
*after* the onion, so a Tor user never touches it; `--clearnet-server`,
`clearnet_url` in `config.toml`, or Settings → Network override it.

**Contacts** are a durable, fingerprint-keyed address book — keyed by
identity, not by an ephemeral LAN address — so a conversation keeps
working after a peer leaves the LAN. `a` adds a contact by HD-ID; over the
relay this reaches them across the internet (live or via the mailbox), and
they accept from the Contacts pane to open a DM. DMs persist across
restarts and keep flowing over the relay.

> **Tor is optional now.** LAN works with no Tor at all, and a clearnet
> relay door needs no Tor either. The onion doors do need a local Tor
> daemon (SOCKS5 on `127.0.0.1:9050`; override with `--tor-socks`). On
> Debian/Ubuntu: `apt install tor && systemctl enable --now tor`. If Tor
> is down, huddle falls through to the next available door.

> **This is a learning project, not production-audited chat.**
> SQLCipher protects the database at rest under your master passphrase,
> Megolm sessions are persisted with an Argon2id-derived key, file
> bytes use ChaCha20-Poly1305, and SAS contact verification ships in
> v0.3 — but the protocol has not been audited and threat-modelling
> work is ongoing. Don't rely on it for real secrets without a
> careful review.

## Install

huddle ships three binaries — install whichever you need:

- **`huddle-gui`** — the native desktop app (egui/eframe). Start here if you
  want a windowed client.
- **`huddle`** — the terminal UI (TUI).
- **`huddle-server`** — the relay + offline mailbox (only if you're hosting
  one; see [Run your own relay](#run-your-own-relay-cloudflared-no-domain)).

### From crates.io

With a stable [Rust toolchain](https://rustup.rs) (edition 2021, 1.75+):

```bash
cargo install huddle-gui      # native desktop GUI
cargo install huddle          # terminal client
cargo install huddle-server   # relay (host-side only)
```

The binaries land in `~/.cargo/bin/` (make sure it's on your `PATH`), then
launch the GUI with `huddle-gui` or the terminal client with `huddle`.

### System prerequisites

You need the Rust toolchain and a C toolchain (the bundled SQLCipher compiles
a vendored OpenSSL from source). Beyond that:

- **macOS** — just the Xcode Command Line Tools: `xcode-select --install`.
- **Windows** — the MSVC "C++ build tools" that `rustup` already prompts for.
  No extra SDK; the GUI uses the native file dialogs.
- **Linux** — a normal graphical desktop already has the runtime libraries the
  GUI needs (X11/Wayland + OpenGL). On a **minimal or headless** box, install
  the build/runtime deps:

  ```bash
  sudo apt-get install -y build-essential pkg-config perl \
    libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev
  ```

  > **No GTK required.** huddle-gui's file dialogs go through the XDG desktop
  > portal (`rfd`'s default `xdg-portal` backend), so `libgtk-3-dev` is **not**
  > needed — only a portal backend at runtime (standard on GNOME/KDE). Add
  > `libclang-dev` only if a dependency's build complains about `libclang`.

### Build from source

```bash
git clone https://github.com/richer-richard/huddle
cd huddle
cargo build --release
./target/release/huddle-gui     # desktop GUI
./target/release/huddle         # terminal client
```

### `huddle app` — build, install & launch the GUI in one step

From a source clone, the terminal client doubles as an installer for the
desktop app:

```bash
huddle app
```

This builds `huddle-gui` in release mode and installs it where your OS keeps
desktop apps, then launches it:

- **macOS** — assembles `Huddle.app` in `/Applications` (falling back to
  `~/Applications` if that isn't writable).
- **Linux** (Ubuntu / Debian / Kali / …) — copies the binary to `~/.local/bin`
  and adds a `huddle.desktop` launcher to your app menu.
- **Windows** — installs to `%LOCALAPPDATA%\Programs\Huddle` with a Start-Menu
  shortcut.

Plain `huddle` (no subcommand) still opens the terminal UI. Run `huddle app`
from inside the repo, or point it at a clone with
`HUDDLE_SRC=/path/to/huddle huddle app`.

### Running the desktop GUI

Launch `huddle-gui`. On **first run** it walks you through a one-time signup:
choose a **username** and a **master passphrase** (used to derive the at-rest
encryption key for your local database — Argon2id, 64 MiB), then confirm it.
Every later launch just asks for that passphrase to unlock. Pass
`--no-master-passphrase` to run with an unencrypted database and skip the
unlock screen.

The GUI takes the **same transport flags as the TUI** — e.g.
`huddle-gui --clearnet-server wss://host/ws` to pin a clearnet relay, plus
`--server` / `--no-server`, `--tor-socks`, `--transport` / `--transport-order`,
`--mode mdns` (also run LAN discovery), and `--name`. Run `huddle-gui doctor`
to print version + paths for a bug report. Your config and data live in the
per-OS app directory:

| OS | Location |
|----|----------|
| **Linux** | `~/.local/share/huddle/` (config: `~/.config/huddle/config.toml`) |
| **macOS** | `~/Library/Application Support/huddle/` |
| **Windows** | `%APPDATA%\huddle\` |

## How it works (high level)

1. **Launch** — your Ed25519 identity loads (or generates) from disk
   silently. The TUI opens on the **Welcome** pane with the sidebar
   on the left. huddle connects to the Tor onion relay in the
   background (the relay dot `●` next to your name turns solid once
   the link is up). With `--mode mdns`/`--mode direct` a libp2p swarm also starts
   for LAN discovery / direct dial alongside the relay.
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
| huddle 1.0.0  ·  745e-fe8a-…  ·  relay ●               12:34 UTC     |
+------------------------+---------------------------------------------+
| ▾ Profile              | # general                                   |
|   alice  HD-AAAA-…  ●  |   4 members · encrypted                     |
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
HKDF produces a Matrix MSC 2241-aligned 7-symbol + three-4-digit-group
decimal code. The TUI shows the symbols as their **English words**
(dog, cat, lion, … — emoji-free) plus the decimal; both peers compare
OOB (call/SMS/in-person) and press
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
connection forms. When libp2p is enabled the Profile pane / sidebar
badge shows the current state (`reachable` / `LAN only` / `detecting…`).

Room announcements optionally carry a `host_addrs` field with up to 4
of the announcer's reachable addresses (relay-circuit and
AutoNAT-confirmed external). Peers receiving an announcement they
have no direct connection for will opportunistically dial the first
listed address (rate-limited per announcer). This lets cross-internet
peers bootstrap without invite links.

## Run your own relay (cloudflared, no domain)

The default relay is reached over Tor. If you (or the people you talk to)
can't use Tor, run **your own relay on a VPS and front it with a
[cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
tunnel** — no registered domain, no TLS cert of your own:

```bash
# On the VPS:
cargo build --release -p huddle-server
./scripts/huddle-relay.sh
# → prints:  wss://<rand>.trycloudflare.com/ws
```

`huddle-server` only ever moves **ciphertext** (it never holds keys or
decrypts). The script runs it on `127.0.0.1:8787` and points cloudflared at it;
cloudflared supplies a publicly-trusted `*.trycloudflare.com` hostname, which
huddle reaches through its TLS `clearnet-wss` door. Point clients at the URL:

- **GUI:** Settings → Network → **"Set / edit"** relay, paste the `wss://…/ws`.
- **CLI:** `huddle --clearnet-server wss://<rand>.trycloudflare.com/ws`, or set
  `clearnet_url = "wss://…/ws"` in `config.toml`.

A configured clearnet relay is tried **first** (you connect without waiting on a
Tor timeout) and the onion stays as a fallback. Any **invite you then generate
embeds this relay** (a signed v3 invite), so your contacts join with zero
config — they just accept the invite.

No tunnel and don't mind exposing your IP? Run the server directly and use a
raw plain-WebSocket door (open the firewall for the port):

```bash
HUDDLE_SERVER_BIND=0.0.0.0:8787 huddle-server      # on the VPS, e.g. 2.24.124.188
huddle --clearnet-server ws://2.24.124.188:8787/ws  # on each client
```

Caveats: free `*.trycloudflare.com` hostnames **rotate** when cloudflared
restarts (so embedded-relay invites go stale — use a *named* cloudflared tunnel
or a real domain for a stable URL); the raw `ws://` door reveals your IP +
WebSocket metadata to on-path observers (messages stay end-to-end encrypted);
and the server's SQLite DB on the VPS is not encrypted at rest (it holds only
ciphertext + routing metadata, never keys). See `scripts/README.md` for detail.

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
  huddle-core    shared library: rooms, crypto, network, storage
  huddle         terminal UI (ratatui TUI)
  huddle-gui     native desktop app (egui/eframe)
  huddle-server  WebSocket relay + offline mailbox (SQLite)
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

## What's new in 1.1.5 — a permanent clearnet address (for Tor-blocked users)

The baked-in clearnet fallback is now a **stable** address that never rotates,
so people in regions where Tor itself is blocked have a reliable non-Tor door.

- **Stable clearnet relay default.** `DEFAULT_CLEARNET_URL` now points at a
  permanent Cloudflare `*.workers.dev` proxy in front of the operator's relay,
  instead of a raw `*.trycloudflare.com` quick-tunnel hostname that rotated on
  every restart and went stale. The proxy reads the relay's current backend from
  KV (kept fresh automatically), so the address is durable. The Tor onion stays
  the canonical, preferred door; this clearnet fallback is tried only when the
  onion is unreachable, and any explicit `--clearnet-server` / `clearnet_url` /
  Settings value still wins over it.

## What's new in 1.1.4 — security & robustness pass

A hardening release across the relay client, the DM/SAS key exchange, the
mailbox, and the updater — plus the TUI catching up to the GUI's live themes.
No new features; the wire/relay protocol gets stricter and a few classes of
abuse close.

- **Relay client auth via Ed25519 challenge-response.** Connecting clients now
  prove control of their identity key to the relay through a signed
  challenge-response handshake before they can subscribe to an inbox or post
  to a mailbox — so a peer can't squat another fingerprint's inbox.
- **X25519 small-order / contributory checks on DM + SAS.** Both the DM wrap-key
  ECDH and the SAS ephemeral exchange now reject small-order and non-contributory
  public keys, closing key-substitution / forced-shared-secret attacks on the
  handshakes.
- **Safer relay mailbox delivery.** Queued ciphertext is now removed only
  after it's handed to the recipient's socket, over a bounded outbound queue,
  so a drop mid-drain no longer silently loses or double-delivers a message.
- **Bounded retention GC.** The relay's SQLite mailbox enforces a bounded
  retention window and garbage-collects expired ciphertext, so an offline
  recipient can't let the queue grow without limit.
- **Update check routed via Tor.** The opt-in crates.io update check now goes
  through the Tor SOCKS proxy instead of a direct clearnet request, so enabling
  it no longer leaks your IP to the index.
- **TUI live Dark / Light themes.** The terminal client gains the live
  Dark/Light theme toggle that shipped for the GUI in 1.1.2 — switchable from
  the Settings pane at runtime, no restart.

## What's new in 1.1.3 — rustls fix, system theme, `huddle app` installer

A reliability + convenience release.

- **rustls CryptoProvider fix.** The desktop GUI's `wss://` clearnet-relay
  worker could panic at startup ("could not automatically determine the
  process-level CryptoProvider"). huddle now links and installs the `ring`
  provider explicitly, so the clearnet door works in every binary.
- **System theme (GUI).** The desktop GUI gains a **System** option that
  follows your OS light/dark setting — now the default; existing Dark/Light
  choices are preserved.
- **`huddle app` installer.** From a source clone the terminal binary doubles
  as a one-step installer that builds, installs, and launches the GUI:
  `huddle app`.

## What's new in 1.1.2 — high-contrast Dark + Light GUI themes

The desktop GUI gains a proper theming pass: hand-tuned, high-contrast **Dark**
and **Light** palettes with a live toggle.

- **Two high-contrast themes.** Both Dark and Light are tuned for legible
  contrast across chat, sidebar, and modals rather than eframe's defaults.
- **Live Settings toggle.** Switch themes from Settings at runtime — the whole
  window re-skins immediately, no restart, and the choice persists.

## What's new in 1.1.1 — GUI install guide on crates.io

A docs-only release so the published crate carries the new install guide.

- **GUI install + run guide.** The README's Install section (with the
  `huddle-gui` install + first-run walkthrough) ships in the crate published to
  crates.io. No code changes.

## What's new in 1.1.0 — baked-in operator clearnet relay

huddle now ships with the operator's clearnet relay built in, so a client that
can't reach Tor connects with zero config — and the GUI reaches clearnet parity.

- **Operator clearnet relay door baked in.** A cloudflared `wss://` tunnel onto
  the very same rooms + mailboxes is compiled in as a default door. It's tried
  only *after* the onion, so a Tor user never touches it; `--clearnet-server`,
  `clearnet_url` in `config.toml`, or Settings → Network override it.
- **GUI clearnet parity.** The desktop GUI gets the same clearnet-relay
  controls as the TUI — set / edit a relay URL from Settings → Network, with
  invites embedding the configured relay.

## What's new in 1.0.1 — the GUI catches up to the unified network

The native egui GUI gains the contacts book, transport doors, and unified
LAN+relay network that landed for the TUI in 1.0.0.

- **Contacts, doors & unified network in the GUI.** The egui desktop client
  now wires up the fingerprint-keyed Contacts book, the add-by-HD-ID relay
  inbox flow, the multi-transport doors, and the LAN+relay-by-default network —
  reaching feature parity with the TUI's 1.0.0 release.

## What's new in 1.0.0 — one app, every network, every door

A big one. huddle stops being "relay-only OR libp2p-only" and becomes a
single E2EE core with both carriers on by default, a durable contact book,
and a menu of anti-censorship transports onto the relay.

- **LAN + relay on by default — no mode switch.** The startup mode now
  resolves to libp2p mDNS (LAN) running *alongside* the relay; the
  Settings LAN toggle picks mDNS vs direct on the next launch, and
  `--mode` still overrides. Pure-relay (`--mode server`) and no-libp2p
  setups are still available, but you no longer choose between "nearby"
  and "internet" — you get both. LAN works even with Tor down.

- **Contacts — a durable, fingerprint-keyed address book.** A new
  `contacts` table keyed by the stable identity (not an ephemeral libp2p
  multiaddr) is the link that lets two people keep chatting after they
  leave the LAN: the relay routes by fingerprint/room, so the DM keeps
  working. The People pane is now **Contacts**; `list_contacts()` joins
  the book with derived username / verified / trusted / reachability.

- **"Add by HD-ID" works over the internet.** Each client subscribes to a
  private relay **inbox** (`inbox:<hash(fingerprint)>` — the relay never
  sees the raw fingerprint, and stores no contact graph). `a` sends a
  signed `ContactRequest` there; the recipient sees it in the Contacts
  pane's **Requests** tab and accepts to open a DM. An echo-back makes
  both sides converge over the relay. **No `huddle-server` change** — it's
  a pure client convention over the existing protocol.

- **DMs persist across restarts.** Pre-1.0, DMs (always encrypted) were
  parked as "restorable" on restart and silently dropped relay-delivered
  messages until reopened. Now DMs re-activate automatically at startup
  (their key derives from your identity + the partner's stored pubkey, no
  passphrase), so a conversation keeps flowing.

- **Transport "doors" onto the relay (anti-censorship).** `huddle
  transports` lists every door with its privacy tradeoff and whether it's
  usable: **onion via system Tor** (default, most private), **onion via a
  private obfs4/WebTunnel bridge** (for blocked-Tor networks), **onion via
  in-process Arti** (`--features arti`), and **clearnet `wss://` / `ws://`
  to a raw IP** (fast; the relay sees your IP, content stays E2E). The app
  tries them in a fallback order (most private first) or a pinned one
  (`--transport`). One `huddle-server` can serve an onion **and** a
  clearnet IP simultaneously — same rooms, same mailboxes. New flags:
  `--clearnet-server`, `--transport`, `--transport-order`, `--tor-bridge`.

- **Per-chat transport indicator.** Every DM/group header shows whether
  it's currently reaching peers `via lan`, `via relay`, or is `offline` —
  status only, no manual switch, so the security context is always
  legible. Settings → Network lists the doors + marks the active one.

- **Clearnet relay needs no domain.** A raw-IP `ws://<ip>:<port>/ws` relay
  works with zero extra setup (bind `huddle-server` to `0.0.0.0`, open the
  port). `wss://` (TLS) adds transport encryption via a real cert (a free
  subdomain + Caddy/Let's Encrypt, or Cloudflare Tunnel). This is the fast
  lane a VPN user can take when they can't bootstrap Tor.

## What's new in 0.7.12 — self-review follow-ups to the 0.7.11 audit pass

A short follow-up after independent self-review of the 0.7.11 release
caught three issues:

- **Notification focus-default trade-off.** 0.7.11 flipped the
  "haven't observed a focus event yet" default from `false` (always
  notify) to `true` (assume focused, suppress). That fixed the
  audit's spam complaint for tmux-without-focus-events but caused
  the opposite regression for the same cohort — they got zero
  notifications instead of all of them. 0.7.12 splits the
  difference: assume focused during a 5-second startup grace
  window, then if no `FocusGained` / `FocusLost` has ever fired,
  fall back to `false` (always notify). Terminals that DO speak
  focus events behave normally throughout.
- **`RelayReservationLost` was dead-wired.** 0.7.11 declared the
  variant and a consumer in `app/mod.rs`, but libp2p 0.56's
  `relay::client::Event` doesn't expose a `ReservationReqFailed`
  arm we can match on, so the producer never emitted it. 0.7.12
  removes the dead variant and consumer rather than ship code
  that's silently unreachable. Reservation loss currently manifests
  as the next AutoNAT probe flipping to "private" once the circuit
  drops; a future health-check timer can re-introduce a dedicated
  signal when libp2p's API supports it.
- **SAS code incompatibility documented.** 0.7.11's rejection
  sampler is correct, but it produces different emoji codes than
  0.7.10's `mod 49` derivation in ~84% of pairings. A 0.7.11↔0.7.10
  SAS verification will silently fail to match. This is a deliberate
  break (the new derivation is uniformly distributed; the old one
  wasn't), but it wasn't called out in the 0.7.11 notes. Both ends
  need to be on 0.7.11+ for SAS to succeed.

## What's new in 0.7.11 — security + UX hardening pass

A wide audit pass on top of the 0.7.10 follow-up. The wire protocol,
authorization gates, panic surface, modal handling, notifier, storage,
clipboard, and SAS derivation all got tightened. **Wire compat with
0.7.10 and earlier is broken on purpose** — signed envelopes now carry
a timestamp and several previously-plain messages now require a
signature. The trade was deliberate: the 0.7.10 line had a few silent
authentication failures that the audit caught.

### Wire protocol

- `MemberLeave`, `MemberAnnounce`, and `FileOffer` must now arrive
  inside a `SignedRoomMessage` whose signer matches the claimed
  sender. Pre-0.7.11 these were plain, so any peer subscribed to a
  room topic could spoof another member's leave (evicting them from
  honest rosters) or pin a fabricated Ed25519 pubkey under a victim's
  fingerprint via a TOFU race.
- `SignedRoomMessage` gained a `signed_at_ms` field. The verifier
  rejects envelopes outside a ±5 min window — closing the indefinite
  replay of captured `BanMember` / `OwnerGrant` / `SasConfirm` /
  `ProfileUpdate`. The timestamp is signature-bound.
- Switched from `Ed25519::verify` to `verify_strict`, which rejects
  low-order / mixed-order pubkeys.

### Invite links

- Bumped invite version to 2. v2 invites carry the creator's Ed25519
  pubkey + an Ed25519 signature over the rest of the payload. Tampering
  with `host_multiaddr`, `salt_b64`, `owner_fingerprints`, or any other
  field is now detected before the receiver dials. v=1 invites still
  decode (with a "this invite is unsigned" hint) so older shared links
  keep working.

### Authorization gaps

- The ban filter now applies to **every** content-bearing arm
  (`Plain`, `Encrypted`, `FileOffer`, `FileChunk`, `Typing`), not just
  `MemberAnnounce`. Banned peers in unencrypted rooms used to keep
  posting plaintext that honest clients rendered.
- The outbound dial-then-auto-DM flow now consults the persistent
  blocklist before opening a DM tab. Previously, dialing a blocked
  peer's address still triggered `AutoOpenDm`.
- `send_file` rejects read-only joiners (code-joined peers). Previously
  the read-only gate only covered `send_room_message`.
- The Direct-announcement auto-bootstrap rejects messages from blocked
  peers before creating a DM row.

### Panic prevention

- `now_unix` returns 0 on a backwards clock instead of panicking. The
  network task used to crash on every encrypt/decrypt when the wall
  clock sat before 1970 (ARM SBCs without RTC, virt clones).
- `wipe_file` writes zeros in a fixed 64 KiB scratch buffer rather
  than allocating `vec![0u8; meta.len()]`. Go-dark used to OOM
  mid-wipe when a user had downloaded a multi-GB attachment.
- `bootstrap_direct_room` returns an error instead of `.expect()`-ing,
  so a transient DB write failure can't take down the spawned task.
- `cleanup_expired_pending_friend_requests` uses `saturating_sub` for
  the cutoff so a `now < TTL` clock doesn't match every row.

### Critical UX

- Settings → Privacy `c` opens a confirmation modal before wiping the
  blocklist. Pre-0.7.11 it cleared everything instantly — one
  keystroke from total data loss, and the same `c` opened the
  join-code modal in the lobby so muscle memory was destructive.
- Clipboard yank now runs on a dedicated OS thread with a 2 s
  timeout. Previously, `xclip`/`wl-copy` with no display could hang
  the entire TUI on a routine `y`.
- File-chunk receiver caps per-chunk size (256 KiB), bounds
  `chunk_index < total_chunks`, and tracks `bytes_received` against
  the advertised `expected_size`. Pre-0.7.11 a hostile peer could
  advertise 1 MiB and stream multi-GB chunks before the SHA gate ran.
- DM sidebar "online" dot now compares the partner's fingerprint to
  `known_peers[i].fingerprint` instead of `.label`. Every DM showed
  `○` offline even when the partner was connected.
- The member-margin toggle is now bound to **Alt+M** (Ctrl+I was
  unreachable — terminals deliver it as Tab). Hint bar and help
  screen updated.
- Activity pane `c` now clears the status history, matching the hint
  text. Previously it fell through to `OpenJoinWithCode`.

### Crypto correctness

- SAS emoji derivation switched from `mod 49` (biased — indices 0..14
  were twice as likely) to rejection sampling with HKDF re-expansion.
  Restores the full uniform distribution over the 49^7 table.
- Argon2id-derived passphrase keys returned in a `Zeroizing<[u8; 32]>`
  wrapper so they don't linger on the heap after their last use.

### Network resilience

- `ConnectionClosed` now emits `PeerDisconnected` so the lobby's
  "online" dots clear for relay / internet peers, not just mDNS
  expiries. Also cleans gossipsub's explicit-peers set.
- `RelayClient` events are no longer swallowed — reservation status
  surfaces in the logs.
- DCUtR failures cap at 6 warn-logs per peer so symmetric-NAT pairs
  don't spam.

### Modal + input

- `Shift+?` now opens the "what's new" card from the sidebar (the
  cheat sheet advertised this for a while; the handler was missing).
- Inside the command palette, **Ctrl+N / Ctrl+P** navigate the result
  list instead of typing literal `n`/`p` into the filter. Other Ctrl
  chords inside the palette are dropped instead of corrupting the
  query.
- `Help` / `Info` / `QrIdentity` / `ShowJoinCode` / `ShowInvite` now
  dismiss only on `Esc` / `Enter` / `q`. Pre-0.7.11 any unbound key
  closed them — reflexive vim-`h` or `?` silently dismissed.
- `Modal::Sas` no longer cancels on bare `c` or `q`. Common letters
  when reading emoji words aloud used to abort the verification.
- `Modal::AttachPicker` no longer ascends on bare `h` (typo hazard).
- `Ctrl+C` only opens the quit-confirm modal when no modal is open.
  Mid-typing a passphrase / username / GoDark confirmation, an
  accidental Ctrl+C used to discard the typed buffer.
- Settings tab digits 1-4 require pane focus, matching the 0.7.9
  Tab/BackTab fix.
- The Onboarding modal degrades gracefully on tiny terminals instead
  of returning a zero-rect and silently disappearing.

### Storage

- Migrations now run inside `BEGIN; …; PRAGMA user_version = N;
  COMMIT;` so a partial-batch failure rolls back cleanly. Pre-0.7.11
  a mid-migration error left the schema half-applied with
  `user_version` un-bumped and wedged every subsequent startup.
- After `PRAGMA key`, we run `SELECT count(*) FROM sqlite_master` as
  a sentinel. A wrong master passphrase now returns a clean
  "wrong master passphrase, or DB file corrupt" instead of a cryptic
  downstream `CREATE TABLE` error.

### Notifier

- macOS / Linux / Windows notifier paths strip control characters
  from titles + bodies. Pre-0.7.11 a peer-controllable room name
  with a literal CR broke the AppleScript invocation silently.
- `notify-send` now passes `--category=im.received` for proper
  app-grouping in GNOME Shell / KDE.
- `is_focused()` defaults to `true` when no FocusChange event has
  ever been observed. tmux without `set -g focus-events on` and
  basic SSH shells no longer fire a desktop notification for every
  message regardless of focus.

### Polish + dead code

- Removed dead `let r = app.active_room()` shadow, unused
  `Theme.accent_dim`, unused `UnreadCounts::unread_count` /
  `pending_count`. Build now warning-free at warn level.
- Mention detection bumped from a 4-hex-char prefix to 8 hex chars,
  cutting false positives from ~1/65 K to ~1/4 B per token and
  closing the trivial "include the victim's prefix to bell their
  terminal" weaponization.
- SAS double-fire race fixed via a `finalized` latch on `SasFlow`.
- Selected encrypted-room rows in the sidebar now preserve the
  magenta lock-marker color instead of stomping it to selection-yellow.
- Generate-join-code doc clarified: 31 chars / ~39.6 bits, not 32.

## What's new in 0.7.10 — restore the Profile sidebar-nav gate

A follow-up to 0.7.9. Dropping the pane-focus gate on Profile's
`j/k/y` trapped sidebar navigation: when the cursor scrolled into the
Profile sub-item, `sync_pane_from_selection` live-previewed the pane
(intentional 0.7 design), and the ungated `j/k/y` handler then stole
every subsequent arrow/letter — so the cursor couldn't reach Direct,
Group, People, Activity, or Settings without `Shift+Tab`'ing past it.

0.7.10 reinstates the `SidebarFocus::Pane` gate on `j/k/y`. Capital-
case `E` / `Q` chords stay ungated — they don't conflict with
sidebar nav and the one-keystroke discovery flow is worth keeping.

The People analogy 0.7.9 cited turned out to be sharper than it
looked: People only captures `j/k` inside the Pending sub-tab, and
reaching Pending requires `Tab`'ing into the pane first. Profile
auto-switches on selection, so the equivalent gate is "user has
explicitly `Shift+→`'d into the pane".

## What's new in 0.7.9 — keybinding-scope fixes from a self-audit

A small follow-up patch from a self-review of the 0.7.8 release. No new
features; three keybinding bugs that the 0.7.8 ship-checklist missed:

- **Tab in Settings no longer swallows the focus toggle.** In 0.7.8,
  pressing Tab anywhere in `Pane::Settings` cycled tabs even when the
  sidebar was focused, which silently disabled the universal "Tab =
  toggle sidebar↔pane focus" gesture for users in Settings. 0.7.9 only
  intercepts Tab / Shift+Tab for tab cycling when the pane itself is
  focused. From sidebar focus, Tab now correctly moves focus into the
  pane (one keystroke), then subsequent Tabs cycle.
- **Profile j/k/y match People's pattern.** 0.7.8 required pane focus
  for the Profile field cursor; People's analogous sublist nav has
  always worked regardless of focus. 0.7.9 makes Profile consistent —
  pane-active is enough to claim j/k/y, no separate focus gate.
- **Dead `Action::OpenSettings` removed.** The `,` chord routes through
  `JumpToSettingsPane` (which now resets to the Account tab). The
  legacy `OpenSettings` variant was unreachable in 0.7.8; removed in
  0.7.9 along with its dispatcher.

## What's new in 0.7.8 — three connection paths, tabbed Settings, copyable identity

A round of UX polish that borrows the right things from neighbouring apps
without backsliding on huddle's privacy stance. Three discovery/connection
paths now read as **co-equal parallel options** instead of "mDNS first,
everything else as fallback", Settings became a tabbed pane that finally
includes the toggles that used to live in `config.toml`, the Profile pane
copies fields to the OS clipboard, and the People sidebar surfaces
pending friend-request counts where you can actually see them.

- **Three connection paths, equally surfaced.** Welcome copy spells out
  the trio: LAN (mDNS) · direct IP dial · invite link. The Settings →
  Network tab shows the same three rows with their live status. A new
  `M` toggle in Settings → Network lets you disable LAN broadcast
  entirely for privacy — peers can still reach you over direct dial or
  invite link with no LAN advertisement (restart-required to apply;
  flipping a `Toggle<Mdns>` mid-run would have required a behaviour
  rebuild for negligible benefit).

- **Tabbed Settings pane.** `Modal::Settings` is gone. Pressing `,`
  lands you on `Pane::Settings` with four tabs cycled via Tab /
  Shift+Tab or numeric jumps `1`–`4`:
  - **Account** — username (`E`), HD-ID, derived **Safety Code**
    (`SAFE-XXXX-XXXX-XXXX`), QR (`Q`), replay onboarding (`W`).
  - **Network** — LAN mDNS toggle (`M`), reachability badge, listen
    addresses, relay list from `config.toml`.
  - **Appearance** — placeholder (single read-only `theme: dark` row;
    light + high-contrast in a future release).
  - **Privacy** — verified-only inbound (`V`), desktop notifications
    (`N`), update check (`U`), blocked peers (`c` clears all), and
    the Go Dark `Alt+Shift+1` chord.

- **Copyable identity fields.** The Profile pane is now a cursor-
  navigable list: `j`/`k` move, `y` copies the highlighted field to the
  OS clipboard. Username, HD-ID, Safety Code, full fingerprint, and
  every listen address each get their own yankable row. Clipboard
  helper shells out to `pbcopy` (macOS) / `wl-copy` then `xclip` /
  `clip.exe` (Windows) — no new crate dependency, failures degrade
  to a status message instead of crashing.

- **Sidebar density.** Direct messages and Group rooms each pin a
  `+ Add Friend` / `+ New Group` row at the top so the action is a
  cursor-and-Enter away, not a chord lookup. Pending friend requests
  surface twice in the People section: as `N pending` next to the section
  header, and as a dedicated row at the top of an expanded section
  when there's at least one outstanding request.

- **Notifications opt-out.** `Settings → Privacy → N` toggles the
  OS-native toast notifications introduced in 0.7.4. Default ON;
  turning it OFF skips both the per-message path and the startup
  catch-up summary. Notifications remain 100% local — the toggle is
  for users who don't want any signal leaving the terminal at all.

- **No protocol changes.** Only new local rows in the existing
  `app_settings` KV table (`mdns_enabled`, `notifications_enabled`).
  Both default to ON so existing users see zero functional change
  until they opt out.

## What's new in 0.7.7 — friends, invites, and a fixed dial dead-end

Three coordinated UX fixes around the "first contact" flow. Dialing a peer
now actually opens a chat instead of dead-ending at a connection, the
People pane shows real usernames, friend requests survive longer than
15 seconds, and inviting peers to a group no longer requires pasting a
link into Signal.

- **Dial → DM auto-open.** When you initiate a dial (`d` IP:port, `a`
  HD-ID, or paste-invite), the post-Identify handler now opens (or reuses)
  a DM with the peer and switches your pane to the new `Dm(room_id)`. No
  more "connected to 192.168.1.5" status with no way to chat. Auto-
  reconnects and announcement-driven opportunistic dials do NOT trigger
  this — only paths the user explicitly chose register an address in
  `pending_auto_dm_addrs`.
- **Usernames in Known peers.** The People pane's Known sublist now
  renders each peer as `username · HD-XXXX-XXXX · address · last`,
  pulling the username from the cached `peer_profiles` table. Falls back
  to `[anonymous] · HD-pending` for peers we haven't yet seen a signed
  `ProfileUpdate` from.
- **Row actions actually fire.** The People pane header advertises
  `m message · r reconnect · b block · x forget · u unblock`, but those
  keystrokes were previously hitting the *global* handlers (e.g. `m`
  opened an empty Compose-DM modal instead of DM'ing the selected peer).
  Now they route to the selection-aware row actions. Tab cycles the
  sub-tabs (Pending / Known / Verified / Blocked).
- **Friend requests survive 3 days.** Previously an inbound dial modal
  auto-rejected (with a `block_peer`!) after 15 seconds. Now the 15-second
  timeout *spills the request* to a new `pending_friend_requests` table
  and just disconnects the live socket; the user has up to 3 days to
  Accept (re-dial + trust) or Reject (delete + block) from the People
  pane's new "Pending requests" sublist. A startup sweep prunes rows
  older than the TTL. The pane header shows `(N pending)` so a forgotten
  request from yesterday is the first thing you see on landing.
- **Invite picker — pick peers and they get the link auto-DM'd.** New
  `Modal::InvitePicker` (Ctrl+I inside a group room; also reachable from
  the `+ Add member` row pinned at the bottom of the member margin, and
  from the command palette as `invite peers to room…`). Lists candidates
  in three tiers — **Verified** (SAS-completed, safest), **DM partners**
  (existing trust), **Known peers** (weakest) — with checkboxes, live
  `/` filter, soft-cap of 20 selections per send. Enter sends: each
  selected peer gets an idempotent DM (`start_direct`) containing the
  same invite link `Shift+I` produces. `Shift+I` (OOB link copy) is
  unchanged — the picker is purely additive for peers you already have
  some trust relationship with.

The dial-then-DM auto-open is the load-bearing fix: huddle now behaves
the way a "basic social app" intuition expects — add someone, chat with
them, invite them places — without users needing to memorize the
fingerprint resolution flow under Compose-DM.

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
