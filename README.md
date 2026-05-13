# Huddle

Decentralized, end-to-end encrypted chat for your local network.

Two laptops on the same Wi-Fi discover each other automatically via mDNS
and exchange messages encrypted with vodozemac (the Matrix Olm
implementation). No servers, no accounts, no internet required.

> **This is a learning project, not production-secure chat.**
> The serialization encryption key is hardcoded, the SQLite database is
> unencrypted, and the protocol has not been audited. Do not use this
> for real secrets. See `plan.md` for the roadmap toward production
> security (Phases 3-5).

## Build

Requires Rust 1.75+ (edition 2021).

```bash
cargo build --release
```

The binary is at `target/release/huddle-tui`.

## Run

Start on two machines connected to the same Wi-Fi network:

```bash
# Machine A
./target/release/huddle-tui

# Machine B
./target/release/huddle-tui
```

Each instance generates a cryptographic identity on first run and
displays a fingerprint (e.g., `a3b1-c2d4-e5f6-7890-1234-abcd`).

Both nodes will discover each other via mDNS within a few seconds.

## Usage

| Key        | Action                        |
|------------|-------------------------------|
| Tab        | Cycle focus between panes     |
| j/k or arrows | Navigate within focused pane |
| Enter      | Select peer / send message    |
| /          | Focus chat input              |
| Esc        | Blur input                    |
| q          | Quit (when input not active)  |
| Ctrl-C     | Quit (always)                 |

1. Select a peer from the left pane (Enter)
2. An encrypted session is established automatically
3. Type your message and press Enter to send
4. Messages appear in real-time on the other machine

## Architecture

```
huddle/
  huddle-core    Library: networking, crypto, storage
  huddle-tui     Terminal UI (ratatui)
  huddle-tauri   Desktop UI scaffold (Phase 2)
```

- **Networking:** libp2p with mDNS discovery, TCP+Noise+Yamux transport
- **Encryption:** vodozemac Olm sessions (Double Ratchet)
- **Identity:** Ed25519 keypairs (ed25519-dalek)
- **Storage:** SQLite via rusqlite

## Current Limitations

- Same-LAN only (no internet/cross-network discovery)
- Two-peer chat only (no groups)
- No offline message delivery
- Serialization encryption key is hardcoded (not user-derived)
- SQLite database is unencrypted on disk
- No message delivery guarantees beyond basic ACK
- mDNS may not work on some corporate/restricted networks

## Testing

```bash
# Unit + integration tests
cargo test --workspace

# Manual two-machine test
see MANUAL_TESTING.md
```

## Roadmap

See `plan.md` for Phases 2-5: cross-network discovery (Kademlia/DHT),
Tauri desktop UI, robustness improvements, at-rest encryption, group
chat (MLS), and more.

## Data Directory

Identity keys and the database are stored in:
- **macOS:** `~/Library/Application Support/huddle/`
- **Linux:** `~/.local/share/huddle/`
- **Windows:** `%APPDATA%\huddle\`

## License

MIT
