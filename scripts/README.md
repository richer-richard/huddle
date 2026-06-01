# scripts

## `huddle-up.sh`

Brings up **Tor** and launches huddle with the **onion relay and LAN mDNS
running at the same time** (`--mode mdns` keeps the libp2p swarm alive
alongside the relay).

```bash
./scripts/huddle-up.sh           # GUI (huddle-gui)
./scripts/huddle-up.sh --cli     # terminal UI (huddle)
./scripts/huddle-up.sh -- --port 4001   # pass extra flags through to huddle
```

What it does:

1. Checks whether Tor's SOCKS proxy is listening on `127.0.0.1:9050`
   (override with `HUDDLE_TOR_SOCKS_HOST` / `HUDDLE_TOR_SOCKS_PORT`). If not,
   it starts Tor (`brew services start tor` when available, otherwise a
   background `tor`) and waits for the port.
2. Locates the binary — the installed `/Applications/Huddle.app` (GUI), then
   `PATH`, then `target/release` / `target/debug`.
3. Launches it with `--mode mdns`, so the **Tor onion relay** and **LAN mDNS
   discovery** both run together.

If you don't want a launcher, you can instead toggle **Settings → Network →
"Run LAN discovery (mDNS) alongside the relay"** inside the app (GUI or TUI);
that preference is honored on the next launch — no need to edit `config.toml`.
mDNS works on the LAN without Tor; the onion relay needs Tor running.
