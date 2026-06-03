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

## `huddle-relay.sh`

Run **your own relay on a VPS, exposed over a cloudflared tunnel** — no domain,
no TLS cert of your own, no Tor required for the people connecting to it. Good
for "I have a VPS and some of us can't reach Tor."

```bash
# On the VPS (after: cargo build --release -p huddle-server):
./scripts/huddle-relay.sh                 # server on 127.0.0.1:8787 + tunnel
HUDDLE_RELAY_PORT=9000 ./scripts/huddle-relay.sh
./scripts/huddle-relay.sh --no-tunnel     # server only → use a raw ws://<ip> door
```

What it does:

1. Locates `huddle-server` (`PATH`, then `target/release` / `target/debug`).
2. Starts it on `127.0.0.1:$HUDDLE_RELAY_PORT` (default `8787`), DB at
   `$HUDDLE_SERVER_DB` (default `./huddle-server.db`). The relay only ever
   moves **ciphertext** — it never holds keys or decrypts.
3. Starts `cloudflared tunnel --url http://127.0.0.1:<port>`, waits for the
   assigned `https://<rand>.trycloudflare.com` hostname, and prints the
   ready-to-paste relay URL:

   ```
   wss://<rand>.trycloudflare.com/ws
   ```

Point your clients at it:

- **GUI:** Settings → Network → **"Set / edit"** relay, paste the `wss://…/ws`.
- **CLI:** `huddle --clearnet-server wss://<rand>.trycloudflare.com/ws`
  (or `huddle-gui --clearnet-server …`), or `clearnet_url = "…"` in `config.toml`.

A configured clearnet relay is **tried first** (so you connect without waiting
on a Tor timeout) and the onion stays as a fallback. Once you've set it, any
**invite you generate embeds this relay** (a v3 invite), so your contacts join
with zero config.

### Caveats

- Free `*.trycloudflare.com` hostnames **rotate** every time `cloudflared`
  restarts, so embedded-relay invites go stale on restart. For a stable URL,
  use a **named** cloudflared tunnel (free Cloudflare account) or a real domain
  with `wss://`.
- `--no-tunnel` exposes a raw `ws://<your-vps-ip>:<port>/ws` door (open the
  firewall for that TCP port). It needs no domain/cert but reveals your IP +
  WebSocket metadata to on-path observers — messages stay end-to-end encrypted.
- The server's SQLite DB on the VPS is **not** encrypted at rest. It holds only
  ciphertext payloads + routing metadata (room ids, fingerprints), never keys.
