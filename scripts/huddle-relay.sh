#!/usr/bin/env bash
# huddle-relay — run your own huddle relay on a VPS and expose it over a
# cloudflared tunnel, with NO domain and NO TLS cert of your own.
#
# It starts `huddle-server` on localhost and `cloudflared` in front of it,
# then prints the `wss://<rand>.trycloudflare.com/ws` URL to paste into your
# clients (Settings → Network → "Set / edit" relay, the `--clearnet-server`
# flag, or `clearnet_url` in config.toml). Generate an invite afterwards and
# it carries this relay automatically (v3 invite) so your contacts need zero
# config.
#
# Usage:
#   scripts/huddle-relay.sh                 # server on 127.0.0.1:8787 + tunnel
#   HUDDLE_RELAY_PORT=9000 scripts/huddle-relay.sh
#   scripts/huddle-relay.sh --no-tunnel     # server only (use a raw ws:// IP)
#
# The relay only ever sees ciphertext — it never holds keys or decrypts.
# Note: a free `*.trycloudflare.com` hostname ROTATES every time cloudflared
# restarts, so invites embedding it go stale on restart. For a stable URL use
# a named cloudflared tunnel (needs a free Cloudflare account) or a real
# domain; see scripts/README.md.
set -euo pipefail

PORT="${HUDDLE_RELAY_PORT:-8787}"
BIND="127.0.0.1:${PORT}"
DB="${HUDDLE_SERVER_DB:-${PWD}/huddle-server.db}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log() { printf '\033[35m[huddle-relay]\033[0m %s\n' "$*"; }

NO_TUNNEL=0
[ "${1:-}" = "--no-tunnel" ] && NO_TUNNEL=1

find_server() {
  if command -v huddle-server >/dev/null 2>&1; then command -v huddle-server; return 0; fi
  for p in "$REPO_ROOT/target/release/huddle-server" "$REPO_ROOT/target/debug/huddle-server"; do
    [ -x "$p" ] && { echo "$p"; return 0; }
  done
  return 1
}

SERVER_BIN="$(find_server || true)"
if [ -z "${SERVER_BIN:-}" ]; then
  log "huddle-server not found — build it first:"
  log "  cargo build --release -p huddle-server"
  exit 1
fi

SERVER_PID=""
TUNNEL_PID=""
TUNNEL_LOG=""
cleanup() {
  [ -n "$TUNNEL_PID" ] && kill "$TUNNEL_PID" >/dev/null 2>&1 || true
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" >/dev/null 2>&1 || true
  [ -n "$TUNNEL_LOG" ] && rm -f "$TUNNEL_LOG" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

log "starting huddle-server on $BIND (db: $DB)"
HUDDLE_SERVER_BIND="$BIND" HUDDLE_SERVER_DB="$DB" "$SERVER_BIN" &
SERVER_PID=$!
sleep 1
if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
  log "huddle-server failed to start — check the port isn't already in use."
  exit 1
fi

if [ "$NO_TUNNEL" = "1" ]; then
  IP="$(curl -fsS https://api.ipify.org 2>/dev/null || echo '<your-vps-ip>')"
  log "server up (no tunnel). Point clients at a raw clearnet door:"
  log "    ws://${IP}:${PORT}/ws"
  # huddle 2.0.3 (audit N-L8): be explicit that plaintext ws:// leaks identity-
  # level metadata, not just "IP + WS metadata".
  log "(open the firewall for tcp/${PORT}. WARNING: plaintext ws:// lets any"
  log " on-path observer read your server IP AND the client + recipient"
  log " fingerprints, room ids, and message ids in the clear — only the message"
  log " BODIES stay end-to-end encrypted. Prefer the Tor/cloudflared tunnel.)"
  log "Ctrl-C to stop."
  wait "$SERVER_PID"
  exit 0
fi

if ! command -v cloudflared >/dev/null 2>&1; then
  log "cloudflared not found. Install it:"
  log "  macOS:  brew install cloudflared"
  log "  Debian: https://pkg.cloudflare.com/  (cloudflared package)"
  log "Or run with --no-tunnel to expose a raw ws://<ip>:${PORT}/ws door instead."
  exit 1
fi

TUNNEL_LOG="$(mktemp -t huddle-cloudflared.XXXXXX)"
log "starting cloudflared tunnel → http://127.0.0.1:${PORT}"
cloudflared tunnel --url "http://127.0.0.1:${PORT}" >"$TUNNEL_LOG" 2>&1 &
TUNNEL_PID=$!

# cloudflared prints the assigned https://<rand>.trycloudflare.com URL a few
# seconds after start. Poll the log for it.
HOST=""
for _ in $(seq 1 60); do
  HOST="$(grep -Eo 'https://[a-z0-9-]+\.trycloudflare\.com' "$TUNNEL_LOG" 2>/dev/null | head -n1 || true)"
  [ -n "$HOST" ] && break
  if ! kill -0 "$TUNNEL_PID" >/dev/null 2>&1; then
    log "cloudflared exited early — its log:"; cat "$TUNNEL_LOG"; exit 1
  fi
  sleep 1
done

if [ -z "$HOST" ]; then
  log "couldn't read the tunnel URL from cloudflared in time. Its log:"
  cat "$TUNNEL_LOG"
  exit 1
fi

WSS="wss://${HOST#https://}/ws"
echo
log "relay is live. Paste this clearnet relay URL into your huddle clients:"
printf '\n    \033[1;32m%s\033[0m\n\n' "$WSS"
log "  GUI:  Settings → Network → 'Set / edit' relay"
log "  CLI:  huddle --clearnet-server $WSS   (or huddle-gui --clearnet-server …)"
log "Then make an invite — it embeds this relay so your contacts join with zero config."
log "Ctrl-C to stop the relay + tunnel."
wait "$TUNNEL_PID"
