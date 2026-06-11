#!/usr/bin/env bash
# huddle-up — bring Tor up, then launch huddle with BOTH transports live:
# the Tor onion relay AND LAN mDNS at the same time (`--mode mdns` keeps the
# libp2p swarm running alongside the relay).
#
# Usage:
#   scripts/huddle-up.sh            # launch the GUI (huddle-gui)
#   scripts/huddle-up.sh --cli      # launch the terminal UI (huddle)
#   scripts/huddle-up.sh -- <args>  # pass extra args straight to huddle
#
# It is safe to run repeatedly: if Tor's SOCKS proxy is already listening it
# is left alone.
set -euo pipefail

SOCKS_HOST="${HUDDLE_TOR_SOCKS_HOST:-127.0.0.1}"
SOCKS_PORT="${HUDDLE_TOR_SOCKS_PORT:-9050}"

# Repo root = parent of this script's dir (for locating cargo target binaries).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log() { printf '\033[36m[huddle-up]\033[0m %s\n' "$*"; }

socks_up() {
  if command -v nc >/dev/null 2>&1; then
    nc -z "$SOCKS_HOST" "$SOCKS_PORT" >/dev/null 2>&1
  else
    # bash /dev/tcp fallback
    (exec 3<>"/dev/tcp/$SOCKS_HOST/$SOCKS_PORT") >/dev/null 2>&1 && exec 3>&-
  fi
}

ensure_tor() {
  if socks_up; then
    log "Tor already listening on $SOCKS_HOST:$SOCKS_PORT"
    return 0
  fi
  if ! command -v tor >/dev/null 2>&1; then
    log "Tor not found. Install it (macOS: 'brew install tor', Debian/Ubuntu:"
    log "'sudo apt install tor'). Continuing without Tor — the relay dot stays"
    log "hollow until Tor is up, but LAN mDNS still works."
    return 0
  fi
  log "starting Tor…"
  # huddle 2.0.3 (audit N-L12): write Tor's log to a per-run mktemp file, not a
  # predictable /tmp path a local attacker could pre-create as a symlink to clobber.
  local tor_log
  tor_log="$(mktemp -t huddle-tor.XXXXXX)"
  if command -v brew >/dev/null 2>&1 && brew list tor >/dev/null 2>&1; then
    brew services start tor >/dev/null 2>&1 || tor >"$tor_log" 2>&1 &
  else
    tor >"$tor_log" 2>&1 &
  fi
  # Wait up to ~30s for the SOCKS port to come up.
  for _ in $(seq 1 60); do
    if socks_up; then log "Tor is up"; return 0; fi
    sleep 0.5
  done
  log "Tor didn't come up in time — launching anyway (it may connect shortly)."
}

find_bin() {
  # $1 = binary name (huddle-gui | huddle); echoes the first one found.
  local name="$1"
  if [ "$name" = "huddle-gui" ] && \
     [ -x "/Applications/Huddle.app/Contents/MacOS/huddle-gui" ]; then
    echo "/Applications/Huddle.app/Contents/MacOS/huddle-gui"; return 0
  fi
  if command -v "$name" >/dev/null 2>&1; then command -v "$name"; return 0; fi
  for p in "$REPO_ROOT/target/release/$name" "$REPO_ROOT/target/debug/$name"; do
    [ -x "$p" ] && { echo "$p"; return 0; }
  done
  return 1
}

CLI=0
if [ "${1:-}" = "--cli" ]; then CLI=1; shift; fi
# Allow a literal `--` to separate huddle-up flags from huddle args.
[ "${1:-}" = "--" ] && shift

ensure_tor

if [ "$CLI" = "1" ]; then
  BIN="$(find_bin huddle || true)"
  [ -n "${BIN:-}" ] || { log "huddle (TUI) not found — run: cargo build --release -p huddle"; exit 1; }
  log "launching TUI with relay + LAN (--mode mdns)"
  exec "$BIN" --mode mdns "$@"
else
  BIN="$(find_bin huddle-gui || true)"
  [ -n "${BIN:-}" ] || { log "huddle-gui not found — run: cargo build --release -p huddle-gui"; exit 1; }
  log "launching GUI with relay + LAN (--mode mdns)"
  exec "$BIN" --mode mdns "$@"
fi
