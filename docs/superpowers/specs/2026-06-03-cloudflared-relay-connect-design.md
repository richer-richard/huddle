# huddle — cloudflared relay + turnkey connect (design)

Date: 2026-06-03. Scope decided with the user: **"my VPS, my people"** + **"just do cloudflared tunnel"**.
Autonomous build (user is away; instructed: start now, do not ask). Does NOT change huddle's shipped
defaults / other users' trust. VPS IP for docs/examples: `2.24.124.188`.

## Goal

Make it turnkey for the user + their contacts to reach the user's own VPS relay over a **cloudflared
tunnel (`wss://<rand>.trycloudflare.com/ws`)**, without Tor, primarily from the **GUI**. Four pieces:

1. **GUI can set + persist a clearnet (wss) relay URL** — today it literally can't (`bridge.rs:141`
   hardcodes onion-only with `..Default::default()`; GUI `cli.rs` lacks `--clearnet-server`).
2. **It "just connects"** — prefer the clearnet door so the user doesn't pay the onion connect
   timeout each reconnect cycle when Tor isn't present.
3. **Relay-in-invite** — bake the relay URL into the invite so *the user's people* connect with zero config.
4. **VPS ops scaffolding** — a script + docs to run `huddle-server` + `cloudflared` and surface the wss URL.

## Ground truth (verified against `main`, 1.0.1)

- Door selection is ALREADY automatic: `spawn_server_connection` (`app/mod.rs:2291`) walks the order,
  skips unavailable doors (`dial.is_some()`), uses the first that connects, 1→30s backoff.
- `TransportConfig` (`app/mod.rs:297`): `onion_url, clearnet_url, tor_socks, tor_bridge, pin, order`.
  TUI `main.rs` builds the full struct from CLI; GUI `bridge.rs` builds onion-only.
- Startup resolution (`app/mod.rs:453-494`): `clearnet_url = transports.clearnet_url.or_else(config::clearnet_url)`;
  `transport_order` falls back to `repo::get_setting("transport_order")` then `default_fallback_order()`.
  `transport_pin` ← `get_setting("transport_pin")`. **No setter writes these today.**
- Settings KV: `repo::get_setting(db,key)` / `repo::set_setting(db,key,val)` (`repo.rs:1020/1029`).
  Persisted-setting + "applies next launch" + Restart-button pattern already exists for mDNS
  (`set_mdns_enabled` 4308; GUI `UiAction::ToggleMdns`/`RestartApp`).
- `clearnet-wss` door = `DialMode::Tls{pinned_cert_der:None}` over system roots → a `*.trycloudflare.com`
  cert works today, zero core changes (`transport.rs`, `server.rs`).
- Invite (`invite.rs`): `InviteLink{v,host_multiaddr,fingerprint,room,creator_pubkey_b64,signed_at_ms,
  signature_b64}`; v2 signs `signable_bytes()` (field order frozen). Literals at GUI `app.rs:839`,
  TUI `app.rs:3954` + `5343`, test fixture `invite.rs:278`.
- ViewModel (`model.rs:428`): `from_handle` init + sync (`561-582`) reads `h.mdns_enabled()` etc.;
  preview mock at `~970`.

## Implementation phases (each compiles + commits)

### Phase 1 — core: persist + prefer a clearnet relay
- `app/mod.rs` resolution: extend `clearnet_url` fallback to also read `repo::get_setting(&db,"clearnet_url")`,
  filtering empty strings. Precedence: TransportConfig/CLI > config.toml > DB-setting.
- Add `AppHandle::clearnet_relay() -> Option<String>` (reads DB setting, empty→None).
- Add `AppHandle::set_clearnet_relay(&self, url: Option<&str>) -> Result<()>`:
  - `Some(u)` → `set_setting("clearnet_url", u)` AND `set_setting("transport_order",
    "clearnet-wss,clearnet-ws,onion-tor,onion-bridge,onion-arti")` (clearnet-first so no onion timeout).
  - `None`/empty → `set_setting("clearnet_url","")` + `set_setting("transport_order","")` (reset to default).
- Takes effect next launch (mirror mDNS). Unit test: repo round-trip + (if feasible) resolution via in-memory DB.

### Phase 2 — GUI parity + persist + Settings UI
- `cli.rs`: add `--clearnet-server`, `--transport`, `--transport-order`, `--tor-bridge` + resolvers
  (mirror TUI, with `config::*` fallbacks).
- `bridge.rs`: `BuildParams` gains `clearnet_url, tor_bridge, transport_pin, transport_order`; build the
  FULL `TransportConfig` (stop using `..Default::default()`).
- `app.rs`: pass new Cli fields into `BuildParams`.
- `model.rs`: `ViewModel.clearnet_relay: Option<String>` (init None, sync `= h.clearnet_relay()`, preview mock);
  `UiAction::OpenSetRelay`, `UiAction::SetClearnetRelay(Option<String>)`; `SetRelayState{url,error}` modal;
  `Modal::SetRelay`.
- `panes/settings.rs` (Network tab): show current clearnet relay (or "none") + "Set / Edit" button →
  `OpenSetRelay`; show "applies on next launch" + Restart when changed.
- `modals/mod.rs`: `set_relay` modal (text field + Save/Clear/Cancel), mirrors `paste_invite`.
- `app.rs apply()`: `OpenSetRelay` → open modal prefilled with `vm.clearnet_relay`; `SetClearnetRelay(u)` →
  `handle.set_clearnet_relay(...)`, update `vm.clearnet_relay`, set restart-pending status.

### Phase 3 — relay-in-invite (core + both front-ends)
- `invite.rs`: add `relay_url: Option<String>` (`#[serde(default, skip_serializing_if=Option::is_none)]`).
  `signable_bytes`: when `relay_url.is_some()`, append `b"relay|"+url` segment (absent when None →
  byte-identical to today, so existing v2 invites still verify). `sign_invite`: set `v = if relay_url.is_some(){3}else{2}`.
  `decode`: accept `2 | 3` with the same verify+freshness. Old clients see v3 → reject (fine; they can't use it).
  Tests: v3 round-trip with relay; tampered relay fails; v2 (no relay) unchanged.
- `app/mod.rs`: a helper to stamp the configured relay onto an outgoing invite (use `self.clearnet_relay()`),
  and apply on accept. Simplest: front-ends set `relay_url: self.handle.clearnet_relay()` in the literal,
  then `sign_invite`. On accept, if `invite.relay_url` is Some, call `handle.set_clearnet_relay(Some(u))`.
- Update all 3 `InviteLink` literals + fixture with `relay_url`.
- TUI `app.rs` (3954/5343 build; 4008 accept) + GUI `app.rs` (839 build; 856 confirm) + confirm modals
  show "connects you to inviter's relay: <url>".

### Phase 4 — VPS ops + docs
- `scripts/huddle-relay.sh`: start `huddle-server` (`HUDDLE_SERVER_BIND=127.0.0.1:8787`) + `cloudflared
  tunnel --url http://127.0.0.1:8787`, parse the `*.trycloudflare.com` URL from cloudflared output, print
  the ready-to-paste `wss://.../ws`. Include systemd + torrc-free notes; mention raw-IP fallback
  (`ws://2.24.124.188:8787/ws`).
- `scripts/README.md` + `README.md`: a "Run your own relay (cloudflared, no domain)" section.

### Phase 5 — verify
- `cargo build --workspace`; `cargo test --workspace -- --test-threads=1`. Fix. Final commit.

## Risks / notes
- Changing `transport_order` to clearnet-first is PER-USER (a DB setting), not a shipped default.
- v3 invites are rejected by pre-this-build clients (acceptable for "my people" who all update).
- cloudflared quick tunnels rotate hostnames on restart → invites embedding the URL go stale; named
  tunnels (with a CF account) are stable. Documented; out of scope to automate.
- Server DB is unencrypted at rest on the VPS (metadata only; payloads E2E). Documented.
