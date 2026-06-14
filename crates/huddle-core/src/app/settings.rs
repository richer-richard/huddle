//! `AppHandle` settings & preferences accessors — thin getters/setters over the
//! `settings` table plus a few in-memory toggles. Split out of the `app/mod.rs`
//! god file (huddle 2.1.x maintainability refactor) as an additional inherent
//! `impl AppHandle` block; the struct, its fields, and shared private helpers
//! (e.g. `persist_key`) stay in `app/mod.rs` and remain accessible here because
//! this is a child module of `app`.

use super::*;

impl AppHandle {
    /// Phase E: global toggle — when true, inbound dials from
    /// unverified fingerprints are auto-rejected without prompting.
    pub fn verified_only_inbound(&self) -> bool {
        repo::get_setting(&self.db, "verified_only_inbound")
            .unwrap_or(None)
            .map(|v| v == "1")
            .unwrap_or(false)
    }

    pub fn set_verified_only_inbound(&self, on: bool) -> Result<()> {
        repo::set_setting(
            &self.db,
            "verified_only_inbound",
            if on { "1" } else { "0" },
        )
    }

    /// huddle 0.7.8: persisted LAN-discovery toggle. When true, the next
    /// launch starts in `NetworkMode::Mdns` so the device joins LAN mDNS
    /// announcements **alongside** the onion relay (both transports run
    /// together). When false, the next launch starts relay-only
    /// (`NetworkMode::Server`).
    ///
    /// huddle 0.9.2: default **OFF** (was ON pre-onion-relay) — the
    /// relay-only `Server` mode is the 0.8+ baseline, so the toggle is a
    /// true opt-in. Restart required to apply (a live `Toggle<Mdns>` flip
    /// would require rebuilding the libp2p behaviour).
    pub fn mdns_enabled(&self) -> bool {
        repo::get_setting(&self.db, "mdns_enabled")
            .unwrap_or(None)
            .map(|v| v == "1")
            .unwrap_or(false)
    }

    pub fn set_mdns_enabled(&self, on: bool) -> Result<()> {
        repo::set_setting(&self.db, "mdns_enabled", if on { "1" } else { "0" })
    }

    /// Persisted attach-mode toggle (desktop GUI). When true, the GUI's
    /// "Attach" button opens a manual file-path text entry instead of the
    /// native OS file dialog (rfd) — useful when the native picker is
    /// unavailable (headless / remote display) or simply not wanted. The TUI
    /// is unaffected (it always uses its in-terminal picker + path entry).
    /// Default **OFF** (use the native dialog).
    pub fn attach_via_path(&self) -> bool {
        repo::get_setting(&self.db, "attach_via_path")
            .unwrap_or(None)
            .map(|v| v == "1")
            .unwrap_or(false)
    }

    pub fn set_attach_via_path(&self, on: bool) -> Result<()> {
        repo::set_setting(&self.db, "attach_via_path", if on { "1" } else { "0" })
    }

    /// huddle 1.1.3: the persisted theme — `"system"` (default; the GUI follows
    /// the OS light/dark setting), `"dark"`, or `"light"`. The desktop GUI reads
    /// this to pick its egui visuals. huddle 1.1.4: the TUI now honors it too
    /// (`"dark"`/`"light"`; `"system"` resolves to Dark there). Unset resolves to
    /// `"system"`; installs that already persisted `"dark"`/`"light"` keep them.
    pub fn theme(&self) -> String {
        repo::get_setting(&self.db, "theme")
            .ok()
            .flatten()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "system".to_string())
    }

    /// huddle 1.1.4: the resolved Tor SOCKS5 proxy address (e.g.
    /// `127.0.0.1:9050`). Lets privacy-sensitive clearnet fetches (the
    /// opt-in update check) tunnel through Tor rather than leak the IP.
    pub fn tor_socks(&self) -> &str {
        &self.tor_socks
    }

    pub fn set_theme(&self, theme: &str) -> Result<()> {
        repo::set_setting(&self.db, "theme", theme)
    }

    /// huddle 1.0: the persisted clearnet relay URL (a `ws://<ip>:<port>/ws`
    /// or `wss://host/ws` door onto the relay backend — e.g. a cloudflared
    /// tunnel). `None` when unset/blank. This is what the GUI "Set relay" field
    /// writes and what [`Self::set_clearnet_relay`] manages; the startup
    /// resolution in `start_with_db_and_options` reads it as the lowest-
    /// precedence source (CLI → config.toml → this).
    pub fn clearnet_relay(&self) -> Option<String> {
        repo::get_setting(&self.db, "clearnet_url")
            .unwrap_or(None)
            .filter(|s| !s.trim().is_empty())
    }

    /// huddle 1.0: persist (or clear) the clearnet relay URL and bias the
    /// transport order so it's tried first.
    ///
    /// `Some(url)` saves the URL AND pins a clearnet-first door order so the
    /// app connects straight to the clearnet relay without paying the onion
    /// connect timeout each reconnect cycle (the point of "my VPS, no Tor").
    /// `None` (or a blank url) clears both, restoring the default
    /// most-private-first order. huddle 2.1.1: applies **immediately** — the
    /// in-memory order is swapped and the relay loop re-dials with it, no
    /// relaunch needed.
    pub fn set_clearnet_relay(&self, url: Option<&str>) -> Result<()> {
        match url.map(str::trim).filter(|s| !s.is_empty()) {
            Some(u) => {
                repo::set_setting(&self.db, "clearnet_url", u)?;
                // Clearnet doors first so a no-Tor user connects immediately;
                // onion doors stay in the list as fallback.
                self.set_transport_order(&transport::clearnet_first_order())
            }
            None => {
                repo::set_setting(&self.db, "clearnet_url", "")?;
                // Empty → restore the default most-private-first order.
                self.set_transport_order(&transport::default_fallback_order())
            }
        }
    }

    /// huddle 2.1.1: the live transport door order the relay loop is using
    /// (clearnet-first, Tor-first, or a custom/pinned order). Surfaced in the
    /// GUI/TUI "Connection priority" selector.
    pub fn current_transport_order(&self) -> Vec<TransportId> {
        self.transport_order.lock().clone()
    }

    /// huddle 2.1.1: set the door priority order and apply it live — persists
    /// the `transport_order` setting, swaps the in-memory order, and pokes the
    /// relay loop to reconnect with it. An empty list restores the default
    /// most-private-first order. The "Connection priority" control passes a
    /// [`transport::priority_presets`] order; an explicit CLI `--transport-order`
    /// still wins at the next launch's startup resolution.
    pub fn set_transport_order(&self, order: &[TransportId]) -> Result<()> {
        let resolved = if order.is_empty() {
            transport::default_fallback_order()
        } else {
            order.to_vec()
        };
        let csv = resolved
            .iter()
            .map(|id| id.as_str())
            .collect::<Vec<_>>()
            .join(",");
        repo::set_setting(&self.db, "transport_order", &csv)?;
        *self.transport_order.lock() = resolved;
        // Wake the relay loop so it drops the current door and re-dials in the
        // new order (no-op if the relay is disabled / no socket is open).
        self.relay_reconnect.notify_one();
        Ok(())
    }

    /// huddle 0.7.8: persisted desktop-notification opt-out. The
    /// notifier itself is a local-only `osascript`/`notify-send`
    /// process call — toggling this OFF skips the call entirely so
    /// nothing reaches the OS notification daemon. Default ON to
    /// preserve current behavior.
    pub fn notifications_enabled(&self) -> bool {
        repo::get_setting(&self.db, "notifications_enabled")
            .unwrap_or(None)
            .map(|v| v == "1")
            .unwrap_or(true)
    }

    pub fn set_notifications_enabled(&self, on: bool) -> Result<()> {
        repo::set_setting(
            &self.db,
            "notifications_enabled",
            if on { "1" } else { "0" },
        )
    }

    /// huddle 0.7.8: stable 12-hex Safety Code derived from our Ed25519
    /// pubkey. Display-only; used as a quick visual fingerprint match in
    /// Profile / Account. SAS-via-emoji remains the actual verification
    /// primitive.
    pub fn safety_code(&self) -> String {
        crate::identity::safety_code(&self.identity.public_bytes())
    }

    /// Phase E: per-room verified-only-join. When true, the host (and
    /// every honest existing member) drops MemberAnnounce from joiners
    /// who aren't globally SAS-verified, and the lowest-fp owner sends
    /// back a signed `JoinRefused` so the joiner sees an explanation.
    pub fn room_verified_only(&self, room_id: &str) -> bool {
        repo::get_room_verified_only(&self.db, room_id).unwrap_or(false)
    }

    pub fn set_room_verified_only(&self, room_id: &str, on: bool) -> Result<()> {
        repo::set_room_verified_only(&self.db, room_id, on)
    }

    /// Phase H: first-launch onboarding flag.
    pub fn onboarding_seen(&self) -> bool {
        repo::is_onboarding_seen(&self.db).unwrap_or(true)
    }

    pub fn mark_onboarding_seen(&self) -> Result<()> {
        repo::mark_onboarding_seen(&self.db)
    }

    /// huddle 0.6: version string of huddle the user last finished
    /// onboarding for. Compared against `env!("CARGO_PKG_VERSION")` at
    /// startup so a version bump re-fires the "what's new" card.
    pub fn last_seen_onboarding_version(&self) -> Option<String> {
        repo::get_last_seen_onboarding_version(&self.db).unwrap_or(None)
    }

    pub fn set_last_seen_onboarding_version(&self, version: &str) -> Result<()> {
        repo::set_last_seen_onboarding_version(&self.db, version)
    }

    /// huddle 0.6: opt-in flag for the crates.io update check.
    /// `None` ⇒ the user hasn't been asked yet.
    pub fn update_check_enabled(&self) -> Option<bool> {
        repo::get_update_check_enabled(&self.db).unwrap_or(None)
    }

    pub fn set_update_check_enabled(&self, enabled: bool) -> Result<()> {
        repo::set_update_check_enabled(&self.db, enabled)
    }

    /// huddle 0.6: cache anchor for the once-per-24h crates.io poll.
    /// Returns 0 if nothing has been recorded yet.
    pub fn last_update_check_at(&self) -> i64 {
        repo::get_setting(&self.db, "last_update_check_at")
            .ok()
            .flatten()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    pub fn set_last_update_check_at(&self, ts: i64) -> Result<()> {
        repo::set_setting(&self.db, "last_update_check_at", &ts.to_string())
    }

    /// huddle 0.6: the most recent `max_stable_version` we saw on
    /// crates.io. Persisted so a re-launch within the 24h window
    /// can render the banner without re-fetching.
    pub fn last_known_remote_version(&self) -> Option<String> {
        repo::get_setting(&self.db, "last_known_remote_version")
            .ok()
            .flatten()
    }

    pub fn set_last_known_remote_version(&self, v: &str) -> Result<()> {
        repo::set_setting(&self.db, "last_known_remote_version", v)
    }
}
