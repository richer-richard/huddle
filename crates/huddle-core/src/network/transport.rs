//! huddle 1.0: transport "doors" onto the relay backend.
//!
//! The relay (`huddle-server`) can be reached through several different
//! transports, each a different tradeoff between privacy / censorship
//! resistance and speed / simplicity. Because one relay process can be
//! exposed as a Tor onion AND on a clearnet IP at the same time, these are
//! interchangeable doors onto the *same* set of rooms and mailboxes. The app
//! tries them in a fallback order (most private first) — or a user-pinned
//! one — and surfaces the active door plus each door's tradeoff in the TUI
//! and CLI, so the anti-censorship effort is legible rather than hidden.

/// How to physically open the WebSocket to a relay URL. Generalizes the old
/// `if url.contains(".onion") { socks } else { direct }` branch.
#[derive(Debug, Clone)]
pub enum DialMode {
    /// Plain TCP → `ws://` (clearnet, no Tor, no TLS). Fast; the relay sees
    /// your IP and on-path observers see the WebSocket (the payload is still
    /// end-to-end encrypted). The easiest thing for a censor to block.
    Direct,
    /// rustls TLS → `wss://` (clearnet, TLS). `pinned_cert_der` would pin a
    /// self-signed cert; `None` uses the system trust store (a real cert via
    /// Caddy / Let's Encrypt / Cloudflare — the recommended clearnet setup).
    Tls { pinned_cert_der: Option<Vec<u8>> },
    /// SOCKS5 to a local Tor (the system `tor`, optionally configured with a
    /// bridge to punch through censorship). Hides your IP from the relay.
    Socks5 { proxy: String },
    /// huddle 1.0: in-process Tor (Arti) — no separate tor daemon. `bridge`
    /// is reserved for a future obfs4/WebTunnel line (needs an external PT
    /// binary, so it's not wired yet); plain onion connect works today.
    #[cfg(feature = "arti")]
    Arti { bridge: Option<String> },
}

/// huddle 1.0: a process-global, lazily-bootstrapped Arti Tor client, reused
/// across reconnects (bootstrapping is expensive). Returns a cheap clone.
#[cfg(feature = "arti")]
pub async fn arti_client(
    _bridge: Option<&str>,
) -> crate::error::Result<arti_client::TorClient<tor_rtcompat::PreferredRuntime>> {
    use arti_client::{TorClient, TorClientConfig};
    use tokio::sync::OnceCell;
    use tor_rtcompat::PreferredRuntime;

    static ARTI: OnceCell<TorClient<PreferredRuntime>> = OnceCell::const_new();
    let client = ARTI
        .get_or_try_init(|| async {
            let config = TorClientConfig::default();
            TorClient::create_bootstrapped(config)
                .await
                .map_err(|e| crate::error::HuddleError::Network(format!("arti bootstrap: {e}")))
        })
        .await?;
    Ok(client.clone())
}

/// Stable identifier for each door — persisted as a setting and accepted on
/// the CLI (`--transport`, `--transport-order`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportId {
    OnionSystemTor,
    OnionBridge,
    OnionArti,
    ClearnetWss,
    ClearnetWs,
}

impl TransportId {
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportId::OnionSystemTor => "onion-tor",
            TransportId::OnionBridge => "onion-bridge",
            TransportId::OnionArti => "onion-arti",
            TransportId::ClearnetWss => "clearnet-wss",
            TransportId::ClearnetWs => "clearnet-ws",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "onion-tor" | "onion" | "tor" => TransportId::OnionSystemTor,
            "onion-bridge" | "bridge" => TransportId::OnionBridge,
            "onion-arti" | "arti" => TransportId::OnionArti,
            "clearnet-wss" | "wss" => TransportId::ClearnetWss,
            "clearnet-ws" | "ws" | "clearnet" => TransportId::ClearnetWs,
            _ => return None,
        })
    }

    pub fn label(&self) -> &'static str {
        match self {
            TransportId::OnionSystemTor => "Tor onion (system Tor)",
            TransportId::OnionBridge => "Tor onion via bridge (obfs4/WebTunnel)",
            TransportId::OnionArti => "Tor onion (built-in Arti)",
            TransportId::ClearnetWss => "Clearnet TLS (wss)",
            TransportId::ClearnetWs => "Clearnet plain (ws)",
        }
    }

    /// One-line privacy / anti-censorship tradeoff, shown in the UI + CLI.
    pub fn description(&self) -> &'static str {
        match self {
            TransportId::OnionSystemTor => {
                "Routes through Tor via your system tor daemon. Hides your IP from the relay. Needs Tor running. Most private."
            }
            TransportId::OnionBridge => {
                "Tor with a private bridge (obfs4/WebTunnel) to get through networks that block Tor. Configure the bridge in your tor (or use --tor-bridge with the arti build)."
            }
            TransportId::OnionArti => {
                "Tor built into huddle (Arti) — same IP protection, no separate Tor install. Requires the `arti` build."
            }
            TransportId::ClearnetWss => {
                "Direct TLS to the relay. Fast and works behind most VPNs, but the relay sees your IP (messages stay end-to-end encrypted)."
            }
            TransportId::ClearnetWs => {
                "Direct WebSocket, no transport encryption (messages still E2E). Fastest; relay + on-path observers see your IP. LAN / testing / last resort."
            }
        }
    }
}

/// A resolved door: identity/label/description (always present) plus, when
/// usable in this build + config, the URL and dial parameters. `dial == None`
/// means the door is shown in the UI but isn't currently usable — `reason`
/// explains why (so the user can act on it).
#[derive(Debug, Clone)]
pub struct TransportProfile {
    pub id: TransportId,
    pub url: Option<String>,
    pub dial: Option<DialMode>,
    pub reason: Option<&'static str>,
}

impl TransportProfile {
    pub fn available(&self) -> bool {
        self.dial.is_some()
    }
}

fn unavailable(id: TransportId, reason: &'static str) -> TransportProfile {
    TransportProfile {
        id,
        url: None,
        dial: None,
        reason: Some(reason),
    }
}

/// How to dial an "onion" relay URL. A real `.onion` goes through Tor's
/// SOCKS5 proxy; a plain `ws://` / `wss://` host pointed at by `--server`
/// (tests, or a non-Tor relay) is dialed directly / over TLS.
///
/// huddle 2.0.3 (audit N-L3): the door is chosen by the URL's HOST, matching
/// `.onion` as a real TLD suffix. The pre-1.0 `url.contains(".onion")` was a
/// substring test, so `ws://x.onion.evil.com` matched and would be routed
/// through a Tor exit to the clearnet host `evil.com`, leaking the cleartext
/// `Hello` (fingerprint + room list). A genuine onion host always goes through
/// Tor regardless of scheme.
fn onion_dial(url: &str, tor_socks: &str) -> DialMode {
    let host = ws_url_host(url);
    let is_onion =
        host.eq_ignore_ascii_case("onion") || host.to_ascii_lowercase().ends_with(".onion");
    if is_onion {
        DialMode::Socks5 {
            proxy: tor_socks.to_string(),
        }
    } else if url.starts_with("wss://") {
        DialMode::Tls {
            pinned_cert_der: None,
        }
    } else {
        DialMode::Direct
    }
}

/// Extract the bare host from a `ws://`/`wss://` URL: strip the scheme, any
/// `userinfo@`, the path/query/fragment, the `:port`, and IPv6 brackets.
fn ws_url_host(url: &str) -> &str {
    let after_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("");
    let no_port = authority
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(authority);
    no_port.trim_start_matches('[').trim_end_matches(']')
}

/// Build the full set of doors from resolved config. Always returns all five
/// (so the UI/CLI can show every option + its availability); unusable ones
/// carry `dial = None` and a `reason`.
pub fn builtin_profiles(
    onion_url: Option<&str>,
    clearnet_url: Option<&str>,
    tor_socks: &str,
    _tor_bridge: Option<&str>,
) -> Vec<TransportProfile> {
    let mut out = Vec::new();

    // Onion via system Tor.
    out.push(match onion_url {
        Some(u) => TransportProfile {
            id: TransportId::OnionSystemTor,
            url: Some(u.to_string()),
            dial: Some(onion_dial(u, tor_socks)),
            reason: None,
        },
        None => unavailable(TransportId::OnionSystemTor, "no onion relay URL configured"),
    });

    // Onion via bridge — same SOCKS path; the user's system Tor carries the
    // bridge line. (With the arti build this can map to Arti+bridge instead.)
    out.push(match onion_url {
        Some(u) => TransportProfile {
            id: TransportId::OnionBridge,
            url: Some(u.to_string()),
            dial: Some(onion_dial(u, tor_socks)),
            reason: None,
        },
        None => unavailable(TransportId::OnionBridge, "no onion relay URL configured"),
    });

    // Onion via Arti (in-process Tor) — only with the `arti` build.
    #[cfg(feature = "arti")]
    out.push(match onion_url {
        Some(u) => TransportProfile {
            id: TransportId::OnionArti,
            url: Some(u.to_string()),
            dial: Some(DialMode::Arti {
                bridge: _tor_bridge.map(|s| s.to_string()),
            }),
            reason: None,
        },
        None => unavailable(TransportId::OnionArti, "no onion relay URL configured"),
    });
    #[cfg(not(feature = "arti"))]
    out.push(unavailable(
        TransportId::OnionArti,
        "rebuild huddle with --features arti to enable",
    ));

    // Clearnet — availability follows the configured URL's scheme so one
    // `clearnet_url` lights up exactly one clearnet door.
    let (wss, ws) = match clearnet_url {
        Some(u) if u.starts_with("wss://") => (Some(u.to_string()), None),
        Some(u) if u.starts_with("ws://") => (None, Some(u.to_string())),
        _ => (None, None),
    };
    out.push(match wss {
        Some(u) => TransportProfile {
            id: TransportId::ClearnetWss,
            url: Some(u),
            dial: Some(DialMode::Tls {
                pinned_cert_der: None,
            }),
            reason: None,
        },
        None => unavailable(
            TransportId::ClearnetWss,
            "set a wss:// clearnet relay URL (--clearnet-server / config)",
        ),
    });
    out.push(match ws {
        Some(u) => TransportProfile {
            id: TransportId::ClearnetWs,
            url: Some(u),
            dial: Some(DialMode::Direct),
            reason: None,
        },
        None => unavailable(
            TransportId::ClearnetWs,
            "set a ws:// clearnet relay URL (--clearnet-server / config)",
        ),
    });

    out
}

/// Default order to try doors in: most private first, clearnet last.
pub fn default_fallback_order() -> Vec<TransportId> {
    vec![
        TransportId::OnionSystemTor,
        TransportId::OnionBridge,
        TransportId::OnionArti,
        TransportId::ClearnetWss,
        TransportId::ClearnetWs,
    ]
}

/// huddle 2.1.1: a clearnet-first order — the clearnet relay (cloudflared /
/// Worker tunnel) tried before Tor, with the onion doors kept as fallback.
/// What `set_clearnet_relay` pins and what the "Prefer clearnet" priority
/// preset selects, so a no-Tor user connects without paying the onion timeout.
pub fn clearnet_first_order() -> Vec<TransportId> {
    vec![
        TransportId::ClearnetWss,
        TransportId::ClearnetWs,
        TransportId::OnionSystemTor,
        TransportId::OnionBridge,
        TransportId::OnionArti,
    ]
}

/// Parse a comma-separated id list (`--transport-order`) into ids, dropping
/// unknown tokens.
pub fn parse_order(csv: &str) -> Vec<TransportId> {
    csv.split(',').filter_map(TransportId::from_str).collect()
}

/// huddle 2.1.1: a connection-priority preset surfaced in the GUI/TUI Settings
/// so the user can tune which door is tried first without hand-editing
/// `--transport-order`. Each maps to a concrete door order the app applies
/// live (see `AppHandle::set_transport_order`).
pub struct PriorityPreset {
    /// Stable key — persisted in the order CSV's shape and compared by
    /// [`match_priority_preset`]; not shown to the user.
    pub key: &'static str,
    /// Short selector label.
    pub label: &'static str,
    /// One-line tradeoff note.
    pub detail: &'static str,
    /// The door order this preset applies, in priority order.
    pub order: Vec<TransportId>,
}

/// The connection-priority presets, in display order. `auto` is the default
/// most-private-first order; `prefer-clearnet` is clearnet-first with Tor
/// fallback; the `*-only` presets drop the other family entirely so no connect
/// attempts are wasted on a door the user has ruled out.
pub fn priority_presets() -> Vec<PriorityPreset> {
    vec![
        PriorityPreset {
            key: "auto",
            label: "Auto — most private first",
            detail: "Tor onion first, clearnet relay as fallback (default).",
            order: default_fallback_order(),
        },
        PriorityPreset {
            key: "prefer-clearnet",
            label: "Prefer clearnet",
            detail: "Clearnet relay first, Tor as fallback — fastest when Tor is blocked.",
            order: clearnet_first_order(),
        },
        PriorityPreset {
            key: "clearnet-only",
            label: "Clearnet only",
            detail: "Never attempt Tor — connect straight to the clearnet relay.",
            order: vec![TransportId::ClearnetWss, TransportId::ClearnetWs],
        },
        PriorityPreset {
            key: "tor-only",
            label: "Tor only",
            detail: "Never touch the clearnet relay — onion doors only.",
            order: vec![
                TransportId::OnionSystemTor,
                TransportId::OnionBridge,
                TransportId::OnionArti,
            ],
        },
    ]
}

/// huddle 2.1.1: the preset `key` whose order matches `order` exactly, or
/// `"custom"` for an order set some other way (e.g. an explicit
/// `--transport-order`). Lets the settings UI highlight the active preset.
pub fn match_priority_preset(order: &[TransportId]) -> &'static str {
    priority_presets()
        .into_iter()
        .find(|p| p.order == order)
        .map(|p| p.key)
        .unwrap_or("custom")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_id_str_round_trips() {
        for id in default_fallback_order() {
            assert_eq!(TransportId::from_str(id.as_str()), Some(id));
        }
    }

    #[test]
    fn priority_presets_round_trip_and_reject_custom() {
        // Every preset's order maps back to its own key.
        for p in priority_presets() {
            assert_eq!(match_priority_preset(&p.order), p.key);
        }
        // The clearnet-first preset matches what set_clearnet_relay pins.
        assert_eq!(
            match_priority_preset(&clearnet_first_order()),
            "prefer-clearnet"
        );
        // An order set some other way is "custom", not silently a preset.
        assert_eq!(match_priority_preset(&[TransportId::OnionArti]), "custom");
        assert_eq!(match_priority_preset(&[]), "custom");
    }

    #[test]
    fn clearnet_scheme_selects_the_right_door() {
        let p = builtin_profiles(None, Some("ws://1.2.3.4:8787/ws"), "127.0.0.1:9050", None);
        let ws = p.iter().find(|p| p.id == TransportId::ClearnetWs).unwrap();
        let wss = p.iter().find(|p| p.id == TransportId::ClearnetWss).unwrap();
        assert!(ws.available());
        assert!(!wss.available());

        let p = builtin_profiles(None, Some("wss://relay.example/ws"), "127.0.0.1:9050", None);
        let ws = p.iter().find(|p| p.id == TransportId::ClearnetWs).unwrap();
        let wss = p.iter().find(|p| p.id == TransportId::ClearnetWss).unwrap();
        assert!(!ws.available());
        assert!(wss.available());
    }

    #[test]
    fn onion_available_only_with_url() {
        let p = builtin_profiles(Some("ws://x.onion:80/ws"), None, "127.0.0.1:9050", None);
        assert!(p
            .iter()
            .find(|p| p.id == TransportId::OnionSystemTor)
            .unwrap()
            .available());
        // Arti availability tracks the build feature: available (with an
        // onion url) under `--features arti`, otherwise off-with-a-reason.
        let arti = p.iter().find(|p| p.id == TransportId::OnionArti).unwrap();
        #[cfg(feature = "arti")]
        assert!(arti.available());
        #[cfg(not(feature = "arti"))]
        assert!(!arti.available());
    }

    #[test]
    fn onion_dial_matches_onion_as_host_suffix_not_substring() {
        // huddle 2.0.3 (audit N-L3): a genuine onion host routes through Tor…
        assert!(matches!(
            onion_dial("ws://abcdefghij234567.onion:80/ws", "127.0.0.1:9050"),
            DialMode::Socks5 { .. }
        ));
        // …but `.onion` as a mere substring of a clearnet host must NOT (that
        // would tunnel a clearnet host through a Tor exit and leak the Hello).
        assert!(!matches!(
            onion_dial("ws://x.onion.evil.example/ws", "127.0.0.1:9050"),
            DialMode::Socks5 { .. }
        ));
        // Cross-transport doors onto the same relay: cloudflare/clearnet TLS via
        // wss → TLS; raw clearnet ws → Direct. (Tor is the third door above.)
        assert!(matches!(
            onion_dial("wss://relay.example.com/ws", "127.0.0.1:9050"),
            DialMode::Tls { .. }
        ));
        assert!(matches!(
            onion_dial("ws://1.2.3.4:8787/ws", "127.0.0.1:9050"),
            DialMode::Direct
        ));
    }

    #[test]
    fn ws_url_host_strips_scheme_port_path_and_userinfo() {
        assert_eq!(
            ws_url_host("wss://relay.example.com:443/ws"),
            "relay.example.com"
        );
        assert_eq!(ws_url_host("ws://1.2.3.4:8787/ws"), "1.2.3.4");
        assert_eq!(ws_url_host("ws://user@host.example/x"), "host.example");
        assert_eq!(ws_url_host("ws://abc.onion"), "abc.onion");
    }
}
