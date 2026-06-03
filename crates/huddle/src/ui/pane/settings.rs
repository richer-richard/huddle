//! Settings pane — tabbed view (Account / Network / Appearance /
//! Privacy). huddle 0.7.8 replaced the modal-and-pane dual presentation
//! with a single pane that owns every setting. Tab cycling: Tab /
//! Shift+Tab, or 1-4 for direct jump.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Padding, Paragraph};
use ratatui::Frame;

use crate::app::{SettingsTab, TuiApp};
use crate::ui::display_id;
use crate::ui::theme::Theme;

pub fn render(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme) {
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Min(0),
        ])
        .split(area);

    let title = Paragraph::new(Line::from(vec![Span::styled(
        "Settings",
        Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
    )]));
    f.render_widget(title, parts[0]);

    render_tab_strip(f, parts[1], app, theme);

    let body = Block::default()
        .borders(Borders::ALL)
        .border_style(theme.border_style())
        .padding(Padding::horizontal(1));
    let body_inner = body.inner(parts[2]);
    f.render_widget(body, parts[2]);

    let lines = match app.settings_tab {
        SettingsTab::Account => render_account(app, theme),
        SettingsTab::Network => render_network(app, theme),
        SettingsTab::Appearance => render_appearance(app, theme),
        SettingsTab::Privacy => render_privacy(app, theme),
    };
    f.render_widget(Paragraph::new(lines), body_inner);
}

fn render_tab_strip(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme) {
    let tabs = [
        SettingsTab::Account,
        SettingsTab::Network,
        SettingsTab::Appearance,
        SettingsTab::Privacy,
    ];
    let mut spans: Vec<Span> = Vec::new();
    for (i, t) in tabs.iter().enumerate() {
        let is_active = *t == app.settings_tab;
        let style = if is_active {
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            theme.dim()
        };
        spans.push(Span::styled(format!(" {} ", t.label()), style));
        spans.push(Span::styled(format!("{}", i + 1), theme.dim()));
        if i + 1 < tabs.len() {
            spans.push(Span::raw("  ·  "));
        }
    }
    spans.push(Span::raw("    "));
    spans.push(Span::styled("Tab", theme.warn_style()));
    spans.push(Span::styled(" cycle", theme.dim()));
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_account<'a>(app: &TuiApp, theme: &Theme) -> Vec<Line<'a>> {
    let username = app
        .handle
        .display_name()
        .unwrap_or_else(|| "[anonymous]".into());
    let hd = display_id(app.handle.fingerprint());
    let safety = app.handle.safety_code();
    vec![
        identity_row(theme, "username", &username),
        identity_row(theme, "HD-ID", &hd),
        identity_row(theme, "Safety Code", &safety),
        Line::raw(""),
        row(theme, "E", "edit username", "open editor".into()),
        row(theme, "Q", "show QR / HD-ID", "open viewer".into()),
        row(theme, "W", "replay onboarding", "press W".into()),
        Line::raw(""),
        Line::from(vec![Span::styled(
            "  (visit Profile pane to copy fields with `y`)",
            theme.dim(),
        )]),
    ]
}

fn render_network<'a>(app: &TuiApp, theme: &Theme) -> Vec<Line<'a>> {
    let libp2p = app.libp2p_active();
    let mut lines: Vec<Line> = Vec::new();

    // huddle 1.0: LAN discovery (libp2p mDNS) and the relay both run by
    // default; the mDNS toggle below switches the next launch to relay-only.
    lines.push(Line::from(vec![Span::styled(
        "  huddle runs LAN discovery and the relay together by default —",
        theme.dim(),
    )]));
    lines.push(Line::from(vec![Span::styled(
        "  messages ride whichever reaches the peer (always E2E encrypted):",
        theme.dim(),
    )]));
    lines.push(Line::raw(""));

    // Relay connection + the live transport door.
    let (relay_label, relay_style) = if !app.handle.server_enabled() {
        ("off (--no-server)".to_string(), theme.warn_style())
    } else if app.handle.server_connected() {
        let door = app.handle.active_transport_label().unwrap_or("relay");
        (format!("● connected  ·  {}", door), theme.ok())
    } else {
        (
            "○ connecting…  (Tor down? try a clearnet door)".to_string(),
            theme.dim(),
        )
    };
    lines.push(Line::from(vec![
        Span::styled("    Relay        ", theme.dim()),
        Span::styled(relay_label, relay_style),
    ]));

    let (libp2p_label, libp2p_style) = if libp2p {
        (format!("on  ·  {}", app.mode_str()), theme.ok())
    } else {
        (
            "off  ·  enable LAN with the Settings toggle / --mode mdns".to_string(),
            theme.dim(),
        )
    };
    lines.push(Line::from(vec![
        Span::styled("    LAN (libp2p) ", theme.dim()),
        Span::styled(libp2p_label, libp2p_style),
    ]));
    lines.push(Line::raw(""));

    // huddle 1.0: the transport "doors" onto the relay + their anti-
    // censorship tradeoff. Active door is marked; unavailable ones show why
    // (run `huddle transports` for the full descriptions).
    lines.push(Line::from(vec![Span::styled(
        "  transport doors (anti-censorship paths onto the relay):",
        theme.dim(),
    )]));
    for p in app.handle.transport_profiles() {
        let (mark, mstyle) = if Some(p.id) == app.handle.active_transport() {
            ("● active ", theme.ok())
        } else if p.available() {
            ("· ready  ", theme.dim())
        } else {
            ("  off    ", theme.dim())
        };
        let detail = if p.available() {
            String::new()
        } else {
            format!("  ({})", p.reason.unwrap_or(""))
        };
        lines.push(Line::from(vec![
            Span::styled("    ", theme.dim()),
            Span::styled(mark, mstyle),
            Span::styled(p.id.label(), theme.text_style()),
            Span::styled(detail, theme.dim()),
        ]));
    }
    lines.push(Line::raw(""));

    // Override hint — repoint the relay without recompiling.
    lines.push(Line::from(vec![Span::styled(
        format!(
            "  override relay in {}  (server_url / tor_socks)",
            huddle_core::config::config_path().display()
        ),
        theme.dim(),
    )]));

    // huddle 0.9.2: the mDNS toggle now drives the NEXT launch's transport
    // (relay-only vs relay + LAN together), so show it whether or not a
    // swarm is currently up — that's how you opt in from relay-only mode.
    lines.push(Line::raw(""));
    let mdns_on = app.handle.mdns_enabled();
    lines.push(row(
        theme,
        "M",
        "LAN discovery (mDNS)",
        if mdns_on {
            "on  ·  relay + LAN   (restart to apply)"
        } else {
            "off ·  relay only    (restart to apply)"
        }
        .into(),
    ));

    // The rest is libp2p-specific; only meaningful when a swarm is up.
    if libp2p {
        lines.push(Line::raw(""));
        let nat = match app.nat_status.as_deref() {
            Some("reachable") => "reachable",
            Some("private") => "private",
            _ => "detecting",
        };
        lines.push(Line::from(vec![
            Span::styled("  reachability  ", theme.dim()),
            Span::styled(nat.to_string(), theme.text_style()),
        ]));
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![Span::styled(
            "  listen addresses (cross-network dialable):",
            theme.dim(),
        )]));
        if app.listen_addresses.is_empty() {
            lines.push(Line::from(vec![Span::styled("    (binding…)", theme.dim())]));
        } else {
            for a in app.listen_addresses.iter().take(6) {
                lines.push(Line::from(vec![Span::styled(
                    format!("    {}", a),
                    theme.text_style(),
                )]));
            }
        }
        lines.push(Line::raw(""));
        let relays = huddle_core::config::load_relays().unwrap_or_default();
        lines.push(Line::from(vec![Span::styled(
            format!("  libp2p relays from config.toml: {}", relays.len()),
            theme.dim(),
        )]));
        for r in &relays {
            lines.push(Line::from(vec![Span::styled(
                format!("    {}", r),
                theme.text_style(),
            )]));
        }
    }
    lines
}

fn render_appearance<'a>(app: &TuiApp, theme: &Theme) -> Vec<Line<'a>> {
    // huddle 1.1.4: live Dark/Light toggle (the `T` chord). The active option
    // is highlighted in the accent; press T to flip — applies instantly.
    let dark_active = matches!(app.theme_kind, crate::ui::theme::ThemeKind::Dark);
    let dark_style = if dark_active {
        theme.accent_bold()
    } else {
        theme.dim()
    };
    let light_style = if dark_active {
        theme.dim()
    } else {
        theme.accent_bold()
    };
    vec![
        row(theme, "T", "theme", String::new()),
        Line::from(vec![
            Span::raw("        "),
            Span::styled("Dark", dark_style),
            Span::styled("   ·   ", theme.dim()),
            Span::styled("Light", light_style),
            Span::styled("     (press ", theme.dim()),
            Span::styled("T", theme.warn_style()),
            Span::styled(" to switch — applies instantly)", theme.dim()),
        ]),
        Line::raw(""),
        Line::from(vec![Span::styled(
            "  High-contrast Dark + Light, persisted across restarts and",
            theme.dim(),
        )]),
        Line::from(vec![Span::styled(
            "  shared with the desktop GUI (one theme setting drives both).",
            theme.dim(),
        )]),
    ]
}

fn render_privacy<'a>(app: &TuiApp, theme: &Theme) -> Vec<Line<'a>> {
    let v_only = app.handle.verified_only_inbound();
    let notifications = app.handle.notifications_enabled();
    let update_check = app.handle.update_check_enabled();
    let last_check_t = app.handle.last_update_check_at();
    let last_check = if last_check_t > 0 {
        relative_time(last_check_t)
    } else {
        "never".into()
    };
    let blocked_count = app.handle.list_blocked_peers().len();

    let mut lines: Vec<Line> = Vec::new();
    lines.push(row(
        theme,
        "V",
        "verified-only inbound",
        format!("{}    (default: off)", on_off(v_only)),
    ));
    lines.push(row(
        theme,
        "N",
        "desktop notifications",
        format!(
            "{}    (default: on; OS-local toasts only — never networked)",
            on_off(notifications)
        ),
    ));
    lines.push(row(
        theme,
        "U",
        "update check (crates.io)",
        match update_check {
            Some(true) => format!("on    last checked {}", last_check),
            Some(false) => "off".into(),
            None => "not asked yet".into(),
        },
    ));
    lines.push(row(theme, "B", "blocked peers", format!("{}", blocked_count)));
    if blocked_count > 0 {
        lines.push(Line::from(vec![
            Span::styled("      ", theme.dim()),
            Span::styled("c", theme.warn_style()),
            Span::styled(" clears them all", theme.dim()),
        ]));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(vec![Span::styled(
        "  ─── danger zone ───",
        theme.dim(),
    )]));
    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled("  Alt+Shift+1", theme.err_style()),
        Span::raw("  "),
        Span::styled(format!("{:<20}", "go dark"), theme.err_style()),
        Span::styled("delete account, wipe data, exit", theme.dim()),
    ]));
    lines
}

fn row<'a>(theme: &Theme, key: &'a str, label: &'a str, value: String) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("  {}", key), theme.warn_style()),
        Span::raw("    "),
        Span::styled(format!("{:<28}", label), theme.text_style()),
        Span::styled(value, theme.dim()),
    ])
}

fn identity_row<'a>(theme: &Theme, label: &str, value: &str) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("  {:<12}", label), theme.dim()),
        Span::styled(value.to_string(), theme.accent_bold()),
    ])
}

fn on_off(b: bool) -> String {
    if b {
        "on".into()
    } else {
        "off".into()
    }
}

fn relative_time(unix_secs: i64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let dt = now - unix_secs;
    if dt < 60 {
        format!("{}s ago", dt.max(0))
    } else if dt < 3600 {
        format!("{}m ago", dt / 60)
    } else if dt < 86400 {
        format!("{}h ago", dt / 3600)
    } else {
        format!("{}d ago", dt / 86400)
    }
}
