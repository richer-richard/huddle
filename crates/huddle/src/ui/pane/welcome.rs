//! Welcome pane — shown when nothing's selected. Quick actions + recent
//! peers so first-launch users have somewhere to start.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::TuiApp;
use crate::ui::short_fp;
use crate::ui::theme::Theme;

pub fn render(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme) {
    let block = Block::default().borders(Borders::NONE);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let vparts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(7),
            Constraint::Length(2),
            Constraint::Length(8),
            Constraint::Min(0),
        ])
        .split(inner);

    let title = Paragraph::new(Line::from(vec![Span::styled(
        format!("huddle {}", env!("CARGO_PKG_VERSION")),
        Style::default()
            .fg(theme.accent)
            .add_modifier(Modifier::BOLD),
    )]));
    f.render_widget(title, vparts[0]);

    // huddle 1.0: connection status — LAN discovery + relay both run
    // automatically (no manual mode switch). Shows the live transport door.
    let (lan_label, lan_style) = if app.libp2p_active() {
        ("LAN ● on".to_string(), theme.ok())
    } else {
        ("LAN ○ off".to_string(), theme.dim())
    };
    let (relay_label, relay_style) = if app.handle.server_connected() {
        (
            format!(
                "relay ● {}",
                app.handle.active_transport_label().unwrap_or("connected")
            ),
            theme.ok(),
        )
    } else if app.handle.server_enabled() {
        ("relay ○ connecting…".to_string(), theme.dim())
    } else {
        ("relay off".to_string(), theme.dim())
    };

    let intro_lines = vec![
        Line::from(vec![Span::styled(
            "Welcome.",
            Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![Span::styled(
            "terminal-native · end-to-end encrypted · LAN + relay, automatic.",
            theme.dim(),
        )]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(lan_label, lan_style),
            Span::styled("    ", theme.dim()),
            Span::styled(relay_label, relay_style),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled("  m  ", theme.warn_style()),
            Span::styled("start a DM with a contact", theme.text_style()),
        ]),
        Line::from(vec![
            Span::styled("  g  ", theme.warn_style()),
            Span::styled("start a group room", theme.text_style()),
        ]),
        Line::from(vec![
            Span::styled("  a  ", theme.warn_style()),
            Span::styled(
                "add a contact by HD-ID (works over the internet)",
                theme.text_style(),
            ),
        ]),
    ];
    f.render_widget(Paragraph::new(intro_lines), vparts[1]);

    let more_lines = vec![
        Line::from(vec![
            Span::styled("  p  ", theme.warn_style()),
            Span::styled("contacts + requests", theme.text_style()),
            Span::raw("    "),
            Span::styled("  v  ", theme.warn_style()),
            Span::styled("paste invite", theme.text_style()),
        ]),
        Line::from(vec![
            Span::styled("  ,  ", theme.warn_style()),
            Span::styled("settings", theme.text_style()),
            Span::raw("    "),
            Span::styled("  i  ", theme.warn_style()),
            Span::styled("QR / HD-ID", theme.text_style()),
            Span::raw("    "),
            Span::styled("  Ctrl+P  ", theme.warn_style()),
            Span::styled("palette", theme.text_style()),
        ]),
    ];
    f.render_widget(Paragraph::new(more_lines), vparts[2]);

    let mut peers_lines = vec![Line::from(vec![Span::styled(
        "Recent peers",
        Style::default()
            .fg(theme.accent)
            .add_modifier(Modifier::BOLD),
    )])];
    if app.known_peers.is_empty() {
        peers_lines.push(Line::from(vec![Span::styled(
            "  (no peers yet — paste an invite or add a friend with `a`)",
            theme.dim(),
        )]));
    } else {
        for p in app.known_peers.iter().take(5) {
            let dot = if p.connected_peer_id.is_some() {
                "●"
            } else {
                "○"
            };
            let label = p
                .label
                .clone()
                .unwrap_or_else(|| p.address.split('/').last().unwrap_or("?").to_string());
            let fp_short = p.label.as_deref().map(short_fp).unwrap_or_default();
            peers_lines.push(Line::from(vec![
                Span::styled(format!("  {} ", dot), theme.text_style()),
                Span::styled(label, theme.text_style()),
                Span::raw("  "),
                Span::styled(fp_short.to_uppercase(), theme.dim()),
            ]));
        }
    }
    f.render_widget(Paragraph::new(peers_lines), vparts[3]);
}
