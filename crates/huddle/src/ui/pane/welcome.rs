//! Welcome pane — shown when nothing's selected. Quick actions + recent
//! peers so first-launch users have somewhere to start.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;
use ratatui::style::Style;

use crate::app::TuiApp;
use crate::ui::theme::Theme;
use crate::ui::short_fp;

pub fn render(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme) {
    let block = Block::default()
        .borders(Borders::NONE);
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

    let intro_lines = vec![
        Line::from(vec![Span::styled(
            "Welcome.",
            Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
        )]),
        Line::raw(""),
        Line::from(vec![Span::styled(
            "huddle is a terminal-native chat app: peer-to-peer, encrypted, no central server.",
            theme.dim(),
        )]),
        Line::from(vec![Span::styled(
            "Pick a section in the sidebar, or use one of these quick actions:",
            theme.dim(),
        )]),
        Line::raw(""),
        Line::from(vec![
            Span::styled("  m  ", theme.warn_style()),
            Span::styled("start a DM with someone you know", theme.text_style()),
        ]),
        Line::from(vec![
            Span::styled("  g  ", theme.warn_style()),
            Span::styled("start a group room", theme.text_style()),
        ]),
    ];
    f.render_widget(Paragraph::new(intro_lines), vparts[1]);

    let more_lines = vec![
        Line::from(vec![
            Span::styled("  ,  ", theme.warn_style()),
            Span::styled("settings", theme.text_style()),
            Span::raw("       "),
            Span::styled("  i  ", theme.warn_style()),
            Span::styled("show your QR / HD-ID", theme.text_style()),
        ]),
        Line::from(vec![
            Span::styled("  ?  ", theme.warn_style()),
            Span::styled("keybindings", theme.text_style()),
            Span::raw("    "),
            Span::styled("  Ctrl+P  ", theme.warn_style()),
            Span::styled("command palette", theme.text_style()),
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
            let label = p.label.clone().unwrap_or_else(|| {
                p.address
                    .split('/')
                    .last()
                    .unwrap_or("?")
                    .to_string()
            });
            let fp_short = p
                .label
                .as_deref()
                .map(short_fp)
                .unwrap_or_default();
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
