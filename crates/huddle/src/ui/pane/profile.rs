//! Profile pane — your identity card. HD-ID, username, NAT badge, listen
//! addrs, quick actions. Replaces the lobby's identity header.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;
use ratatui::style::Style;

use crate::app::TuiApp;
use crate::ui::display_id;
use crate::ui::theme::Theme;

pub fn render(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme) {
    let block = Block::default().borders(Borders::NONE);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let v = Layout::default()
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
        "Profile",
        Style::default()
            .fg(theme.accent)
            .add_modifier(Modifier::BOLD),
    )]));
    f.render_widget(title, v[0]);

    let username = app
        .handle
        .display_name()
        .unwrap_or_else(|| "[anonymous]".into());
    let hd = display_id(app.handle.fingerprint());
    let nat = match app.nat_status.as_deref() {
        Some("reachable") => "🌐 reachable",
        Some("private") => "🏠 private (relay required for cross-internet)",
        _ => "🔍 detecting…",
    };
    let id_lines = vec![
        Line::from(vec![
            Span::styled("  username  ", theme.dim()),
            Span::styled(username, theme.text_style()),
            Span::raw("    "),
            Span::styled("(E to edit)", theme.dim()),
        ]),
        Line::from(vec![
            Span::styled("  HD-ID     ", theme.dim()),
            Span::styled(hd, theme.accent_bold()),
            Span::raw("    "),
            Span::styled("(Q to show QR)", theme.dim()),
        ]),
        Line::from(vec![
            Span::styled("  network   ", theme.dim()),
            Span::styled(nat.to_string(), theme.text_style()),
        ]),
        Line::from(vec![
            Span::styled("  mode      ", theme.dim()),
            Span::styled(
                app.mode_str().to_string(),
                theme.text_style(),
            ),
        ]),
        Line::raw(""),
        Line::from(vec![Span::styled(
            "Share these:",
            Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![
            Span::styled("  ", theme.dim()),
            Span::styled("Q", theme.warn_style()),
            Span::raw("  show QR code (paste into another huddle)   "),
            Span::styled("Shift+I", theme.warn_style()),
            Span::raw("  generate invite link"),
        ]),
    ];
    f.render_widget(Paragraph::new(id_lines), v[1]);

    let acts_title = Paragraph::new(Line::from(vec![Span::styled(
        "Listen addresses",
        Style::default()
            .fg(theme.accent)
            .add_modifier(Modifier::BOLD),
    )]));
    f.render_widget(acts_title, v[2]);

    let addrs = app.listen_addresses.clone();
    let mut addr_lines: Vec<Line> = Vec::new();
    if addrs.is_empty() {
        addr_lines.push(Line::from(vec![Span::styled(
            "  (listener bind in progress…)",
            theme.dim(),
        )]));
    } else {
        for a in addrs.iter().take(6) {
            addr_lines.push(Line::from(vec![Span::styled(
                format!("  {}", a),
                theme.text_style(),
            )]));
        }
    }
    f.render_widget(Paragraph::new(addr_lines), v[3]);
}
