//! Profile pane — your identity card. huddle 0.7.8 reworks this into a
//! cursor-navigable list of monospaced rows. `j`/`k` move the cursor;
//! `y` copies the highlighted row's value to the OS clipboard via the
//! `clipboard` module. `E` edits username, `Q` shows the QR.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::{profile_fields, TuiApp};
use crate::ui::theme::Theme;

pub fn render(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme) {
    let block = Block::default().borders(Borders::NONE);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Min(0),
            Constraint::Length(2),
        ])
        .split(inner);

    let title = Paragraph::new(Line::from(vec![Span::styled(
        "Profile",
        Style::default()
            .fg(theme.accent)
            .add_modifier(Modifier::BOLD),
    )]));
    f.render_widget(title, parts[0]);

    // huddle 0.8: the centralized Tor-onion relay is the cross-internet
    // lifeline. In the relay-only default it's the headline status; the
    // libp2p NAT badge is only shown when a swarm is actually running.
    let (relay_glyph, relay_text, relay_style) = if !app.handle.server_enabled() {
        ("", "off".to_string(), theme.dim())
    } else if app.handle.server_connected() {
        ("🧅 ", "connected".to_string(), theme.text_style())
    } else {
        ("🧅 ", "connecting…".to_string(), theme.dim())
    };
    let mut mode_spans = vec![Span::styled("  network  ", theme.dim())];
    if app.libp2p_active() {
        let nat = match app.nat_status.as_deref() {
            Some("reachable") => "🌐 reachable",
            Some("private") => "🏠 private (relay required for cross-internet)",
            _ => "🔍 detecting…",
        };
        mode_spans.push(Span::styled(nat.to_string(), theme.text_style()));
        mode_spans.push(Span::raw("    "));
    }
    mode_spans.push(Span::styled("relay  ", theme.dim()));
    mode_spans.push(Span::styled(format!("{relay_glyph}{relay_text}"), relay_style));
    mode_spans.push(Span::raw("    "));
    mode_spans.push(Span::styled("mode  ", theme.dim()));
    mode_spans.push(Span::styled(app.mode_str().to_string(), theme.text_style()));
    f.render_widget(Paragraph::new(Line::from(mode_spans)), parts[1]);

    let fields = profile_fields(app);
    let cursor = app.profile_cursor.min(fields.len().saturating_sub(1));
    let label_width = fields
        .iter()
        .map(|(label, _)| label.chars().count())
        .max()
        .unwrap_or(8)
        .max(8);
    let mut lines: Vec<Line> = Vec::new();
    for (i, (label, value)) in fields.iter().enumerate() {
        let is_sel = i == cursor;
        let prefix = if is_sel { "►" } else { " " };
        let label_text = format!(
            "{:>w$}",
            label,
            w = label_width
        );
        let style = if is_sel {
            theme
                .text_style()
                .add_modifier(Modifier::BOLD)
                .fg(theme.warn)
        } else {
            theme.text_style()
        };
        let label_style = if is_sel {
            theme.dim().add_modifier(Modifier::BOLD)
        } else {
            theme.dim()
        };
        let line = Line::from(vec![
            Span::styled(format!("  {} ", prefix), theme.warn_style()),
            Span::styled(label_text, label_style),
            Span::raw("  "),
            Span::styled(value.clone(), style),
        ]);
        lines.push(line);
    }
    f.render_widget(Paragraph::new(lines), parts[2]);

    let hint = Paragraph::new(Line::from(vec![
        Span::styled(" j/k", theme.warn_style()),
        Span::styled(" move", theme.dim()),
        Span::raw("   "),
        Span::styled(" y", theme.warn_style()),
        Span::styled(" copy highlighted field", theme.dim()),
        Span::raw("   "),
        Span::styled(" E", theme.warn_style()),
        Span::styled(" edit username", theme.dim()),
        Span::raw("   "),
        Span::styled(" Q", theme.warn_style()),
        Span::styled(" QR", theme.dim()),
        Span::raw("   "),
        Span::styled(" Shift+I", theme.warn_style()),
        Span::styled(" invite link", theme.dim()),
    ]));
    f.render_widget(hint, parts[3]);
}
