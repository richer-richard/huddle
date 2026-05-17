//! Settings pane — global toggles, blocked-peer manager, theme, go-dark.
//! All toggles are reachable from the pane; some also have their own
//! modals (`,` quick-open) for the same actions.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Padding, Paragraph};
use ratatui::Frame;

use crate::app::TuiApp;
use crate::ui::theme::Theme;

pub fn render(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme) {
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(0)])
        .split(area);

    let title = Paragraph::new(Line::from(vec![Span::styled(
        "Settings",
        Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
    )]));
    f.render_widget(title, parts[0]);

    let v_only = app.handle.verified_only_inbound();
    let update_check = app.handle.update_check_enabled();
    let last_check_t = app.handle.last_update_check_at();
    let last_check = if last_check_t > 0 {
        relative_time(last_check_t)
    } else {
        "never".into()
    };
    let username = app.handle.display_name().unwrap_or_else(|| "[anonymous]".into());
    let blocked_count = app.handle.list_blocked_peers().len();

    let mut lines: Vec<Line> = Vec::new();
    lines.push(row(theme, "V", "verified-only inbound", on_off(v_only)));
    lines.push(row(
        theme,
        "U",
        "update check (crates.io)",
        match update_check {
            Some(true) => format!("on  ·  last checked {}", last_check),
            Some(false) => "off".into(),
            None => "not asked yet".into(),
        },
    ));
    lines.push(row(theme, "E", "username", username));
    lines.push(row(theme, "W", "replay onboarding", "press W".into()));
    lines.push(row(
        theme,
        "B",
        "blocked peers",
        format!("{}", blocked_count),
    ));
    lines.push(Line::raw(""));
    lines.push(Line::from(vec![Span::styled(
        "  ─── danger zone ───",
        theme.dim(),
    )]));
    lines.push(Line::raw(""));
    // huddle 0.7.4 follow-up: column alignment. The other rows use
    // `"  X"` (3) + 4 spaces = 7 cols before the label; this row uses
    // `"  ⌥⇧1"` (5) + 2 spaces = 7 cols, matching their leading-edge.
    lines.push(Line::from(vec![
        Span::styled("  ⌥⇧1", theme.err_style()),
        Span::raw("  "),
        Span::styled(format!("{:<28}", "go dark"), theme.err_style()),
        Span::styled("delete account, wipe data, exit", theme.dim()),
    ]));

    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme.border_style())
            .padding(Padding::horizontal(1)),
    );
    f.render_widget(p, parts[1]);
}

fn row<'a>(theme: &Theme, key: &'a str, label: &'a str, value: String) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("  {}", key), theme.warn_style()),
        Span::raw("    "),
        Span::styled(format!("{:<28}", label), theme.text_style()),
        Span::styled(value, theme.dim()),
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
