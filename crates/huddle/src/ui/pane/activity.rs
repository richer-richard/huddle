//! Activity pane — status history + in-flight file transfers.

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
        .constraints([Constraint::Length(2), Constraint::Percentage(40), Constraint::Min(0)])
        .split(area);

    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            "Activity",
            Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
        ),
        Span::raw("    "),
        Span::styled("c", theme.warn_style()),
        Span::styled(" clear status history", theme.dim()),
    ]));
    f.render_widget(title, parts[0]);

    render_transfers(f, parts[1], app, theme);
    render_history(f, parts[2], app, theme);
}

fn render_transfers(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme.border_style())
        .padding(Padding::horizontal(1))
        .title(Span::styled(
            " In-flight transfers ",
            Style::default().fg(theme.accent),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    // Aggregate transfers across all rooms.
    let mut all = Vec::new();
    for room_id in app.handle.active_room_ids() {
        let atts = app
            .handle
            .list_room_attachments(&room_id)
            .unwrap_or_default();
        for a in atts {
            // Surface only "currently in-flight" rows: offered or downloading.
            match a.status {
                huddle_core::storage::repo::AttachmentStatus::Offered
                | huddle_core::storage::repo::AttachmentStatus::Downloading => {
                    all.push((room_id.clone(), a));
                }
                _ => {}
            }
        }
    }
    if all.is_empty() {
        let p = Paragraph::new(Line::from(Span::styled(
            "  (no transfers in progress)",
            theme.dim(),
        )));
        f.render_widget(p, inner);
        return;
    }
    let mut lines: Vec<Line> = Vec::new();
    for (rid, a) in &all {
        let kb = a.size_bytes / 1024;
        lines.push(Line::from(vec![
            Span::styled(format!("  {}  ", a.name), theme.text_style()),
            Span::styled(format!("({} KB)", kb), theme.dim()),
            Span::raw("  "),
            Span::styled(format!("room {}", &rid[..rid.len().min(8)]), theme.dim()),
        ]));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn render_history(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme.border_style())
        .padding(Padding::horizontal(1))
        .title(Span::styled(
            " Status history ",
            Style::default().fg(theme.accent),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.status_history.is_empty() {
        let p = Paragraph::new(Line::from(Span::styled(
            "  (nothing yet — events appear here as they happen)",
            theme.dim(),
        )));
        f.render_widget(p, inner);
        return;
    }
    let mut lines: Vec<Line> = Vec::new();
    for e in app.status_history.iter().rev() {
        let time = format_hhmm(e.timestamp);
        lines.push(Line::from(vec![
            Span::styled(format!("  {}  ", time), theme.dim()),
            Span::styled(e.message.clone(), theme.text_style()),
        ]));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn format_hhmm(unix_secs: i64) -> String {
    let secs_today = (unix_secs.rem_euclid(86_400)) as u32;
    let hh = (secs_today / 3600) % 24;
    let mm = (secs_today / 60) % 60;
    let ss = secs_today % 60;
    format!("{:02}:{:02}:{:02}", hh, mm, ss)
}
