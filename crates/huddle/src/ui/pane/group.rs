//! Group pane — N-way room chat. Header shows name + member count +
//! encryption + verified-only-join. Optional right-margin member list
//! when width permits (toggleable via Ctrl+I).

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Padding, Paragraph};
use ratatui::Frame;

use crate::app::TuiApp;
use crate::ui::pane::chat_common;
use crate::ui::short_fp;
use crate::ui::theme::Theme;

const MEMBER_MARGIN_COLS: u16 = 22;

pub fn render(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme, room_id: &str) {
    let r = match app.open_room(room_id) {
        Some(r) => r,
        None => {
            let para = Paragraph::new(Line::from(Span::styled(
                "  (room not joined — select it from the sidebar)",
                theme.dim(),
            )));
            f.render_widget(para, area);
            return;
        }
    };

    let show_members = app.show_member_margin && area.width >= 64;
    let (chat_area, member_area) = if show_members {
        let hparts = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(0), Constraint::Length(MEMBER_MARGIN_COLS)])
            .split(area);
        (hparts[0], Some(hparts[1]))
    } else {
        (area, None)
    };

    let input_h = chat_common::input_height(r, chat_area.width);
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(input_h),
        ])
        .split(chat_area);

    render_header(f, parts[0], app, theme, room_id);
    chat_common::render_messages(f, parts[1], app, theme, room_id);
    chat_common::render_input(f, parts[2], app, theme, room_id);

    if let Some(m_area) = member_area {
        render_member_margin(f, m_area, app, theme, room_id);
    }
}

fn render_header(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme, room_id: &str) {
    let info = app.handle.active_room_info(room_id);
    let name = info
        .as_ref()
        .map(|r| r.name.clone())
        .unwrap_or_else(|| "(unknown)".into());
    let encrypted = info.as_ref().map(|r| r.encrypted).unwrap_or(false);
    let members = app.handle.room_members(room_id).len().max(1);
    let muted = app.handle.is_room_muted(room_id);
    let read_only = app.handle.is_room_read_only(room_id);

    let mut spans: Vec<Span> = vec![
        Span::styled(
            format!("#{}", name),
            Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(format!("{} members", members), theme.dim()),
    ];
    spans.push(Span::raw("  "));
    if encrypted {
        spans.push(Span::styled("🔒 encrypted", theme.enc()));
    } else {
        spans.push(Span::styled("public", theme.ok()));
    }
    if muted {
        spans.push(Span::raw("  "));
        spans.push(Span::styled("(muted)", theme.dim()));
    }
    if read_only {
        spans.push(Span::raw("  "));
        spans.push(Span::styled("(read-only)", theme.dim()));
    }

    let mut lines = vec![Line::from(spans)];
    if let Some(t) = chat_common::typing_line(app, theme, room_id) {
        lines.push(t);
    }

    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme.border_style())
            .padding(Padding::horizontal(1)),
    );
    f.render_widget(para, area);
}

fn render_member_margin(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme, room_id: &str) {
    let members = app.handle.room_members(room_id);
    let verified: std::collections::HashSet<String> = app
        .handle
        .verified_fingerprints(room_id)
        .into_iter()
        .collect();
    let me = app.handle.fingerprint().to_string();
    let mut lines: Vec<Line> = vec![Line::from(vec![Span::styled(
        "Members",
        Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
    )])];
    for fp in &members {
        let name = if fp == &me {
            app.handle.display_name()
        } else {
            app.handle.lookup_username(fp)
        };
        let short = short_fp(fp);
        let label = match name {
            Some(n) if !n.is_empty() => {
                let trunc: String = n.chars().take(8).collect();
                format!("{}·{}", trunc, short)
            }
            _ => short,
        };
        let mut spans = vec![Span::styled(label, theme.text_style())];
        if verified.contains(fp) {
            spans.push(Span::styled(" ✓", theme.ok()));
        }
        if fp == &me {
            spans.push(Span::styled(" *", theme.dim()));
        }
        lines.push(Line::from(spans));
    }
    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::LEFT)
            .border_style(theme.border_style())
            .padding(Padding::horizontal(1)),
    );
    f.render_widget(para, area);
}
