use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Padding, Paragraph, Tabs, Wrap};

use crate::app::TuiApp;
use crate::ui::file_card;
use crate::ui::short_fp;

pub fn render_room_screen(f: &mut Frame, area: Rect, app: &TuiApp) {
    let input_h = input_height(app, area.width);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),       // tabs
            Constraint::Length(3),       // header
            Constraint::Min(3),          // messages
            Constraint::Length(input_h), // input (grows with content)
            Constraint::Length(2),       // hints
        ])
        .split(area);

    render_tabs(f, chunks[0], app);
    render_header(f, chunks[1], app);
    render_messages(f, chunks[2], app);
    render_input(f, chunks[3], app);
    render_hints(f, chunks[4], app);
}

/// Compute the desired height for the input box, accounting for the
/// number of lines the user has typed (including soft-wrapped lines).
/// Clamps to a reasonable range so the chat doesn't get crushed.
fn input_height(app: &TuiApp, screen_width: u16) -> u16 {
    let r = match app.active_room() {
        Some(r) => r,
        None => return 3,
    };
    let inner_w = screen_width.saturating_sub(4) as usize; // 2 borders + 2 padding
    let prompt_w = 2usize; // "> "
    let body_w = inner_w.saturating_sub(prompt_w).max(1);
    let mut lines: usize = 0;
    if r.input.is_empty() {
        lines = 1;
    } else {
        for raw_line in r.input.split('\n') {
            let chars = raw_line.chars().count();
            let n = ((chars + body_w) / body_w).max(1);
            lines += n;
        }
    }
    let clamped = lines.clamp(1, 8) as u16;
    clamped + 2 // borders
}

fn render_tabs(f: &mut Frame, area: Rect, app: &TuiApp) {
    let titles: Vec<Line> = app
        .open_rooms
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let prefix = format!("[{}] ", i + 1);
            let lock = if r.encrypted { " E" } else { "" };
            let unread = if r.unread && i != app.active_tab {
                "*"
            } else {
                ""
            };
            Line::from(vec![
                Span::styled(prefix, Style::default().fg(Color::DarkGray)),
                Span::raw(&r.name),
                Span::styled(lock, Style::default().fg(Color::Magenta)),
                Span::styled(unread, Style::default().fg(Color::Yellow)),
            ])
        })
        .collect();

    let tabs = Tabs::new(titles)
        .select(app.active_tab)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .style(Style::default().fg(Color::White))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .divider(Span::styled("│", Style::default().fg(Color::DarkGray)));

    f.render_widget(tabs, area);
}

fn render_header(f: &mut Frame, area: Rect, app: &TuiApp) {
    let r = match app.active_room() {
        Some(r) => r,
        None => return,
    };
    let kind = if r.encrypted { "encrypted" } else { "public" };
    let kind_style = if r.encrypted {
        Style::default().fg(Color::Magenta)
    } else {
        Style::default().fg(Color::Green)
    };

    let me = app.handle.fingerprint().to_string();
    let verified: std::collections::HashSet<String> = app
        .handle
        .verified_fingerprints(&r.room_id)
        .into_iter()
        .collect();
    let mut member_spans: Vec<Span> = vec![Span::styled(
        format!("{} members: ", r.members.len().max(1)),
        Style::default().fg(Color::DarkGray),
    )];
    let mut first = true;
    for fp in &r.members {
        if !first {
            member_spans.push(Span::styled(" ", Style::default()));
        }
        first = false;
        let label = if fp == &me {
            format!("{}*", short_fp(fp))
        } else {
            short_fp(fp)
        };
        member_spans.push(Span::styled(
            label,
            if fp == &me {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::White)
            },
        ));
        if verified.contains(fp) {
            member_spans.push(Span::styled(
                "✓",
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            ));
        }
    }

    let lines = vec![Line::from({
        let mut spans = vec![
            Span::styled(format!("#{} ", r.name), Style::default().fg(Color::Cyan).bold()),
            Span::styled(format!("{}  ", kind), kind_style),
        ];
        spans.extend(member_spans);
        spans
    })];

    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .padding(Padding::horizontal(1)),
    );
    f.render_widget(para, area);
}

/// Width (in cols) of the "  HH:MM  label   " prefix. Continuation lines
/// of a wrapped or multiline message are indented this many spaces so
/// they sit under the body column.
const MSG_PREFIX_WIDTH: usize = 2 + 5 + 2 + 6 + 2; // 17

fn render_messages(f: &mut Frame, area: Rect, app: &TuiApp) {
    let r = match app.active_room() {
        Some(r) => r,
        None => return,
    };
    let me = app.handle.fingerprint().to_string();

    // Available width for body text — account for borders + padding.
    let inner_w = area.width.saturating_sub(4) as usize;
    let body_w = inner_w.saturating_sub(MSG_PREFIX_WIDTH).max(8);

    // Build a unified, chronologically-sorted timeline of text messages
    // and file cards so they interleave naturally in the chat history.
    enum Row<'a> {
        Text(&'a huddle_core::storage::repo::StoredRoomMessage),
        Card(&'a huddle_core::storage::repo::StoredAttachment, bool),
    }
    let mut timeline: Vec<(i64, Row)> = Vec::new();
    for m in &r.messages {
        timeline.push((m.sent_at, Row::Text(m)));
    }
    for (i, a) in r.attachments.iter().enumerate() {
        let focused = r.card_focus && i == r.focused_card_idx;
        timeline.push((a.created_at, Row::Card(a, focused)));
    }
    timeline.sort_by_key(|(ts, _)| *ts);

    let mut lines: Vec<Line> = Vec::new();
    for (_, row) in timeline {
        match row {
            Row::Text(m) => {
                let is_me = m.sender_fingerprint == me || m.direction == "out";
                let label = if is_me {
                    "you".to_string()
                } else {
                    short_fp(&m.sender_fingerprint)
                };
                let label_style = if is_me {
                    Style::default().fg(Color::Yellow).bold()
                } else {
                    Style::default().fg(Color::Cyan).bold()
                };
                let time = format_time(m.sent_at);
                let chunks = wrap_body(&m.body, body_w);
                for (i, chunk) in chunks.iter().enumerate() {
                    if i == 0 {
                        lines.push(Line::from(vec![
                            Span::styled(
                                format!("  {}  ", time),
                                Style::default().fg(Color::DarkGray),
                            ),
                            Span::styled(format!("{:<6}", label), label_style),
                            Span::styled("  ", Style::default()),
                            Span::styled(chunk.clone(), Style::default().fg(Color::White)),
                        ]));
                    } else {
                        lines.push(Line::from(vec![
                            Span::styled(
                                " ".repeat(MSG_PREFIX_WIDTH),
                                Style::default().fg(Color::DarkGray),
                            ),
                            Span::styled(chunk.clone(), Style::default().fg(Color::White)),
                        ]));
                    }
                }
            }
            Row::Card(a, focused) => {
                let card = file_card::render_card_lines(a, inner_w, focused);
                lines.extend(card);
            }
        }
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "  no messages yet — say hi!",
            Style::default().fg(Color::DarkGray),
        )));
    }

    // visible_h = inner area minus 2 borders. Cap at 0 in case the
    // window is impossibly small.
    let visible_h = area.height.saturating_sub(2);
    let total = lines.len() as u16;
    let max_scroll = total.saturating_sub(visible_h);
    // Publish max_scroll so action handlers can clamp without re-running
    // the wrap.
    r.last_max_scroll.set(max_scroll);
    let scroll_y = if r.follow_mode {
        max_scroll
    } else {
        r.scroll.min(max_scroll)
    };

    let widget = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .padding(Padding::horizontal(1)),
        )
        .scroll((scroll_y, 0));
    f.render_widget(widget, area);
}

/// Split `body` into chunks no wider than `width` chars. Honors explicit
/// `\n` newlines AND hard-wraps long single lines. We do character-based
/// wrapping (not word-based) so long URLs / random text behave predictably.
fn wrap_body(body: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![body.to_string()];
    }
    let mut out = Vec::new();
    for line in body.split('\n') {
        if line.is_empty() {
            out.push(String::new());
            continue;
        }
        let chars: Vec<char> = line.chars().collect();
        let mut start = 0;
        while start < chars.len() {
            let end = (start + width).min(chars.len());
            out.push(chars[start..end].iter().collect());
            start = end;
        }
    }
    out
}

fn render_input(f: &mut Frame, area: Rect, app: &TuiApp) {
    let r = match app.active_room() {
        Some(r) => r,
        None => return,
    };
    let border_style = if r.input_active {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let lines: Vec<Line> = if !r.input_active {
        vec![Line::from(Span::styled(
            "press / to type   ·   Alt+Enter or ^J for newline",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        // Build the multiline input. Each row gets a "> " prompt on the
        // first physical line and a "  " continuation on subsequent
        // visual rows. We rely on Paragraph::wrap to do the soft wrap.
        let mut out: Vec<Line> = Vec::new();
        let raw_lines: Vec<&str> = if r.input.is_empty() {
            vec![""]
        } else {
            r.input.split('\n').collect()
        };
        let last = raw_lines.len().saturating_sub(1);
        for (i, line) in raw_lines.iter().enumerate() {
            let prompt = if i == 0 { "> " } else { "  " };
            let body = if i == last {
                format!("{}_", line) // crude cursor on the last line
            } else {
                (*line).to_string()
            };
            out.push(Line::from(vec![
                Span::styled(prompt, Style::default().fg(Color::DarkGray)),
                Span::styled(body, Style::default().fg(Color::White)),
            ]));
        }
        out
    };

    let widget = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(border_style)
                .padding(Padding::horizontal(1)),
        );
    f.render_widget(widget, area);
}

fn render_hints(f: &mut Frame, area: Rect, app: &TuiApp) {
    let card_focus = app.active_room().map(|r| r.card_focus).unwrap_or(false);
    let hints = if card_focus {
        Line::from(vec![
            Span::styled("  card mode  ", Style::default().fg(Color::Cyan).bold()),
            Span::styled("j/k", Style::default().fg(Color::Yellow)),
            Span::styled(" next/prev   ", Style::default().fg(Color::DarkGray)),
            Span::styled("Enter", Style::default().fg(Color::Yellow)),
            Span::styled(" save   ", Style::default().fg(Color::DarkGray)),
            Span::styled("o", Style::default().fg(Color::Yellow)),
            Span::styled(" open   ", Style::default().fg(Color::DarkGray)),
            Span::styled("c", Style::default().fg(Color::Yellow)),
            Span::styled(" cancel   ", Style::default().fg(Color::DarkGray)),
            Span::styled("Esc/f", Style::default().fg(Color::Yellow)),
            Span::styled(" exit", Style::default().fg(Color::DarkGray)),
        ])
    } else {
        Line::from(vec![
            Span::styled("  ^Tab", Style::default().fg(Color::Yellow)),
            Span::styled(" next tab  ", Style::default().fg(Color::DarkGray)),
            Span::styled("/", Style::default().fg(Color::Yellow)),
            Span::styled(" type  ", Style::default().fg(Color::DarkGray)),
            Span::styled("f", Style::default().fg(Color::Yellow)),
            Span::styled(" files  ", Style::default().fg(Color::DarkGray)),
            Span::styled("^A", Style::default().fg(Color::Yellow)),
            Span::styled(" attach  ", Style::default().fg(Color::DarkGray)),
            Span::styled("^L", Style::default().fg(Color::Yellow)),
            Span::styled(" leave  ", Style::default().fg(Color::DarkGray)),
            Span::styled("^B", Style::default().fg(Color::Yellow)),
            Span::styled(" lobby  ", Style::default().fg(Color::DarkGray)),
            Span::styled("?", Style::default().fg(Color::Yellow)),
            Span::styled(" help", Style::default().fg(Color::DarkGray)),
        ])
    };
    let para = Paragraph::new(hints).block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(para, area);
}

fn format_time(unix_secs: i64) -> String {
    // Simple HH:MM format from epoch seconds (no chrono dep).
    let secs_today = (unix_secs % 86_400) as u32;
    let hh = (secs_today / 3600) % 24;
    let mm = (secs_today / 60) % 60;
    format!("{:02}:{:02}", hh, mm)
}
