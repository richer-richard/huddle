use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Padding, Paragraph, Tabs, Wrap};

use crate::app::TuiApp;
use crate::keybindings;
use crate::ui::file_card;
use crate::ui::short_fp;

pub fn render_room_screen(f: &mut Frame, area: Rect, app: &TuiApp) {
    let input_h = input_height(app, area.width);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),       // tabs
            Constraint::Length(4),       // header (room name + optional typing)
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
            // huddle 0.6: render the unread count instead of a bare
            // '*'. Active tab always shows nothing (it's the one in
            // focus).
            let unread_str: String = if i == app.active_tab || r.unread == 0 {
                String::new()
            } else if r.unread > 99 {
                " (99+)".to_string()
            } else {
                format!(" ({})", r.unread)
            };
            let muted = if app.handle.is_room_muted(&r.room_id) {
                " (muted)"
            } else {
                ""
            };
            let read_only = if app.handle.is_room_read_only(&r.room_id) {
                " (read-only)"
            } else {
                ""
            };
            Line::from(vec![
                Span::styled(prefix, Style::default().fg(Color::DarkGray)),
                Span::raw(r.name.clone()),
                Span::styled(lock, Style::default().fg(Color::Magenta)),
                Span::styled(unread_str, Style::default().fg(Color::Yellow).bold()),
                Span::styled(muted, Style::default().fg(Color::DarkGray)),
                Span::styled(read_only, Style::default().fg(Color::DarkGray)),
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
        // huddle 0.5: render `{username}·{short_fp}` for set users,
        // bare short_fp for [anonymous]. Self gets a trailing `*`.
        let name = if fp == &me {
            app.handle.display_name()
        } else {
            app.handle.lookup_username(fp)
        };
        let short = short_fp(fp);
        let base = match name {
            Some(n) if !n.is_empty() => {
                let trunc: String = n.chars().take(10).collect();
                format!("{}·{}", trunc, short)
            }
            _ => short,
        };
        let label = if fp == &me {
            format!("{}*", base)
        } else {
            base
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

    let mut header_line_spans = vec![
        Span::styled(format!("#{} ", r.name), Style::default().fg(Color::Cyan).bold()),
        Span::styled(format!("{}  ", kind), kind_style),
    ];
    header_line_spans.extend(member_spans);

    let typers = app.handle.typers_in_room(&r.room_id);
    let mut lines: Vec<Line> = vec![Line::from(header_line_spans)];
    if !typers.is_empty() {
        let me = app.handle.fingerprint().to_string();
        let names: Vec<String> = typers
            .iter()
            .filter(|fp| *fp != &me)
            .map(|fp| short_fp(fp))
            .collect();
        if !names.is_empty() {
            let txt = if names.len() == 1 {
                format!("{} is typing…", names[0])
            } else {
                format!("{} are typing…", names.join(", "))
            };
            lines.push(Line::from(Span::styled(
                format!("  {}", txt),
                Style::default().fg(Color::DarkGray),
            )));
        }
    }

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
const MSG_LABEL_WIDTH: usize = 12;
const MSG_PREFIX_WIDTH: usize = 2 + 5 + 2 + MSG_LABEL_WIDTH + 2; // 23

fn render_messages(f: &mut Frame, area: Rect, app: &TuiApp) {
    let r = match app.active_room() {
        Some(r) => r,
        None => return,
    };
    let me = app.handle.fingerprint().to_string();
    // huddle 0.5 / Phase 3: precompute the verified set once so each
    // message-line render is a constant-time lookup. The set is
    // per-room and tiny (usually < 32 members).
    let verified: std::collections::HashSet<String> = app
        .handle
        .verified_fingerprints(&r.room_id)
        .into_iter()
        .collect();

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
    // huddle 0.6: day separators — when the date rolls between two
    // consecutive rows, render a dim "─── YYYY-MM-DD ───" divider.
    let mut prev_day: Option<i64> = None;
    for (ts, row) in timeline {
        let day = ts / 86_400;
        if prev_day.map(|p| p != day).unwrap_or(true) {
            // Skip the very first separator only if the buffer is
            // empty — otherwise users see a divider sandwich between
            // gaps, which is helpful context.
            if prev_day.is_some() || !lines.is_empty() {
                lines.push(separator_line(ts, inner_w));
            } else {
                // First message: render a single date label so the
                // user knows when the conversation started.
                lines.push(separator_line(ts, inner_w));
            }
            prev_day = Some(day);
        }
        match row {
            Row::Text(m) => {
                let is_me = m.sender_fingerprint == me || m.direction == "out";
                // huddle 0.5: prefer the signed `lookup_username`. Fall
                // back to `[anonymous]` so peers who haven't set a name
                // still get a label rather than a bare fingerprint.
                let label = if is_me {
                    app.handle
                        .display_name()
                        .unwrap_or_else(|| "you".to_string())
                } else {
                    app.handle
                        .lookup_username(&m.sender_fingerprint)
                        .unwrap_or_else(|| "[anonymous]".to_string())
                };
                let label: String = label.chars().take(MSG_LABEL_WIDTH).collect();
                let label_style = if is_me {
                    Style::default().fg(Color::Yellow).bold()
                } else {
                    Style::default().fg(Color::Cyan).bold()
                };
                // Phase 3: green ✓ in the sender column for peers we've
                // SAS-verified. Suppressed for our own outbound messages
                // (tautological).
                let is_verified = !is_me && verified.contains(&m.sender_fingerprint);
                let time = format_time(m.sent_at);
                let chunks = wrap_body(&m.body, body_w);
                for (i, chunk) in chunks.iter().enumerate() {
                    if i == 0 {
                        let mut spans = vec![
                            Span::styled(
                                format!("  {}  ", time),
                                Style::default().fg(Color::DarkGray),
                            ),
                            Span::styled(
                                format!("{:<width$}", label, width = MSG_LABEL_WIDTH),
                                label_style,
                            ),
                            Span::styled("  ", Style::default()),
                        ];
                        if is_verified {
                            spans.push(Span::styled(
                                "✓ ",
                                Style::default().fg(Color::Green).bold(),
                            ));
                        }
                        spans.push(Span::styled(
                            chunk.clone(),
                            Style::default().fg(Color::White),
                        ));
                        lines.push(Line::from(spans));
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
            "  no messages yet — say hi! press / to type.",
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

    // huddle 0.6: scroll position indicator embedded in the title bar
    // so the user can see "I'm at 42/210" without guessing whether
    // PageUp would do anything.
    let title = if max_scroll == 0 {
        " ".to_string()
    } else if r.follow_mode {
        format!(" {}/{}  · live ", total.saturating_sub(1), total)
    } else {
        let current_line = scroll_y + visible_h.min(total);
        format!(
            " {}/{}  · ↑ {} above  · g/G top/bottom ",
            current_line.min(total),
            total,
            scroll_y
        )
    };

    let widget = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .padding(Padding::horizontal(1))
                .title_bottom(Line::from(Span::styled(
                    title,
                    Style::default().fg(Color::DarkGray),
                ))),
        )
        .scroll((scroll_y, 0));
    f.render_widget(widget, area);
}

/// huddle 0.6: a dim horizontal separator showing the calendar date
/// of the messages immediately following. `inner_w` is the width
/// inside the borders so we can size the dashes.
fn separator_line(unix_secs: i64, inner_w: usize) -> Line<'static> {
    let date = format_ymd(unix_secs);
    let label = format!(" {} ", date);
    let total = inner_w.saturating_sub(2); // 2 for the leading spaces below
    let side = total.saturating_sub(label.chars().count()) / 2;
    let dashes = "─".repeat(side.max(3));
    Line::from(vec![
        Span::raw("  "),
        Span::styled(dashes.clone(), Style::default().fg(Color::DarkGray)),
        Span::styled(label, Style::default().fg(Color::DarkGray)),
        Span::styled(dashes, Style::default().fg(Color::DarkGray)),
    ])
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
            "press / to type   ·   Alt+Enter or ^J for newline   ·   : for command palette",
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
    // huddle 0.6: adaptive hint bar (see lobby.rs equivalent).
    let mut spans: Vec<Span> = vec![Span::raw("  ")];
    for (i, (key, label)) in keybindings::adaptive_hints(app).into_iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled("   ", Style::default()));
        }
        spans.push(Span::styled(
            format!("[{}]", key),
            Style::default().fg(Color::Yellow),
        ));
        spans.push(Span::styled(
            format!(" {}", label),
            Style::default().fg(Color::DarkGray),
        ));
    }
    // Pending-modal indicator embedded in the hint bar — visible from
    // inside a room too, not just from the lobby.
    if app.pending_count() > 0 {
        spans.push(Span::styled(
            format!("   [{} pending]", app.pending_count()),
            Style::default().fg(Color::Yellow).bold(),
        ));
    }
    let para = Paragraph::new(Line::from(spans)).block(
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

/// huddle 0.6: format a unix timestamp as YYYY-MM-DD using
/// a tiny Julian-day calculation — avoids a chrono dep while
/// remaining correct for the Gregorian calendar (any date after
/// 1970).
fn format_ymd(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    // 1970-01-01 = Julian Day 2440588.
    let jdn = days + 2440588;
    // Algorithm from Hatcher (1985), as documented in the Wikipedia
    // Julian-day-number article.
    let f = jdn + 1401 + ((((4 * jdn) + 274_277) / 146_097) * 3) / 4 - 38;
    let e = 4 * f + 3;
    let g = (e.rem_euclid(1461)) / 4;
    let h = 5 * g + 2;
    let day = (h.rem_euclid(153)) / 5 + 1;
    let month = (h / 153 + 2).rem_euclid(12) + 1;
    let year = e.div_euclid(1461) - 4716 + (12 + 2 - month) / 12;
    format!("{:04}-{:02}-{:02}", year, month, day)
}
