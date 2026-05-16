//! Shared chat rendering for DM + Group panes — extracted from the legacy
//! `ui/room.rs`. Message list, input box, day separators, scroll indicator,
//! verified marker, typing indicator. The DM and Group panes wrap this
//! with their own header and (for Group) member margin.

use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Padding, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{OpenRoom, TuiApp};
use crate::ui::file_card;
use crate::ui::short_fp;
use crate::ui::theme::Theme;

const MSG_LABEL_WIDTH: usize = 12;
const MSG_PREFIX_WIDTH: usize = 2 + 5 + 2 + MSG_LABEL_WIDTH + 2; // 23

/// Compute the desired height for the input box, accounting for the
/// number of lines the user has typed (including soft-wrapped lines).
pub fn input_height(r: &OpenRoom, screen_width: u16) -> u16 {
    let inner_w = screen_width.saturating_sub(4) as usize;
    let prompt_w = 2usize;
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

pub fn render_messages(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme, room_id: &str) {
    let r = match app.open_room(room_id) {
        Some(r) => r,
        None => return,
    };
    let me = app.handle.fingerprint().to_string();
    let verified: std::collections::HashSet<String> = app
        .handle
        .verified_fingerprints(room_id)
        .into_iter()
        .collect();

    let inner_w = area.width.saturating_sub(4) as usize;
    let body_w = inner_w.saturating_sub(MSG_PREFIX_WIDTH).max(8);

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
    let mut prev_day: Option<i64> = None;
    for (ts, row) in timeline {
        let day = ts / 86_400;
        if prev_day.map(|p| p != day).unwrap_or(true) {
            lines.push(separator_line(ts, inner_w, theme));
            prev_day = Some(day);
        }
        match row {
            Row::Text(m) => {
                let is_me = m.sender_fingerprint == me || m.direction == "out";
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
                    Style::default().fg(theme.warn).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)
                };
                let is_verified = !is_me && verified.contains(&m.sender_fingerprint);
                let time = format_time(m.sent_at);
                let chunks = wrap_body(&m.body, body_w);
                for (i, chunk) in chunks.iter().enumerate() {
                    if i == 0 {
                        let mut spans = vec![
                            Span::styled(format!("  {}  ", time), theme.dim()),
                            Span::styled(
                                format!("{:<width$}", label, width = MSG_LABEL_WIDTH),
                                label_style,
                            ),
                            Span::raw("  "),
                        ];
                        if is_verified {
                            spans.push(Span::styled("✓ ", theme.ok()));
                        }
                        spans.push(Span::styled(chunk.clone(), theme.text_style()));
                        lines.push(Line::from(spans));
                    } else {
                        lines.push(Line::from(vec![
                            Span::styled(" ".repeat(MSG_PREFIX_WIDTH), theme.dim()),
                            Span::styled(chunk.clone(), theme.text_style()),
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
            theme.dim(),
        )));
    }

    let visible_h = area.height.saturating_sub(2);
    let total = lines.len() as u16;
    let max_scroll = total.saturating_sub(visible_h);
    r.last_max_scroll.set(max_scroll);
    let scroll_y = if r.follow_mode {
        max_scroll
    } else {
        r.scroll.min(max_scroll)
    };

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
                .border_style(theme.border_style())
                .padding(Padding::horizontal(1))
                .title_bottom(Line::from(Span::styled(title, theme.dim()))),
        )
        .scroll((scroll_y, 0));
    f.render_widget(widget, area);
}

pub fn render_input(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme, room_id: &str) {
    let r = match app.open_room(room_id) {
        Some(r) => r,
        None => return,
    };
    let border_style = if r.input_active {
        theme.warn_style()
    } else {
        theme.border_style()
    };

    let lines: Vec<Line> = if !r.input_active {
        vec![Line::from(Span::styled(
            "press / to type   ·   Alt+Enter or ^J for newline   ·   Ctrl+P for command palette",
            theme.dim(),
        ))]
    } else {
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
                format!("{}_", line)
            } else {
                (*line).to_string()
            };
            out.push(Line::from(vec![
                Span::styled(prompt, theme.dim()),
                Span::styled(body, theme.text_style()),
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

fn separator_line(unix_secs: i64, inner_w: usize, theme: &Theme) -> Line<'static> {
    let date = format_ymd(unix_secs);
    let label = format!(" {} ", date);
    let total = inner_w.saturating_sub(2);
    let side = total.saturating_sub(label.chars().count()) / 2;
    let dashes = "─".repeat(side.max(3));
    Line::from(vec![
        Span::raw("  "),
        Span::styled(dashes.clone(), theme.dim()),
        Span::styled(label, theme.dim()),
        Span::styled(dashes, theme.dim()),
    ])
}

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

fn format_time(unix_secs: i64) -> String {
    let secs_today = (unix_secs % 86_400) as u32;
    let hh = (secs_today / 3600) % 24;
    let mm = (secs_today / 60) % 60;
    format!("{:02}:{:02}", hh, mm)
}

fn format_ymd(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let jdn = days + 2440588;
    let f = jdn + 1401 + ((((4 * jdn) + 274_277) / 146_097) * 3) / 4 - 38;
    let e = 4 * f + 3;
    let g = (e.rem_euclid(1461)) / 4;
    let h = 5 * g + 2;
    let day = (h.rem_euclid(153)) / 5 + 1;
    let month = (h / 153 + 2).rem_euclid(12) + 1;
    let year = e.div_euclid(1461) - 4716 + (12 + 2 - month) / 12;
    format!("{:04}-{:02}-{:02}", year, month, day)
}

/// huddle 0.7: render the typing indicator (used by both DM and Group headers).
pub fn typing_line<'a>(app: &TuiApp, theme: &Theme, room_id: &str) -> Option<Line<'a>> {
    let typers = app.handle.typers_in_room(room_id);
    let me = app.handle.fingerprint().to_string();
    let names: Vec<String> = typers
        .iter()
        .filter(|fp| *fp != &me)
        .map(|fp| short_fp(fp))
        .collect();
    if names.is_empty() {
        return None;
    }
    let txt = if names.len() == 1 {
        format!("{} is typing…", names[0])
    } else {
        format!("{} are typing…", names.join(", "))
    };
    Some(Line::from(Span::styled(format!("  {}", txt), theme.dim())))
}
