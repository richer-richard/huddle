//! File card widget — a 4-line styled block that sits in the message
//! column when an attachment exists. Lifecycle states map to border
//! colors so a glance tells you what the card is doing.

use huddle_core::storage::repo::{AttachmentStatus, StoredAttachment};
use ratatui::prelude::*;

/// Card height in rows. The renderer emits exactly this many lines so
/// interleaving with text in a shared Paragraph stays sane.
#[allow(dead_code)]
pub const CARD_HEIGHT: u16 = 4;

/// Width reserved for the message prefix column ("  HH:MM  label  ").
/// Mirrors `MSG_PREFIX_WIDTH` in room.rs so cards sit under the body
/// column.
const PREFIX_WIDTH: usize = 2 + 5 + 2 + 6 + 2;

/// Render one file card as 4 `Line`s. The caller is responsible for
/// stacking them. `focused` overrides the normal border colour with
/// Cyan + bold.
pub fn render_card_lines(
    attachment: &StoredAttachment,
    inner_w: usize,
    focused: bool,
) -> Vec<Line<'static>> {
    let body_w = inner_w.saturating_sub(PREFIX_WIDTH).max(20);
    let inside_w = body_w.saturating_sub(4); // 2 wall chars + 2 padding

    let (status_color, _status_text, action_hints) = card_state(attachment);
    let border_color = if focused { Color::Cyan } else { status_color };
    let border_style = Style::default().fg(border_color);
    let prefix = " ".repeat(PREFIX_WIDTH);

    let header = build_header(attachment, inside_w.saturating_sub(8));
    let progress = build_progress(attachment, inside_w);
    let hints = build_hints(action_hints, inside_w);

    let top_label = format!("┌─[file] {} ", header);
    let top = pad_right_with(&top_label, body_w.saturating_sub(1), '─');
    let top = format!("{}┐", top);
    let bot = format!("└{}┘", "─".repeat(body_w.saturating_sub(2)));

    let status_style = Style::default().fg(status_color);
    let hint_style = Style::default().fg(Color::DarkGray);

    vec![
        Line::from(vec![
            Span::raw(prefix.clone()),
            Span::styled(top, border_style),
        ]),
        Line::from(vec![
            Span::raw(prefix.clone()),
            Span::styled("│ ", border_style),
            Span::styled(pad_right(&progress, inside_w), status_style),
            Span::styled(" │", border_style),
        ]),
        Line::from(vec![
            Span::raw(prefix.clone()),
            Span::styled("│ ", border_style),
            Span::styled(pad_right(&hints, inside_w), hint_style),
            Span::styled(" │", border_style),
        ]),
        Line::from(vec![
            Span::raw(prefix),
            Span::styled(bot, border_style),
        ]),
    ]
}

fn card_state(a: &StoredAttachment) -> (Color, &'static str, &'static str) {
    match a.status {
        AttachmentStatus::Offered => (
            Color::DarkGray,
            "offered",
            "[Enter] download   [c] dismiss",
        ),
        AttachmentStatus::Downloading => (
            Color::Yellow,
            "downloading",
            "[Enter] wait   [c] cancel",
        ),
        AttachmentStatus::Ready => (
            Color::Green,
            "ready",
            "[Enter] save to Downloads   [o] open   [s] save copy",
        ),
        AttachmentStatus::Saved => (
            Color::Green,
            "saved",
            "[o] open   [s] save copy",
        ),
        AttachmentStatus::Failed => (Color::Red, "failed", "[Enter] retry"),
        AttachmentStatus::Cancelled => (Color::DarkGray, "cancelled", "[Enter] retry"),
    }
}

fn build_header(a: &StoredAttachment, max_inside: usize) -> String {
    let size = format_size(a.size_bytes as u64);
    let kind = a.mime.as_deref().unwrap_or("file");
    let s = format!("{} · {} · {}", a.name, size, kind);
    if s.len() > max_inside {
        s.chars().take(max_inside).collect()
    } else {
        s
    }
}

fn build_progress(a: &StoredAttachment, max_inside: usize) -> String {
    let total = a.size_bytes.max(1) as f32;
    let (label_text, fraction) = match a.status {
        AttachmentStatus::Offered => ("offered · press [Enter] to download".into(), 0.0),
        AttachmentStatus::Downloading => ("downloading…".into(), 0.5),
        AttachmentStatus::Ready => ("ready · 100%".into(), 1.0),
        AttachmentStatus::Saved => (
            match &a.saved_path {
                Some(p) => format!("saved · {}", short_path(p)),
                None => "saved".into(),
            },
            1.0,
        ),
        AttachmentStatus::Failed => (
            match &a.error {
                Some(e) => format!("failed · {}", e),
                None => "failed".into(),
            },
            0.0,
        ),
        AttachmentStatus::Cancelled => ("cancelled".into(), 0.0),
    };
    let _ = total;
    let bar_w = 12;
    let filled = (fraction * bar_w as f32).round() as usize;
    let bar: String = (0..bar_w)
        .map(|i| if i < filled { '█' } else { '░' })
        .collect();
    let s = format!("{}  {}", bar, label_text);
    if s.len() > max_inside {
        s.chars().take(max_inside).collect()
    } else {
        s
    }
}

fn build_hints(action_hints: &str, max_inside: usize) -> String {
    if action_hints.len() > max_inside {
        action_hints.chars().take(max_inside).collect()
    } else {
        action_hints.into()
    }
}

fn pad_right(s: &str, w: usize) -> String {
    let len = s.chars().count();
    if len >= w {
        s.chars().take(w).collect()
    } else {
        let mut out = s.to_string();
        for _ in 0..(w - len) {
            out.push(' ');
        }
        out
    }
}

fn pad_right_with(s: &str, w: usize, fill: char) -> String {
    let len = s.chars().count();
    if len >= w {
        s.chars().take(w).collect()
    } else {
        let mut out = s.to_string();
        for _ in 0..(w - len) {
            out.push(fill);
        }
        out
    }
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f32 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f32 / 1_048_576.0)
    }
}

fn short_path(p: &str) -> String {
    let parts: Vec<&str> = p.split('/').collect();
    if parts.len() <= 3 {
        return p.to_string();
    }
    let tail: Vec<&str> = parts.iter().rev().take(2).rev().cloned().collect();
    format!(".../{}", tail.join("/"))
}
