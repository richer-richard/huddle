//! DM pane — 1-1 direct chat. Header shows the partner's username +
//! HD-ID + verified marker. No member list, no moderation keybindings.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Padding, Paragraph};
use ratatui::Frame;

use crate::app::TuiApp;
use crate::ui::display_id;
use crate::ui::pane::chat_common;
use crate::ui::theme::Theme;

pub fn render(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme, room_id: &str) {
    let r = match app.open_room(room_id) {
        Some(r) => r,
        None => {
            let para = Paragraph::new(Line::from(Span::styled(
                "  (DM not loaded — try selecting it from the sidebar again)",
                theme.dim(),
            )));
            f.render_widget(para, area);
            return;
        }
    };

    let input_h = chat_common::input_height(r, area.width);
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),       // header
            Constraint::Min(3),          // messages
            Constraint::Length(input_h), // input
        ])
        .split(area);

    render_header(f, parts[0], app, theme, room_id);
    chat_common::render_messages(f, parts[1], app, theme, room_id);
    chat_common::render_input(f, parts[2], app, theme, room_id);
}

fn render_header(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme, room_id: &str) {
    let partner_fp = app.handle.dm_partner_fingerprint(room_id);
    let partner_label = partner_fp
        .as_deref()
        .and_then(|fp| app.handle.lookup_username(fp))
        .unwrap_or_else(|| "[anonymous]".into());
    let partner_id = partner_fp
        .as_deref()
        .map(display_id)
        .unwrap_or_else(|| "(pending)".into());
    let verified = partner_fp
        .as_deref()
        .map(|fp| {
            app.handle
                .verified_fingerprints(room_id)
                .iter()
                .any(|v| v == fp)
        })
        .unwrap_or(false);

    let mut spans: Vec<Span> = vec![
        Span::styled(
            partner_label,
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(partner_id, theme.dim()),
    ];
    if verified {
        spans.push(Span::raw("  "));
        spans.push(Span::styled("✓ verified", theme.ok()));
    } else {
        spans.push(Span::raw("  "));
        spans.push(Span::styled("(unverified — Ctrl+V to SAS)", theme.dim()));
    }
    spans.push(Span::raw("  "));
    spans.push(Span::styled("Direct", theme.dim()));
    // huddle 1.0: per-chat transport indicator (status only — the app picks
    // the path automatically). Makes the security context legible: is this
    // riding the LAN, the Tor/clearnet relay, or nothing right now?
    spans.push(Span::raw("  ·  "));
    let (tlabel, tstyle) = match app.handle.room_transport(room_id) {
        huddle_core::app::RoomTransport::LanDirect => ("via lan", theme.ok()),
        huddle_core::app::RoomTransport::Relay => ("via relay", theme.warn_style()),
        huddle_core::app::RoomTransport::Offline => ("offline", theme.dim()),
    };
    spans.push(Span::styled(tlabel, tstyle));

    // huddle 2.0.0 (F9): disappearing-messages indicator.
    if let Some(secs) = app.handle.room_disappearing_ttl(room_id) {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            format!("⧖ expires in {}", chat_common::format_ttl(secs)),
            theme.warn_style(),
        ));
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
