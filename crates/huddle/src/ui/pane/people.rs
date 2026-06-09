//! People pane — every known peer (manually-dialed), every globally
//! SAS-verified peer, and every blocked peer. Per-row actions: reconnect,
//! dial, message (start DM), verify, block, unblock, forget.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Padding, Paragraph};
use ratatui::Frame;

use crate::app::{PeopleFocus, TuiApp};
use crate::ui::short_fp;
use crate::ui::theme::Theme;

pub fn render(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme) {
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(0)])
        .split(area);

    // huddle 0.7.7 / 1.0: surface request counts in the header so the user
    // sees them at a glance even when the sub-tab isn't focused. "Contacts"
    // is the address book; relay-inbox contact requests + libp2p friend
    // requests both surface as their own sub-tabs.
    let contact_req_count = app.pending_contact_requests.len();
    let pending_count = app.pending_requests.len();
    let mut title_spans = vec![
        Span::styled(
            "Contacts",
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("    "),
    ];
    if contact_req_count > 0 {
        title_spans.push(Span::styled(
            format!(
                "({} request{})  ·  ",
                contact_req_count,
                if contact_req_count == 1 { "" } else { "s" }
            ),
            theme.warn_style(),
        ));
    }
    if pending_count > 0 {
        title_spans.push(Span::styled(
            format!("({} pending)  ·  ", pending_count),
            theme.warn_style(),
        ));
    }
    title_spans.extend(vec![
        Span::styled("a", theme.warn_style()),
        Span::styled(" add by HD-ID  ·  ", theme.dim()),
        Span::styled("Tab", theme.warn_style()),
        Span::styled(" switches lists  ·  ", theme.dim()),
        Span::styled("m", theme.warn_style()),
        Span::styled(" message  ·  ", theme.dim()),
        Span::styled("b", theme.warn_style()),
        Span::styled(" block", theme.dim()),
    ]);
    let title = Paragraph::new(Line::from(title_spans));
    f.render_widget(title, parts[0]);

    // huddle 1.0: optional Contact-requests + Pending sub-lists sit at the
    // top (each only when non-empty), then the always-present Known /
    // Verified / Blocked sections fill the rest.
    let mut constraints: Vec<Constraint> = Vec::new();
    if contact_req_count > 0 {
        constraints.push(Constraint::Min(4));
    }
    if pending_count > 0 {
        constraints.push(Constraint::Min(4));
    }
    constraints.push(Constraint::Percentage(40));
    constraints.push(Constraint::Percentage(30));
    constraints.push(Constraint::Percentage(30));
    let body = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(parts[1]);
    let mut i = 0;
    if contact_req_count > 0 {
        render_contact_requests(f, body[i], app, theme);
        i += 1;
    }
    if pending_count > 0 {
        render_pending(f, body[i], app, theme);
        i += 1;
    }
    render_known(f, body[i], app, theme);
    render_verified(f, body[i + 1], app, theme);
    render_blocked(f, body[i + 2], app, theme);
}

fn render_contact_requests(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme) {
    let focused = app.people_focus == PeopleFocus::ContactRequests;
    let border = if focused {
        theme.border_focus_style()
    } else {
        theme.border_style()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .padding(Padding::horizontal(1))
        .title(Span::styled(
            format!(
                " Contact requests ({}) ",
                app.pending_contact_requests.len()
            ),
            Style::default().fg(theme.warn),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines: Vec<Line> = Vec::new();
    if focused {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled("a", theme.warn_style()),
            Span::styled(" accept (opens DM)  ·  ", theme.dim()),
            Span::styled("r", theme.warn_style()),
            Span::styled(" decline  ·  ", theme.dim()),
            Span::styled("j/k", theme.warn_style()),
            Span::styled(" navigate", theme.dim()),
        ]));
    }
    for (i, req) in app.pending_contact_requests.iter().enumerate() {
        let name = req
            .display_name
            .clone()
            .or_else(|| app.handle.lookup_username(&req.fingerprint))
            .unwrap_or_else(|| "[anonymous]".into());
        let hd_id = format!("HD-{}", short_fp(&req.fingerprint).to_uppercase());
        let age = format_rel(req.received_at);
        let mut spans = vec![
            Span::styled(" [request] ", theme.warn_style()),
            Span::styled(name, theme.text_style()),
            Span::raw("  "),
            Span::styled(hd_id, theme.dim()),
        ];
        if let Some(note) = req.note.as_deref().filter(|n| !n.is_empty()) {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(format!("\"{}\"", note), theme.dim()));
        }
        spans.push(Span::raw("  "));
        spans.push(Span::styled(format!("({})", age), theme.dim()));
        if focused && i == app.selected_contact_request_idx {
            spans.insert(0, Span::styled("▸", theme.warn_style()));
        } else {
            spans.insert(0, Span::raw(" "));
        }
        lines.push(Line::from(spans));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn render_pending(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme) {
    let focused = app.people_focus == PeopleFocus::Pending;
    let border = if focused {
        theme.border_focus_style()
    } else {
        theme.border_style()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .padding(Padding::horizontal(1))
        .title(Span::styled(
            format!(" Pending requests ({}) ", app.pending_requests.len()),
            Style::default().fg(theme.warn),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.pending_requests.is_empty() {
        let p = Paragraph::new(Line::from(Span::styled(
            "  (no pending requests)",
            theme.dim(),
        )));
        f.render_widget(p, inner);
        return;
    }

    let mut lines: Vec<Line> = Vec::new();
    if focused {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled("a", theme.warn_style()),
            Span::styled(" accept (re-dial)  ·  ", theme.dim()),
            Span::styled("r", theme.warn_style()),
            Span::styled(" reject + block  ·  ", theme.dim()),
            Span::styled("j/k", theme.warn_style()),
            Span::styled(" navigate", theme.dim()),
        ]));
    }
    for (i, req) in app.pending_requests.iter().enumerate() {
        let username = app
            .handle
            .lookup_username(&req.fingerprint)
            .unwrap_or_else(|| "[anonymous]".into());
        let hd_id = format!("HD-{}", short_fp(&req.fingerprint).to_uppercase());
        let age = format_rel(req.received_at);
        let mut spans = vec![
            Span::styled(" [pending] ", theme.warn_style()),
            Span::styled(username, theme.text_style()),
            Span::raw("  "),
            Span::styled(hd_id, theme.dim()),
            Span::raw("  "),
            Span::styled(req.address.clone(), theme.dim()),
            Span::raw("  "),
            Span::styled(format!("({})", age), theme.dim()),
        ];
        if focused && i == app.selected_pending_idx {
            spans.insert(0, Span::styled("▸", theme.warn_style()));
        } else {
            spans.insert(0, Span::raw(" "));
        }
        lines.push(Line::from(spans));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn render_known(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme) {
    let focused = app.people_focus == PeopleFocus::Known;
    let border = if focused {
        theme.border_focus_style()
    } else {
        theme.border_style()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .padding(Padding::horizontal(1))
        .title(Span::styled(
            " Known peers ",
            Style::default().fg(theme.accent),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.known_peers.is_empty() {
        let p = Paragraph::new(Line::from(Span::styled(
            "  (no known peers — `a` to add a friend or `v` to paste an invite)",
            theme.dim(),
        )));
        f.render_widget(p, inner);
        return;
    }

    let mut lines: Vec<Line> = Vec::new();
    for (i, p) in app.known_peers.iter().enumerate() {
        let online = p.connected_peer_id.is_some();
        let dot = if online { "●" } else { "○" };
        // huddle 0.7.7: prefer the peer's self-declared username (cached
        // in `peer_profiles` via `lookup_username`) over the raw label.
        // If neither is available, fall back to the address so the row
        // still has *something* navigable.
        let username = p
            .fingerprint
            .as_deref()
            .and_then(|fp| app.handle.lookup_username(fp));
        let display_name = username
            .or_else(|| p.label.clone())
            .unwrap_or_else(|| p.address.clone());
        let hd_id = p
            .fingerprint
            .as_deref()
            .map(|fp| format!("HD-{}", short_fp(fp).to_uppercase()))
            .unwrap_or_else(|| "HD-pending".to_string());
        let last = p
            .last_connected_at
            .map(|t| format_rel(t))
            .unwrap_or_else(|| "—".to_string());
        let mut spans = vec![
            Span::styled(
                format!(" {} ", dot),
                if online { theme.ok() } else { theme.dim() },
            ),
            Span::styled(display_name, theme.text_style()),
            Span::raw("  "),
            Span::styled(hd_id, theme.dim()),
            Span::raw("  "),
            Span::styled(p.address.clone(), theme.dim()),
            Span::raw("  "),
            Span::styled(last, theme.dim()),
        ];
        if focused && i == app.selected_known_idx {
            spans.insert(0, Span::styled("▸", theme.warn_style()));
        } else {
            spans.insert(0, Span::raw(" "));
        }
        lines.push(Line::from(spans));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn render_verified(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme) {
    let focused = app.people_focus == PeopleFocus::Verified;
    let border = if focused {
        theme.border_focus_style()
    } else {
        theme.border_style()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .padding(Padding::horizontal(1))
        .title(Span::styled(
            " Verified ",
            Style::default().fg(theme.success),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let verified = app.handle.list_verified_peers();
    if verified.is_empty() {
        let p = Paragraph::new(Line::from(Span::styled(
            "  (no verified peers yet — Ctrl+V on a chat starts SAS)",
            theme.dim(),
        )));
        f.render_widget(p, inner);
        return;
    }
    let mut lines: Vec<Line> = Vec::new();
    for fp in verified.iter() {
        let label = app
            .handle
            .lookup_username(fp)
            .unwrap_or_else(|| "[anonymous]".into());
        lines.push(Line::from(vec![
            Span::styled(" ✓ ", theme.ok()),
            Span::styled(label, theme.text_style()),
            Span::raw("  "),
            Span::styled(short_fp(fp).to_uppercase(), theme.dim()),
        ]));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn render_blocked(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme) {
    let focused = app.people_focus == PeopleFocus::Blocked;
    let border = if focused {
        theme.border_focus_style()
    } else {
        theme.border_style()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .padding(Padding::horizontal(1))
        .title(Span::styled(" Blocked ", Style::default().fg(theme.error)));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let blocked = app.handle.list_blocked_peers();
    if blocked.is_empty() {
        let p = Paragraph::new(Line::from(Span::styled(
            "  (no blocked peers)",
            theme.dim(),
        )));
        f.render_widget(p, inner);
        return;
    }
    let mut lines: Vec<Line> = Vec::new();
    for (i, fp) in blocked.iter().enumerate() {
        let mut spans = vec![
            Span::styled(" [blocked] ", theme.err_style()),
            Span::styled(short_fp(fp).to_uppercase(), theme.text_style()),
        ];
        if focused && i == app.selected_blocked_idx {
            spans.insert(0, Span::styled("▸", theme.warn_style()));
        } else {
            spans.insert(0, Span::raw(" "));
        }
        lines.push(Line::from(spans));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn format_rel(unix_secs: i64) -> String {
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
