use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Padding, Paragraph};

use huddle_core::network::NetworkMode;

use crate::app::{LobbyFocus, TuiApp};
use crate::keybindings;
use crate::ui::short_fp;

pub fn render_lobby(f: &mut Frame, area: Rect, app: &TuiApp) {
    // Known-peers panel is always visible — listing + dialing coexist
    // in both LAN (mDNS) and Direct modes.
    let peer_h: u16 = ((app.known_peers.len() as u16).clamp(1, 6)) + 2;
    let status_h: u16 = if app.current_status().is_some() || app.pending_count() > 0 {
        1
    } else {
        0
    };
    let banner_h: u16 = if app.update_banner.is_some() { 1 } else { 0 };

    let mut constraints = vec![Constraint::Length(7)];
    if banner_h > 0 {
        constraints.push(Constraint::Length(banner_h));
    }
    constraints.push(Constraint::Length(peer_h));
    constraints.push(Constraint::Min(5));
    if status_h > 0 {
        constraints.push(Constraint::Length(status_h));
    }
    constraints.push(Constraint::Length(3));

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    let mut idx = 0;
    render_header(f, chunks[idx], app);
    idx += 1;
    if banner_h > 0 {
        render_update_banner(f, chunks[idx], app);
        idx += 1;
    }
    render_known_peers(f, chunks[idx], app);
    idx += 1;
    render_rooms_list(f, chunks[idx], app);
    idx += 1;
    if status_h > 0 {
        render_status(f, chunks[idx], app);
        idx += 1;
    }
    render_hints(f, chunks[idx], app);
}

fn render_header(f: &mut Frame, area: Rect, app: &TuiApp) {
    let listen = app
        .listen_addresses
        .iter()
        .find(|a| !a.contains("127.0.0.1") && !a.contains("/ip6/"))
        .cloned()
        .or_else(|| app.listen_addresses.first().cloned())
        .unwrap_or_else(|| "starting...".into());

    let mode_label = match app.mode {
        NetworkMode::Mdns => Span::styled(
            "LAN (mDNS)",
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        ),
        NetworkMode::Direct => Span::styled(
            "Direct (no broadcast)",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
    };

    // huddle 0.6: cyan "huddle X.Y.Z" anchor at the top-left + clock
    // at the top-right. The clock + version disambiguate which build
    // is running when several huddle instances are tiled across panes.
    let area_inner_w = area.width.saturating_sub(2) as usize;
    let version_str = format!("huddle {}", env!("CARGO_PKG_VERSION"));
    let clock_str = current_hhmm();
    let title_inner = format!("  {}  ·  {}", version_str, "decentralized rooms");
    let title_w = title_inner.chars().count();
    let pad = area_inner_w
        .saturating_sub(title_w + clock_str.chars().count())
        .max(1);

    let connected: usize = app
        .known_peers
        .iter()
        .filter(|p| p.connected_peer_id.is_some())
        .count();
    let total = app.known_peers.len();
    let connection_count = if total == 0 {
        Span::styled("·  no peers yet", Style::default().fg(Color::DarkGray))
    } else if connected == total {
        Span::styled(
            format!("·  {} peer{} connected", connected, if connected == 1 { "" } else { "s" }),
            Style::default().fg(Color::Green),
        )
    } else {
        Span::styled(
            format!("·  {}/{} peers connected", connected, total),
            Style::default().fg(Color::Yellow),
        )
    };

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                format!("  {}  ", version_str),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::styled("·  ", Style::default().fg(Color::DarkGray)),
            mode_label,
            Span::raw(" ".repeat(pad)),
            Span::styled(
                clock_str,
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(Span::styled(
            "  decentralized rooms",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  you  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                match app.handle.display_name() {
                    Some(n) if !n.is_empty() => n,
                    _ => "[anonymous]".into(),
                },
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  ", Style::default()),
            Span::styled(
                super::display_id(app.handle.fingerprint()),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("       ", Style::default()),
            Span::styled(
                format!("listening on {}  ", listen),
                Style::default().fg(Color::DarkGray),
            ),
            nat_badge(app),
            Span::styled("  ", Style::default()),
            connection_count,
        ]),
    ];
    let para = Paragraph::new(lines);
    f.render_widget(para, area);
}

/// huddle 0.6: HH:MM in the local timezone (best-effort — we don't
/// pull in chrono just for this. UTC offset is approximated from
/// SystemTime; for users west of UTC the clock will be a few hours
/// behind their wall clock but the relative tick is still useful).
fn current_hhmm() -> String {
    // Pull wall-clock seconds since epoch and apply the local
    // timezone offset from `localtime_r` via libc — but to avoid an
    // FFI dep, we fall back on showing UTC if we can't get local.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // crude approximation of the system local offset: derive from
    // the difference between `SystemTime::now()` formatted in local
    // and UTC. Without chrono we can't easily do this, so just show
    // UTC. The user can read this as "UTC HH:MM" — better than no clock.
    let secs_today = (now % 86_400) as u32;
    let hh = (secs_today / 3600) % 24;
    let mm = (secs_today / 60) % 60;
    format!("{:02}:{:02} UTC  ", hh, mm)
}

/// Phase D follow-up: emoji-badge of the AutoNAT-aggregated reachability
/// state. None ⇒ '🔍 detecting…' (the probe stream hasn't told us
/// anything yet), Some("reachable") ⇒ '🌐 reachable', anything else
/// ⇒ '🏠 LAN only' (we couldn't confirm a public address).
fn nat_badge(app: &TuiApp) -> Span<'_> {
    match app.nat_status.as_deref() {
        Some("reachable") => Span::styled(
            "🌐 reachable",
            Style::default().fg(Color::Green),
        ),
        Some(_) => Span::styled(
            "🏠 LAN only",
            Style::default().fg(Color::DarkGray),
        ),
        None => Span::styled(
            "🔍 detecting…",
            Style::default().fg(Color::DarkGray),
        ),
    }
}

fn render_known_peers(f: &mut Frame, area: Rect, app: &TuiApp) {
    let focused = app.lobby_focus == LobbyFocus::KnownPeers;
    let border = if focused { Color::Cyan } else { Color::DarkGray };

    if app.known_peers.is_empty() {
        let para = Paragraph::new(vec![
            Line::from(Span::styled(
                "  no known peers yet — press [d] to dial one,",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::styled(
                "  [a] to add by HD ID, or [v] to paste an invite.",
                Style::default().fg(Color::DarkGray),
            )),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border))
                .padding(Padding::horizontal(1))
                .title(Span::styled(
                    " known peers ",
                    Style::default().fg(border),
                )),
        );
        f.render_widget(para, area);
        return;
    }

    let items: Vec<ListItem> = app
        .known_peers
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let connected = p.connected_peer_id.is_some();
            let dot = if connected { "●" } else { "○" };
            let dot_style = if connected {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            let addr_style = if focused && i == app.selected_peer_idx {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            let suffix = if connected {
                Span::styled(
                    "  connected",
                    Style::default().fg(Color::Green),
                )
            } else {
                Span::styled(
                    "  offline",
                    Style::default().fg(Color::DarkGray),
                )
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("  {} ", dot), dot_style),
                Span::styled(format!("{:<40}", p.address), addr_style),
                suffix,
            ]))
        })
        .collect();

    let title = format!(" known peers ({}) ", app.known_peers.len());
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border))
                .padding(Padding::horizontal(1))
                .title(Span::styled(title, Style::default().fg(border))),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(40, 40, 60))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">");

    let mut state = ListState::default();
    if focused {
        state.select(Some(app.selected_peer_idx));
    }
    f.render_stateful_widget(list, area, &mut state);
}

fn render_rooms_list(f: &mut Frame, area: Rect, app: &TuiApp) {
    let focused = app.lobby_focus == LobbyFocus::Rooms;
    let border = if focused { Color::Cyan } else { Color::DarkGray };

    if app.discovered_rooms.is_empty() {
        let para = Paragraph::new(vec![
            Line::from(""),
            Line::from(""),
            Line::from(Span::styled(
                "    no rooms discovered yet.",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "    press [s] to start one, or wait for others",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::styled(
                match app.mode {
                    NetworkMode::Mdns => "    on this network to appear.",
                    NetworkMode::Direct => "    you've dialed to appear.",
                },
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "    or paste an invite link with [v].",
                Style::default().fg(Color::DarkGray),
            )),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border))
                .padding(Padding::horizontal(1))
                .title(Span::styled(" rooms ", Style::default().fg(border))),
        );
        f.render_widget(para, area);
        return;
    }

    // Column widths for the meta block on the right. Name takes the
    // remaining space; if a name is too long it gets ellipsised so the
    // meta block always lines up.
    const LOCK_W: usize = 9; // "encrypted" / "public"
    const MIDDLE_W: usize = 29; // "saved · press Enter to rejoin"
    const FP_W: usize = 4;
    const GAP: usize = 2;
    const LEADING: usize = 2;
    // List reserves: 2 borders + 2 horizontal padding + 1 highlight
    // symbol = 5 cols of chrome around the content.
    let inner_w = (area.width as usize).saturating_sub(5);
    let meta_w = LOCK_W + GAP + MIDDLE_W + GAP + FP_W;
    let name_w = inner_w
        .saturating_sub(LEADING + GAP + meta_w)
        .max(8);

    let items: Vec<ListItem> = app
        .discovered_rooms
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let lock = if r.encrypted { "encrypted" } else { "public" };
            let lock_style = if r.encrypted {
                Style::default().fg(Color::Magenta)
            } else {
                Style::default().fg(Color::Green)
            };
            let highlighted = focused && i == app.selected_room_idx;
            let name_style = if highlighted {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            // Restorable rooms: "saved" tag instead of member count; the
            // user enters via the join modal (passphrase prompt).
            let (middle_text, middle_style) = if r.restorable {
                (
                    "saved · press Enter to rejoin".to_string(),
                    Style::default().fg(Color::Yellow),
                )
            } else {
                (
                    format!("{} members", r.member_count),
                    Style::default().fg(Color::DarkGray),
                )
            };
            let name_display = truncate_with_ellipsis(&r.name, name_w);
            let line = Line::from(vec![
                Span::raw(" ".repeat(LEADING)),
                Span::styled(pad_right(&name_display, name_w), name_style),
                Span::raw(" ".repeat(GAP)),
                Span::styled(pad_right(lock, LOCK_W), lock_style),
                Span::raw(" ".repeat(GAP)),
                Span::styled(pad_right(&middle_text, MIDDLE_W), middle_style),
                Span::raw(" ".repeat(GAP)),
                Span::styled(
                    short_fp(&r.creator_fingerprint),
                    Style::default().fg(Color::DarkGray),
                ),
            ]);
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border))
                .padding(Padding::horizontal(1))
                .title(Span::styled(
                    format!(" rooms ({}) ", app.discovered_rooms.len()),
                    Style::default().fg(border),
                )),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(40, 40, 60))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">");

    let mut state = ListState::default();
    if focused {
        state.select(Some(app.selected_room_idx));
    }
    f.render_stateful_widget(list, area, &mut state);
}

fn truncate_with_ellipsis(s: &str, max: usize) -> String {
    let count = s.chars().count();
    if count <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    if max == 1 {
        return "…".into();
    }
    let mut out: String = s.chars().take(max - 1).collect();
    out.push('…');
    out
}

fn pad_right(s: &str, w: usize) -> String {
    let count = s.chars().count();
    if count >= w {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + (w - count));
    out.push_str(s);
    for _ in 0..(w - count) {
        out.push(' ');
    }
    out
}

fn render_status(f: &mut Frame, area: Rect, app: &TuiApp) {
    let msg = app.current_status().unwrap_or("").to_string();
    let mut spans: Vec<Span> = Vec::new();
    spans.push(Span::styled(
        format!("  {}", msg),
        Style::default().fg(Color::Cyan),
    ));
    let pending = app.pending_count();
    if pending > 0 {
        spans.push(Span::styled(
            format!("   [{} pending · Ctrl+H to view]", pending),
            Style::default().fg(Color::Yellow).bold(),
        ));
    }
    let para = Paragraph::new(Line::from(spans));
    f.render_widget(para, area);
}

/// huddle 0.6: one-line banner under the lobby header announcing a
/// new release. Dismissible via the command palette
/// ("dismiss update banner"). The banner appears only when the user
/// opted in to crates.io update checks AND a newer version was
/// detected on the once-per-24h poll.
fn render_update_banner(f: &mut Frame, area: Rect, app: &TuiApp) {
    let v = match &app.update_banner {
        Some(v) => v.clone(),
        None => return,
    };
    let line = Line::from(vec![
        Span::styled("  update available: ", Style::default().fg(Color::Yellow).bold()),
        Span::styled(
            v,
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "  ·  run  ",
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            "cargo install huddle --force",
            Style::default().fg(Color::Cyan),
        ),
        Span::styled(
            "  ·  ':' → dismiss update banner",
            Style::default().fg(Color::DarkGray),
        ),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn render_hints(f: &mut Frame, area: Rect, app: &TuiApp) {
    // huddle 0.6: adaptive hint bar — pulls 5-6 most-likely actions
    // from `keybindings::adaptive_hints` based on current focus/state.
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

    let para = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(para, area);
}
