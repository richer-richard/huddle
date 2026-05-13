use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Padding, Paragraph};

use huddle_core::network::NetworkMode;

use crate::app::{LobbyFocus, TuiApp};
use crate::ui::short_fp;

pub fn render_lobby(f: &mut Frame, area: Rect, app: &TuiApp) {
    // Known-peers panel is always visible — listing + dialing coexist
    // in both LAN (mDNS) and Direct modes.
    let peer_h: u16 = ((app.known_peers.len() as u16).clamp(1, 6)) + 2;
    let status_h: u16 = if app.current_status().is_some() { 1 } else { 0 };

    let mut constraints = vec![Constraint::Length(7), Constraint::Length(peer_h)];
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

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  huddle  ",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::styled("·  ", Style::default().fg(Color::DarkGray)),
            mode_label,
        ]),
        Line::from(Span::styled(
            "  decentralized rooms",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  you  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                app.handle.fingerprint(),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("       ", Style::default()),
            Span::styled(
                format!("listening on {}", listen),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    ];
    let para = Paragraph::new(lines);
    f.render_widget(para, area);
}

fn render_known_peers(f: &mut Frame, area: Rect, app: &TuiApp) {
    let focused = app.lobby_focus == LobbyFocus::KnownPeers;
    let border = if focused { Color::Cyan } else { Color::DarkGray };

    if app.known_peers.is_empty() {
        let para = Paragraph::new(Line::from(Span::styled(
            "  no known peers yet — press [d] to dial one.",
            Style::default().fg(Color::DarkGray),
        )))
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

    let items: Vec<ListItem> = app
        .discovered_rooms
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let lock = if r.encrypted { "encrypted" } else { "public   " };
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
            // Restorable rooms: "[saved]" tag instead of member count; the
            // user enters via the join modal (passphrase prompt).
            let last_col = if r.restorable {
                Span::styled(
                    "saved · press Enter to rejoin",
                    Style::default().fg(Color::Yellow),
                )
            } else {
                Span::styled(
                    format!("{:<3} members  ", r.member_count),
                    Style::default().fg(Color::DarkGray),
                )
            };
            let line = Line::from(vec![
                Span::styled(format!("  {:<28}", r.name), name_style),
                Span::styled(format!("{:<11}", lock), lock_style),
                last_col,
                Span::styled("  ", Style::default()),
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

fn render_status(f: &mut Frame, area: Rect, app: &TuiApp) {
    let msg = app.current_status().unwrap_or("").to_string();
    let para = Paragraph::new(Line::from(Span::styled(
        format!("  {}", msg),
        Style::default().fg(Color::Cyan),
    )));
    f.render_widget(para, area);
}

fn render_hints(f: &mut Frame, area: Rect, app: &TuiApp) {
    let mut spans = vec![
        Span::styled("  [s]", Style::default().fg(Color::Yellow)),
        Span::styled(" start    ", Style::default().fg(Color::DarkGray)),
        Span::styled("[d]", Style::default().fg(Color::Yellow)),
        Span::styled(" dial    ", Style::default().fg(Color::DarkGray)),
        Span::styled("[Tab]", Style::default().fg(Color::Yellow)),
        Span::styled(" switch    ", Style::default().fg(Color::DarkGray)),
        Span::styled("[Enter]", Style::default().fg(Color::Yellow)),
    ];
    spans.push(Span::styled(
        match app.lobby_focus {
            LobbyFocus::Rooms => " join    ",
            LobbyFocus::KnownPeers => " reconnect    ",
        },
        Style::default().fg(Color::DarkGray),
    ));
    spans.extend([
        Span::styled("[r]", Style::default().fg(Color::Yellow)),
        Span::styled(
            match app.lobby_focus {
                LobbyFocus::Rooms => " refresh    ",
                LobbyFocus::KnownPeers => " retry    ",
            },
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled("[?]", Style::default().fg(Color::Yellow)),
        Span::styled(" help    ", Style::default().fg(Color::DarkGray)),
        Span::styled("[q]", Style::default().fg(Color::Yellow)),
        Span::styled(" quit", Style::default().fg(Color::DarkGray)),
    ]);

    let para = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(para, area);
}
