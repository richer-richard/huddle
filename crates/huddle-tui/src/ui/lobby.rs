use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Padding, Paragraph};

use crate::app::TuiApp;
use crate::ui::short_fp;

pub fn render_lobby(f: &mut Frame, area: Rect, app: &TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(area);

    render_header(f, chunks[0], app);
    render_rooms_list(f, chunks[1], app);
    render_hints(f, chunks[2], app);
}

fn render_header(f: &mut Frame, area: Rect, app: &TuiApp) {
    let listen = app
        .listen_addresses
        .iter()
        .find(|a| !a.contains("127.0.0.1"))
        .cloned()
        .or_else(|| app.listen_addresses.first().cloned())
        .unwrap_or_else(|| "starting...".into());

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  huddle",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
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

fn render_rooms_list(f: &mut Frame, area: Rect, app: &TuiApp) {
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
                "    on this network to appear.",
                Style::default().fg(Color::DarkGray),
            )),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .padding(Padding::horizontal(1))
                .title(Span::styled(
                    " rooms ",
                    Style::default().fg(Color::DarkGray),
                )),
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
            let line = Line::from(vec![
                Span::styled(
                    format!("  {:<28}", r.name),
                    if i == app.selected_room_idx {
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    },
                ),
                Span::styled(format!("{:<11}", lock), lock_style),
                Span::styled(
                    format!("{:<3} members  ", r.member_count),
                    Style::default().fg(Color::DarkGray),
                ),
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
                .border_style(Style::default().fg(Color::Cyan))
                .padding(Padding::horizontal(1))
                .title(Span::styled(
                    format!(" rooms ({}) ", app.discovered_rooms.len()),
                    Style::default().fg(Color::Cyan),
                )),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(40, 40, 60))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">");

    let mut state = ListState::default();
    state.select(Some(app.selected_room_idx));
    f.render_stateful_widget(list, area, &mut state);
}

fn render_hints(f: &mut Frame, area: Rect, _app: &TuiApp) {
    let hints = Line::from(vec![
        Span::styled("  [s]", Style::default().fg(Color::Yellow)),
        Span::styled(" start    ", Style::default().fg(Color::DarkGray)),
        Span::styled("[j/Enter]", Style::default().fg(Color::Yellow)),
        Span::styled(" join    ", Style::default().fg(Color::DarkGray)),
        Span::styled("[r]", Style::default().fg(Color::Yellow)),
        Span::styled(" refresh    ", Style::default().fg(Color::DarkGray)),
        Span::styled("[?]", Style::default().fg(Color::Yellow)),
        Span::styled(" help    ", Style::default().fg(Color::DarkGray)),
        Span::styled("[q]", Style::default().fg(Color::Yellow)),
        Span::styled(" quit", Style::default().fg(Color::DarkGray)),
    ]);
    let para = Paragraph::new(hints).block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(para, area);
}
