use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Padding, Paragraph, Tabs, Wrap};

use crate::app::TuiApp;
use crate::ui::short_fp;

pub fn render_room_screen(f: &mut Frame, area: Rect, app: &TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // tabs
            Constraint::Length(3), // header
            Constraint::Min(3),    // messages
            Constraint::Length(3), // input
            Constraint::Length(2), // hints
        ])
        .split(area);

    render_tabs(f, chunks[0], app);
    render_header(f, chunks[1], app);
    render_messages(f, chunks[2], app);
    render_input(f, chunks[3], app);
    render_hints(f, chunks[4]);
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

fn render_messages(f: &mut Frame, area: Rect, app: &TuiApp) {
    let r = match app.active_room() {
        Some(r) => r,
        None => return,
    };
    let me = app.handle.fingerprint().to_string();

    let mut lines: Vec<Line> = Vec::new();
    for m in &r.messages {
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
        lines.push(Line::from(vec![
            Span::styled(format!("  {}  ", time), Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{:<6}", label), label_style),
            Span::styled("  ", Style::default()),
            Span::styled(&m.body, Style::default().fg(Color::White)),
        ]));
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "  no messages yet — say hi!",
            Style::default().fg(Color::DarkGray),
        )));
    }

    let widget = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .padding(Padding::horizontal(1)),
        )
        .wrap(Wrap { trim: false })
        .scroll((r.scroll, 0));
    f.render_widget(widget, area);
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
    let text = if r.input_active {
        format!("> {}_", r.input)
    } else {
        "  press / to type".to_string()
    };
    let widget = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .padding(Padding::horizontal(1)),
    );
    f.render_widget(widget, area);
}

fn render_hints(f: &mut Frame, area: Rect) {
    let hints = Line::from(vec![
        Span::styled("  ^Tab", Style::default().fg(Color::Yellow)),
        Span::styled(" next tab   ", Style::default().fg(Color::DarkGray)),
        Span::styled("/", Style::default().fg(Color::Yellow)),
        Span::styled(" type   ", Style::default().fg(Color::DarkGray)),
        Span::styled("Esc", Style::default().fg(Color::Yellow)),
        Span::styled(" back   ", Style::default().fg(Color::DarkGray)),
        Span::styled("^L", Style::default().fg(Color::Yellow)),
        Span::styled(" leave   ", Style::default().fg(Color::DarkGray)),
        Span::styled("^B", Style::default().fg(Color::Yellow)),
        Span::styled(" lobby   ", Style::default().fg(Color::DarkGray)),
        Span::styled("?", Style::default().fg(Color::Yellow)),
        Span::styled(" help", Style::default().fg(Color::DarkGray)),
    ]);
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
