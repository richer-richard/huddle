use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph, Wrap};

use crate::app::{DialPeerState, JoinRoomState, StartField, StartRoomState};
use crate::ui::centered_rect;

pub fn render_start_room(f: &mut Frame, s: &StartRoomState) {
    let area = centered_rect(50, 13, f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Span::styled(
            " start a new room ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .padding(Padding::uniform(1));

    let lines = vec![
        Line::from(""),
        field_line("name", &s.name, matches!(s.focus, StartField::Name), false),
        Line::from(""),
        encrypted_line(s),
        Line::from(""),
        passphrase_line(s),
        Line::from(""),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Tab", Style::default().fg(Color::Yellow)),
            Span::styled(" next  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Enter", Style::default().fg(Color::Yellow)),
            Span::styled(" start  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

fn field_line(label: &str, value: &str, focused: bool, mask: bool) -> Line<'static> {
    let display = if mask {
        "*".repeat(value.chars().count())
    } else {
        value.to_string()
    };
    let cursor = if focused { "_" } else { "" };
    let value_str = format!("[ {}{} ]", display, cursor);
    let value_style = if focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::White)
    };
    Line::from(vec![
        Span::styled(format!(" {:<11}", label), Style::default().fg(Color::DarkGray)),
        Span::styled(value_str, value_style),
    ])
}

fn encrypted_line(s: &StartRoomState) -> Line<'static> {
    let check = if s.encrypted { "[x]" } else { "[ ]" };
    let label = if s.encrypted { "yes" } else { "no" };
    let focused = matches!(s.focus, StartField::Encrypted);
    let style = if focused {
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };
    Line::from(vec![
        Span::styled(" encrypted   ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{} {}", check, label), style),
        Span::styled(
            if focused { "   (Enter/Space toggle)" } else { "" },
            Style::default().fg(Color::DarkGray),
        ),
    ])
}

fn passphrase_line(s: &StartRoomState) -> Line<'static> {
    if !s.encrypted {
        return Line::from(Span::styled(
            " passphrase  (encryption disabled)",
            Style::default().fg(Color::DarkGray),
        ));
    }
    field_line(
        "passphrase",
        &s.passphrase,
        matches!(s.focus, StartField::Passphrase),
        true,
    )
}

pub fn render_join_room(f: &mut Frame, j: &JoinRoomState) {
    let area = centered_rect(54, 9, f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta))
        .title(Span::styled(
            format!(" join #{} (encrypted) ", j.room_name),
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ))
        .padding(Padding::uniform(1));

    let masked = "*".repeat(j.passphrase.chars().count());
    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(" passphrase  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("[ {}_ ]", masked),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(""),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Enter", Style::default().fg(Color::Yellow)),
            Span::styled(" join  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

pub fn render_quit_confirm(f: &mut Frame) {
    let area = centered_rect(40, 6, f.area());
    f.render_widget(Clear, area);
    let para = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            " quit huddle?",
            Style::default().fg(Color::White),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" [y]", Style::default().fg(Color::Yellow)),
            Span::styled(" yes  ", Style::default().fg(Color::DarkGray)),
            Span::styled("[Esc/n]", Style::default().fg(Color::Yellow)),
            Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
        ]),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red))
            .padding(Padding::uniform(1)),
    );
    f.render_widget(para, area);
}

pub fn render_help(f: &mut Frame) {
    let area = centered_rect(64, 22, f.area());
    f.render_widget(Clear, area);
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(" Lobby", Style::default().fg(Color::Cyan).bold())),
        Line::from(""),
        kv("  s", "start a new room"),
        kv("  d", "dial a peer by IP:port (Direct mode)"),
        kv("  Tab", "switch focus: known peers <-> rooms"),
        kv("  Enter", "join selected room / reconnect peer"),
        kv("  j/k or arrows", "navigate the focused list"),
        kv("  r", "refresh rooms / retry connect"),
        kv("  x", "forget the highlighted peer"),
        kv("  ?", "this help"),
        kv("  q / Ctrl-C", "quit"),
        Line::from(""),
        Line::from(Span::styled(" In a room", Style::default().fg(Color::Cyan).bold())),
        Line::from(""),
        kv("  /", "type a message"),
        kv("  Esc", "blur input / back to lobby"),
        kv("  ^Tab / ^N", "next tab"),
        kv("  ^P", "previous tab"),
        kv("  1..9", "jump to tab N"),
        kv("  ^L", "leave the current room"),
        kv("  ^B", "back to lobby (without leaving)"),
    ];
    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .padding(Padding::uniform(1))
                .title(Span::styled(
                    " help  (press any key to close) ",
                    Style::default().fg(Color::Cyan).bold(),
                )),
        );
    f.render_widget(para, area);
}

fn kv(k: &'static str, v: &'static str) -> Line<'static> {
    Line::from(vec![
        Span::styled(k, Style::default().fg(Color::Yellow)),
        Span::styled(format!("   {}", v), Style::default().fg(Color::White)),
    ])
}

pub fn render_dial_peer(f: &mut Frame, s: &DialPeerState) {
    let area = centered_rect(64, 11, f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .padding(Padding::uniform(1))
        .title(Span::styled(
            " dial a peer ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));

    let status = s
        .status
        .clone()
        .unwrap_or_else(|| "ip:port  ·  [ipv6]:port  ·  /ip4/.../tcp/...".into());

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(" address  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("[ {}_ ]", s.address),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            format!(" {}", status),
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Enter", Style::default().fg(Color::Yellow)),
            Span::styled(" dial  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(block);
    f.render_widget(para, area);
}

pub fn render_info(f: &mut Frame, msg: &str) {
    let area = centered_rect(56, 8, f.area());
    f.render_widget(Clear, area);
    let para = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(msg, Style::default().fg(Color::White))),
        Line::from(""),
        Line::from(""),
        Line::from(Span::styled(
            "  press any key to dismiss",
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .wrap(Wrap { trim: false })
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .padding(Padding::uniform(1)),
    );
    f.render_widget(para, area);
}

pub fn render_error(f: &mut Frame, msg: &str) {
    let area = centered_rect(56, 8, f.area());
    f.render_widget(Clear, area);
    let para = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(msg, Style::default().fg(Color::White))),
        Line::from(""),
        Line::from(""),
        Line::from(Span::styled(
            "  press any key to dismiss",
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .wrap(Wrap { trim: false })
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red))
            .padding(Padding::uniform(1))
            .title(Span::styled(
                " error ",
                Style::default().fg(Color::Red).bold(),
            )),
    );
    f.render_widget(para, area);
}
