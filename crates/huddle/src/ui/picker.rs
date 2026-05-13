use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Padding, Paragraph, Wrap};

use crate::ui::centered_rect;

pub fn render_mode_picker(f: &mut Frame, selected: usize) {
    let bg = Block::default().style(Style::default().bg(Color::Reset));
    f.render_widget(bg, f.area());

    let area = centered_rect(72, 22, f.area());
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .padding(Padding::uniform(1))
        .title(Span::styled(
            " huddle — pick a connection mode ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  how do you want to find other people?",
            Style::default().fg(Color::White),
        )),
        Line::from(""),
    ];
    lines.extend(option_block(
        0,
        selected,
        "LAN  ·  mDNS",
        "you broadcast your presence on this Wi-Fi. you see rooms",
        "hosted by anyone on the same network, and you can be dialed.",
    ));
    lines.push(Line::from(""));
    lines.extend(option_block(
        1,
        selected,
        "Direct  ·  manual dial only",
        "you are invisible to mDNS. the only people you connect to",
        "are those you explicitly dial (or who dial you). works across",
    ));
    lines.push(Line::from(Span::styled(
        "      networks, NAT permitting.",
        Style::default().fg(Color::DarkGray),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  ↑/↓ or 1/2", Style::default().fg(Color::Yellow)),
        Span::styled(" pick   ", Style::default().fg(Color::DarkGray)),
        Span::styled("Enter", Style::default().fg(Color::Yellow)),
        Span::styled(" confirm   ", Style::default().fg(Color::DarkGray)),
        Span::styled("Esc/q", Style::default().fg(Color::Yellow)),
        Span::styled(" quit", Style::default().fg(Color::DarkGray)),
    ]));

    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(block);
    f.render_widget(para, area);
}

fn option_block(
    index: usize,
    selected: usize,
    title: &str,
    body1: &str,
    body2: &str,
) -> Vec<Line<'static>> {
    let active = index == selected;
    let marker = if active { ">" } else { " " };
    let title_style = if active {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };
    let body_style = Style::default().fg(if active {
        Color::Gray
    } else {
        Color::DarkGray
    });
    vec![
        Line::from(vec![
            Span::styled(
                format!("  {} ", marker),
                Style::default().fg(Color::Yellow),
            ),
            Span::styled(title.to_string(), title_style),
        ]),
        Line::from(Span::styled(format!("      {}", body1), body_style)),
        Line::from(Span::styled(format!("      {}", body2), body_style)),
    ]
}
