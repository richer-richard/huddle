use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Padding, Paragraph};

use crate::ui::centered_rect;

/// Render the startup info/welcome card. Purely informational — any key
/// dismisses it.
pub fn render_welcome(f: &mut Frame) {
    let bg = Block::default().style(Style::default().bg(Color::Reset));
    f.render_widget(bg, f.area());

    let area = centered_rect(110, 22, f.area());
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .padding(Padding::uniform(1))
        .title(Span::styled(
            " huddle — welcome ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));

    let g = |s: &'static str| Span::styled(s, Style::default().fg(Color::DarkGray));
    let w = |s: &'static str| Span::styled(s, Style::default().fg(Color::White));
    let y = |s: &'static str| {
        Span::styled(
            s,
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )
    };

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  terminal-native, end-to-end encrypted chat over Tor.",
            Style::default().fg(Color::White),
        )),
        Line::from(g(
            "  routes through a Tor onion relay — ciphertext only, no account.",
        )),
        Line::from(""),
        Line::from(vec![w("  what you can do")]),
        bullet("start a room", "public or end-to-end encrypted (Megolm)"),
        bullet(
            "invite a friend",
            "[Shift+I] — they paste it and join over the relay",
        ),
        bullet(
            "watch the relay",
            "the relay dot by your name turns solid once connected",
        ),
        bullet(
            "history",
            "messages persist locally per room across restarts",
        ),
        bullet(
            "go LAN (opt-in)",
            "--mode mdns | direct also runs libp2p alongside",
        ),
        Line::from(""),
        Line::from(vec![
            g("  "),
            Span::styled(
                "heads up: ",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
            g("learning project, not audited. don't use for real secrets."),
        ]),
        Line::from(""),
        Line::from(vec![
            y("  press any key"),
            g(" to continue   ·   "),
            y("?"),
            g(" for help   ·   needs Tor running (SOCKS 127.0.0.1:9050)"),
        ]),
    ];

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

fn bullet(head: &'static str, tail: &'static str) -> Line<'static> {
    Line::from(vec![
        Span::styled("    • ", Style::default().fg(Color::Yellow)),
        Span::styled(
            format!("{:<22}", head),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(tail, Style::default().fg(Color::DarkGray)),
    ])
}
