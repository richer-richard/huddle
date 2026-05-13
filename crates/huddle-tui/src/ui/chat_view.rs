use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::app::TuiApp;

pub fn render_chat_view(f: &mut Frame, area: Rect, app: &TuiApp) {
    let is_focused = app.active_pane == crate::app::Pane::Chat;
    let border_style = if is_focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(area);

    let title = if let Some(peer_id) = app.active_peer {
        if let Some(peer) = app.peers.iter().find(|p| p.peer_id == peer_id) {
            format!(" Chat: {} ", &peer.fingerprint)
        } else {
            " Chat ".to_string()
        }
    } else {
        " Chat - select a peer ".to_string()
    };

    let messages: Vec<Line> = if let Some(peer_id) = app.active_peer {
        app.messages
            .get(&peer_id)
            .map(|msgs| {
                msgs.iter()
                    .map(|m| {
                        let (prefix, style) = if m.direction == "out" {
                            ("You: ", Style::default().fg(Color::Cyan))
                        } else {
                            ("Them: ", Style::default().fg(Color::Green))
                        };
                        Line::from(vec![
                            Span::styled(prefix, style.bold()),
                            Span::styled(&m.body, style),
                        ])
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        vec![Line::from(Span::styled(
            "Select a peer from the list to start chatting",
            Style::default().fg(Color::DarkGray),
        ))]
    };

    let msg_widget = Paragraph::new(messages)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(border_style)
                .title(title),
        )
        .wrap(Wrap { trim: false })
        .scroll((app.scroll_offset as u16, 0));

    f.render_widget(msg_widget, chunks[0]);

    let input_style = if app.input_active {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let input_text = if app.input_active {
        format!(" {}_", &app.input_buffer)
    } else {
        " Press / to type...".to_string()
    };

    let input_widget = Paragraph::new(input_text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(input_style)
            .title(" Input "),
    );

    f.render_widget(input_widget, chunks[1]);
}
