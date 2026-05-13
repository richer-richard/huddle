use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::{Pane, TuiApp};

pub fn render_status(f: &mut Frame, area: Rect, app: &TuiApp) {
    let is_focused = app.active_pane == Pane::Status;
    let border_style = if is_focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let fingerprint = app.handle.fingerprint();
    let peer_count = app.peers.iter().filter(|p| p.online).count();
    let total_msgs: usize = app.messages.values().map(|m| m.len()).sum();
    let session_count = app.peers.iter().filter(|p| p.has_session).count();

    let listen_addr = app
        .listen_addresses
        .first()
        .cloned()
        .unwrap_or_else(|| "...".into());

    let active_peer_status = if let Some(peer_id) = app.active_peer {
        if let Some(peer) = app.peers.iter().find(|p| p.peer_id == peer_id) {
            if peer.has_session {
                "E2EE Active"
            } else {
                "No Session"
            }
        } else {
            "Unknown"
        }
    } else {
        "No Peer Selected"
    };

    let text = vec![
        Line::from(Span::styled("Your ID", Style::default().bold())),
        Line::from(Span::styled(fingerprint, Style::default().fg(Color::Cyan))),
        Line::from(""),
        Line::from(Span::styled("Network", Style::default().bold())),
        Line::from(format!("Peers: {peer_count}")),
        Line::from(format!("Sessions: {session_count}")),
        Line::from("Transport: TCP"),
        Line::from(""),
        Line::from(Span::styled("Encryption", Style::default().bold())),
        Line::from(Span::styled(
            active_peer_status,
            if active_peer_status == "E2EE Active" {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Yellow)
            },
        )),
        Line::from(""),
        Line::from(Span::styled("Stats", Style::default().bold())),
        Line::from(format!("Messages: {total_msgs}")),
        Line::from(""),
        Line::from(Span::styled("Listen", Style::default().bold())),
        Line::from(Span::styled(
            if listen_addr.len() > 18 {
                &listen_addr[..18]
            } else {
                &listen_addr
            },
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let widget = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(" Status "),
    );

    f.render_widget(widget, area);
}
