use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};

use crate::app::{Pane, TuiApp};

pub fn render_peer_list(f: &mut Frame, area: Rect, app: &TuiApp) {
    let is_focused = app.active_pane == Pane::PeerList;
    let border_style = if is_focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let items: Vec<ListItem> = app
        .peers
        .iter()
        .enumerate()
        .map(|(i, peer)| {
            let status = if peer.online { "+" } else { "-" };
            let lock = if peer.has_session { " E" } else { "" };
            let short_fp = if peer.fingerprint.len() > 9 {
                &peer.fingerprint[..9]
            } else {
                &peer.fingerprint
            };

            let style = if Some(peer.peer_id) == app.active_peer {
                Style::default().fg(Color::Yellow).bold()
            } else if i == app.selected_peer_idx && is_focused {
                Style::default().fg(Color::White).bold()
            } else if peer.online {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::DarkGray)
            };

            ListItem::new(format!("{status} {short_fp}{lock}")).style(style)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(border_style)
                .title(" Peers "),
        )
        .highlight_style(Style::default().bg(Color::DarkGray));

    let mut state = ListState::default();
    if is_focused {
        state.select(Some(app.selected_peer_idx));
    }

    f.render_stateful_widget(list, area, &mut state);
}
