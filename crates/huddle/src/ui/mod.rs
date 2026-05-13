pub mod file_card;
pub mod lobby;
pub mod modal;
pub mod picker;
pub mod room;

use ratatui::prelude::*;

use crate::app::{Modal, Screen, TuiApp};

pub fn render(f: &mut Frame, app: &TuiApp) {
    match app.screen {
        Screen::Lobby => lobby::render_lobby(f, f.area(), app),
        Screen::InRoom => room::render_room_screen(f, f.area(), app),
    }

    match &app.modal {
        Modal::None => {}
        Modal::StartRoom(s) => modal::render_start_room(f, s),
        Modal::JoinRoom(j) => modal::render_join_room(f, j),
        Modal::DialPeer(d) => modal::render_dial_peer(f, d),
        Modal::AttachPicker(s) => modal::render_attach_picker(f, s),
        Modal::RotateRoom(s) => modal::render_rotate_room(f, s),
        Modal::AcceptRotation(s) => modal::render_accept_rotation(f, s),
        Modal::Verify(s) => modal::render_verify(f, s),
        Modal::Search(s) => modal::render_search(f, s),
        Modal::QuitConfirm => modal::render_quit_confirm(f),
        Modal::Help => modal::render_help(f),
        Modal::Error(msg) => modal::render_error(f, msg),
        Modal::Info(msg) => modal::render_info(f, msg),
    }
}

/// Compute a centered rect with given absolute width/height.
pub fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length((area.height.saturating_sub(height)) / 2),
            Constraint::Length(height),
            Constraint::Min(0),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length((area.width.saturating_sub(width)) / 2),
            Constraint::Length(width),
            Constraint::Min(0),
        ])
        .split(popup_layout[1])[1]
}

/// Truncate a fingerprint to its first group (4 hex chars).
pub fn short_fp(fp: &str) -> String {
    fp.split('-').next().unwrap_or(fp).to_string()
}
