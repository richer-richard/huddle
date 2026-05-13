use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{Modal, Screen, TuiApp};

#[derive(Debug)]
pub enum Action {
    Nothing,
    Quit,
    OpenQuitConfirm,
    CloseModal,
    OpenStartRoom,
    OpenHelp,
    // Lobby
    LobbyNavigateUp,
    LobbyNavigateDown,
    LobbyJoinSelected,
    LobbyRefresh,
    // Start room modal
    StartRoomNextField,
    StartRoomToggleEncrypted,
    StartRoomTypeChar(char),
    StartRoomBackspace,
    StartRoomConfirm,
    // Join room modal
    JoinRoomTypeChar(char),
    JoinRoomBackspace,
    JoinRoomConfirm,
    // In-room
    TabNext,
    TabPrev,
    TabSelect(usize),
    BackToLobby,
    LeaveRoom,
    FocusInput,
    BlurInput,
    ScrollUp,
    ScrollDown,
    ChatTypeChar(char),
    ChatBackspace,
    ChatSend,
}

pub fn map_key(key: KeyEvent, app: &TuiApp) -> Action {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return Action::OpenQuitConfirm;
    }

    match &app.modal {
        Modal::QuitConfirm => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => Action::Quit,
            _ => Action::CloseModal,
        },
        Modal::Error(_) => match key.code {
            _ => Action::CloseModal,
        },
        Modal::Help => match key.code {
            _ => Action::CloseModal,
        },
        Modal::StartRoom(_) => match key.code {
            KeyCode::Esc => Action::CloseModal,
            KeyCode::Tab => Action::StartRoomNextField,
            KeyCode::Enter => {
                // On Encrypted field: Enter toggles; otherwise confirms.
                if let Modal::StartRoom(s) = &app.modal {
                    if matches!(s.focus, crate::app::StartField::Encrypted) {
                        return Action::StartRoomToggleEncrypted;
                    }
                }
                Action::StartRoomConfirm
            }
            KeyCode::Char(' ') => {
                if let Modal::StartRoom(s) = &app.modal {
                    if matches!(s.focus, crate::app::StartField::Encrypted) {
                        return Action::StartRoomToggleEncrypted;
                    }
                }
                Action::StartRoomTypeChar(' ')
            }
            KeyCode::Backspace => Action::StartRoomBackspace,
            KeyCode::Char(c) => Action::StartRoomTypeChar(c),
            _ => Action::Nothing,
        },
        Modal::JoinRoom(_) => match key.code {
            KeyCode::Esc => Action::CloseModal,
            KeyCode::Enter => Action::JoinRoomConfirm,
            KeyCode::Backspace => Action::JoinRoomBackspace,
            KeyCode::Char(c) => Action::JoinRoomTypeChar(c),
            _ => Action::Nothing,
        },
        Modal::None => map_normal(key, app),
    }
}

fn map_normal(key: KeyEvent, app: &TuiApp) -> Action {
    match app.screen {
        Screen::Lobby => map_lobby(key),
        Screen::InRoom => map_in_room(key, app),
    }
}

fn map_lobby(key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Char('q') => Action::OpenQuitConfirm,
        KeyCode::Char('s') => Action::OpenStartRoom,
        KeyCode::Char('?') => Action::OpenHelp,
        KeyCode::Char('r') => Action::LobbyRefresh,
        KeyCode::Char('j') | KeyCode::Down => Action::LobbyNavigateDown,
        KeyCode::Char('k') | KeyCode::Up => Action::LobbyNavigateUp,
        KeyCode::Enter => Action::LobbyJoinSelected,
        _ => Action::Nothing,
    }
}

fn map_in_room(key: KeyEvent, app: &TuiApp) -> Action {
    let input_active = app.active_room().map(|r| r.input_active).unwrap_or(false);

    // Ctrl chords first (apply regardless of input focus).
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return match key.code {
            KeyCode::Char('l') => Action::LeaveRoom,
            KeyCode::Char('b') => Action::BackToLobby,
            KeyCode::Char('n') => Action::TabNext,
            KeyCode::Char('p') => Action::TabPrev,
            _ => Action::Nothing,
        };
    }

    if key.code == KeyCode::Tab {
        return Action::TabNext;
    }

    // Numeric tab jump (only if input is not active).
    if !input_active {
        if let KeyCode::Char(c @ '1'..='9') = key.code {
            let n = (c as u8 - b'1') as usize;
            return Action::TabSelect(n);
        }
    }

    if input_active {
        match key.code {
            KeyCode::Enter => Action::ChatSend,
            KeyCode::Esc => Action::BlurInput,
            KeyCode::Backspace => Action::ChatBackspace,
            KeyCode::Char(c) => Action::ChatTypeChar(c),
            _ => Action::Nothing,
        }
    } else {
        match key.code {
            KeyCode::Char('q') => Action::OpenQuitConfirm,
            KeyCode::Char('/') => Action::FocusInput,
            KeyCode::Char('?') => Action::OpenHelp,
            KeyCode::Char('j') | KeyCode::Down => Action::ScrollDown,
            KeyCode::Char('k') | KeyCode::Up => Action::ScrollUp,
            KeyCode::Esc => Action::BackToLobby,
            _ => Action::Nothing,
        }
    }
}
