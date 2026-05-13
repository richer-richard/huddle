use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{LobbyFocus, Modal, Screen, TuiApp};

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
    LobbyFocusToggle,
    LobbyReconnectPeer,
    LobbyForgetPeer,
    OpenDialPeer,
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
    // Dial peer modal
    DialPeerTypeChar(char),
    DialPeerBackspace,
    DialPeerConfirm,
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
    PageUp,
    PageDown,
    JumpTop,
    JumpBottom,
    ChatTypeChar(char),
    ChatBackspace,
    ChatSend,
    ChatInsertNewline,
    // File cards
    ToggleCardFocus,
    CardNext,
    CardPrev,
    ActivateFocusedCard,
    OpenFocusedCard,
    CancelFocusedCard,
    SaveAgainFocusedCard,
    OpenAttachmentPicker,
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
        Modal::DialPeer(_) => match key.code {
            KeyCode::Esc => Action::CloseModal,
            KeyCode::Enter => Action::DialPeerConfirm,
            KeyCode::Backspace => Action::DialPeerBackspace,
            KeyCode::Char(c) => Action::DialPeerTypeChar(c),
            _ => Action::Nothing,
        },
        Modal::Info(_) => match key.code {
            _ => Action::CloseModal,
        },
        Modal::None => map_normal(key, app),
    }
}

fn map_normal(key: KeyEvent, app: &TuiApp) -> Action {
    match app.screen {
        Screen::Lobby => map_lobby(key, app),
        Screen::InRoom => map_in_room(key, app),
    }
}

fn map_lobby(key: KeyEvent, app: &TuiApp) -> Action {
    match key.code {
        KeyCode::Char('q') => Action::OpenQuitConfirm,
        KeyCode::Char('s') => Action::OpenStartRoom,
        KeyCode::Char('?') => Action::OpenHelp,
        KeyCode::Char('d') => Action::OpenDialPeer,
        KeyCode::Tab => Action::LobbyFocusToggle,
        KeyCode::Char('j') | KeyCode::Down => Action::LobbyNavigateDown,
        KeyCode::Char('k') | KeyCode::Up => Action::LobbyNavigateUp,
        KeyCode::Char('r') => match app.lobby_focus {
            LobbyFocus::KnownPeers => Action::LobbyReconnectPeer,
            LobbyFocus::Rooms => Action::LobbyRefresh,
        },
        KeyCode::Char('x') => match app.lobby_focus {
            LobbyFocus::KnownPeers => Action::LobbyForgetPeer,
            LobbyFocus::Rooms => Action::Nothing,
        },
        KeyCode::Enter => match app.lobby_focus {
            LobbyFocus::KnownPeers => Action::LobbyReconnectPeer,
            LobbyFocus::Rooms => Action::LobbyJoinSelected,
        },
        _ => Action::Nothing,
    }
}

fn map_in_room(key: KeyEvent, app: &TuiApp) -> Action {
    let input_active = app.active_room().map(|r| r.input_active).unwrap_or(false);

    let card_focus = app.active_room().map(|r| r.card_focus).unwrap_or(false);

    // Ctrl chords first (apply regardless of input focus).
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return match key.code {
            // ^J inserts a newline in the input (the canonical
            // multiline trick; works on every terminal).
            KeyCode::Char('j') if input_active => Action::ChatInsertNewline,
            KeyCode::Char('l') => Action::LeaveRoom,
            KeyCode::Char('b') => Action::BackToLobby,
            KeyCode::Char('n') => Action::TabNext,
            KeyCode::Char('p') => Action::TabPrev,
            KeyCode::Char('a') if !input_active => Action::OpenAttachmentPicker,
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
        // Alt+Enter (Option+Enter on macOS) and Shift+Enter both insert
        // a newline. Plain Enter sends.
        if matches!(key.code, KeyCode::Enter)
            && (key.modifiers.contains(KeyModifiers::ALT)
                || key.modifiers.contains(KeyModifiers::SHIFT))
        {
            return Action::ChatInsertNewline;
        }
        match key.code {
            KeyCode::Enter => Action::ChatSend,
            // Some terminals deliver Option+Enter as a literal LF char.
            KeyCode::Char('\n') => Action::ChatInsertNewline,
            KeyCode::Esc => Action::BlurInput,
            KeyCode::Backspace => Action::ChatBackspace,
            KeyCode::PageUp => Action::PageUp,
            KeyCode::PageDown => Action::PageDown,
            KeyCode::Char(c) => Action::ChatTypeChar(c),
            _ => Action::Nothing,
        }
    } else if card_focus {
        // Card-focus keystrokes when input is blurred and the user has
        // entered card navigation mode (via `f`). Esc / `f` exit.
        match key.code {
            KeyCode::Esc | KeyCode::Char('f') => Action::ToggleCardFocus,
            KeyCode::Char('j') | KeyCode::Down => Action::CardNext,
            KeyCode::Char('k') | KeyCode::Up => Action::CardPrev,
            KeyCode::Enter => Action::ActivateFocusedCard,
            KeyCode::Char('o') => Action::OpenFocusedCard,
            KeyCode::Char('c') => Action::CancelFocusedCard,
            KeyCode::Char('s') => Action::SaveAgainFocusedCard,
            KeyCode::Char('r') => Action::ActivateFocusedCard,
            _ => Action::Nothing,
        }
    } else {
        match key.code {
            KeyCode::Char('q') => Action::OpenQuitConfirm,
            KeyCode::Char('/') => Action::FocusInput,
            KeyCode::Char('?') => Action::OpenHelp,
            KeyCode::Char('f') => Action::ToggleCardFocus,
            KeyCode::Char('j') | KeyCode::Down => Action::ScrollDown,
            KeyCode::Char('k') | KeyCode::Up => Action::ScrollUp,
            KeyCode::PageDown => Action::PageDown,
            KeyCode::PageUp => Action::PageUp,
            KeyCode::Home | KeyCode::Char('g') => Action::JumpTop,
            KeyCode::End | KeyCode::Char('G') => Action::JumpBottom,
            KeyCode::Esc => Action::BackToLobby,
            _ => Action::Nothing,
        }
    }
}
