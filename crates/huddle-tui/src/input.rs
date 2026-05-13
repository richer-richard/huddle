use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{Pane, TuiApp};

#[derive(Debug)]
pub enum TuiAction {
    Quit,
    CyclePaneForward,
    NavigateUp,
    NavigateDown,
    Select,
    FocusInput,
    BlurInput,
    SendMessage,
    CharInput(char),
    Backspace,
    None,
}

pub fn handle_key(key: KeyEvent, app: &TuiApp) -> TuiAction {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return TuiAction::Quit;
    }

    if app.input_active {
        return match key.code {
            KeyCode::Enter => TuiAction::SendMessage,
            KeyCode::Esc => TuiAction::BlurInput,
            KeyCode::Backspace => TuiAction::Backspace,
            KeyCode::Char(c) => TuiAction::CharInput(c),
            _ => TuiAction::None,
        };
    }

    match key.code {
        KeyCode::Char('q') => TuiAction::Quit,
        KeyCode::Tab => TuiAction::CyclePaneForward,
        KeyCode::Char('j') | KeyCode::Down => TuiAction::NavigateDown,
        KeyCode::Char('k') | KeyCode::Up => TuiAction::NavigateUp,
        KeyCode::Enter => TuiAction::Select,
        KeyCode::Char('/') => TuiAction::FocusInput,
        KeyCode::Esc => TuiAction::BlurInput,
        _ => TuiAction::None,
    }
}
