//! huddle 0.7: pane router.
//!
//! Each `Pane` variant has its own renderer module. The router dispatches
//! to the right one based on `app.pane`. Modal rendering is independent
//! and happens on top in `crate::ui::mod`.

pub mod activity;
pub mod chat_common;
pub mod dm;
pub mod group;
pub mod people;
pub mod profile;
pub mod settings;
pub mod welcome;

use ratatui::layout::Rect;
use ratatui::Frame;

use crate::app::{Pane, TuiApp};
use crate::ui::theme::Theme;

pub fn render(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme) {
    match &app.pane {
        Pane::Welcome => welcome::render(f, area, app, theme),
        Pane::Profile => profile::render(f, area, app, theme),
        Pane::Dm(room_id) => dm::render(f, area, app, theme, room_id),
        Pane::Group(room_id) => group::render(f, area, app, theme, room_id),
        Pane::People => people::render(f, area, app, theme),
        Pane::Activity => activity::render(f, area, app, theme),
        Pane::Settings => settings::render(f, area, app, theme),
    }
}
