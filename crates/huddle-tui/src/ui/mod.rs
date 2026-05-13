pub mod chat_view;
pub mod layout;
pub mod peer_list;
pub mod status;

use ratatui::prelude::*;

use crate::app::TuiApp;

pub fn render_ui(f: &mut Frame, app: &TuiApp) {
    let [left, center, right] = layout::three_pane_layout(f.area());
    peer_list::render_peer_list(f, left, app);
    chat_view::render_chat_view(f, center, app);
    status::render_status(f, right, app);
}
