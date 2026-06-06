pub mod file_card;
pub mod layout;
pub mod modal;
pub mod pane;
pub mod picker;
pub mod sidebar;
pub mod theme;

use ratatui::prelude::*;

use crate::app::{Modal, TuiApp};

pub fn render(f: &mut Frame, app: &TuiApp) {
    // huddle 0.7: outer layout = header + (sidebar | pane) + status.
    let rects = layout::outer_split(f.area());
    sidebar::render_top_header(f, rects.header, app, &app.theme);
    sidebar::render(f, rects.sidebar, app, &app.theme);
    pane::render(f, rects.pane, app, &app.theme);
    sidebar::render_status_footer(f, rects.status, app, &app.theme);

    match &app.modal {
        Modal::None => {}
        Modal::StartRoom(s) => modal::render_start_room(f, s),
        Modal::JoinRoom(j) => modal::render_join_room(f, j),
        Modal::DialPeer(d) => modal::render_dial_peer(f, d),
        Modal::AttachPicker(s) => modal::render_attach_picker(f, s),
        Modal::AttachPath(s) => modal::render_attach_path(f, s),
        Modal::RotateRoom(s) => modal::render_rotate_room(f, s),
        Modal::AcceptRotation(s) => modal::render_accept_rotation(f, s),
        Modal::Verify(s) => modal::render_verify(f, s),
        Modal::Search(s) => modal::render_search(f, s),
        Modal::QrIdentity => modal::render_qr_identity(f, app),
        Modal::InboundDial(s) => modal::render_inbound_dial(f, s),
        Modal::MemberAction(s) => modal::render_member_action(f, s),
        Modal::Sas(s) => modal::render_sas(f, s),
        Modal::EditUsername(s) => modal::render_edit_username(f, s),
        Modal::GoDark(s) => modal::render_go_dark(f, s),
        Modal::AddFriend(s) => modal::render_add_friend(f, s),
        Modal::ConnectCode(s) => modal::render_connect_code(f, s),
        Modal::ShowJoinCode(s) => modal::render_show_join_code(f, s),
        Modal::JoinWithCode(s) => modal::render_join_with_code(f, s),
        Modal::ShowInvite(s) => modal::render_show_invite(f, s),
        Modal::PasteInvite(s) => modal::render_paste_invite(f, s),
        Modal::ConfirmInvite(s) => modal::render_confirm_invite(f, s),
        Modal::Onboarding { pages, cursor } => modal::render_onboarding(f, pages, *cursor),
        Modal::StatusHistory { scroll } => modal::render_status_history(f, app, *scroll),
        Modal::CommandPalette(s) => modal::render_command_palette(f, s),
        Modal::UpdateCheckOptIn => modal::render_update_opt_in(f),
        Modal::QuitConfirm => modal::render_quit_confirm(f),
        Modal::ConfirmClearBlocked => {
            modal::render_clear_blocked_confirm(f, app.handle.list_blocked_peers().len())
        }
        Modal::Help => modal::render_help(f, app.help_scroll),
        Modal::Error(msg) => modal::render_error(f, msg),
        Modal::Info(msg) => modal::render_info(f, msg),
        Modal::ComposeDm(s) => modal::render_compose_dm(f, s, app),
        Modal::InvitePicker(s) => modal::render_invite_picker(f, s),
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

/// Render a full fingerprint as a branded huddle ID: `HD-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`.
/// Tolerant of inputs that are already `HD-`-prefixed (returned as-is), already
/// dash-separated lowercase (the canonical `identity::compute_fingerprint`
/// output — uppercased and prefixed), or a bare 24-char hex run (grouped into
/// 4-char blocks and prefixed). Anything else is returned uppercased with the
/// `HD-` prefix on a best-effort basis.
pub fn display_id(fp: &str) -> String {
    if fp.starts_with("HD-") {
        return fp.to_string();
    }
    let upper = fp.to_ascii_uppercase();
    if upper.contains('-') {
        return format!("HD-{}", upper);
    }
    if upper.len() == 24 && upper.chars().all(|c| c.is_ascii_hexdigit()) {
        let groups: Vec<String> = upper
            .as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap().to_string())
            .collect();
        return format!("HD-{}", groups.join("-"));
    }
    format!("HD-{}", upper)
}
