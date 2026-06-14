//! The TUI action dispatcher — `handle_action`, the central `match` over every
//! `input::Action` variant. Split out of the `app/mod.rs` TUI god file (huddle
//! 2.1.x maintainability refactor). It is a free function (takes `&mut TuiApp`)
//! and reaches the `TuiApp` methods + free helpers via `use super::*`; it stays
//! one big match for now (a later step groups arms into per-domain sub-handlers).

use super::*;

pub(crate) async fn handle_action(action: Action, app: &mut TuiApp) -> Result<bool> {
    match action {
        Action::Nothing => Ok(false),
        Action::Quit => Ok(true),
        Action::OpenQuitConfirm => {
            app.modal = Modal::QuitConfirm;
            Ok(false)
        }
        Action::OpenClearBlockedConfirm => {
            app.modal = Modal::ConfirmClearBlocked;
            Ok(false)
        }
        Action::CloseModal => {
            app.modal = Modal::None;
            Ok(false)
        }
        Action::OpenStartRoom => {
            app.modal = Modal::StartRoom(StartRoomState::new());
            Ok(false)
        }
        Action::OpenHelp => {
            app.help_scroll = 0;
            app.modal = Modal::Help;
            Ok(false)
        }
        Action::LobbyNavigateUp => {
            sidebar_move(app, -1);
            Ok(false)
        }
        Action::LobbyNavigateDown => {
            sidebar_move(app, 1);
            Ok(false)
        }
        Action::LobbyRefresh => {
            app.refresh_discovered();
            app.refresh_known_peers();
            Ok(false)
        }
        Action::LobbyFocusToggle => {
            // huddle 0.7: Tab now jumps to the next sidebar section
            // (rather than toggling between two flat lists). Acts as
            // pane-focus toggle when on the sidebar and a chat pane.
            sidebar_jump_section(app, 1);
            Ok(false)
        }
        Action::FocusSidebar => {
            // huddle 0.7.2: Ctrl+Left. Blur chat input if active so
            // typing keystrokes route to sidebar nav, not into the
            // last-active chat.
            if let Some(r) = app.active_room_mut() {
                r.input_active = false;
            }
            app.sidebar.focus = SidebarFocus::Sidebar;
            Ok(false)
        }
        Action::FocusPane => {
            // huddle 0.7.2: Ctrl+Right. On chat panes, also focus the
            // input so typing goes straight into the composer.
            app.sidebar.focus = SidebarFocus::Pane;
            if matches!(app.pane, Pane::Dm(_) | Pane::Group(_)) {
                if let Some(r) = app.active_room_mut() {
                    r.input_active = true;
                }
            }
            Ok(false)
        }
        Action::LobbyReconnectPeer => {
            if let Some(p) = app.known_peers.get(app.selected_known_idx).cloned() {
                if let Err(e) = app.handle.redial(&p.address).await {
                    app.modal = Modal::Error(format!("dial failed: {e}"));
                }
            }
            Ok(false)
        }
        Action::LobbyForgetPeer => {
            if let Some(p) = app.known_peers.get(app.selected_known_idx).cloned() {
                if let Err(e) = app.handle.forget_peer(&p.address).await {
                    app.modal = Modal::Error(format!("forget failed: {e}"));
                }
                app.refresh_known_peers();
                if app.selected_known_idx >= app.known_peers.len() && !app.known_peers.is_empty() {
                    app.selected_known_idx = app.known_peers.len() - 1;
                }
            }
            Ok(false)
        }
        Action::OpenDialPeer => {
            app.modal = Modal::DialPeer(DialPeerState::default());
            Ok(false)
        }
        Action::DialPeerTypeChar(c) => {
            if let Modal::DialPeer(s) = &mut app.modal {
                s.address.push(c);
            }
            Ok(false)
        }
        Action::DialPeerBackspace => {
            if let Modal::DialPeer(s) = &mut app.modal {
                s.address.pop();
            }
            Ok(false)
        }
        Action::DialPeerConfirm => {
            let address = match &app.modal {
                Modal::DialPeer(s) => s.address.clone(),
                _ => return Ok(false),
            };
            if address.trim().is_empty() {
                if let Modal::DialPeer(s) = &mut app.modal {
                    s.status = Some("address is empty".into());
                }
                return Ok(false);
            }
            match app.handle.dial(&address).await {
                Ok(()) => {
                    if let Modal::DialPeer(s) = &mut app.modal {
                        s.status = Some(format!("dialing {}…", address));
                    }
                }
                Err(e) => {
                    app.modal = Modal::Error(format!("invalid address: {e}"));
                }
            }
            Ok(false)
        }
        Action::LobbyJoinSelected => {
            // huddle 0.7: Enter on the sidebar commits the selection.
            // For Dm/Group items, switch the pane. For GroupDiscover
            // children, walk the discovered list and join the first
            // unjoined group.
            match app.sidebar.selection.clone() {
                SidebarItem::Dm(room_id) | SidebarItem::Group(room_id) => {
                    if app.handle.active_room_info(&room_id).is_some() {
                        open_existing_room_tab(app, &room_id);
                        return Ok(false);
                    }
                    let room = app
                        .handle
                        .discovered_rooms()
                        .into_iter()
                        .find(|d| d.room_id == room_id);
                    if let Some(room) = room {
                        if room.encrypted {
                            app.modal = Modal::JoinRoom(JoinRoomState {
                                room_id: room.room_id.clone(),
                                room_name: room.name.clone(),
                                encrypted: true,
                                passphrase: String::new(),
                            });
                        } else if let Err(e) = app.handle.join_room(&room.room_id, None).await {
                            app.modal = Modal::Error(format!("join failed: {e}"));
                        }
                    }
                }
                SidebarItem::Section(s) => {
                    // Enter on a section header toggles its expand state.
                    if app.sidebar.expanded.contains(&s) {
                        app.sidebar.expanded.remove(&s);
                    } else {
                        app.sidebar.expanded.insert(s);
                    }
                }
                SidebarItem::Profile => app.pane = Pane::Profile,
                SidebarItem::Person(_) => app.pane = Pane::People,
                SidebarItem::Activity => app.pane = Pane::Activity,
                SidebarItem::Settings => app.pane = Pane::Settings,
                SidebarItem::DirectAddFriend => {
                    // huddle 0.7.8: pinned "+ Add Friend" row → fire the
                    // same flow as the global `m` shortcut.
                    return Box::pin(handle_action(Action::OpenComposeDm, app)).await;
                }
                SidebarItem::GroupNew => {
                    return Box::pin(handle_action(Action::OpenStartRoom, app)).await;
                }
                SidebarItem::PeoplePendingBadge => {
                    return Box::pin(handle_action(Action::JumpToPeoplePane, app)).await;
                }
                SidebarItem::GroupDiscover => {
                    // Find first unjoined group room and open its join modal.
                    if let Some(room) = app.handle.discovered_rooms().into_iter().find(|r| {
                        r.kind != huddle_core::storage::repo::RoomKind::Direct
                            && !app
                                .handle
                                .active_room_ids()
                                .iter()
                                .any(|aid| aid == &r.room_id)
                    }) {
                        if room.encrypted {
                            app.modal = Modal::JoinRoom(JoinRoomState {
                                room_id: room.room_id.clone(),
                                room_name: room.name.clone(),
                                encrypted: true,
                                passphrase: String::new(),
                            });
                        } else if let Err(e) = app.handle.join_room(&room.room_id, None).await {
                            app.modal = Modal::Error(format!("join failed: {e}"));
                        }
                    }
                }
            }
            Ok(false)
        }
        Action::StartRoomNextField => {
            if let Modal::StartRoom(s) = &mut app.modal {
                s.focus = match s.focus {
                    StartField::Name => StartField::Encrypted,
                    StartField::Encrypted => {
                        if s.encrypted {
                            StartField::Passphrase
                        } else {
                            StartField::Name
                        }
                    }
                    StartField::Passphrase => StartField::Name,
                };
            }
            Ok(false)
        }
        Action::StartRoomToggleEncrypted => {
            if let Modal::StartRoom(s) = &mut app.modal {
                s.encrypted = !s.encrypted;
                if !s.encrypted {
                    s.passphrase.clear();
                    // The passphrase field is hidden when encryption is
                    // off — don't strand focus on an invisible field.
                    if s.focus == StartField::Passphrase {
                        s.focus = StartField::Encrypted;
                    }
                }
            }
            Ok(false)
        }
        Action::StartRoomTypeChar(c) => {
            if let Modal::StartRoom(s) = &mut app.modal {
                match s.focus {
                    StartField::Name => s.name.push(c),
                    StartField::Passphrase => s.passphrase.push(c),
                    StartField::Encrypted => {}
                }
            }
            Ok(false)
        }
        Action::StartRoomBackspace => {
            if let Modal::StartRoom(s) = &mut app.modal {
                match s.focus {
                    StartField::Name => {
                        s.name.pop();
                    }
                    StartField::Passphrase => {
                        s.passphrase.pop();
                    }
                    StartField::Encrypted => {}
                }
            }
            Ok(false)
        }
        Action::StartRoomConfirm => {
            let (name, encrypted, passphrase) = match &app.modal {
                Modal::StartRoom(s) => (s.name.clone(), s.encrypted, s.passphrase.clone()),
                _ => return Ok(false),
            };
            if name.trim().is_empty() {
                app.modal = Modal::Error("room name cannot be empty".into());
                return Ok(false);
            }
            if encrypted && passphrase.is_empty() {
                app.modal = Modal::Error("encrypted room requires a passphrase".into());
                return Ok(false);
            }
            app.modal = Modal::None;
            let pp = if encrypted {
                Some(passphrase.as_str())
            } else {
                None
            };
            if let Err(e) = app
                .handle
                .start_room(
                    &name,
                    encrypted,
                    pp,
                    huddle_core::storage::repo::RoomKind::Group,
                )
                .await
            {
                app.modal = Modal::Error(format!("start failed: {e}"));
            }
            Ok(false)
        }
        Action::JoinRoomTypeChar(c) => {
            if let Modal::JoinRoom(j) = &mut app.modal {
                j.passphrase.push(c);
            }
            Ok(false)
        }
        Action::JoinRoomBackspace => {
            if let Modal::JoinRoom(j) = &mut app.modal {
                j.passphrase.pop();
            }
            Ok(false)
        }
        Action::JoinRoomConfirm => {
            let (room_id, passphrase) = match &app.modal {
                Modal::JoinRoom(j) => (j.room_id.clone(), j.passphrase.clone()),
                _ => return Ok(false),
            };
            app.modal = Modal::None;
            if let Err(e) = app.handle.join_room(&room_id, Some(&passphrase)).await {
                app.modal = Modal::Error(format!("join failed: {e}"));
            }
            Ok(false)
        }
        Action::TabNext => {
            // huddle 0.7: Tab-next now walks DM + Group rooms in
            // sidebar order. Retired the tab-bar concept; sidebar is
            // the navigation source of truth.
            switch_chat_relative(app, 1);
            Ok(false)
        }
        Action::TabPrev => {
            switch_chat_relative(app, -1);
            Ok(false)
        }
        Action::TabSelect(n) => {
            // huddle 0.7: Alt+1..9 jumps to the Nth chat (DM + Group
            // combined, sidebar order).
            switch_chat_absolute(app, n);
            Ok(false)
        }
        Action::BackToLobby => {
            // huddle 0.7: "back to lobby" is now "focus the sidebar".
            // The Welcome pane is the home screen.
            app.sidebar.focus = SidebarFocus::Sidebar;
            if matches!(app.pane, Pane::Dm(_) | Pane::Group(_)) {
                // Don't actually change pane — let the user choose. The
                // explicit way to leave a chat is `Ctrl+L` (LeaveRoom).
            } else {
                app.pane = Pane::Welcome;
            }
            Ok(false)
        }
        Action::LeaveRoom => {
            if let Some(room) = app.active_room() {
                let id = room.room_id.clone();
                match app.handle.leave_room(&id).await {
                    Ok(true) => {}
                    Ok(false) => app.set_status(
                        "left locally — peers may still see you until they time you out",
                    ),
                    Err(e) => app.modal = Modal::Error(format!("leave failed: {e}")),
                }
            }
            Ok(false)
        }
        Action::FocusInput => {
            if let Some(r) = app.active_room_mut() {
                r.input_active = true;
            }
            Ok(false)
        }
        Action::BlurInput => {
            if let Some(r) = app.active_room_mut() {
                r.input_active = false;
                // huddle 2.0.0 (F10): blurring cancels an in-progress edit
                // (discard the draft body) or reply. Predictable: the
                // compose-mode banners only show while the input is focused.
                if r.editing_msg.take().is_some() {
                    r.input.clear();
                }
                r.reply_to = None;
            }
            Ok(false)
        }
        Action::ScrollUp => {
            scroll_by(app, -1);
            Ok(false)
        }
        Action::ScrollDown => {
            scroll_by(app, 1);
            Ok(false)
        }
        Action::PageUp => {
            scroll_by(app, -10);
            Ok(false)
        }
        Action::PageDown => {
            scroll_by(app, 10);
            Ok(false)
        }
        Action::JumpTop => {
            if let Some(r) = app.active_room_mut() {
                r.scroll = 0;
                r.follow_mode = false;
            }
            Ok(false)
        }
        Action::JumpBottom => {
            if let Some(r) = app.active_room_mut() {
                r.follow_mode = true;
            }
            Ok(false)
        }
        Action::ChatTypeChar(c) => {
            let (room_id, should_pulse) = {
                let r = match app.active_room_mut() {
                    Some(r) if r.input_active => r,
                    _ => return Ok(false),
                };
                r.input.push(c);
                let pulse = match r.last_typing_sent {
                    Some(t) if t.elapsed() < TYPING_DEBOUNCE => false,
                    _ => true,
                };
                if pulse {
                    r.last_typing_sent = Some(Instant::now());
                }
                (r.room_id.clone(), pulse)
            };
            if should_pulse {
                app.handle.broadcast_typing(&room_id).await;
            }
            Ok(false)
        }
        Action::ChatBackspace => {
            if let Some(r) = app.active_room_mut() {
                if r.input_active {
                    r.input.pop();
                }
            }
            Ok(false)
        }
        Action::ChatSend => {
            // huddle 2.0.0 (F10): capture the compose mode (new / edit / reply)
            // along with the body. `editing_msg` / `reply_to` are cleared
            // optimistically; restored below if the send fails.
            let (room_id, body, editing, reply_to) = {
                match app.active_room_mut() {
                    Some(r) if r.input_active && !r.input.trim().is_empty() => {
                        let body = r.input.clone();
                        r.input.clear();
                        let editing = r.editing_msg.take();
                        let reply_to = r.reply_to.take();
                        (r.room_id.clone(), body, editing, reply_to)
                    }
                    _ => return Ok(false),
                }
            };
            // huddle 1.2: gate on real deliverability. If no transport can
            // carry this message, restore the user's text and tell them why
            // rather than optimistically echoing a message that reaches no one.
            let readiness = app.handle.room_send_readiness(&room_id);
            if !readiness.can_send() {
                if let Some(r) = app.active_room_mut() {
                    if r.input.is_empty() {
                        r.input = body; // give the text back, unsent
                        r.editing_msg = editing;
                        r.reply_to = reply_to;
                    }
                }
                app.set_status(format!("not sent — {}", readiness.reason()));
                return Ok(false);
            }
            // huddle 2.0.0 (F10): an active edit re-sends the targeted message's
            // body; an active reply threads under the target; otherwise a plain
            // send. Last-write-wins on edits, so a failed edit just restores the
            // draft and the previous body stands.
            let result = if let Some(ref target) = editing {
                app.handle.edit_message(&room_id, target, &body).await
            } else if let Some(ref target) = reply_to {
                app.handle.send_reply(&room_id, &body, target).await
            } else {
                app.handle.send_room_message(&room_id, &body).await
            };
            if let Err(e) = result {
                // Read the verb before the restore below can move `editing`.
                let verb = if editing.is_some() { "edit" } else { "send" };
                // huddle 1.3.1: a send failure after readiness passed (read-only
                // room, crypto/DB error, …) must not silently eat the composed
                // text — restore it, mirroring the readiness branch above.
                if let Some(r) = app.active_room_mut() {
                    if r.input.is_empty() {
                        r.input = body; // give the text back, unsent
                        r.editing_msg = editing;
                        r.reply_to = reply_to;
                    }
                }
                app.modal = Modal::Error(format!("{verb} failed: {e}"));
            }
            Ok(false)
        }
        Action::ChatInsertNewline => {
            if let Some(r) = app.active_room_mut() {
                if r.input_active {
                    r.input.push('\n');
                }
            }
            Ok(false)
        }
        Action::ToggleCardFocus => {
            if let Some(r) = app.active_room_mut() {
                if r.attachments.is_empty() {
                    return Ok(false);
                }
                r.card_focus = !r.card_focus;
                if r.card_focus {
                    r.input_active = false;
                    if r.focused_card_idx >= r.attachments.len() {
                        r.focused_card_idx = 0;
                    }
                }
            }
            Ok(false)
        }
        Action::CardNext => {
            if let Some(r) = app.active_room_mut() {
                if !r.attachments.is_empty() {
                    r.focused_card_idx = (r.focused_card_idx + 1) % r.attachments.len();
                }
            }
            Ok(false)
        }
        Action::CardPrev => {
            if let Some(r) = app.active_room_mut() {
                if !r.attachments.is_empty() {
                    r.focused_card_idx = if r.focused_card_idx == 0 {
                        r.attachments.len() - 1
                    } else {
                        r.focused_card_idx - 1
                    };
                }
            }
            Ok(false)
        }
        Action::ActivateFocusedCard => {
            let (room_id, file_id, status, encrypted) = match focused_card_info(app) {
                Some(t) => t,
                None => return Ok(false),
            };
            use huddle_core::storage::repo::AttachmentStatus;
            match status {
                AttachmentStatus::Offered | AttachmentStatus::Downloading => {
                    // Auto-pulled by gossipsub; just status nudge.
                    app.set_status("waiting for chunks…");
                }
                AttachmentStatus::Ready | AttachmentStatus::Saved => {
                    match app.handle.save_to_downloads(&room_id, &file_id).await {
                        Ok(path) => app.set_status(format!("saved to {}", path.display())),
                        Err(e) => app.modal = Modal::Error(format!("save failed: {e}")),
                    }
                }
                AttachmentStatus::Failed => {
                    app.set_status("retry not yet implemented — ask the sender to resend");
                }
                AttachmentStatus::Cancelled => {
                    app.set_status("transfer was cancelled");
                }
            }
            let _ = encrypted;
            Ok(false)
        }
        Action::OpenFocusedCard => {
            let (room_id, file_id, _, _) = match focused_card_info(app) {
                Some(t) => t,
                None => return Ok(false),
            };
            if let Err(e) = app.handle.open_saved(&room_id, &file_id) {
                app.modal = Modal::Error(format!("open failed: {e}"));
            }
            Ok(false)
        }
        Action::CancelFocusedCard => {
            let (room_id, file_id, _, _) = match focused_card_info(app) {
                Some(t) => t,
                None => return Ok(false),
            };
            if let Err(e) = app.handle.cancel_transfer(&room_id, &file_id).await {
                app.modal = Modal::Error(format!("cancel failed: {e}"));
            }
            Ok(false)
        }
        Action::SaveAgainFocusedCard => {
            let (room_id, file_id, _, _) = match focused_card_info(app) {
                Some(t) => t,
                None => return Ok(false),
            };
            match app.handle.save_to_downloads(&room_id, &file_id).await {
                Ok(path) => app.set_status(format!("saved to {}", path.display())),
                Err(e) => app.modal = Modal::Error(format!("save failed: {e}")),
            }
            Ok(false)
        }
        Action::OpenAttachmentPicker => {
            if app.active_room().is_none() {
                app.set_status("attach is only available inside a room");
                return Ok(false);
            }
            app.modal = Modal::AttachPicker(AttachPickerState::new());
            Ok(false)
        }
        Action::AttachPickerUp => {
            if let Modal::AttachPicker(s) = &mut app.modal {
                s.move_up();
            }
            Ok(false)
        }
        Action::AttachPickerDown => {
            if let Modal::AttachPicker(s) = &mut app.modal {
                s.move_down();
            }
            Ok(false)
        }
        Action::AttachPickerToggle => {
            if let Modal::AttachPicker(s) = &mut app.modal {
                s.toggle_expand();
            }
            Ok(false)
        }
        Action::AttachPickerExpand => {
            if let Modal::AttachPicker(s) = &mut app.modal {
                s.expand();
            }
            Ok(false)
        }
        Action::AttachPickerCollapse => {
            if let Modal::AttachPicker(s) = &mut app.modal {
                s.collapse_or_parent();
            }
            Ok(false)
        }
        Action::AttachPickerToggleHidden => {
            if let Modal::AttachPicker(s) = &mut app.modal {
                s.toggle_hidden();
            }
            Ok(false)
        }
        Action::OpenRotateRoom => {
            let room_id = match app.active_room() {
                Some(r) if r.encrypted => r.room_id.clone(),
                Some(_) => {
                    app.set_status("rotation only applies to encrypted rooms");
                    return Ok(false);
                }
                None => return Ok(false),
            };
            app.modal = Modal::RotateRoom(RotateRoomState {
                room_id,
                passphrase: String::new(),
            });
            Ok(false)
        }
        Action::RotateRoomTypeChar(c) => {
            if let Modal::RotateRoom(s) = &mut app.modal {
                s.passphrase.push(c);
            }
            Ok(false)
        }
        Action::RotateRoomBackspace => {
            if let Modal::RotateRoom(s) = &mut app.modal {
                s.passphrase.pop();
            }
            Ok(false)
        }
        Action::RotateRoomConfirm => {
            let (room_id, pp) = match &app.modal {
                Modal::RotateRoom(s) => (s.room_id.clone(), s.passphrase.clone()),
                _ => return Ok(false),
            };
            if pp.is_empty() {
                app.modal = Modal::Error("new passphrase cannot be empty".into());
                return Ok(false);
            }
            app.modal = Modal::None;
            match app.handle.rotate_room(&room_id, &pp).await {
                Ok(()) => {
                    app.set_status("rotation broadcast — share the new passphrase out-of-band")
                }
                Err(e) => app.modal = Modal::Error(format!("rotate failed: {e}")),
            }
            Ok(false)
        }
        Action::AcceptRotationTypeChar(c) => {
            if let Modal::AcceptRotation(s) = &mut app.modal {
                s.passphrase.push(c);
            }
            Ok(false)
        }
        Action::AcceptRotationBackspace => {
            if let Modal::AcceptRotation(s) = &mut app.modal {
                s.passphrase.pop();
            }
            Ok(false)
        }
        Action::AcceptRotationConfirm => {
            let (room_id, new_salt, pp) = match &app.modal {
                Modal::AcceptRotation(s) => {
                    (s.room_id.clone(), s.new_salt.clone(), s.passphrase.clone())
                }
                _ => return Ok(false),
            };
            if pp.is_empty() {
                return Ok(false);
            }
            app.modal = Modal::None;
            match app.handle.accept_rotation(&room_id, &new_salt, &pp).await {
                Ok(()) => app.set_status("accepted rotation — new key in use"),
                Err(e) => app.modal = Modal::Error(format!("accept rotation failed: {e}")),
            }
            Ok(false)
        }
        Action::OpenQrIdentity => {
            app.modal = Modal::QrIdentity;
            Ok(false)
        }
        Action::ToggleMute => {
            let room_id = match app.active_room() {
                Some(r) => r.room_id.clone(),
                None => return Ok(false),
            };
            let now_muted = app.handle.is_room_muted(&room_id);
            if let Err(e) = app.handle.set_room_muted(&room_id, !now_muted) {
                app.modal = Modal::Error(format!("mute toggle failed: {e}"));
            } else {
                app.set_status(if !now_muted { "muted" } else { "unmuted" });
            }
            Ok(false)
        }
        Action::OpenSearch => {
            let room_id = match app.active_room() {
                Some(r) => r.room_id.clone(),
                None => return Ok(false),
            };
            app.modal = Modal::Search(SearchState {
                room_id,
                query: String::new(),
                results: Vec::new(),
                selected: 0,
                searched: false,
            });
            Ok(false)
        }
        Action::SearchTypeChar(c) => {
            if let Modal::Search(s) = &mut app.modal {
                s.query.push(c);
            }
            Ok(false)
        }
        Action::SearchBackspace => {
            if let Modal::Search(s) = &mut app.modal {
                s.query.pop();
            }
            Ok(false)
        }
        Action::SearchSubmit => {
            let (room_id, query) = match &app.modal {
                Modal::Search(s) => (s.room_id.clone(), s.query.clone()),
                _ => return Ok(false),
            };
            if query.trim().is_empty() {
                return Ok(false);
            }
            let results = app
                .handle
                .search_room_messages(&room_id, &query, 100)
                .unwrap_or_default();
            if let Modal::Search(s) = &mut app.modal {
                s.results = results;
                s.selected = 0;
                s.searched = true;
            }
            Ok(false)
        }
        Action::SearchNext => {
            if let Modal::Search(s) = &mut app.modal {
                if s.selected + 1 < s.results.len() {
                    s.selected += 1;
                }
            }
            Ok(false)
        }
        Action::SearchPrev => {
            if let Modal::Search(s) = &mut app.modal {
                if s.selected > 0 {
                    s.selected -= 1;
                }
            }
            Ok(false)
        }
        Action::OpenVerify => {
            let room_id = match app.active_room() {
                Some(r) => r.room_id.clone(),
                None => return Ok(false),
            };
            let our_fp = app.handle.fingerprint().to_string();
            let verified_set: std::collections::HashSet<String> = app
                .handle
                .verified_fingerprints(&room_id)
                .into_iter()
                .collect();
            let members: Vec<(String, bool)> = app
                .active_room()
                .map(|r| {
                    r.members
                        .iter()
                        .filter(|fp| **fp != our_fp)
                        .map(|fp| (fp.clone(), verified_set.contains(fp)))
                        .collect()
                })
                .unwrap_or_default();
            if members.is_empty() {
                app.set_status("no other members to verify yet");
                return Ok(false);
            }
            app.modal = Modal::Verify(VerifyState {
                room_id,
                our_fingerprint: our_fp,
                members,
                selected: 0,
            });
            Ok(false)
        }
        Action::VerifyNext => {
            if let Modal::Verify(s) = &mut app.modal {
                if s.selected + 1 < s.members.len() {
                    s.selected += 1;
                }
            }
            Ok(false)
        }
        Action::VerifyPrev => {
            if let Modal::Verify(s) = &mut app.modal {
                if s.selected > 0 {
                    s.selected -= 1;
                }
            }
            Ok(false)
        }
        Action::VerifyToggle => {
            let (room_id, fp, new_state) = match &mut app.modal {
                Modal::Verify(s) => {
                    let m = match s.members.get_mut(s.selected) {
                        Some(x) => x,
                        None => return Ok(false),
                    };
                    m.1 = !m.1;
                    (s.room_id.clone(), m.0.clone(), m.1)
                }
                _ => return Ok(false),
            };
            if let Err(e) = app.handle.set_member_verified(&room_id, &fp, new_state) {
                app.modal = Modal::Error(format!("verify failed: {e}"));
            }
            Ok(false)
        }
        Action::OnboardingNext => {
            if let Modal::Onboarding { pages, cursor } = &mut app.modal {
                if *cursor + 1 < pages.len() {
                    *cursor += 1;
                } else {
                    let _ = app.handle.mark_onboarding_seen();
                    let _ = app
                        .handle
                        .set_last_seen_onboarding_version(env!("CARGO_PKG_VERSION"));
                    app.modal = Modal::None;
                }
            }
            Ok(false)
        }
        Action::OnboardingPrev => {
            if let Modal::Onboarding { cursor, .. } = &mut app.modal {
                if *cursor > 0 {
                    *cursor -= 1;
                }
            }
            Ok(false)
        }
        Action::OnboardingDismiss => {
            // Esc still records last_seen so the same pages don't re-pop
            // on next launch. Users replay via Settings → "Show what's
            // new" or the command palette.
            let _ = app.handle.mark_onboarding_seen();
            let _ = app
                .handle
                .set_last_seen_onboarding_version(env!("CARGO_PKG_VERSION"));
            app.modal = Modal::None;
            Ok(false)
        }
        // huddle 0.6: re-open onboarding regardless of last_seen. Shows
        // every page — gives users a way to revisit the welcome cards.
        Action::OpenWhatsNew => {
            let pages: Vec<usize> = (0..ONBOARDING_PAGES.len()).collect();
            app.modal = Modal::Onboarding { pages, cursor: 0 };
            Ok(false)
        }
        Action::OpenStatusHistory => {
            app.modal = Modal::StatusHistory { scroll: 0 };
            Ok(false)
        }
        Action::StatusHistoryScrollUp => {
            if let Modal::StatusHistory { scroll } = &mut app.modal {
                *scroll = scroll.saturating_sub(1);
            }
            Ok(false)
        }
        Action::StatusHistoryScrollDown => {
            if let Modal::StatusHistory { scroll } = &mut app.modal {
                *scroll = scroll.saturating_add(1);
            }
            Ok(false)
        }
        Action::StatusHistoryPageUp => {
            if let Modal::StatusHistory { scroll } = &mut app.modal {
                *scroll = scroll.saturating_sub(10);
            }
            Ok(false)
        }
        Action::StatusHistoryPageDown => {
            if let Modal::StatusHistory { scroll } = &mut app.modal {
                *scroll = scroll.saturating_add(10);
            }
            Ok(false)
        }
        Action::ClearStatusHistory => {
            app.status_history.clear();
            app.set_status("notification history cleared");
            app.modal = Modal::None;
            Ok(false)
        }
        Action::OpenCommandPalette => {
            app.modal = Modal::CommandPalette(CommandPaletteState::default());
            Ok(false)
        }
        Action::CommandPaletteTypeChar(c) => {
            if let Modal::CommandPalette(s) = &mut app.modal {
                s.query.push(c);
                s.selected = 0;
            }
            Ok(false)
        }
        Action::CommandPaletteBackspace => {
            if let Modal::CommandPalette(s) = &mut app.modal {
                s.query.pop();
                s.selected = 0;
            }
            Ok(false)
        }
        Action::CommandPaletteNext => {
            if let Modal::CommandPalette(s) = &mut app.modal {
                let total = palette_filtered(&s.query).len();
                if s.selected + 1 < total {
                    s.selected += 1;
                }
            }
            Ok(false)
        }
        Action::CommandPalettePrev => {
            if let Modal::CommandPalette(s) = &mut app.modal {
                if s.selected > 0 {
                    s.selected -= 1;
                }
            }
            Ok(false)
        }
        Action::CommandPaletteConfirm => {
            let picked: Option<String> = if let Modal::CommandPalette(s) = &app.modal {
                let filtered = palette_filtered(&s.query);
                filtered.get(s.selected).map(|e| e.label.to_string())
            } else {
                None
            };
            app.modal = Modal::None;
            if let Some(label) = picked {
                return run_palette_action(&label, app).await;
            }
            Ok(false)
        }
        Action::MarkAllRead => {
            let mut n = 0u32;
            for r in &mut app.open_rooms {
                if r.unread > 0 {
                    n = n.saturating_add(r.unread);
                    r.unread = 0;
                }
            }
            app.set_status(if n == 0 {
                "no unread to mark".to_string()
            } else {
                format!(
                    "marked {} message(s) read across {} room(s)",
                    n,
                    app.open_rooms.len()
                )
            });
            Ok(false)
        }
        Action::HelpScrollUp => {
            app.help_scroll = app.help_scroll.saturating_sub(1);
            Ok(false)
        }
        Action::HelpScrollDown => {
            app.help_scroll = app.help_scroll.saturating_add(1);
            Ok(false)
        }
        Action::HelpPageUp => {
            app.help_scroll = app.help_scroll.saturating_sub(10);
            Ok(false)
        }
        Action::HelpPageDown => {
            app.help_scroll = app.help_scroll.saturating_add(10);
            Ok(false)
        }
        Action::UpdateCheckOptInYes => {
            let _ = app.handle.set_update_check_enabled(true);
            app.modal = Modal::None;
            app.set_status("update check enabled — polling crates.io once per day");
            // Kick off a check immediately so the user sees the
            // outcome rather than waiting for the 24h timer.
            spawn_update_check(app);
            Ok(false)
        }
        Action::UpdateCheckOptInNo => {
            let _ = app.handle.set_update_check_enabled(false);
            app.modal = Modal::None;
            app.set_status("update check disabled — toggle later in settings");
            Ok(false)
        }
        Action::ToggleUpdateCheck => {
            let cur = app.handle.update_check_enabled().unwrap_or(false);
            let _ = app.handle.set_update_check_enabled(!cur);
            app.set_status(if !cur {
                "update check ON — polling crates.io once per day"
            } else {
                "update check OFF"
            });
            if !cur {
                spawn_update_check(app);
            } else {
                app.update_banner = None;
            }
            Ok(false)
        }
        Action::DismissUpdateBanner => {
            app.update_banner = None;
            Ok(false)
        }
        Action::GenerateInvite => {
            // Build an invite payload from what we know. host_multiaddr
            // is the best routable host address + our peer_id. Room
            // section is included iff we're in a room view.
            let our_peer = app.handle.peer_id().to_string();
            let our_fp = app.handle.fingerprint().to_string();
            // huddle 0.8: the libp2p multiaddr is now optional. In the
            // relay-only default there's no swarm and no listen address —
            // the recipient joins over the onion relay (seed room +
            // subscribe), so an empty `host_multiaddr` is expected and
            // fine. When libp2p IS running we still embed the best routable
            // address (+ /p2p/<peer-id>) so a direct dial can short-circuit
            // the relay on a LAN.
            let host_multiaddr = build_host_multiaddr(app, &our_peer);

            let room = match app.active_room() {
                Some(r) => {
                    if let Some(info) = app.handle.active_room_info(&r.room_id) {
                        let salt_b64 = info
                            .passphrase_salt
                            .as_ref()
                            .map(|s| base64::engine::general_purpose::STANDARD.encode(s));
                        Some(huddle_core::invite::InviteRoom {
                            id: info.id.clone(),
                            name: info.name.clone(),
                            encrypted: info.encrypted,
                            salt_b64,
                            creator_fingerprint: info.creator_fingerprint.clone(),
                            owner_fingerprints: app.handle.room_owners(&info.id),
                        })
                    } else {
                        None
                    }
                }
                _ => None,
            };

            let unsigned = huddle_core::invite::InviteLink {
                v: 1,
                host_multiaddr,
                fingerprint: our_fp,
                room: room.clone(),
                creator_pubkey_b64: None,
                signed_at_ms: 0,
                signature_b64: None,
                // huddle 1.0: carry our configured clearnet relay so the
                // joiner connects to it with zero config (v3 invite).
                relay_url: app.handle.clearnet_relay(),
                // huddle 2.0 (F1): classical invite by default (stays v2/v3,
                // readable by older clients). sign_invite promotes to a
                // PQ-bound v4 only when this is Some.
                mlkem_ek_b64: None,
            };
            // huddle 0.7.11: sign via AppHandle so the invite is bound
            // to the local Ed25519 identity. Falls back to v=1 only if
            // signing somehow fails — the receiver will then show the
            // "this invite is unsigned" warning.
            let invite = app.handle.sign_invite(unsigned.clone()).unwrap_or(unsigned);
            match huddle_core::invite::encode(&invite) {
                Ok(url) => {
                    app.modal = Modal::ShowInvite(ShowInviteState {
                        url,
                        includes_room: room.map(|r| r.name),
                    });
                }
                Err(e) => app.modal = Modal::Error(format!("encode invite: {e}")),
            }
            Ok(false)
        }
        Action::OpenPasteInvite => {
            app.modal = Modal::PasteInvite(PasteInviteState { url: String::new() });
            Ok(false)
        }
        Action::PasteInviteTypeChar(c) => {
            if let Modal::PasteInvite(s) = &mut app.modal {
                s.url.push(c);
            }
            Ok(false)
        }
        Action::PasteInviteBackspace => {
            if let Modal::PasteInvite(s) = &mut app.modal {
                s.url.pop();
            }
            Ok(false)
        }
        Action::PasteInviteConfirm => {
            let url = match &app.modal {
                Modal::PasteInvite(s) => s.url.clone(),
                _ => return Ok(false),
            };
            match huddle_core::invite::decode(url.trim()) {
                Ok(invite) => {
                    app.modal = Modal::ConfirmInvite(ConfirmInviteState { invite });
                }
                Err(e) => {
                    app.modal = Modal::Error(format!("bad invite link: {e}"));
                }
            }
            Ok(false)
        }
        Action::ConfirmInviteAccept => {
            let invite = match &app.modal {
                Modal::ConfirmInvite(s) => s.invite.clone(),
                _ => return Ok(false),
            };
            app.modal = Modal::None;
            // huddle 1.0: a v3 invite carries the inviter's clearnet relay.
            // Adopt it so we connect to their relay with zero config (takes
            // effect on the next launch — same as the mDNS toggle). Best
            // effort; a failure here must not block the join.
            if let Some(relay) = invite.relay_url.as_deref() {
                match app.handle.set_clearnet_relay(Some(relay)) {
                    Ok(()) => app.set_status(format!(
                        "saved invite relay {relay} — restart to connect through it"
                    )),
                    Err(e) => tracing::warn!(%e, "failed to save invite relay"),
                }
            }
            // huddle 0.8: the libp2p dial is now optional. Relay-only
            // invites carry an empty `host_multiaddr` — there's no swarm to
            // dial and the recipient reaches the room purely over the onion
            // relay (seed + subscribe, below). Only attempt the dial when
            // an address is present (libp2p invites): libp2p enforces the
            // embedded /p2p/<peer-id> check at the transport level, AND once
            // Identify lands the app-layer post-dial arm compares the
            // cryptographic fp against `invite.fingerprint`, disconnecting
            // on mismatch. A dial failure here is non-fatal — we still join
            // over the relay — so it no longer aborts the join.
            if !invite.host_multiaddr.trim().is_empty() {
                match app
                    .handle
                    .dial_invite(&invite.host_multiaddr, &invite.fingerprint)
                    .await
                {
                    Ok(()) => app.set_status(format!(
                        "dialing {} via invite…",
                        short_fp(&invite.fingerprint)
                    )),
                    Err(e) => {
                        // Parse/transport hiccup — log it but keep going;
                        // the relay path below is what actually delivers.
                        app.set_status(format!("invite dial skipped: {e}"));
                    }
                }
            }
            if let Some(room) = invite.room {
                // huddle 0.7.12: seed the room (salt + metadata) from the
                // invite so the join below doesn't race the host's gossip
                // announcement and error "room not found". Covers both the
                // encrypted (passphrase-modal) and unencrypted branches.
                app.handle.seed_invite_room(&room);
                if room.encrypted {
                    app.modal = Modal::JoinRoom(JoinRoomState {
                        room_id: room.id.clone(),
                        room_name: room.name.clone(),
                        encrypted: true,
                        passphrase: String::new(),
                    });
                } else if let Err(e) = app.handle.join_room(&room.id, None).await {
                    app.modal = Modal::Error(format!("join failed: {e}"));
                }
            }
            Ok(false)
        }
        Action::OpenGenerateJoinCode => {
            let (room_id, room_name) = match app.active_room() {
                Some(r) => (r.room_id.clone(), r.name.clone()),
                None => return Ok(false),
            };
            match app.handle.generate_join_code(&room_id) {
                Ok(code) => {
                    app.modal = Modal::ShowJoinCode(ShowJoinCodeState {
                        room_id,
                        room_name,
                        code,
                    });
                }
                Err(e) => app.set_status(format!("can't generate code: {e}")),
            }
            Ok(false)
        }
        Action::OpenJoinWithCode => {
            // huddle 0.7: meaningful on a Group sidebar item or the
            // GroupDiscover row.
            let room = match &app.sidebar.selection {
                SidebarItem::Group(id) | SidebarItem::Dm(id) => app
                    .handle
                    .discovered_rooms()
                    .into_iter()
                    .find(|d| d.room_id == *id),
                _ => None,
            };
            let room = match room {
                Some(r) => r,
                None => {
                    app.set_status("select an encrypted group in the sidebar first");
                    return Ok(false);
                }
            };
            if !room.encrypted {
                app.set_status("code-join only applies to encrypted rooms");
                return Ok(false);
            }
            app.modal = Modal::JoinWithCode(JoinWithCodeState {
                room_id: room.room_id,
                room_name: room.name,
                code: String::new(),
            });
            Ok(false)
        }
        Action::JoinWithCodeTypeChar(c) => {
            if let Modal::JoinWithCode(s) = &mut app.modal {
                s.code.push(c);
            }
            Ok(false)
        }
        Action::JoinWithCodeBackspace => {
            if let Modal::JoinWithCode(s) = &mut app.modal {
                s.code.pop();
            }
            Ok(false)
        }
        Action::JoinWithCodeConfirm => {
            let (room_id, code) = match &app.modal {
                Modal::JoinWithCode(s) => (s.room_id.clone(), s.code.clone()),
                _ => return Ok(false),
            };
            if code.trim().is_empty() {
                return Ok(false);
            }
            app.modal = Modal::None;
            if let Err(e) = app.handle.join_room_with_code(&room_id, code.trim()).await {
                app.modal = Modal::Error(format!("code join failed: {e}"));
            } else {
                app.set_status("code submitted — waiting for owner (up to 30 s)");
            }
            Ok(false)
        }
        Action::SettingsTabNext => {
            app.settings_tab = app.settings_tab.next();
            Ok(false)
        }
        Action::SettingsTabPrev => {
            app.settings_tab = app.settings_tab.prev();
            Ok(false)
        }
        Action::SettingsTabSelect(tab) => {
            app.settings_tab = tab;
            Ok(false)
        }
        Action::SettingsToggleTheme => {
            // huddle 1.1.4: flip Dark ⇄ Light, persist, and swap the live
            // palette so the next frame renders it (ratatui redraws from
            // `app.theme` every tick — no egui-style repaint plumbing needed).
            let next = app.theme_kind.toggled();
            if let Err(e) = app.handle.set_theme(next.as_str()) {
                // Don't switch the on-screen palette if the write failed, so
                // what's shown matches what's on disk.
                app.modal = Modal::Error(format!("save failed: {e}"));
                return Ok(false);
            }
            app.theme_kind = next;
            app.theme = next.palette();
            app.set_status(&format!("theme: {}", next.label()));
            Ok(false)
        }
        Action::SettingsToggleMdns => {
            let now_on = app.handle.mdns_enabled();
            if let Err(e) = app.handle.set_mdns_enabled(!now_on) {
                app.modal = Modal::Error(format!("save failed: {e}"));
                return Ok(false);
            }
            let new_state = !now_on;
            app.set_status(if new_state {
                "LAN discovery enabled — restart huddle to apply"
            } else {
                "LAN discovery disabled — restart huddle to apply"
            });
            Ok(false)
        }
        Action::SettingsCyclePriority => {
            // huddle 2.1.1: advance to the next connection-priority preset and
            // apply it live (the relay loop re-dials in the new door order).
            use huddle_core::network::transport::{match_priority_preset, priority_presets};
            let presets = priority_presets();
            let current = match_priority_preset(&app.handle.current_transport_order());
            // From a known preset, advance + wrap; from "custom", start at the top.
            let idx = presets
                .iter()
                .position(|p| p.key == current)
                .map(|i| (i + 1) % presets.len())
                .unwrap_or(0);
            let next = &presets[idx];
            if let Err(e) = app.handle.set_transport_order(&next.order) {
                app.modal = Modal::Error(format!("save failed: {e}"));
                return Ok(false);
            }
            app.set_status(format!("connection priority: {}", next.label));
            Ok(false)
        }
        Action::SettingsToggleNotifications => {
            let now_on = app.handle.notifications_enabled();
            if let Err(e) = app.handle.set_notifications_enabled(!now_on) {
                app.modal = Modal::Error(format!("save failed: {e}"));
                return Ok(false);
            }
            app.set_status(if !now_on {
                "desktop notifications on (OS-local only)"
            } else {
                "desktop notifications off"
            });
            Ok(false)
        }
        Action::ProfileFieldUp => {
            if app.profile_cursor > 0 {
                app.profile_cursor -= 1;
            }
            Ok(false)
        }
        Action::ProfileFieldDown => {
            let max = profile_field_count(app).saturating_sub(1);
            if app.profile_cursor < max {
                app.profile_cursor += 1;
            }
            Ok(false)
        }
        Action::ProfileFieldYank => {
            let (label, value) = match profile_field_at(app, app.profile_cursor) {
                Some(v) => v,
                None => return Ok(false),
            };
            match crate::clipboard::copy(&value) {
                Ok(()) => app.set_status(format!("copied {} to clipboard", label)),
                Err(e) => app.set_status(format!("copy failed: {}", e)),
            }
            Ok(false)
        }
        Action::OpenEditUsername => {
            // Pre-fill the editor with the current username so the user
            // can tweak rather than retype. Empty submission clears.
            let current = app.handle.display_name().unwrap_or_default();
            app.modal = Modal::EditUsername(EditUsernameState { input: current });
            Ok(false)
        }
        Action::EditUsernameTypeChar(c) => {
            if let Modal::EditUsername(s) = &mut app.modal {
                if s.input.chars().count() < 32 {
                    s.input.push(c);
                }
            }
            Ok(false)
        }
        Action::EditUsernameBackspace => {
            if let Modal::EditUsername(s) = &mut app.modal {
                s.input.pop();
            }
            Ok(false)
        }
        Action::EditUsernameConfirm => {
            let input = match &app.modal {
                Modal::EditUsername(s) => s.input.clone(),
                _ => return Ok(false),
            };
            let trimmed = input.trim();
            let new_name = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
            app.modal = Modal::None;
            if let Err(e) = app.handle.set_username(new_name.as_deref()).await {
                app.modal = Modal::Error(format!("set username failed: {e}"));
            } else {
                app.set_status(match &new_name {
                    Some(n) => format!("username set to {n}"),
                    None => "username cleared — you are now [anonymous]".into(),
                });
            }
            Ok(false)
        }
        Action::OpenGoDarkModal => {
            app.modal = Modal::GoDark(GoDarkState {
                requires_passphrase: app.handle.has_master_passphrase(),
                ..GoDarkState::default()
            });
            Ok(false)
        }
        Action::OpenAddFriend => {
            app.modal = Modal::AddFriend(AddFriendState::default());
            Ok(false)
        }
        Action::GenerateConnectCode => {
            // huddle 1.2.1: ask the relay to mint a short-lived code others can
            // use to add us. The code arrives via AppEvent::ConnectCodeCreated.
            match app.handle.create_connect_code() {
                Ok(()) => app.set_status("generating a connect code…".to_string()),
                Err(e) => app.modal = Modal::Error(format!("connect code: {e}")),
            }
            Ok(false)
        }
        Action::CloseConnectCode => {
            app.modal = Modal::None;
            Ok(false)
        }
        Action::CopyConnectCode => {
            if let Modal::ConnectCode(s) = &app.modal {
                let code = s.code.clone();
                match crate::clipboard::copy(&code) {
                    Ok(()) => app.set_status(format!("copied connect code {code}")),
                    Err(e) => app.set_status(format!("copy failed: {e}")),
                }
            }
            Ok(false)
        }
        Action::AddFriendTypeChar(c) => {
            if let Modal::AddFriend(s) = &mut app.modal {
                if s.input.chars().count() < 64 {
                    s.input.push(c);
                }
            }
            Ok(false)
        }
        Action::AddFriendBackspace => {
            if let Modal::AddFriend(s) = &mut app.modal {
                s.input.pop();
            }
            Ok(false)
        }
        Action::AddFriendConfirm => {
            let input = match &app.modal {
                Modal::AddFriend(s) => s.input.clone(),
                _ => return Ok(false),
            };
            if input.trim().is_empty() {
                return Ok(false);
            }
            app.modal = Modal::None;
            let trimmed = input.trim();
            // huddle 1.2.1: a connect code (8 Crockford-base32 chars) is the
            // short-lived alternative to a full HD-ID — resolve it via the relay
            // and send a contact request. Checked first; it can't collide with a
            // 24-hex HD-ID (different length).
            if huddle_core::app::normalize_connect_code(trimmed).is_some() {
                match app.handle.redeem_connect_code(trimmed) {
                    Ok(()) => app.set_status("looking up connect code…".to_string()),
                    Err(e) => app.modal = Modal::Error(format!("connect code: {e}")),
                }
                return Ok(false);
            }
            // huddle 1.0: a literal HD-ID sends a signed contact request over
            // the relay inbox — that works over the INTERNET (not just the LAN
            // mesh), reaching the peer live or via the offline mailbox. We
            // also race a best-effort LAN dial for same-network immediacy. A
            // bare username can only be resolved on a shared mesh, so it keeps
            // the existing dial-by-username path.
            if let Some(fp) = huddle_core::app::normalize_to_fingerprint(trimmed) {
                if fp.as_str() == app.handle.fingerprint() {
                    app.modal = Modal::Error("that's your own HD-ID".into());
                    return Ok(false);
                }
                match app.handle.send_contact_request(&fp, None).await {
                    Ok(()) => {
                        app.set_status(format!(
                            "contact request sent to HD-{} — opens a DM when they accept",
                            short_fp(&fp).to_uppercase()
                        ));
                    }
                    Err(e) => {
                        app.modal = Modal::Error(format!("add contact: {e}"));
                        return Ok(false);
                    }
                }
                // Same-LAN immediacy; ignored when the peer isn't on the mesh.
                let _ = app.handle.dial_by_id_or_username(trimmed).await;
            } else {
                match app.handle.dial_by_id_or_username(trimmed).await {
                    Ok(()) => {
                        app.set_status(format!("dialing {} (racing LAN / IP / relay)…", trimmed));
                    }
                    Err(e) => {
                        app.modal = Modal::Error(format!("add friend: {e}"));
                    }
                }
            }
            Ok(false)
        }
        Action::GoDarkTypeChar(c) => {
            if let Modal::GoDark(s) = &mut app.modal {
                if s.input.chars().count() < 128 {
                    s.input.push(c);
                }
            }
            Ok(false)
        }
        Action::GoDarkBackspace => {
            if let Modal::GoDark(s) = &mut app.modal {
                s.input.pop();
            }
            Ok(false)
        }
        Action::GoDarkConfirm => {
            // Snapshot mode + input before touching the modal again.
            let (input, requires_passphrase) = match &app.modal {
                Modal::GoDark(s) => (s.input.clone(), s.requires_passphrase),
                _ => return Ok(false),
            };
            // huddle 0.7.6: single gate per session mode.
            //   master passphrase mode → passphrase IS the gate; `go_dark`
            //     does the constant-time check internally.
            //   --no-master-passphrase mode → typed `DELETE EVERYTHING`
            //     is the only gate (no key to compare against).
            if !requires_passphrase && input != GO_DARK_CONFIRM_PHRASE {
                if let Modal::GoDark(s) = &mut app.modal {
                    s.last_error = Some(format!(
                        "type `{}` exactly to confirm",
                        GO_DARK_CONFIRM_PHRASE
                    ));
                    s.input.clear();
                }
                return Ok(false);
            }
            // For passphrase mode, pass `input` as the passphrase.
            // For no-master mode, the passphrase argument is ignored
            // by `go_dark` (it short-circuits the check on a zeroed key).
            let passphrase_to_send = if requires_passphrase {
                input
            } else {
                String::new()
            };
            match app.handle.go_dark(&passphrase_to_send).await {
                Ok(()) => {
                    // WentDark event fires from go_dark; the handler
                    // schedules the actual exit so the goodbye modal
                    // is visible for a beat.
                    Ok(false)
                }
                Err(e) => {
                    if let Modal::GoDark(s) = &mut app.modal {
                        s.last_error = Some(format!("{e}"));
                        s.input.clear();
                    }
                    Ok(false)
                }
            }
        }
        Action::SettingsToggleGlobalVerifiedOnly => {
            // huddle 0.7.8: pane-driven toggle. The previous version
            // mutated a per-modal snapshot; the pane reads the live
            // value via `handle.verified_only_inbound()` every render
            // so we just flip and persist.
            let new_state = !app.handle.verified_only_inbound();
            if let Err(e) = app.handle.set_verified_only_inbound(new_state) {
                app.modal = Modal::Error(format!("save failed: {e}"));
                return Ok(false);
            }
            Ok(false)
        }
        Action::ClearBlockedPeers => {
            // Iterate the persisted blocklist and unblock each. We do
            // this in two phases (snapshot, then loop) so the SQLite
            // connection isn't borrowed across the unblock_peer calls.
            let blocked = app.handle.list_blocked_peers();
            let n = blocked.len();
            let mut errors = 0usize;
            for fp in blocked {
                if app.handle.unblock_peer(&fp).is_err() {
                    errors += 1;
                }
            }
            // huddle 0.7.8: the Settings pane reads the live blocklist
            // count on every render, so no snapshot needs updating here.
            let msg = if errors == 0 {
                format!("cleared {} blocked peer(s)", n)
            } else {
                format!(
                    "cleared {} blocked peer(s); {} error(s)",
                    n.saturating_sub(errors),
                    errors
                )
            };
            app.set_status(msg);
            // huddle 0.7.11: ClearBlockedPeers is now reached via the
            // ConfirmClearBlocked modal; close it on success.
            app.modal = Modal::None;
            Ok(false)
        }
        Action::ToggleRoomVerifiedOnly => {
            let room_id = match app.active_room() {
                Some(r) => r.room_id.clone(),
                None => return Ok(false),
            };
            let our_fp = app.handle.fingerprint().to_string();
            if !app.handle.is_owner(&room_id, &our_fp) {
                app.set_status("only an owner can toggle room verified-only");
                return Ok(false);
            }
            let new_state = !app.handle.room_verified_only(&room_id);
            if let Err(e) = app.handle.set_room_verified_only(&room_id, new_state) {
                app.modal = Modal::Error(format!("toggle failed: {e}"));
                return Ok(false);
            }
            app.set_status(if new_state {
                "room is now verified-only — non-SAS-verified joiners refused"
            } else {
                "room verified-only mode off"
            });
            Ok(false)
        }
        Action::VerifyStartSas => {
            // From the Verify modal: kick off an SAS exchange with the
            // focused member. Replaces the Verify modal with the SAS
            // in-progress modal (Waiting → Comparing on response).
            let (room_id, partner_fp) = match &app.modal {
                Modal::Verify(v) => match v.members.get(v.selected) {
                    Some((fp, _)) => (v.room_id.clone(), fp.clone()),
                    None => return Ok(false),
                },
                _ => return Ok(false),
            };
            match app.handle.sas_start(&room_id, &partner_fp).await {
                Ok(tx_id) => {
                    app.modal = Modal::Sas(SasState {
                        room_id,
                        partner_fingerprint: partner_fp,
                        tx_id,
                        stage: SasStage::Waiting,
                    });
                }
                Err(e) => app.modal = Modal::Error(format!("SAS start failed: {e}")),
            }
            Ok(false)
        }
        Action::SasMatch => {
            if let Modal::Sas(s) = &mut app.modal {
                let tx_id = s.tx_id.clone();
                if let SasStage::Comparing {
                    ref mut our_matched,
                    ..
                } = s.stage
                {
                    *our_matched = true;
                }
                if let Err(e) = app.handle.sas_match(&tx_id).await {
                    app.modal = Modal::Error(format!("SAS match failed: {e}"));
                    return Ok(false);
                }
                app.set_status("SAS match sent — waiting for partner to confirm");
            }
            Ok(false)
        }
        Action::SasCancel => {
            if let Modal::Sas(s) = &app.modal {
                app.handle.sas_cancel(&s.tx_id);
            }
            app.modal = Modal::None;
            Ok(false)
        }
        Action::OpenKickPicker => {
            let (room_id, members) = match owner_action_members(app, MemberActionKind::Kick) {
                Some(t) => t,
                None => return Ok(false),
            };
            app.modal = Modal::MemberAction(MemberActionState {
                room_id,
                kind: MemberActionKind::Kick,
                members,
                selected: 0,
            });
            Ok(false)
        }
        Action::OpenGrantPicker => {
            let (room_id, members) = match owner_action_members(app, MemberActionKind::Grant) {
                Some(t) => t,
                None => return Ok(false),
            };
            app.modal = Modal::MemberAction(MemberActionState {
                room_id,
                kind: MemberActionKind::Grant,
                members,
                selected: 0,
            });
            Ok(false)
        }
        Action::ShowRoomBans => {
            // Owners only. We use the same `we_are_owner` gate as
            // kick/grant so the keybinding is silently ignored for
            // non-owners (matching the rest of the moderation surface).
            let room_id = match app.active_room() {
                Some(r) => r.room_id.clone(),
                None => return Ok(false),
            };
            if !app.handle.we_are_owner(&room_id) {
                return Ok(false);
            }
            let bans = app.handle.list_room_bans(&room_id);
            let body = if bans.is_empty() {
                "no bans in this room.".to_string()
            } else {
                let mut s = format!("{} ban(s) in this room:\n\n", bans.len());
                for fp in &bans {
                    s.push_str(&format!("  {}\n", short_fp(fp)));
                }
                s.push_str("\nban is enforced by key rotation (the banned peer can no longer derive the room key). press any key to dismiss.");
                s
            };
            app.replace_modal_if_idle(Modal::Info(body));
            Ok(false)
        }
        Action::MemberActionNext => {
            if let Modal::MemberAction(s) = &mut app.modal {
                if s.selected + 1 < s.members.len() {
                    s.selected += 1;
                }
            }
            Ok(false)
        }
        Action::MemberActionPrev => {
            if let Modal::MemberAction(s) = &mut app.modal {
                if s.selected > 0 {
                    s.selected -= 1;
                }
            }
            Ok(false)
        }
        Action::MemberActionConfirm => {
            let snapshot = if let Modal::MemberAction(s) = &app.modal {
                s.members
                    .get(s.selected)
                    .map(|(fp, _)| (s.room_id.clone(), s.kind, fp.clone()))
            } else {
                None
            };
            let (room_id, kind, target_fp) = match snapshot {
                Some(t) => t,
                None => return Ok(false),
            };
            app.modal = Modal::None;
            match kind {
                MemberActionKind::Grant => {
                    match app.handle.grant_owner(&room_id, &target_fp).await {
                        Ok(()) => {
                            app.set_status(format!("granted owner to {}", short_fp(&target_fp)))
                        }
                        Err(e) => app.modal = Modal::Error(format!("grant failed: {e}")),
                    }
                }
                MemberActionKind::Kick => {
                    match app.handle.kick_member(&room_id, &target_fp).await {
                        Ok(new_pp) if new_pp.is_empty() => {
                            app.set_status(format!("kicked {}", short_fp(&target_fp)));
                        }
                        Ok(new_pp) => {
                            // Show the new passphrase prominently so the
                            // owner can copy + share OOB with remaining
                            // members. Modal::Info dismisses on any key.
                            app.modal = Modal::Info(format!(
                                "kicked {}. new passphrase (share OOB with remaining members):\n\n  {}",
                                short_fp(&target_fp),
                                new_pp
                            ));
                        }
                        Err(e) => app.modal = Modal::Error(format!("kick failed: {e}")),
                    }
                }
            }
            Ok(false)
        }
        Action::InboundDialAccept => {
            if let Modal::InboundDial(s) = app.modal.clone() {
                app.handle.accept_inbound(s.peer_id, &s.address).await;
                app.set_status(format!("connected to {}", short_fp(&s.fingerprint)));
                app.modal = Modal::None;
                app.refresh_known_peers();
            }
            Ok(false)
        }
        Action::InboundDialReject => {
            if let Modal::InboundDial(s) = app.modal.clone() {
                if let Err(e) = app.handle.reject_inbound(s.peer_id, &s.fingerprint).await {
                    app.modal = Modal::Error(format!("reject failed: {e}"));
                    return Ok(false);
                }
                app.set_status(format!("rejected {}", short_fp(&s.fingerprint)));
                app.modal = Modal::None;
            }
            Ok(false)
        }
        Action::InboundDialTrust => {
            if let Modal::InboundDial(s) = app.modal.clone() {
                if let Err(e) = app
                    .handle
                    .trust_inbound(s.peer_id, &s.fingerprint, &s.address)
                    .await
                {
                    app.modal = Modal::Error(format!("trust failed: {e}"));
                    return Ok(false);
                }
                app.set_status(format!(
                    "trusted {} — won't ask again",
                    short_fp(&s.fingerprint)
                ));
                app.modal = Modal::None;
                app.refresh_known_peers();
            }
            Ok(false)
        }
        Action::AttachPickerConfirm => {
            let pick: Option<std::path::PathBuf> = match &mut app.modal {
                Modal::AttachPicker(s) => match s.flat.get(s.selected) {
                    Some(r) if r.is_dir => {
                        // Enter on a directory toggles it, like Space.
                        s.toggle_expand();
                        None
                    }
                    Some(_) => s.selected_path(),
                    None => None,
                },
                _ => None,
            };
            if let Some(path) = pick {
                let room_id = match app.active_room() {
                    Some(r) => r.room_id.clone(),
                    None => return Ok(false),
                };
                app.modal = Modal::None;
                match app.handle.send_file(&room_id, &path).await {
                    Ok(file_id) => {
                        app.set_status(format!("sending {} ({})", path.display(), &file_id[..12]));
                    }
                    Err(e) => {
                        app.modal = Modal::Error(format!("send failed: {e}"));
                    }
                }
            }
            Ok(false)
        }
        Action::OpenAttachByPath => {
            // Guard on an active room like OpenAttachmentPicker — the palette
            // can reach this from outside a room, where there'd be nowhere to
            // send (the confirm would otherwise silently no-op).
            if app.active_room().is_none() {
                app.set_status("attach is only available inside a room");
                return Ok(false);
            }
            // Replaces the picker modal if it's open — that's fine; the
            // two are alternatives for the same task.
            app.modal = Modal::AttachPath(AttachPathState::default());
            Ok(false)
        }
        Action::AttachPathTypeChar(c) => {
            if let Modal::AttachPath(s) = &mut app.modal {
                s.input.push(c);
                s.error = None;
            }
            Ok(false)
        }
        Action::AttachPathBackspace => {
            if let Modal::AttachPath(s) = &mut app.modal {
                s.input.pop();
                s.error = None;
            }
            Ok(false)
        }
        Action::AttachPathConfirm => {
            let raw = match &app.modal {
                Modal::AttachPath(s) => s.input.trim().to_string(),
                _ => return Ok(false),
            };
            if raw.is_empty() {
                // Give feedback rather than a silent no-op (matches the GUI).
                if let Modal::AttachPath(s) = &mut app.modal {
                    s.error = Some("type a file path".into());
                }
                return Ok(false);
            }
            // Best-effort `~` expansion — shared with the GUI so both behave the
            // same (only `~` and `~/…` expand; `~user` stays literal).
            let path = huddle_core::app::expand_tilde(&raw);
            if !path.is_file() {
                // Keep the modal open with the typed path intact + an inline
                // error (like the attach picker and the GUI sibling), instead of
                // a throwaway Modal::Error that any keypress dismisses.
                if let Modal::AttachPath(s) = &mut app.modal {
                    s.error = Some(format!("no file at {}", path.display()));
                }
                return Ok(false);
            }
            // Resolve room_id exactly as AttachPickerConfirm does.
            let room_id = match app.active_room() {
                Some(r) => r.room_id.clone(),
                None => return Ok(false),
            };
            app.modal = Modal::None;
            match app.handle.send_file(&room_id, &path).await {
                Ok(file_id) => {
                    app.set_status(format!("sending {} ({})", path.display(), &file_id[..12]));
                }
                Err(e) => {
                    app.modal = Modal::Error(format!("send failed: {e}"));
                }
            }
            Ok(false)
        }
        // huddle 0.7 sidebar/pane helpers
        Action::SidebarSectionPrev => {
            sidebar_jump_section(app, -1);
            Ok(false)
        }
        Action::SidebarToggleExpand => {
            sidebar_toggle_expand(app);
            Ok(false)
        }
        Action::JumpToPeoplePane => {
            app.pane = Pane::People;
            app.sidebar.selection = SidebarItem::Section(SidebarSection::People);
            // huddle 0.7.7: pull fresh pending-request rows so the
            // section count is right + the cursor stays in range. If
            // there are pending requests, land on that tab — that's
            // where the user almost certainly wants to look first.
            app.refresh_pending_requests();
            app.refresh_pending_contact_requests();
            // huddle 1.0: land on whichever request list has something to
            // act on — relay contact requests first, then libp2p friend
            // requests — so an incoming request is the first thing seen.
            if !app.pending_contact_requests.is_empty() {
                app.people_focus = PeopleFocus::ContactRequests;
                app.selected_contact_request_idx = 0;
            } else if !app.pending_requests.is_empty() {
                app.people_focus = PeopleFocus::Pending;
                app.selected_pending_idx = 0;
            }
            Ok(false)
        }
        Action::JumpToSettingsPane => {
            app.pane = Pane::Settings;
            // huddle 0.7.8: reset to Account tab on jump so `,` from
            // anywhere lands on a predictable surface.
            app.settings_tab = SettingsTab::Account;
            app.sidebar.selection = SidebarItem::Section(SidebarSection::Settings);
            Ok(false)
        }
        Action::OpenComposeDm => {
            app.modal = Modal::ComposeDm(ComposeDmState::default());
            Ok(false)
        }
        Action::ComposeDmTypeChar(c) => {
            if let Modal::ComposeDm(s) = &mut app.modal {
                s.input.push(c);
            }
            Ok(false)
        }
        Action::ComposeDmBackspace => {
            if let Modal::ComposeDm(s) = &mut app.modal {
                s.input.pop();
            }
            Ok(false)
        }
        Action::ComposeDmCancel => {
            app.modal = Modal::None;
            Ok(false)
        }
        Action::ComposeDmConfirm => {
            let input = match &app.modal {
                Modal::ComposeDm(s) => s.input.trim().to_string(),
                _ => return Ok(false),
            };
            if input.is_empty() {
                return Ok(false);
            }
            // Resolve input to a fingerprint via lookup helpers, then
            // start the DM. On unresolvable input we morph to AddFriend.
            let resolved = resolve_dm_target(app, &input);
            match resolved {
                Some(fp) => {
                    app.modal = Modal::None;
                    match app.handle.start_direct(&fp).await {
                        Ok(room_id) => {
                            app.switch_to_room(&room_id);
                            app.set_status(format!("DM with {}", short_fp(&fp)));
                        }
                        Err(e) => app.modal = Modal::Error(format!("DM failed: {e}")),
                    }
                }
                None => {
                    // State C: unrecognized text → morph into AddFriend.
                    app.modal = Modal::AddFriend(AddFriendState { input });
                }
            }
            Ok(false)
        }
        Action::ToggleMemberMargin => {
            app.show_member_margin = !app.show_member_margin;
            Ok(false)
        }
        Action::OpenInvitePicker => {
            // Picker only makes sense inside a group room — the
            // generated invite has to scope to *some* room, and DMs
            // can't take a third member by design. From any other
            // pane (Welcome, Profile, People, Activity, Settings) we
            // surface a status hint and bail.
            let (room_id, room_name, is_group) = match app.active_room() {
                Some(r) => {
                    let info = app.handle.active_room_info(&r.room_id);
                    let is_group = info
                        .as_ref()
                        .map(|i| i.kind != huddle_core::storage::repo::RoomKind::Direct)
                        .unwrap_or(false);
                    (
                        r.room_id.clone(),
                        info.map(|i| i.name).unwrap_or_default(),
                        is_group,
                    )
                }
                None => {
                    app.set_status("open a group first — `Shift+I` for OOB or `s` to create");
                    return Ok(false);
                }
            };
            if !is_group {
                app.set_status("DMs are 1-1 by design — open a group to invite peers");
                return Ok(false);
            }
            let candidates = gather_invite_candidates(app, &room_id);
            if candidates.is_empty() {
                app.set_status(
                    "no peers to invite yet — verify someone with Ctrl+V or share `Shift+I` OOB",
                );
                return Ok(false);
            }
            app.modal = Modal::InvitePicker(InvitePickerState {
                room_id,
                room_name,
                candidates,
                selected: HashSet::new(),
                filter: String::new(),
                cursor: 0,
                status_line: None,
            });
            Ok(false)
        }
        Action::InvitePickerCancel => {
            app.modal = Modal::None;
            Ok(false)
        }
        Action::InvitePickerFilterTypeChar(c) => {
            if let Modal::InvitePicker(s) = &mut app.modal {
                s.filter.push(c);
                s.cursor = 0;
                s.status_line = None;
            }
            Ok(false)
        }
        Action::InvitePickerFilterBackspace => {
            if let Modal::InvitePicker(s) = &mut app.modal {
                s.filter.pop();
                s.cursor = 0;
                s.status_line = None;
            }
            Ok(false)
        }
        Action::InvitePickerCursorUp => {
            if let Modal::InvitePicker(s) = &mut app.modal {
                if s.cursor > 0 {
                    s.cursor -= 1;
                }
                s.status_line = None;
            }
            Ok(false)
        }
        Action::InvitePickerCursorDown => {
            if let Modal::InvitePicker(s) = &mut app.modal {
                let visible_len = filtered_invite_candidates(s).len();
                if s.cursor + 1 < visible_len {
                    s.cursor += 1;
                }
                s.status_line = None;
            }
            Ok(false)
        }
        Action::InvitePickerToggleSelected => {
            if let Modal::InvitePicker(s) = &mut app.modal {
                let visible = filtered_invite_candidates(s);
                if let Some(c) = visible.get(s.cursor).cloned() {
                    if s.selected.contains(&c.fingerprint) {
                        s.selected.remove(&c.fingerprint);
                        s.status_line = None;
                    } else if s.selected.len() >= INVITE_PICKER_SOFT_CAP {
                        s.status_line = Some(format!(
                            "selection cap: {} max per send",
                            INVITE_PICKER_SOFT_CAP
                        ));
                    } else {
                        s.selected.insert(c.fingerprint);
                        s.status_line = None;
                    }
                }
            }
            Ok(false)
        }
        Action::InvitePickerSend => {
            let (room_id, selected_fps) = match &app.modal {
                Modal::InvitePicker(s) => {
                    if s.selected.is_empty() {
                        if let Modal::InvitePicker(s2) = &mut app.modal {
                            s2.status_line =
                                Some("Space to select peers · Enter sends · Esc cancels".into());
                        }
                        return Ok(false);
                    }
                    (
                        s.room_id.clone(),
                        s.selected.iter().cloned().collect::<Vec<_>>(),
                    )
                }
                _ => return Ok(false),
            };
            // Build the invite link exactly once — same code path as
            // `Shift+I` but scoped to the captured room. Failure here
            // is structural (no listen address yet) and shows an error.
            let invite_text = match build_room_invite_link(app, &room_id) {
                Ok(t) => t,
                Err(e) => {
                    if let Modal::InvitePicker(s) = &mut app.modal {
                        s.status_line = Some(format!("invite build failed: {e}"));
                    }
                    return Ok(false);
                }
            };
            let mut sent = 0usize;
            let mut failures: Vec<String> = Vec::new();
            for fp in &selected_fps {
                let dm_room_id = match app.handle.start_direct(fp).await {
                    Ok(rid) => rid,
                    Err(e) => {
                        failures.push(format!("{}: {}", short_fp(fp), e));
                        continue;
                    }
                };
                match app
                    .handle
                    .send_room_message(&dm_room_id, &invite_text)
                    .await
                {
                    Ok(()) => sent += 1,
                    Err(e) => failures.push(format!("{}: {}", short_fp(fp), e)),
                }
            }
            app.modal = Modal::None;
            if failures.is_empty() {
                app.set_status(format!("sent invite to {} peer(s)", sent));
            } else {
                app.set_status(format!("sent to {}; failed for {}", sent, failures.len()));
                tracing::warn!(?failures, "invite-picker send had partial failures");
            }
            Ok(false)
        }
        Action::PeopleFocusNext => {
            // huddle 0.7.7: Pending joins the rotation. Skipped when
            // empty so the cycle doesn't land on an empty tab the
            // user can't act on. Known is always present (even with
            // zero peers, it shows the "no known peers" hint), so
            // it's the safe fallback at the end.
            app.refresh_pending_requests();
            app.refresh_pending_contact_requests();
            let has_pending = !app.pending_requests.is_empty();
            let has_contact_reqs = !app.pending_contact_requests.is_empty();
            app.people_focus = match app.people_focus {
                PeopleFocus::ContactRequests => {
                    if has_pending {
                        PeopleFocus::Pending
                    } else {
                        PeopleFocus::Known
                    }
                }
                PeopleFocus::Pending => PeopleFocus::Known,
                PeopleFocus::Known => PeopleFocus::Verified,
                PeopleFocus::Verified => PeopleFocus::Blocked,
                PeopleFocus::Blocked => {
                    if has_contact_reqs {
                        PeopleFocus::ContactRequests
                    } else if has_pending {
                        PeopleFocus::Pending
                    } else {
                        PeopleFocus::Known
                    }
                }
            };
            Ok(false)
        }
        Action::PendingRequestUp => {
            if app.selected_pending_idx > 0 {
                app.selected_pending_idx -= 1;
            }
            Ok(false)
        }
        Action::PendingRequestDown => {
            if app.selected_pending_idx + 1 < app.pending_requests.len() {
                app.selected_pending_idx += 1;
            }
            Ok(false)
        }
        Action::PendingRequestAccept => {
            let fp = app
                .pending_requests
                .get(app.selected_pending_idx)
                .map(|r| r.fingerprint.clone());
            if let Some(fp) = fp {
                match app.handle.accept_pending_friend_request(&fp).await {
                    Ok(()) => {
                        app.set_status(format!("re-dialing {} …", short_fp(&fp)));
                    }
                    Err(e) => {
                        app.modal = Modal::Error(format!("accept failed: {e}"));
                    }
                }
                app.refresh_pending_requests();
                if app.pending_requests.is_empty() {
                    app.people_focus = PeopleFocus::Known;
                }
            }
            Ok(false)
        }
        Action::PendingRequestReject => {
            let fp = app
                .pending_requests
                .get(app.selected_pending_idx)
                .map(|r| r.fingerprint.clone());
            if let Some(fp) = fp {
                if let Err(e) = app.handle.reject_pending_friend_request(&fp) {
                    app.modal = Modal::Error(format!("reject failed: {e}"));
                } else {
                    app.set_status(format!("rejected + blocked {}", short_fp(&fp)));
                }
                app.refresh_pending_requests();
                if app.pending_requests.is_empty() {
                    app.people_focus = PeopleFocus::Known;
                }
            }
            Ok(false)
        }
        Action::ContactRequestUp => {
            if app.selected_contact_request_idx > 0 {
                app.selected_contact_request_idx -= 1;
            }
            Ok(false)
        }
        Action::ContactRequestDown => {
            if app.selected_contact_request_idx + 1 < app.pending_contact_requests.len() {
                app.selected_contact_request_idx += 1;
            }
            Ok(false)
        }
        Action::ContactRequestAccept => {
            let fp = app
                .pending_contact_requests
                .get(app.selected_contact_request_idx)
                .map(|r| r.fingerprint.clone());
            if let Some(fp) = fp {
                match app.handle.accept_contact_request(&fp).await {
                    Ok(()) => {
                        app.set_status(format!("accepted — opening DM with {}", short_fp(&fp)));
                    }
                    Err(e) => {
                        app.modal = Modal::Error(format!("accept failed: {e}"));
                    }
                }
                app.refresh_pending_contact_requests();
                if app.selected_contact_request_idx >= app.pending_contact_requests.len() {
                    app.selected_contact_request_idx =
                        app.pending_contact_requests.len().saturating_sub(1);
                }
                if app.pending_contact_requests.is_empty() {
                    app.people_focus = PeopleFocus::Known;
                }
            }
            Ok(false)
        }
        Action::ContactRequestReject => {
            let fp = app
                .pending_contact_requests
                .get(app.selected_contact_request_idx)
                .map(|r| r.fingerprint.clone());
            if let Some(fp) = fp {
                if let Err(e) = app.handle.reject_contact_request(&fp, false) {
                    app.modal = Modal::Error(format!("decline failed: {e}"));
                } else {
                    app.set_status(format!("declined {}", short_fp(&fp)));
                }
                app.refresh_pending_contact_requests();
                if app.selected_contact_request_idx >= app.pending_contact_requests.len() {
                    app.selected_contact_request_idx =
                        app.pending_contact_requests.len().saturating_sub(1);
                }
                if app.pending_contact_requests.is_empty() {
                    app.people_focus = PeopleFocus::Known;
                }
            }
            Ok(false)
        }
        Action::PeoplePersonReconnect => {
            if let Some(p) = app.known_peers.get(app.selected_known_idx).cloned() {
                if let Err(e) = app.handle.redial(&p.address).await {
                    app.modal = Modal::Error(format!("dial failed: {e}"));
                }
            }
            Ok(false)
        }
        Action::PeoplePersonBlock => {
            if let Some(p) = app.known_peers.get(app.selected_known_idx).cloned() {
                // huddle 0.7.7: read from `fingerprint`, not `label`
                // (label is only set on add-by-id / username-resolved
                // peers; plain `d` dial peers leave it as None).
                if let Some(fp) = p.fingerprint.as_deref() {
                    let _ = app.handle.block_peer(fp);
                    app.set_status(format!("blocked {}", short_fp(fp)));
                } else {
                    app.set_status(
                        "can't block — fingerprint not learned yet (try after Identify)",
                    );
                }
            }
            Ok(false)
        }
        Action::PeoplePersonUnblock => {
            let blocked = app.handle.list_blocked_peers();
            if let Some(fp) = blocked.get(app.selected_blocked_idx).cloned() {
                let _ = app.handle.unblock_peer(&fp);
                app.set_status(format!("unblocked {}", short_fp(&fp)));
            }
            Ok(false)
        }
        Action::PeoplePersonForget => {
            if let Some(p) = app.known_peers.get(app.selected_known_idx).cloned() {
                let _ = app.handle.forget_peer(&p.address).await;
                app.refresh_known_peers();
            }
            Ok(false)
        }
        Action::PeoplePersonStartDm => {
            if let Some(p) = app.known_peers.get(app.selected_known_idx).cloned() {
                // huddle 0.7.7: use `fingerprint` (populated post-Identify
                // for every dialed peer). Previously this used `label`,
                // which is `None` for plain `d` dials — silently no-op'd.
                if let Some(fp) = p.fingerprint.clone() {
                    match app.handle.start_direct(&fp).await {
                        Ok(rid) => app.switch_to_room(&rid),
                        Err(e) => app.modal = Modal::Error(format!("DM failed: {e}")),
                    }
                } else {
                    app.set_status(
                        "can't DM yet — peer hasn't identified (try after they connect)",
                    );
                }
            }
            Ok(false)
        }

        // ============================================================
        // huddle 2.0.0 (F3): safety-number-change alarm modal
        // ============================================================
        Action::SafetyChangeNext => {
            if let Modal::SafetyNumberChanged(s) = &mut app.modal {
                s.focus = (s.focus + 1) % 2;
            }
            Ok(false)
        }
        Action::SafetyChangePrev => {
            if let Modal::SafetyNumberChanged(s) = &mut app.modal {
                s.focus = (s.focus + 1) % 2; // two options — prev == next
            }
            Ok(false)
        }
        Action::SafetyChangeConfirm => {
            // Activate whichever option is focused.
            let focus = match &app.modal {
                Modal::SafetyNumberChanged(s) => s.focus,
                _ => return Ok(false),
            };
            if focus == 0 {
                return Box::pin(handle_action(Action::SafetyChangeVerify, app)).await;
            }
            Box::pin(handle_action(Action::SafetyChangeBlock, app)).await
        }
        Action::SafetyChangeVerify => {
            // Re-verify the (possibly new) key out-of-band via SAS. The drift
            // message stays dropped; SAS is the safe way to re-establish trust.
            let (room_id, fp) = match &app.modal {
                Modal::SafetyNumberChanged(s) => (s.room_id.clone(), s.fingerprint.clone()),
                _ => return Ok(false),
            };
            match app.handle.sas_start(&room_id, &fp).await {
                Ok(tx_id) => {
                    app.modal = Modal::Sas(SasState {
                        room_id,
                        partner_fingerprint: fp,
                        tx_id,
                        stage: SasStage::Waiting,
                    });
                }
                Err(e) => app.modal = Modal::Error(format!("SAS start failed: {e}")),
            }
            Ok(false)
        }
        Action::SafetyChangeBlock => {
            let fp = match &app.modal {
                Modal::SafetyNumberChanged(s) => s.fingerprint.clone(),
                _ => return Ok(false),
            };
            match app.handle.block_peer(&fp) {
                Ok(()) => app.set_status(format!("blocked {}", short_fp(&fp))),
                Err(e) => {
                    app.modal = Modal::Error(format!("block failed: {e}"));
                    return Ok(false);
                }
            }
            app.modal = Modal::None;
            Ok(false)
        }

        // ============================================================
        // huddle 2.0.0 (F5): change master passphrase
        // ============================================================
        Action::OpenChangePassphrase => {
            if !app.handle.has_master_passphrase() {
                app.set_status(
                    "no master passphrase to change (started with --no-master-passphrase)",
                );
                return Ok(false);
            }
            app.modal = Modal::ChangePassphrase(ChangePassphraseState::default());
            Ok(false)
        }
        Action::ChangePassTypeChar(c) => {
            if let Modal::ChangePassphrase(s) = &mut app.modal {
                let field = match s.focus {
                    PassField::Current => &mut s.current,
                    PassField::New => &mut s.new_pass,
                    PassField::Confirm => &mut s.confirm,
                };
                if field.chars().count() < 128 {
                    field.push(c);
                }
            }
            Ok(false)
        }
        Action::ChangePassBackspace => {
            if let Modal::ChangePassphrase(s) = &mut app.modal {
                match s.focus {
                    PassField::Current => s.current.pop(),
                    PassField::New => s.new_pass.pop(),
                    PassField::Confirm => s.confirm.pop(),
                };
            }
            Ok(false)
        }
        Action::ChangePassNextField => {
            if let Modal::ChangePassphrase(s) = &mut app.modal {
                s.focus = match s.focus {
                    PassField::Current => PassField::New,
                    PassField::New => PassField::Confirm,
                    PassField::Confirm => PassField::Current,
                };
            }
            Ok(false)
        }
        Action::ChangePassConfirm => {
            let (current, new_pass, confirm) = match &app.modal {
                Modal::ChangePassphrase(s) => {
                    (s.current.clone(), s.new_pass.clone(), s.confirm.clone())
                }
                _ => return Ok(false),
            };
            // Local validation before touching the keychain.
            let local_err = if current.is_empty() {
                Some("enter your current passphrase")
            } else if new_pass.is_empty() {
                Some("new passphrase must not be empty")
            } else if new_pass != confirm {
                Some("new passphrase and confirmation don't match")
            } else {
                None
            };
            if let Some(msg) = local_err {
                if let Modal::ChangePassphrase(s) = &mut app.modal {
                    s.error = Some(msg.to_string());
                    s.focus = PassField::Current;
                }
                return Ok(false);
            }
            match app
                .handle
                .change_master_passphrase(&current, &new_pass)
                .await
            {
                Ok(()) => {
                    // PassphraseChanged event closes the modal + sets status.
                    app.modal = Modal::None;
                    app.set_status("master passphrase updated — database re-keyed");
                }
                Err(e) => {
                    if let Modal::ChangePassphrase(s) = &mut app.modal {
                        s.error = Some(format!("{e}"));
                        s.current.clear();
                        s.focus = PassField::Current;
                    }
                }
            }
            Ok(false)
        }

        // ============================================================
        // huddle 2.0.0 (F6): export identity seed phrase
        // ============================================================
        Action::OpenExportSeed => {
            match app.handle.export_seed_phrase() {
                Ok(phrase) => {
                    app.modal = Modal::ExportSeed(ExportSeedState {
                        phrase,
                        revealed: false,
                        reentry: String::new(),
                        error: None,
                        step: ExportStep::Reveal,
                    });
                }
                Err(e) => app.set_status(format!("seed export unavailable: {e}")),
            }
            Ok(false)
        }
        Action::ExportSeedToggleReveal => {
            if let Modal::ExportSeed(s) = &mut app.modal {
                if s.step == ExportStep::Reveal {
                    s.revealed = !s.revealed;
                }
            }
            Ok(false)
        }
        Action::ExportSeedTypeChar(c) => {
            if let Modal::ExportSeed(s) = &mut app.modal {
                if s.step == ExportStep::Reentry && s.reentry.chars().count() < 320 {
                    s.reentry.push(c);
                }
            }
            Ok(false)
        }
        Action::ExportSeedBackspace => {
            if let Modal::ExportSeed(s) = &mut app.modal {
                if s.step == ExportStep::Reentry {
                    s.reentry.pop();
                }
            }
            Ok(false)
        }
        Action::ExportSeedConfirm => {
            // Step machine: Reveal → Reentry → (verify) → Done → close.
            let step = match &app.modal {
                Modal::ExportSeed(s) => s.step,
                _ => return Ok(false),
            };
            match step {
                ExportStep::Reveal => {
                    if let Modal::ExportSeed(s) = &mut app.modal {
                        s.step = ExportStep::Reentry;
                        s.error = None;
                    }
                }
                ExportStep::Reentry => {
                    let entered = match &app.modal {
                        Modal::ExportSeed(s) => s.reentry.clone(),
                        _ => return Ok(false),
                    };
                    match app.handle.verify_seed_reentry(&entered) {
                        Ok(true) => {
                            if let Modal::ExportSeed(s) = &mut app.modal {
                                s.step = ExportStep::Done;
                                s.error = None;
                            }
                        }
                        Ok(false) => {
                            if let Modal::ExportSeed(s) = &mut app.modal {
                                s.error = Some(
                                    "that doesn't match — re-type the 24 words exactly".into(),
                                );
                                s.reentry.clear();
                            }
                        }
                        Err(e) => {
                            if let Modal::ExportSeed(s) = &mut app.modal {
                                s.error = Some(format!("{e}"));
                                s.reentry.clear();
                            }
                        }
                    }
                }
                ExportStep::Done => {
                    app.modal = Modal::None;
                    app.set_status("seed phrase verified — store it somewhere safe & offline");
                }
            }
            Ok(false)
        }

        // ============================================================
        // huddle 2.0.0 (F9): toggle disappearing messages for this room
        // ============================================================
        Action::ToggleDisappearingMessages => {
            let room_id = match app.active_room() {
                Some(r) => r.room_id.clone(),
                None => return Ok(false),
            };
            // None → arm with the 1-hour default; Some → turn it off.
            let next = match app.handle.room_disappearing_ttl(&room_id) {
                Some(_) => None,
                None => Some(DEFAULT_DISAPPEARING_TTL_SECS),
            };
            match app.handle.set_room_disappearing_ttl(&room_id, next).await {
                Ok(()) => {
                    let msg = match next {
                        Some(secs) => format!(
                            "disappearing messages on — expire after {}",
                            crate::ui::pane::chat_common::format_ttl(secs)
                        ),
                        None => "disappearing messages off".to_string(),
                    };
                    app.set_status(msg);
                }
                Err(e) => app.modal = Modal::Error(format!("couldn't change expiry: {e}")),
            }
            Ok(false)
        }

        // ============================================================
        // huddle 2.0.0 (F10): reactions / replies / edits / deletes
        // ============================================================
        Action::MsgSelectPrev => {
            app.move_selected_msg(-1);
            Ok(false)
        }
        Action::MsgSelectNext => {
            app.move_selected_msg(1);
            Ok(false)
        }
        Action::ReactSelected => {
            let room_id = match app.active_room() {
                Some(r) => r.room_id.clone(),
                None => return Ok(false),
            };
            match app.active_target_msg_id() {
                Some(target) => {
                    app.modal = Modal::EmojiPicker(EmojiPickerState {
                        room_id,
                        target_msg_id: target,
                        selected: 0,
                    });
                }
                None => app.set_status("no reactable message here (pre-2.0 messages have no id)"),
            }
            Ok(false)
        }
        Action::ReplySelected => {
            let target = match app.active_target_msg_id() {
                Some(t) => t,
                None => {
                    app.set_status("nothing to reply to here (pre-2.0 messages have no id)");
                    return Ok(false);
                }
            };
            if let Some(r) = app.active_room_mut() {
                r.reply_to = Some(target);
                r.editing_msg = None;
                r.input_active = true;
            }
            app.set_status("replying — type your message, Esc to cancel");
            Ok(false)
        }
        Action::EditSelected => {
            // Only the original sender (our outbound messages) or a room owner
            // may edit; mirror the core's authorization so we don't offer an
            // affordance that will just bounce.
            let room_id = match app.active_room() {
                Some(r) => r.room_id.clone(),
                None => return Ok(false),
            };
            let we_own = app.handle.we_are_owner(&room_id);
            let target = app.active_target_message().and_then(|m| {
                let mine = m.direction == "out";
                if (mine || we_own) && m.client_msg_id.is_some() {
                    m.client_msg_id.clone().map(|id| (id, m.body.clone()))
                } else {
                    None
                }
            });
            match target {
                Some((id, body)) => {
                    if let Some(r) = app.active_room_mut() {
                        r.editing_msg = Some(id);
                        r.reply_to = None;
                        r.input = body;
                        r.input_active = true;
                    }
                    app.set_status("editing — Enter to save, Esc to cancel");
                }
                None => app.set_status("can't edit that message (not yours / pre-2.0)"),
            }
            Ok(false)
        }
        Action::DeleteSelected => {
            let room_id = match app.active_room() {
                Some(r) => r.room_id.clone(),
                None => return Ok(false),
            };
            let we_own = app.handle.we_are_owner(&room_id);
            let target = app.active_target_message().and_then(|m| {
                let mine = m.direction == "out";
                if (mine || we_own) && m.client_msg_id.is_some() {
                    m.client_msg_id.clone()
                } else {
                    None
                }
            });
            match target {
                Some(id) => {
                    app.modal = Modal::ConfirmDelete(ConfirmDeleteState {
                        room_id,
                        target_msg_id: id,
                    });
                }
                None => app.set_status("can't delete that message (not yours / pre-2.0)"),
            }
            Ok(false)
        }
        Action::EmojiPickerNext => {
            if let Modal::EmojiPicker(s) = &mut app.modal {
                if s.selected + 1 < REACTION_EMOJIS.len() {
                    s.selected += 1;
                }
            }
            Ok(false)
        }
        Action::EmojiPickerPrev => {
            if let Modal::EmojiPicker(s) = &mut app.modal {
                s.selected = s.selected.saturating_sub(1);
            }
            Ok(false)
        }
        Action::EmojiPickerConfirm => {
            let (room_id, target, emoji) = match &app.modal {
                Modal::EmojiPicker(s) => (
                    s.room_id.clone(),
                    s.target_msg_id.clone(),
                    REACTION_EMOJIS
                        .get(s.selected)
                        .copied()
                        .unwrap_or("👍")
                        .to_string(),
                ),
                _ => return Ok(false),
            };
            app.modal = Modal::None;
            if let Err(e) = app
                .handle
                .send_reaction(&room_id, &target, &emoji, false)
                .await
            {
                app.modal = Modal::Error(format!("reaction failed: {e}"));
            }
            Ok(false)
        }
        Action::ConfirmDeleteYes => {
            let (room_id, target) = match &app.modal {
                Modal::ConfirmDelete(s) => (s.room_id.clone(), s.target_msg_id.clone()),
                _ => return Ok(false),
            };
            app.modal = Modal::None;
            if let Err(e) = app.handle.delete_message(&room_id, &target).await {
                app.modal = Modal::Error(format!("delete failed: {e}"));
            } else {
                app.set_status("message deleted (best effort across peers)");
            }
            Ok(false)
        }
    }
}
