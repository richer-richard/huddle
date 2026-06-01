//! The chat pane — shared by DMs and group rooms. Header (+ actions), optional
//! members side panel, sender-grouped message list with day separators and
//! avatars, inline attachment cards, and the composer.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use egui::{Align, Id, Key, Label, Layout, RichText, TextEdit};
use huddle_core::app::AppHandle;
use huddle_core::storage::repo::{AttachmentStatus, RoomKind};

use crate::fmt;
use crate::model::{UiAction, ViewModel};
use crate::theme::PALETTE;
use crate::widgets;

const TYPING_DEBOUNCE: Duration = Duration::from_millis(800);

pub fn render(
    ui: &mut egui::Ui,
    vm: &mut ViewModel,
    handle: &AppHandle,
    room_id: &str,
    actions: &mut Vec<UiAction>,
) {
    // Snapshot read-only bits before borrowing the room mutably.
    let our_fp = vm.our_fp.clone();
    let header_label = vm.room_label(room_id);
    let show_members = vm.show_member_panel;
    let typers: Vec<String> = handle
        .typers_in_room(room_id)
        .iter()
        .map(|fp| vm.peer_label(fp))
        .collect();
    let peer_labels = vm.peer_labels.clone();
    let we_own = handle.we_are_owner(room_id);
    let owners: HashSet<String> = handle.room_owners(room_id).into_iter().collect();
    let verified: HashSet<String> = handle.verified_fingerprints(room_id).into_iter().collect();
    let room_vonly = handle.room_verified_only(room_id);

    let Some(room) = vm.open_room_mut(room_id) else {
        ui.centered_and_justified(|ui| {
            ui.label("opening room…");
        });
        return;
    };
    let is_group = room.kind == RoomKind::Group;

    // Header with actions.
    egui::Panel::top(Id::new(("chat-head", room_id))).show_inside(ui, |ui| {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let title = if is_group {
                format!("# {header_label}")
            } else {
                header_label.clone()
            };
            ui.heading(title);
            if room.encrypted {
                ui.label(RichText::new("encrypted").color(PALETTE.encrypted).small());
            }
            ui.label(
                RichText::new(format!("· {} members", room.members.len()))
                    .small()
                    .color(PALETTE.text_dim),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("Leave").clicked() {
                    actions.push(UiAction::LeaveRoom(room_id.to_string()));
                }
                if is_group {
                    if ui.button("Invite").clicked() {
                        actions.push(UiAction::GenerateInvite(room_id.to_string()));
                    }
                    if room.encrypted {
                        if ui.button("Code").clicked() {
                            actions.push(UiAction::GenerateJoinCode(room_id.to_string()));
                        }
                        if we_own && ui.button("Rotate").clicked() {
                            actions.push(UiAction::OpenRotate(room_id.to_string()));
                        }
                    }
                    if ui.selectable_label(show_members, "Members").clicked() {
                        actions.push(UiAction::ToggleMemberPanel);
                    }
                }
                if ui.button("Verify").clicked() {
                    actions.push(UiAction::OpenVerify(room_id.to_string()));
                }
                if ui.button("Search").clicked() {
                    actions.push(UiAction::OpenSearch(room_id.to_string()));
                }
                if ui.button("Attach").clicked() {
                    actions.push(UiAction::AttachFile(room_id.to_string()));
                }
            });
        });
        ui.add_space(4.0);
    });

    // Composer (bottom).
    egui::Panel::bottom(Id::new(("chat-comp", room_id))).show_inside(ui, |ui| {
        ui.add_space(4.0);
        if !typers.is_empty() {
            ui.label(
                RichText::new(format!("{} typing…", typers.join(", ")))
                    .italics()
                    .small()
                    .color(PALETTE.text_dim),
            );
        }
        ui.horizontal(|ui| {
            let btn_w = 64.0;
            let resp = ui.add_sized(
                [ui.available_width() - btn_w - 8.0, 28.0],
                TextEdit::singleline(&mut room.input).hint_text("message…"),
            );
            if resp.changed() && !room.input.is_empty() {
                let now = Instant::now();
                let due = room
                    .last_typing_sent
                    .is_none_or(|t| now.duration_since(t) > TYPING_DEBOUNCE);
                if due {
                    room.last_typing_sent = Some(now);
                    actions.push(UiAction::TypingPing(room_id.to_string()));
                }
            }
            let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
            let clicked = ui.button("Send").clicked();
            if (enter || clicked) && !room.input.trim().is_empty() {
                let body = std::mem::take(&mut room.input);
                actions.push(UiAction::SendMessage {
                    room_id: room_id.to_string(),
                    body,
                });
                room.stick_to_bottom = true;
                resp.request_focus();
            }
        });
        ui.add_space(4.0);
    });

    // Members side panel (group rooms).
    if show_members && is_group {
        egui::Panel::right(Id::new(("chat-members", room_id)))
            .resizable(true)
            .default_size(230.0)
            .show_inside(ui, |ui| {
                ui.add_space(6.0);
                ui.label(RichText::new("MEMBERS").strong().small().color(PALETTE.text_dim));
                let mut vonly = room_vonly;
                if ui.checkbox(&mut vonly, "verified-only").changed() {
                    actions.push(UiAction::ToggleRoomVerifiedOnly {
                        room_id: room_id.to_string(),
                        on: vonly,
                    });
                }
                ui.separator();
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for m in &room.members {
                            let me = m == &our_fp;
                            let label = if me {
                                "you".to_string()
                            } else {
                                peer_labels
                                    .get(m)
                                    .cloned()
                                    .unwrap_or_else(|| fmt::display_id(m))
                            };
                            ui.horizontal(|ui| {
                                widgets::avatar::show(ui, 22.0, m, &label);
                                ui.label(&label);
                                if verified.contains(m) {
                                    widgets::verified_tick(ui);
                                }
                                if owners.contains(m) {
                                    ui.label(RichText::new("owner").small().color(PALETTE.accent));
                                }
                            });
                            if !me {
                                ui.horizontal(|ui| {
                                    ui.add_space(26.0);
                                    if ui.small_button("SAS").clicked() {
                                        actions.push(UiAction::StartSas {
                                            room_id: room_id.to_string(),
                                            fingerprint: m.clone(),
                                        });
                                    }
                                    if we_own {
                                        if !owners.contains(m)
                                            && ui.small_button("grant").clicked()
                                        {
                                            actions.push(UiAction::DoGrant {
                                                room_id: room_id.to_string(),
                                                fingerprint: m.clone(),
                                            });
                                        }
                                        if ui.small_button("kick").clicked() {
                                            actions.push(UiAction::DoKick {
                                                room_id: room_id.to_string(),
                                                fingerprint: m.clone(),
                                            });
                                        }
                                    }
                                });
                            }
                        }
                    });
            });
    }

    // Message list (fills remaining space).
    egui::ScrollArea::vertical()
        .stick_to_bottom(room.stick_to_bottom)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if room.messages.is_empty() && room.attachments.is_empty() {
                ui.add_space(12.0);
                ui.label(RichText::new("no messages yet — say hello").color(PALETTE.text_dim));
            }
            let mut last_sender: Option<String> = None;
            let mut last_day: Option<i64> = None;
            for m in &room.messages {
                let day = fmt::day_bucket(m.sent_at);
                if last_day != Some(day) {
                    last_day = Some(day);
                    ui.add_space(8.0);
                    ui.vertical_centered(|ui| {
                        ui.label(
                            RichText::new(fmt::ymd_string(m.sent_at))
                                .small()
                                .color(PALETTE.text_dim),
                        );
                    });
                }
                let is_me = m.sender_fingerprint == our_fp;
                let sender_label = if is_me {
                    "you".to_string()
                } else {
                    peer_labels
                        .get(&m.sender_fingerprint)
                        .cloned()
                        .unwrap_or_else(|| fmt::display_id(&m.sender_fingerprint))
                };
                let new_group = last_sender.as_deref() != Some(m.sender_fingerprint.as_str());
                last_sender = Some(m.sender_fingerprint.clone());

                if new_group {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        widgets::avatar::show(ui, 26.0, &m.sender_fingerprint, &sender_label);
                        ui.label(
                            RichText::new(&sender_label)
                                .strong()
                                .color(if is_me { PALETTE.accent } else { PALETTE.text }),
                        );
                        ui.label(
                            RichText::new(fmt::hhmm(m.sent_at))
                                .small()
                                .color(PALETTE.text_dim),
                        );
                    });
                }
                ui.add(Label::new(&m.body).wrap());
            }

            // Attachment cards.
            if !room.attachments.is_empty() {
                ui.add_space(8.0);
                ui.separator();
                for a in &room.attachments {
                    attachment_card(ui, room_id, a, actions);
                }
            }
        });
}

fn attachment_card(
    ui: &mut egui::Ui,
    room_id: &str,
    a: &huddle_core::storage::repo::StoredAttachment,
    actions: &mut Vec<UiAction>,
) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new("file").small().color(PALETTE.text_dim));
            ui.label(RichText::new(&a.name).strong());
            ui.label(
                RichText::new(format!("{} KB", (a.size_bytes / 1024).max(1)))
                    .small()
                    .color(PALETTE.text_dim),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| match a.status {
                AttachmentStatus::Offered | AttachmentStatus::Downloading => {
                    if ui.button("Cancel").clicked() {
                        actions.push(UiAction::CancelAttachment {
                            room_id: room_id.to_string(),
                            file_id: a.file_id.clone(),
                        });
                    }
                    ui.label(RichText::new("downloading…").small().color(PALETTE.warn));
                }
                AttachmentStatus::Ready => {
                    if ui.button("Save").clicked() {
                        actions.push(UiAction::SaveAttachment {
                            room_id: room_id.to_string(),
                            file_id: a.file_id.clone(),
                        });
                    }
                }
                AttachmentStatus::Saved => {
                    if ui.button("Open").clicked() {
                        actions.push(UiAction::OpenAttachment {
                            room_id: room_id.to_string(),
                            file_id: a.file_id.clone(),
                        });
                    }
                    ui.label(RichText::new("saved").small().color(PALETTE.success));
                }
                AttachmentStatus::Failed => {
                    ui.label(RichText::new("failed").small().color(PALETTE.error));
                }
                AttachmentStatus::Cancelled => {
                    ui.label(RichText::new("cancelled").small().color(PALETTE.text_dim));
                }
            });
        });
    });
}
