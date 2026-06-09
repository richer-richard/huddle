//! The chat pane — shared by DMs and group rooms. Header (+ actions), optional
//! members side panel, sender-grouped message list with day separators and
//! avatars, inline attachment cards, and the composer.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use egui::{Align, Id, Key, Label, Layout, RichText, Sense, TextEdit};
use huddle_core::app::{AppHandle, RoomTransport};
use huddle_core::storage::repo::{AttachmentStatus, RoomKind};

use crate::fmt;
use crate::model::{ttl_label, UiAction, ViewModel};
use crate::theme::palette;
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
    // Which transport this conversation is currently riding (status only).
    let transport = handle.room_transport(room_id);
    // huddle 1.2: whether a typed message can actually be delivered right now.
    // Gates the composer so we never echo an undeliverable message.
    let readiness = handle.room_send_readiness(room_id);

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
                ui.label(
                    RichText::new("encrypted")
                        .color(palette().encrypted)
                        .small(),
                );
            }
            ui.label(
                RichText::new(format!("· {} members", room.members.len()))
                    .small()
                    .color(palette().text_dim),
            );
            // huddle 2.0.0 (F9): disappearing-messages indicator.
            if let Some(secs) = room.ttl_secs {
                ui.label(
                    RichText::new(format!("· ⏲ disappears in {}", ttl_label(secs)))
                        .small()
                        .color(palette().warn),
                );
            }
            // Per-chat transport badge (lan / relay / offline) — status only.
            let (glyph, label, color) = match transport {
                RoomTransport::LanDirect => ("●", "lan", palette().success),
                RoomTransport::Relay => ("◈", "relay", palette().accent),
                RoomTransport::Offline => ("○", "offline", palette().text_dim),
            };
            ui.label(RichText::new(glyph).color(color));
            ui.label(RichText::new(label).small().color(color));
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
                // huddle 2.0.0 (F9): per-room disappearing-messages TTL.
                if ui
                    .button("Timer")
                    .on_hover_text("disappearing messages")
                    .clicked()
                {
                    actions.push(UiAction::OpenDisappearing(room_id.to_string()));
                }
                if ui.button("Attach").clicked() {
                    actions.push(UiAction::AttachFile(room_id.to_string()));
                }
            });
        });
        ui.add_space(4.0);
    });

    // Composer (bottom). `.resizable(false)` so the panel collapses to its
    // content height instead of inheriting egui's resizable default, which
    // reserved a tall remembered band and left empty space under the input.
    egui::Panel::bottom(Id::new(("chat-comp", room_id)))
        .resizable(false)
        .show_inside(ui, |ui| {
            ui.add_space(4.0);
            if !typers.is_empty() {
                ui.label(
                    RichText::new(format!("{} typing…", typers.join(", ")))
                        .italics()
                        .small()
                        .color(palette().text_dim),
                );
            }
            // huddle 1.2: when no transport can carry the message, don't pretend
            // it sent — show why and keep the user's text intact (no echo).
            let can_send = readiness.can_send();
            if !can_send {
                ui.label(
                    RichText::new(format!("○ {}", readiness.reason()))
                        .small()
                        .color(palette().error),
                );
            }
            // huddle 2.0.0 (F10): reply / edit context banners above the composer.
            // Snapshotted so the send routing below can read them after `room.input`
            // is taken.
            let editing = room.edit_target.clone();
            let replying = room.reply_to.clone();
            if editing.is_some() {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("editing message")
                            .small()
                            .color(palette().accent),
                    );
                    if ui.small_button("cancel").clicked() {
                        actions.push(UiAction::CancelEdit(room_id.to_string()));
                    }
                });
            } else if let Some((_, preview)) = &replying {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("replying to: {preview}"))
                            .small()
                            .color(palette().text_dim),
                    );
                    if ui.small_button("cancel").clicked() {
                        actions.push(UiAction::CancelReply(room_id.to_string()));
                    }
                });
            }
            ui.horizontal(|ui| {
                let btn_w = 64.0;
                let resp = ui.add_sized(
                    [ui.available_width() - btn_w - 8.0, 28.0],
                    TextEdit::singleline(&mut room.input).hint_text(if !can_send {
                        "waiting for connection…"
                    } else if editing.is_some() {
                        "edit your message…"
                    } else {
                        "message…"
                    }),
                );
                if resp.changed() && !room.input.is_empty() && can_send && editing.is_none() {
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
                let send_label = if editing.is_some() { "Save" } else { "Send" };
                let clicked = ui
                    .add_enabled(can_send, egui::Button::new(send_label))
                    .clicked();
                if can_send && (enter || clicked) && !room.input.trim().is_empty() {
                    let body = std::mem::take(&mut room.input);
                    if let Some(target) = editing.clone() {
                        actions.push(UiAction::SendEdit {
                            room_id: room_id.to_string(),
                            target_msg_id: target,
                            new_body: body,
                        });
                    } else if let Some((target, _)) = replying.clone() {
                        actions.push(UiAction::SendReply {
                            room_id: room_id.to_string(),
                            body,
                            reply_to: target,
                        });
                    } else {
                        actions.push(UiAction::SendMessage {
                            room_id: room_id.to_string(),
                            body,
                        });
                    }
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
                ui.label(
                    RichText::new("MEMBERS")
                        .strong()
                        .small()
                        .color(palette().text_dim),
                );
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
                                    ui.label(
                                        RichText::new("owner").small().color(palette().accent),
                                    );
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
                                        if !owners.contains(m) && ui.small_button("grant").clicked()
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
                ui.label(RichText::new("no messages yet — say hello").color(palette().text_dim));
            }
            let mut last_sender: Option<String> = None;
            let mut last_day: Option<i64> = None;
            let mut last_ts: Option<i64> = None;
            // huddle 1.2.3: render chronologically (mirrors the TUI's sort) so a
            // peer message that arrives with a slightly behind sent_at can't
            // land out of order or break the gap grouping. Stable, so equal
            // timestamps keep arrival order.
            let mut ordered: Vec<&_> = room.messages.iter().collect();
            ordered.sort_by_key(|m| m.sent_at);
            // huddle 2.0.0 (F10): index messages by their stable id so a reply can
            // render a quote of its target (attribution + one-line preview).
            let by_id: HashMap<String, (String, String)> = room
                .messages
                .iter()
                .filter_map(|mm| {
                    mm.client_msg_id.as_deref().map(|id| {
                        let who = if mm.sender_fingerprint == our_fp {
                            "you".to_string()
                        } else {
                            peer_labels
                                .get(&mm.sender_fingerprint)
                                .cloned()
                                .unwrap_or_else(|| fmt::display_id(&mm.sender_fingerprint))
                        };
                        let preview = if mm.deleted_at.is_some() {
                            "[deleted]".to_string()
                        } else {
                            msg_preview(&mm.body)
                        };
                        (id.to_string(), (who, preview))
                    })
                })
                .collect();
            for m in ordered {
                let day = fmt::day_bucket(m.sent_at);
                let day_changed = last_day != Some(day);
                if day_changed {
                    last_day = Some(day);
                    ui.add_space(8.0);
                    ui.vertical_centered(|ui| {
                        ui.label(
                            RichText::new(fmt::ymd_string(m.sent_at))
                                .small()
                                .color(palette().text_dim),
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
                // huddle 1.2.3: start a fresh, timestamped group not only when the
                // sender changes, but also after a quiet gap or a day change — so
                // a message sent minutes later shows its own time instead of
                // running on under the previous one's header.
                let gap_big = last_ts
                    .map(|t| m.sent_at - t >= huddle_core::app::MESSAGE_GROUP_GAP_SECS)
                    .unwrap_or(true);
                let new_group = day_changed
                    || gap_big
                    || last_sender.as_deref() != Some(m.sender_fingerprint.as_str());
                last_sender = Some(m.sender_fingerprint.clone());
                last_ts = Some(m.sent_at);

                if new_group {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        widgets::avatar::show(ui, 26.0, &m.sender_fingerprint, &sender_label);
                        ui.label(RichText::new(&sender_label).strong().color(if is_me {
                            palette().accent
                        } else {
                            palette().text
                        }));
                        ui.label(
                            RichText::new(format!("{} UTC", fmt::hms(m.sent_at)))
                                .small()
                                .color(palette().text_dim),
                        );
                    });
                }

                // huddle 2.0.0 (F10): reply quote — the targeted message's
                // attribution + a one-line preview above this message.
                if let Some(rt) = m.reply_to.as_deref() {
                    if let Some((who, preview)) = by_id.get(rt) {
                        ui.horizontal(|ui| {
                            ui.add_space(6.0);
                            ui.label(
                                RichText::new(format!("↩ {who}: {preview}"))
                                    .small()
                                    .italics()
                                    .color(palette().text_dim),
                            );
                        });
                    }
                }

                // huddle 2.0.0 (F10): deleted messages render as a tombstone —
                // no body, reactions, or affordances.
                if m.deleted_at.is_some() {
                    ui.label(
                        RichText::new("[deleted]")
                            .italics()
                            .color(palette().text_dim),
                    );
                    continue;
                }

                // Body (right-click for actions), with an [edited] marker.
                let body_resp = ui.add(Label::new(&m.body).wrap().sense(Sense::click()));
                if m.edited_at.is_some() {
                    ui.label(RichText::new("(edited)").small().color(palette().text_dim));
                }

                // Affordances + reaction badges only exist for messages carrying
                // a stable id (pre-2.0 peers' messages can't be targeted).
                if let Some(cid) = m.client_msg_id.clone() {
                    let preview = msg_preview(&m.body);
                    let body = m.body.clone();
                    body_resp.context_menu(|ui| {
                        if ui.button("React…").clicked() {
                            actions.push(UiAction::OpenEmojiPicker {
                                room_id: room_id.to_string(),
                                target_msg_id: cid.clone(),
                            });
                            ui.close();
                        }
                        if ui.button("Reply").clicked() {
                            actions.push(UiAction::StartReply {
                                room_id: room_id.to_string(),
                                target_msg_id: cid.clone(),
                                preview: preview.clone(),
                            });
                            ui.close();
                        }
                        // Edit is sender-only; delete is sender-or-owner (the core
                        // re-checks and rejects otherwise).
                        if is_me && ui.button("Edit").clicked() {
                            actions.push(UiAction::StartEdit {
                                room_id: room_id.to_string(),
                                target_msg_id: cid.clone(),
                                body: body.clone(),
                            });
                            ui.close();
                        }
                        if (is_me || we_own) && ui.button("Delete").clicked() {
                            actions.push(UiAction::OpenConfirmDelete {
                                room_id: room_id.to_string(),
                                target_msg_id: cid.clone(),
                                preview: preview.clone(),
                            });
                            ui.close();
                        }
                    });

                    // Reaction pills (click to toggle) + quick react / reply.
                    let groups = room.reactions_for(&cid, &our_fp);
                    ui.horizontal_wrapped(|ui| {
                        for (emoji, count, mine) in &groups {
                            if ui
                                .selectable_label(*mine, format!("{emoji} {count}"))
                                .clicked()
                            {
                                actions.push(UiAction::SendReaction {
                                    room_id: room_id.to_string(),
                                    target_msg_id: cid.clone(),
                                    emoji: emoji.clone(),
                                    removed: *mine,
                                });
                            }
                        }
                        if ui.small_button("+ react").clicked() {
                            actions.push(UiAction::OpenEmojiPicker {
                                room_id: room_id.to_string(),
                                target_msg_id: cid.clone(),
                            });
                        }
                        if ui.small_button("reply").clicked() {
                            actions.push(UiAction::StartReply {
                                room_id: room_id.to_string(),
                                target_msg_id: cid.clone(),
                                preview: preview.clone(),
                            });
                        }
                    });
                }
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

/// huddle 2.0.0 (F10): one-line, length-capped preview of a message body for
/// reply quotes and the delete confirmation.
fn msg_preview(body: &str) -> String {
    let single: String = body
        .chars()
        .map(|c| if c == '\n' { ' ' } else { c })
        .collect();
    let trimmed = single.trim();
    if trimmed.chars().count() > 60 {
        format!("{}…", trimmed.chars().take(57).collect::<String>())
    } else {
        trimmed.to_string()
    }
}

fn attachment_card(
    ui: &mut egui::Ui,
    room_id: &str,
    a: &huddle_core::storage::repo::StoredAttachment,
    actions: &mut Vec<UiAction>,
) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new("file").small().color(palette().text_dim));
            ui.label(RichText::new(&a.name).strong());
            ui.label(
                RichText::new(format!("{} KB", (a.size_bytes / 1024).max(1)))
                    .small()
                    .color(palette().text_dim),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| match a.status {
                AttachmentStatus::Offered | AttachmentStatus::Downloading => {
                    if ui.button("Cancel").clicked() {
                        actions.push(UiAction::CancelAttachment {
                            room_id: room_id.to_string(),
                            file_id: a.file_id.clone(),
                        });
                    }
                    ui.label(RichText::new("downloading…").small().color(palette().warn));
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
                    ui.label(RichText::new("saved").small().color(palette().success));
                }
                AttachmentStatus::Failed => {
                    ui.label(RichText::new("failed").small().color(palette().error));
                }
                AttachmentStatus::Cancelled => {
                    ui.label(RichText::new("cancelled").small().color(palette().text_dim));
                }
            });
        });
    });
}
