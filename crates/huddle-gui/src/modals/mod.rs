//! Modal overlays, rendered with egui's `Modal` container (centered, dimmed
//! backdrop that blocks the rest of the UI). Each modal mutates its own state
//! and pushes `UiAction`s on submit / cancel; the app applies them after the
//! frame and owns the actual `AppHandle` calls.

use egui::{Id, RichText, TextEdit};

use crate::fmt;
use crate::model::{
    AcceptRotationState, AddContactState, AttachPathState, ChangePassphraseState,
    ConfirmDeleteState, ConfirmInviteState, DisappearingState, EditAliasState, EditUsernameState,
    EmojiPickerState, ExportSeedState, ExportSeedStep, GoDarkState, InboundDialState, JoinState,
    JoinWithCodeState, Modal, NewDmState, NewGroupState, PasteInviteState, RotateState,
    SafetyNumberChangedState, SasStage, SasState, SearchState, SetRelayState, UiAction,
    VerifyState, DISAPPEARING_OPTIONS, GO_DARK_CONFIRM_PHRASE, ONBOARDING_PAGES, REACTION_EMOJIS,
};
use crate::theme::palette;

fn right<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) {
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), add);
}

pub fn render(ctx: &egui::Context, modal: &mut Modal, our_id: &str, actions: &mut Vec<UiAction>) {
    match modal {
        Modal::None => {}
        Modal::NewGroup(s) => new_group(ctx, s, actions),
        Modal::NewDm(s) => new_dm(ctx, s, actions),
        Modal::AddContact(s) => add_contact(ctx, s, actions),
        Modal::EditAlias(s) => edit_alias(ctx, s, actions),
        Modal::Join(s) => join(ctx, s, actions),
        Modal::InboundDial(s) => inbound_dial(ctx, s, actions),
        Modal::Verify(s) => verify(ctx, s, actions),
        Modal::Sas(s) => sas(ctx, s, actions),
        Modal::Search(s) => search(ctx, s, actions),
        Modal::Rotate(s) => rotate(ctx, s, actions),
        Modal::AcceptRotation(s) => accept_rotation(ctx, s, actions),
        Modal::ShowInvite(url) => show_invite(ctx, url, actions),
        Modal::PasteInvite(s) => paste_invite(ctx, s, actions),
        Modal::ConfirmInvite(s) => confirm_invite(ctx, s, actions),
        Modal::SetRelay(s) => set_relay(ctx, s, actions),
        Modal::AttachPath(s) => attach_path(ctx, s, actions),
        Modal::JoinWithCode(s) => join_with_code(ctx, s, actions),
        Modal::EditUsername(s) => edit_username(ctx, s, actions),
        Modal::GoDark(s) => go_dark(ctx, s, actions),
        Modal::Qr => qr(ctx, our_id, actions),
        Modal::About => about(ctx, actions),
        Modal::Onboarding { cursor } => onboarding(ctx, *cursor, actions),
        Modal::UpdateOptIn => update_opt_in(ctx, actions),
        Modal::QuitConfirm => quit_confirm(ctx, actions),
        Modal::ChangePassphrase(s) => change_passphrase(ctx, s, actions),
        Modal::ExportSeed(s) => export_seed(ctx, s, actions),
        Modal::SafetyNumberChanged(s) => safety_number_changed(ctx, s, actions),
        Modal::Disappearing(s) => disappearing(ctx, s, actions),
        Modal::EmojiPicker(s) => emoji_picker(ctx, s, actions),
        Modal::ConfirmDelete(s) => confirm_delete(ctx, s, actions),
        Modal::Error(m) => message(ctx, "error", m, palette().error, actions),
        Modal::Info(m) => message(ctx, "huddle", m, palette().text, actions),
    }
}

/// huddle 2.0.0 (F5): change the master passphrase. Validates locally (non-empty
/// + new == confirm); the core verifies the current passphrase and re-keys the
/// DB. A wrong-current-passphrase error comes back tagged and lands in `s.error`.
fn change_passphrase(
    ctx: &egui::Context,
    s: &mut ChangePassphraseState,
    actions: &mut Vec<UiAction>,
) {
    let resp = egui::Modal::new(Id::new("modal-change-passphrase")).show(ctx, |ui| {
        ui.set_width(420.0);
        ui.heading("Change master passphrase");
        ui.label(
            RichText::new(
                "re-encrypts your local database under a new key. There is no recovery if \
                 you forget the new passphrase — keep a backup before changing it.",
            )
            .small()
            .color(palette().text_dim),
        );
        ui.add_space(10.0);
        ui.label("current passphrase");
        ui.add(
            TextEdit::singleline(&mut s.current)
                .password(true)
                .desired_width(f32::INFINITY),
        );
        ui.add_space(6.0);
        ui.label("new passphrase");
        ui.add(
            TextEdit::singleline(&mut s.new)
                .password(true)
                .desired_width(f32::INFINITY),
        );
        ui.add_space(6.0);
        ui.label("confirm new passphrase");
        ui.add(
            TextEdit::singleline(&mut s.confirm)
                .password(true)
                .desired_width(f32::INFINITY),
        );
        if let Some(e) = &s.error {
            ui.add_space(6.0);
            ui.colored_label(palette().error, e);
        }
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.button("Change passphrase").clicked() {
                if s.current.is_empty() {
                    s.error = Some("enter your current passphrase".into());
                } else if s.new.is_empty() {
                    s.error = Some("the new passphrase can't be empty".into());
                } else if s.new != s.confirm {
                    s.error = Some("the new passphrases don't match".into());
                } else {
                    s.error = None;
                    actions.push(UiAction::SubmitChangePassphrase {
                        current: s.current.clone(),
                        new: s.new.clone(),
                    });
                }
            }
            if ui.button("Cancel").clicked() {
                actions.push(UiAction::CloseModal);
            }
        });
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

/// huddle 2.0.0 (F6): show the 24-word identity seed once, then make the user
/// re-type it to prove they wrote it down before relying on it for recovery.
fn export_seed(ctx: &egui::Context, s: &mut ExportSeedState, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-export-seed")).show(ctx, |ui| {
        ui.set_width(460.0);
        ui.heading("Recovery seed phrase");
        match s.step {
            ExportSeedStep::Reveal => {
                ui.colored_label(
                    palette().error,
                    "⚠ Anyone with these 24 words IS you. Write them down on paper, never \
                     share them, and store them offline. This is shown only once.",
                );
                ui.add_space(10.0);
                let body = if s.revealed {
                    s.phrase.clone()
                } else {
                    "•••• •••• •••• ••••  (hidden)".to_string()
                };
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.add(
                        egui::Label::new(RichText::new(body).monospace().size(15.0))
                            .wrap()
                            .selectable(s.revealed),
                    );
                });
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui
                        .button(if s.revealed { "Hide" } else { "Reveal" })
                        .clicked()
                    {
                        s.revealed = !s.revealed;
                    }
                    if s.revealed && ui.button("Copy").clicked() {
                        actions.push(UiAction::Copy(s.phrase.clone()));
                    }
                    right(ui, |ui| {
                        if ui.button("I've written it down →").clicked() {
                            s.step = ExportSeedStep::Verify;
                            s.revealed = false;
                            s.error = None;
                        }
                    });
                });
            }
            ExportSeedStep::Verify => {
                ui.label("Re-type the full 24-word phrase to confirm your backup:");
                ui.add_space(8.0);
                ui.add(
                    // `&mut *s.reentry` exposes the inner `String` to egui; the
                    // `Zeroizing` wrapper still scrubs it on drop (F6).
                    TextEdit::multiline(&mut *s.reentry)
                        .desired_width(f32::INFINITY)
                        .desired_rows(3)
                        .hint_text("word1 word2 … word24"),
                );
                if let Some(e) = &s.error {
                    ui.add_space(6.0);
                    ui.colored_label(palette().error, e);
                }
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.button("Verify").clicked() {
                        actions.push(UiAction::ExportSeedVerify {
                            reentry: s.reentry.trim().to_string(),
                        });
                    }
                    if ui.button("Back").clicked() {
                        s.step = ExportSeedStep::Reveal;
                        s.error = None;
                    }
                });
            }
            ExportSeedStep::Done => {
                ui.add_space(8.0);
                ui.colored_label(palette().success, "✓ Backup verified.");
                ui.label(
                    RichText::new(
                        "store the paper somewhere safe. On a fresh install, choose \
                         “Import existing identity” and paste these words to restore.",
                    )
                    .small()
                    .color(palette().text_dim),
                );
                ui.add_space(12.0);
                if ui.button("Done").clicked() {
                    actions.push(UiAction::CloseModal);
                }
            }
        }
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

/// huddle 2.0.0 (F3): a pinned peer key changed mid-session (TOFU drift). The
/// offending message was already dropped; the user re-verifies (SAS) or blocks
/// the peer. "Dismiss" leaves the pin as-is (future messages from the new key
/// keep getting dropped until they re-verify).
fn safety_number_changed(
    ctx: &egui::Context,
    s: &SafetyNumberChangedState,
    actions: &mut Vec<UiAction>,
) {
    let who = s
        .display_name
        .clone()
        .unwrap_or_else(|| fmt::display_id(&s.fingerprint));
    let resp = egui::Modal::new(Id::new("modal-safety-number")).show(ctx, |ui| {
        ui.set_width(460.0);
        ui.heading(RichText::new(format!("⚠ Safety number changed: {who}")).color(palette().warn));
        ui.add_space(6.0);
        ui.label(
            "The identity key huddle pinned for this peer no longer matches the one signing \
             their messages. This happens if they reinstalled or rotated their identity — \
             but it can also be a sign of impersonation. Their last message was dropped.",
        );
        ui.add_space(8.0);
        ui.label(
            RichText::new(format!("peer: {}", fmt::display_id(&s.fingerprint)))
                .small()
                .monospace()
                .color(palette().text_dim),
        );
        ui.label(
            RichText::new(format!("old key: {}", short_key(&s.old_pubkey_b64)))
                .small()
                .monospace()
                .color(palette().text_dim),
        );
        ui.label(
            RichText::new(format!("new key: {}", short_key(&s.new_pubkey_b64)))
                .small()
                .monospace()
                .color(palette().text_dim),
        );
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.button("Re-verify (SAS)").clicked() {
                actions.push(UiAction::StartSas {
                    room_id: s.room_id.clone(),
                    fingerprint: s.fingerprint.clone(),
                });
            }
            if ui
                .button(RichText::new("Block peer").color(palette().error))
                .clicked()
            {
                actions.push(UiAction::PersonBlock(s.fingerprint.clone()));
                actions.push(UiAction::CloseModal);
            }
            right(ui, |ui| {
                if ui.button("Dismiss").clicked() {
                    actions.push(UiAction::CloseModal);
                }
            });
        });
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

/// First 10 chars of a base64 key, for a glanceable (non-authoritative) diff.
fn short_key(b64: &str) -> String {
    let head: String = b64.chars().take(10).collect();
    format!("{head}…")
}

/// huddle 2.0.0 (F9): pick the room's disappearing-messages TTL. Off by default;
/// only owners' choices propagate to other members (enforced in the core).
fn disappearing(ctx: &egui::Context, s: &DisappearingState, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-disappearing")).show(ctx, |ui| {
        ui.set_width(360.0);
        ui.heading("Disappearing messages");
        ui.label(
            RichText::new(
                "auto-delete messages in this room after they age out — locally, on every \
                 peer running huddle 2.0+. Best-effort (depends on each device's clock).",
            )
            .small()
            .color(palette().text_dim),
        );
        ui.add_space(10.0);
        for (label, ttl) in DISAPPEARING_OPTIONS {
            let selected = s.current == *ttl;
            if ui.selectable_label(selected, *label).clicked() && !selected {
                actions.push(UiAction::SetDisappearing {
                    room_id: s.room_id.clone(),
                    ttl_secs: *ttl,
                });
            }
        }
        ui.add_space(12.0);
        if ui.button("Cancel").clicked() {
            actions.push(UiAction::CloseModal);
        }
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

/// huddle 2.0.0 (F10): pick an emoji to react to a message with.
fn emoji_picker(ctx: &egui::Context, s: &EmojiPickerState, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-emoji-picker")).show(ctx, |ui| {
        ui.set_width(280.0);
        ui.heading("React");
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            for emoji in REACTION_EMOJIS {
                if ui.button(RichText::new(*emoji).size(22.0)).clicked() {
                    actions.push(UiAction::SendReaction {
                        room_id: s.room_id.clone(),
                        target_msg_id: s.target_msg_id.clone(),
                        emoji: (*emoji).to_string(),
                        removed: false,
                    });
                }
            }
        });
        ui.add_space(10.0);
        if ui.button("Cancel").clicked() {
            actions.push(UiAction::CloseModal);
        }
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

/// huddle 2.0.0 (F10): confirm a permanent (for-everyone) message delete.
fn confirm_delete(ctx: &egui::Context, s: &ConfirmDeleteState, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-confirm-delete")).show(ctx, |ui| {
        ui.set_width(380.0);
        ui.heading("Delete message?");
        ui.add_space(6.0);
        ui.label(
            RichText::new("This removes it for everyone in the room. It can't be undone.")
                .small()
                .color(palette().text_dim),
        );
        if !s.preview.is_empty() {
            ui.add_space(6.0);
            ui.label(
                RichText::new(format!("“{}”", s.preview))
                    .italics()
                    .color(palette().text_dim),
            );
        }
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui
                .button(RichText::new("Delete").color(palette().error))
                .clicked()
            {
                actions.push(UiAction::SendDelete {
                    room_id: s.room_id.clone(),
                    target_msg_id: s.target_msg_id.clone(),
                });
            }
            if ui.button("Cancel").clicked() {
                actions.push(UiAction::CloseModal);
            }
        });
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

fn edit_username(ctx: &egui::Context, s: &mut EditUsernameState, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-edit-username")).show(ctx, |ui| {
        ui.set_width(360.0);
        ui.heading("Edit username");
        ui.label(
            RichText::new("broadcast to peers you share rooms with. Empty clears it (you show as [anonymous]).")
                .small()
                .color(palette().text_dim),
        );
        ui.add_space(8.0);
        ui.add(TextEdit::singleline(&mut s.input).desired_width(f32::INFINITY).hint_text("display name"));
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if ui.button("Save").clicked() {
                let v = s.input.trim();
                actions.push(UiAction::SubmitUsername(if v.is_empty() {
                    None
                } else {
                    Some(v.to_string())
                }));
            }
            if ui.button("Cancel").clicked() {
                actions.push(UiAction::CloseModal);
            }
        });
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

fn go_dark(ctx: &egui::Context, s: &mut GoDarkState, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-go-dark")).show(ctx, |ui| {
        ui.set_width(420.0);
        ui.heading(RichText::new("Go dark").color(palette().error));
        ui.label(
            "This permanently deletes your account and wipes all local data. There is no undo.",
        );
        ui.add_space(10.0);
        if s.requires_passphrase {
            ui.label("enter your master passphrase to confirm");
            ui.add(
                TextEdit::singleline(&mut s.input)
                    .password(true)
                    .desired_width(f32::INFINITY),
            );
        } else {
            ui.label(format!("type `{GO_DARK_CONFIRM_PHRASE}` to confirm"));
            ui.add(TextEdit::singleline(&mut s.input).desired_width(f32::INFINITY));
        }
        if let Some(e) = &s.error {
            ui.add_space(6.0);
            ui.colored_label(palette().error, e);
        }
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui
                .button(RichText::new("Delete everything").color(palette().error))
                .clicked()
            {
                actions.push(UiAction::SubmitGoDark(s.input.clone()));
            }
            if ui.button("Cancel").clicked() {
                actions.push(UiAction::CloseModal);
            }
        });
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

fn qr(ctx: &egui::Context, data: &str, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-qr")).show(ctx, |ui| {
        ui.set_width(300.0);
        ui.heading("Your identity");
        ui.add_space(10.0);
        ui.vertical_centered(|ui| match qrcode::QrCode::new(data.as_bytes()) {
            Ok(code) => {
                let w = code.width();
                let colors = code.to_colors();
                let px = 240.0;
                let quiet = 2usize;
                let module = px / (w + quiet * 2) as f32;
                let (rect, _) = ui.allocate_exact_size(egui::vec2(px, px), egui::Sense::hover());
                let painter = ui.painter();
                painter.rect_filled(rect, 2.0, egui::Color32::WHITE);
                for y in 0..w {
                    for x in 0..w {
                        if matches!(colors[y * w + x], qrcode::Color::Dark) {
                            let min = rect.min
                                + egui::vec2(
                                    (x + quiet) as f32 * module,
                                    (y + quiet) as f32 * module,
                                );
                            painter.rect_filled(
                                egui::Rect::from_min_size(min, egui::vec2(module, module)),
                                0.0,
                                egui::Color32::BLACK,
                            );
                        }
                    }
                }
            }
            Err(_) => {
                ui.label("could not render QR");
            }
        });
        ui.add_space(8.0);
        ui.monospace(data);
        ui.add_space(10.0);
        if ui.button("Done").clicked() {
            actions.push(UiAction::CloseModal);
        }
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

fn onboarding(ctx: &egui::Context, cursor: usize, actions: &mut Vec<UiAction>) {
    let (title, body) = ONBOARDING_PAGES.get(cursor).copied().unwrap_or(("", ""));
    let last = cursor + 1 >= ONBOARDING_PAGES.len();
    egui::Modal::new(Id::new("modal-onboarding")).show(ctx, |ui| {
        ui.set_width(440.0);
        ui.heading(title);
        ui.add_space(10.0);
        ui.label(body);
        ui.add_space(14.0);
        ui.horizontal(|ui| {
            if ui
                .button(if last { "Get started" } else { "Next" })
                .clicked()
            {
                actions.push(if last {
                    UiAction::OnboardingDone
                } else {
                    UiAction::OnboardingNext
                });
            }
            ui.label(
                RichText::new(format!("{}/{}", cursor + 1, ONBOARDING_PAGES.len()))
                    .small()
                    .color(palette().text_dim),
            );
        });
    });
}

fn update_opt_in(ctx: &egui::Context, actions: &mut Vec<UiAction>) {
    egui::Modal::new(Id::new("modal-update-optin")).show(ctx, |ui| {
        ui.set_width(400.0);
        ui.heading("Check for updates?");
        ui.add_space(8.0);
        ui.label(
            "huddle can check crates.io once a day for a newer version — no telemetry, just a \
             version compare. You can change this later in Settings.",
        );
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.button("Yes, check").clicked() {
                actions.push(UiAction::UpdateOptInSet(true));
            }
            if ui.button("No thanks").clicked() {
                actions.push(UiAction::UpdateOptInSet(false));
            }
        });
    });
}

fn quit_confirm(ctx: &egui::Context, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-quit")).show(ctx, |ui| {
        ui.set_width(320.0);
        ui.heading("Quit huddle?");
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if ui.button("Quit").clicked() {
                actions.push(UiAction::RequestShutdown);
            }
            if ui.button("Stay").clicked() {
                actions.push(UiAction::CancelQuit);
            }
        });
    });
    if resp.should_close() {
        actions.push(UiAction::CancelQuit);
    }
}

fn verify(ctx: &egui::Context, s: &mut VerifyState, actions: &mut Vec<UiAction>) {
    let room_id = s.room_id.clone();
    let resp = egui::Modal::new(Id::new("modal-verify")).show(ctx, |ui| {
        ui.set_width(440.0);
        ui.heading("Verify members");
        ui.label(
            RichText::new("check a peer after confirming their HD-ID out of band, or run an interactive SAS exchange.")
                .small()
                .color(palette().text_dim),
        );
        ui.add_space(8.0);
        egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
            for (fp, verified) in &mut s.members {
                ui.horizontal(|ui| {
                    let mut v = *verified;
                    if ui.checkbox(&mut v, fmt::display_id(fp)).changed() {
                        *verified = v;
                        actions.push(UiAction::ToggleMemberVerified {
                            room_id: room_id.clone(),
                            fingerprint: fp.clone(),
                            verified: v,
                        });
                    }
                    right(ui, |ui| {
                        if ui.button("SAS").clicked() {
                            actions.push(UiAction::StartSas {
                                room_id: room_id.clone(),
                                fingerprint: fp.clone(),
                            });
                        }
                    });
                });
            }
        });
        ui.add_space(8.0);
        if ui.button("Done").clicked() {
            actions.push(UiAction::CloseModal);
        }
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

fn sas(ctx: &egui::Context, s: &mut SasState, actions: &mut Vec<UiAction>) {
    let tx_id = s.tx_id.clone();
    let partner = s.partner_fingerprint.clone();
    let resp = egui::Modal::new(Id::new("modal-sas")).show(ctx, |ui| {
        ui.set_width(400.0);
        ui.heading("SAS verification");
        ui.label(
            RichText::new(format!("with {}", fmt::display_id(&partner))).color(palette().text_dim),
        );
        ui.add_space(12.0);
        match &mut s.stage {
            SasStage::Waiting => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("waiting for the other side…");
                });
            }
            SasStage::Comparing {
                words,
                decimal,
                our_matched,
            } => {
                ui.label("compare these with your partner out of band:");
                ui.add_space(8.0);
                ui.label(
                    RichText::new(decimal.clone())
                        .heading()
                        .monospace()
                        .color(palette().accent),
                );
                ui.label(RichText::new(words.clone()).color(palette().text));
                ui.add_space(12.0);
                if *our_matched {
                    ui.label(
                        RichText::new("waiting for your partner to confirm…")
                            .color(palette().text_dim),
                    );
                } else {
                    ui.horizontal(|ui| {
                        if ui.button("They match").clicked() {
                            *our_matched = true;
                            actions.push(UiAction::SasMatch(tx_id.clone()));
                        }
                        if ui.button("Cancel").clicked() {
                            actions.push(UiAction::SasCancel(tx_id.clone()));
                        }
                    });
                }
            }
        }
        if matches!(s.stage, SasStage::Waiting) && ui.button("Cancel").clicked() {
            actions.push(UiAction::SasCancel(tx_id.clone()));
        }
    });
    if resp.should_close() {
        actions.push(UiAction::SasCancel(s.tx_id.clone()));
    }
}

fn show_invite(ctx: &egui::Context, url: &str, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-show-invite")).show(ctx, |ui| {
        ui.set_width(460.0);
        ui.heading("Invite link");
        ui.label(
            RichText::new(
                "share this out of band. For encrypted rooms, share the passphrase separately.",
            )
            .small()
            .color(palette().text_dim),
        );
        ui.add_space(8.0);
        egui::ScrollArea::vertical()
            .max_height(120.0)
            .show(ui, |ui| {
                ui.add(TextEdit::multiline(&mut url.to_string()).desired_width(f32::INFINITY));
            });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if ui.button("Copy").clicked() {
                actions.push(UiAction::Copy(url.to_string()));
            }
            if ui.button("Done").clicked() {
                actions.push(UiAction::CloseModal);
            }
        });
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

fn paste_invite(ctx: &egui::Context, s: &mut PasteInviteState, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-paste-invite")).show(ctx, |ui| {
        ui.set_width(460.0);
        ui.heading("Paste an invite");
        ui.add_space(8.0);
        ui.add(
            TextEdit::multiline(&mut s.url)
                .desired_width(f32::INFINITY)
                .hint_text("huddle://… invite link"),
        );
        if let Some(e) = &s.error {
            ui.add_space(6.0);
            ui.colored_label(palette().error, e);
        }
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if ui.button("Continue").clicked() {
                if s.url.trim().is_empty() {
                    s.error = Some("paste a link first".into());
                } else {
                    actions.push(UiAction::SubmitPasteInvite(s.url.trim().to_string()));
                }
            }
            if ui.button("Cancel").clicked() {
                actions.push(UiAction::CloseModal);
            }
        });
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

/// huddle 1.0: set (or clear) the clearnet relay URL — e.g. a cloudflared
/// tunnel `wss://<rand>.trycloudflare.com/ws`. Applies on the next launch.
fn set_relay(ctx: &egui::Context, s: &mut SetRelayState, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-set-relay")).show(ctx, |ui| {
        ui.set_width(460.0);
        ui.heading("Clearnet relay");
        ui.add_space(4.0);
        ui.label(
            RichText::new(
                "Connect through a clearnet relay you control instead of (or alongside) \
                 Tor — e.g. a cloudflared tunnel. Paste the wss:// URL, or a ws://ip:port \
                 URL. Leave empty and Save to clear. Applies on the next launch.",
            )
            .small()
            .color(palette().text_dim),
        );
        ui.add_space(8.0);
        ui.add(
            TextEdit::singleline(&mut s.url)
                .desired_width(f32::INFINITY)
                .hint_text("wss://abc123.trycloudflare.com/ws"),
        );
        if let Some(e) = &s.error {
            ui.add_space(6.0);
            ui.colored_label(palette().error, e);
        }
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if ui.button("Save").clicked() {
                let trimmed = s.url.trim();
                let val = if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                };
                actions.push(UiAction::SetClearnetRelay(val));
            }
            if ui.button("Clear").clicked() {
                actions.push(UiAction::SetClearnetRelay(None));
            }
            if ui.button("Cancel").clicked() {
                actions.push(UiAction::CloseModal);
            }
        });
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

/// Manual file-path entry for Attach — the alternative to the native rfd file
/// dialog, enabled by the "Attach by typing a path" Settings toggle.
fn attach_path(ctx: &egui::Context, s: &mut AttachPathState, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-attach-path")).show(ctx, |ui| {
        ui.set_width(460.0);
        ui.heading("Attach a file");
        ui.add_space(4.0);
        ui.label(
            RichText::new("Type an absolute path to a file to send.")
                .small()
                .color(palette().text_dim),
        );
        ui.add_space(8.0);
        let r = ui.add(
            TextEdit::singleline(&mut s.path)
                .desired_width(f32::INFINITY)
                .hint_text("/path/to/file"),
        );
        // Enter in the field submits, like the other single-field modals.
        let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if let Some(e) = &s.error {
            ui.add_space(6.0);
            ui.colored_label(palette().error, e);
        }
        ui.add_space(10.0);
        let mut submit = enter;
        ui.horizontal(|ui| {
            if ui.button("Attach").clicked() {
                submit = true;
            }
            if ui.button("Cancel").clicked() {
                actions.push(UiAction::CloseModal);
            }
        });
        if submit {
            actions.push(UiAction::SubmitAttachPath {
                room_id: s.room_id.clone(),
                path: s.path.trim().to_string(),
            });
        }
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

fn confirm_invite(ctx: &egui::Context, s: &ConfirmInviteState, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-confirm-invite")).show(ctx, |ui| {
        ui.set_width(440.0);
        ui.heading("Confirm invite");
        ui.add_space(8.0);
        ui.label(&s.summary);
        ui.add_space(4.0);
        ui.label(
            RichText::new(format!("from {}", fmt::display_id(&s.invite.fingerprint)))
                .small()
                .color(palette().text_dim),
        );
        if s.invite.signature_b64.is_none() {
            ui.add_space(4.0);
            ui.colored_label(palette().warn, "⚠ this invite is unsigned");
        }
        // huddle 1.0: a v3 invite adopts the inviter's clearnet relay.
        if let Some(relay) = &s.invite.relay_url {
            ui.add_space(6.0);
            ui.label(
                RichText::new(format!("connects you through their relay: {relay}"))
                    .small()
                    .color(palette().text_dim),
            );
        }
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.button("Accept").clicked() {
                actions.push(UiAction::ConfirmInvite);
            }
            if ui.button("Cancel").clicked() {
                actions.push(UiAction::CloseModal);
            }
        });
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

fn join_with_code(ctx: &egui::Context, s: &mut JoinWithCodeState, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-join-code")).show(ctx, |ui| {
        ui.set_width(380.0);
        ui.heading(format!("Join “{}” with a code", s.room_name));
        ui.add_space(8.0);
        ui.label("join code");
        ui.add(TextEdit::singleline(&mut s.code).desired_width(f32::INFINITY));
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if ui.button("Join").clicked() && !s.code.trim().is_empty() {
                actions.push(UiAction::SubmitJoinWithCode {
                    room_id: s.room_id.clone(),
                    code: s.code.trim().to_string(),
                });
            }
            if ui.button("Cancel").clicked() {
                actions.push(UiAction::CloseModal);
            }
        });
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

fn search(ctx: &egui::Context, s: &mut SearchState, actions: &mut Vec<UiAction>) {
    let room_id = s.room_id.clone();
    let resp = egui::Modal::new(Id::new("modal-search")).show(ctx, |ui| {
        ui.set_width(460.0);
        ui.heading("Search this conversation");
        ui.add_space(8.0);
        let r = ui.add(
            TextEdit::singleline(&mut s.query)
                .desired_width(f32::INFINITY)
                .hint_text("type to search…"),
        );
        if r.changed() {
            actions.push(UiAction::RunSearch {
                room_id: room_id.clone(),
                query: s.query.clone(),
            });
        }
        ui.add_space(8.0);
        ui.separator();
        egui::ScrollArea::vertical()
            .max_height(320.0)
            .show(ui, |ui| {
                if s.searched && s.results.is_empty() {
                    ui.label(RichText::new("no matches").color(palette().text_dim));
                }
                for m in &s.results {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(fmt::hhmm(m.sent_at))
                                .small()
                                .monospace()
                                .color(palette().text_dim),
                        );
                        ui.add(egui::Label::new(&m.body).wrap());
                    });
                }
            });
        ui.add_space(8.0);
        if ui.button("Done").clicked() {
            actions.push(UiAction::CloseModal);
        }
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

fn rotate(ctx: &egui::Context, s: &mut RotateState, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-rotate")).show(ctx, |ui| {
        ui.set_width(380.0);
        ui.heading("Rotate room key");
        ui.label(
            RichText::new(
                "everyone re-derives the key from a new passphrase — share it out of band.",
            )
            .small()
            .color(palette().text_dim),
        );
        ui.add_space(8.0);
        ui.label("new passphrase");
        ui.add(
            TextEdit::singleline(&mut s.passphrase)
                .password(true)
                .desired_width(f32::INFINITY),
        );
        if let Some(e) = &s.error {
            ui.add_space(6.0);
            ui.colored_label(palette().error, e);
        }
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if ui.button("Rotate").clicked() {
                if s.passphrase.is_empty() {
                    s.error = Some("passphrase can't be empty".into());
                } else {
                    actions.push(UiAction::SubmitRotate {
                        room_id: s.room_id.clone(),
                        passphrase: s.passphrase.clone(),
                    });
                }
            }
            if ui.button("Cancel").clicked() {
                actions.push(UiAction::CloseModal);
            }
        });
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

fn accept_rotation(ctx: &egui::Context, s: &mut AcceptRotationState, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-accept-rotation")).show(ctx, |ui| {
        ui.set_width(380.0);
        ui.heading("Room key rotated");
        ui.label(
            RichText::new(format!(
                "{} rotated this room's key. Enter the new passphrase to keep receiving messages.",
                fmt::display_id(&s.rotator_fingerprint)
            ))
            .small()
            .color(palette().text_dim),
        );
        ui.add_space(8.0);
        ui.label("new passphrase");
        ui.add(
            TextEdit::singleline(&mut s.passphrase)
                .password(true)
                .desired_width(f32::INFINITY),
        );
        if let Some(e) = &s.error {
            ui.add_space(6.0);
            ui.colored_label(palette().error, e);
        }
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if ui.button("Apply").clicked() {
                if s.passphrase.is_empty() {
                    s.error = Some("passphrase can't be empty".into());
                } else {
                    actions.push(UiAction::SubmitAcceptRotation {
                        room_id: s.room_id.clone(),
                        new_salt: s.new_salt.clone(),
                        passphrase: s.passphrase.clone(),
                    });
                }
            }
            if ui.button("Later").clicked() {
                actions.push(UiAction::CloseModal);
            }
        });
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

fn inbound_dial(ctx: &egui::Context, s: &InboundDialState, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-inbound")).show(ctx, |ui| {
        ui.set_width(380.0);
        ui.heading("Incoming connection");
        ui.add_space(8.0);
        ui.label("an unknown peer is dialing you:");
        ui.monospace(fmt::display_id(&s.fingerprint));
        ui.label(RichText::new(&s.address).small().color(palette().text_dim));
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.button("Accept once").clicked() {
                actions.push(UiAction::InboundAccept {
                    peer_id: s.peer_id,
                    address: s.address.clone(),
                });
            }
            if ui.button("Trust & accept").clicked() {
                actions.push(UiAction::InboundTrust {
                    peer_id: s.peer_id,
                    fingerprint: s.fingerprint.clone(),
                    address: s.address.clone(),
                });
            }
            if ui.button("Reject").clicked() {
                actions.push(UiAction::InboundReject {
                    peer_id: s.peer_id,
                    fingerprint: s.fingerprint.clone(),
                });
            }
        });
    });
    // Backdrop-dismiss = reject (never leave an unknown peer attached).
    if resp.should_close() {
        actions.push(UiAction::InboundReject {
            peer_id: s.peer_id,
            fingerprint: s.fingerprint.clone(),
        });
    }
}

fn new_group(ctx: &egui::Context, s: &mut NewGroupState, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-new-group")).show(ctx, |ui| {
        ui.set_width(340.0);
        ui.heading("New room");
        ui.add_space(8.0);
        ui.label("name");
        ui.add(
            TextEdit::singleline(&mut s.name)
                .desired_width(f32::INFINITY)
                .hint_text("room name"),
        );
        ui.add_space(6.0);
        ui.checkbox(&mut s.encrypted, "end-to-end encrypted");
        if s.encrypted {
            ui.add_space(4.0);
            ui.label("passphrase");
            ui.add(
                TextEdit::singleline(&mut s.passphrase)
                    .password(true)
                    .desired_width(f32::INFINITY),
            );
        }
        if let Some(e) = &s.error {
            ui.add_space(6.0);
            ui.colored_label(palette().error, e);
        }
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.button("Create").clicked() {
                if s.name.trim().is_empty() {
                    s.error = Some("name can't be empty".into());
                } else if s.encrypted && s.passphrase.is_empty() {
                    s.error = Some("an encrypted room needs a passphrase".into());
                } else {
                    actions.push(UiAction::SubmitNewGroup {
                        name: s.name.trim().to_string(),
                        encrypted: s.encrypted,
                        passphrase: s.passphrase.clone(),
                    });
                }
            }
            if ui.button("Cancel").clicked() {
                actions.push(UiAction::CloseModal);
            }
        });
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

fn new_dm(ctx: &egui::Context, s: &mut NewDmState, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-new-dm")).show(ctx, |ui| {
        ui.set_width(340.0);
        ui.heading("New message");
        ui.add_space(8.0);
        ui.label("who? (HD-ID or username)");
        let r = ui.add(
            TextEdit::singleline(&mut s.target)
                .desired_width(f32::INFINITY)
                .hint_text("HD-XXXX-… or a username"),
        );
        let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if let Some(e) = &s.error {
            ui.add_space(6.0);
            ui.colored_label(palette().error, e);
        }
        ui.add_space(12.0);
        let mut go = enter;
        ui.horizontal(|ui| {
            if ui.button("Start chat").clicked() {
                go = true;
            }
            if ui.button("Cancel").clicked() {
                actions.push(UiAction::CloseModal);
            }
        });
        if go {
            if s.target.trim().is_empty() {
                s.error = Some("enter an HD-ID or username".into());
            } else {
                actions.push(UiAction::SubmitNewDm {
                    target: s.target.trim().to_string(),
                });
            }
        }
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

fn add_contact(ctx: &egui::Context, s: &mut AddContactState, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-add-contact")).show(ctx, |ui| {
        ui.set_width(380.0);
        ui.heading("Add a contact");
        ui.label(
            RichText::new(
                "enter their HD-ID or a connect code they shared. huddle sends a signed \
                 contact request over the relay (works across the internet) and also tries \
                 a direct LAN connection.",
            )
            .small()
            .color(palette().text_dim),
        );
        ui.add_space(10.0);
        ui.label("HD-ID or connect code");
        let r = ui.add(
            TextEdit::singleline(&mut s.target)
                .desired_width(f32::INFINITY)
                .hint_text("HD-XXXX-XXXX-…  or  K7M9Q2X4"),
        );
        let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        ui.add_space(6.0);
        ui.label(
            RichText::new("note (optional)")
                .small()
                .color(palette().text_dim),
        );
        ui.add(
            TextEdit::singleline(&mut s.note)
                .desired_width(f32::INFINITY)
                .hint_text("\"hi, it's me from …\""),
        );
        if let Some(e) = &s.error {
            ui.add_space(6.0);
            ui.colored_label(palette().error, e);
        }

        // huddle 1.2.1: the other direction — mint a short-lived code THEY can
        // type to add you, instead of reading out your full HD-ID.
        ui.add_space(12.0);
        ui.separator();
        ui.add_space(6.0);
        ui.label(
            RichText::new("…or let them add you")
                .small()
                .strong()
                .color(palette().text_dim),
        );
        match &s.code {
            Some((code, expires_at)) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let remaining = (*expires_at - now).max(0);
                let pretty = if code.len() == 8 {
                    format!("{}-{}", &code[..4], &code[4..])
                } else {
                    code.clone()
                };
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(&pretty)
                            .heading()
                            .monospace()
                            .color(palette().accent),
                    );
                    if ui.button("Copy").clicked() {
                        actions.push(UiAction::Copy(code.clone()));
                    }
                });
                ui.label(
                    RichText::new(format!(
                        "valid {}m {:02}s — they enter it above on their device",
                        remaining / 60,
                        remaining % 60
                    ))
                    .small()
                    .color(palette().text_dim),
                );
                // Keep the countdown ticking while the modal is open.
                ui.ctx()
                    .request_repaint_after(std::time::Duration::from_secs(1));
            }
            None => {
                if ui.button("Generate a code to share").clicked() {
                    actions.push(UiAction::GenerateConnectCode);
                }
            }
        }

        ui.add_space(12.0);
        let mut go = enter;
        ui.horizontal(|ui| {
            if ui.button("Send request").clicked() {
                go = true;
            }
            if ui.button("Cancel").clicked() {
                actions.push(UiAction::CloseModal);
            }
        });
        if go {
            if s.target.trim().is_empty() {
                s.error = Some("enter an HD-ID".into());
            } else {
                let note = s.note.trim();
                actions.push(UiAction::SubmitAddContact {
                    target: s.target.trim().to_string(),
                    note: (!note.is_empty()).then(|| note.to_string()),
                });
            }
        }
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

/// huddle 1.2.1: the About window — app name, version, a one-line summary, and
/// a clickable link to the GitHub repository.
fn about(ctx: &egui::Context, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-about")).show(ctx, |ui| {
        ui.set_width(360.0);
        ui.vertical_centered(|ui| {
            ui.heading("huddle");
            ui.label(
                RichText::new(format!("version {}", env!("CARGO_PKG_VERSION")))
                    .small()
                    .color(palette().text_dim),
            );
        });
        ui.add_space(10.0);
        ui.label(
            RichText::new(
                "Terminal- and desktop-native chat over a self-hosted Tor onion relay, \
                 end-to-end encrypted.",
            )
            .small()
            .color(palette().text_dim),
        );
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            ui.label("Source code:");
            ui.hyperlink_to(
                "github.com/richer-richard/huddle",
                "https://github.com/richer-richard/huddle",
            );
        });
        ui.add_space(6.0);
        ui.label(
            RichText::new("MIT OR Apache-2.0")
                .small()
                .color(palette().text_dim),
        );
        ui.add_space(12.0);
        ui.vertical_centered(|ui| {
            if ui.button("Close").clicked() {
                actions.push(UiAction::CloseModal);
            }
        });
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

fn edit_alias(ctx: &egui::Context, s: &mut EditAliasState, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-edit-alias")).show(ctx, |ui| {
        ui.set_width(360.0);
        ui.heading("Rename contact");
        ui.label(
            RichText::new(format!(
                "{} — a local nickname, only you see it.",
                s.current_label
            ))
            .small()
            .color(palette().text_dim),
        );
        ui.add_space(8.0);
        let r = ui.add(
            TextEdit::singleline(&mut s.input)
                .desired_width(f32::INFINITY)
                .hint_text("alias (empty clears it)"),
        );
        let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        ui.add_space(10.0);
        let mut go = enter;
        ui.horizontal(|ui| {
            if ui.button("Save").clicked() {
                go = true;
            }
            if ui.button("Cancel").clicked() {
                actions.push(UiAction::CloseModal);
            }
        });
        if go {
            let v = s.input.trim();
            actions.push(UiAction::SubmitEditAlias {
                fingerprint: s.fingerprint.clone(),
                alias: (!v.is_empty()).then(|| v.to_string()),
            });
        }
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

fn join(ctx: &egui::Context, s: &mut JoinState, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-join")).show(ctx, |ui| {
        ui.set_width(340.0);
        ui.heading(format!("Join “{}”", s.room_name));
        ui.add_space(8.0);
        if s.encrypted {
            ui.label("this room is encrypted — enter its passphrase");
            ui.add(
                TextEdit::singleline(&mut s.passphrase)
                    .password(true)
                    .desired_width(f32::INFINITY),
            );
        } else {
            ui.label(
                RichText::new("this room is public (no passphrase)").color(palette().text_dim),
            );
        }
        if let Some(e) = &s.error {
            ui.add_space(6.0);
            ui.colored_label(palette().error, e);
        }
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.button("Join").clicked() {
                if s.encrypted && s.passphrase.is_empty() {
                    s.error = Some("this room needs a passphrase".into());
                } else {
                    let passphrase = if s.encrypted {
                        Some(s.passphrase.clone())
                    } else {
                        None
                    };
                    actions.push(UiAction::SubmitJoin {
                        room_id: s.room_id.clone(),
                        passphrase,
                    });
                }
            }
            if ui.button("Cancel").clicked() {
                actions.push(UiAction::CloseModal);
            }
        });
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}

fn message(
    ctx: &egui::Context,
    title: &str,
    body: &str,
    color: egui::Color32,
    actions: &mut Vec<UiAction>,
) {
    let resp = egui::Modal::new(Id::new("modal-message")).show(ctx, |ui| {
        ui.set_width(360.0);
        ui.heading(title);
        ui.add_space(8.0);
        ui.colored_label(color, body);
        ui.add_space(12.0);
        if ui.button("OK").clicked() {
            actions.push(UiAction::CloseModal);
        }
    });
    if resp.should_close() {
        actions.push(UiAction::CloseModal);
    }
}
