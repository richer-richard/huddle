//! Modal overlays, rendered with egui's `Modal` container (centered, dimmed
//! backdrop that blocks the rest of the UI). Each modal mutates its own state
//! and pushes `UiAction`s on submit / cancel; the app applies them after the
//! frame and owns the actual `AppHandle` calls.

use egui::{Id, RichText, TextEdit};

use crate::fmt;
use crate::model::{
    AcceptRotationState, ConfirmInviteState, EditUsernameState, GoDarkState, InboundDialState,
    JoinState, JoinWithCodeState, Modal, NewDmState, NewGroupState, PasteInviteState, RotateState,
    SasStage, SasState, SearchState, UiAction, VerifyState, GO_DARK_CONFIRM_PHRASE, ONBOARDING_PAGES,
};
use crate::theme::PALETTE;

fn right<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) {
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), add);
}

pub fn render(ctx: &egui::Context, modal: &mut Modal, our_id: &str, actions: &mut Vec<UiAction>) {
    match modal {
        Modal::None => {}
        Modal::NewGroup(s) => new_group(ctx, s, actions),
        Modal::NewDm(s) => new_dm(ctx, s, actions),
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
        Modal::JoinWithCode(s) => join_with_code(ctx, s, actions),
        Modal::EditUsername(s) => edit_username(ctx, s, actions),
        Modal::GoDark(s) => go_dark(ctx, s, actions),
        Modal::Qr => qr(ctx, our_id, actions),
        Modal::Onboarding { cursor } => onboarding(ctx, *cursor, actions),
        Modal::UpdateOptIn => update_opt_in(ctx, actions),
        Modal::QuitConfirm => quit_confirm(ctx, actions),
        Modal::Error(m) => message(ctx, "error", m, PALETTE.error, actions),
        Modal::Info(m) => message(ctx, "huddle", m, PALETTE.text, actions),
    }
}

fn edit_username(ctx: &egui::Context, s: &mut EditUsernameState, actions: &mut Vec<UiAction>) {
    let resp = egui::Modal::new(Id::new("modal-edit-username")).show(ctx, |ui| {
        ui.set_width(360.0);
        ui.heading("Edit username");
        ui.label(
            RichText::new("broadcast to peers you share rooms with. Empty clears it (you show as [anonymous]).")
                .small()
                .color(PALETTE.text_dim),
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
        ui.heading(RichText::new("Go dark").color(PALETTE.error));
        ui.label("This permanently deletes your account and wipes all local data. There is no undo.");
        ui.add_space(10.0);
        if s.requires_passphrase {
            ui.label("enter your master passphrase to confirm");
            ui.add(TextEdit::singleline(&mut s.input).password(true).desired_width(f32::INFINITY));
        } else {
            ui.label(format!("type `{GO_DARK_CONFIRM_PHRASE}` to confirm"));
            ui.add(TextEdit::singleline(&mut s.input).desired_width(f32::INFINITY));
        }
        if let Some(e) = &s.error {
            ui.add_space(6.0);
            ui.colored_label(PALETTE.error, e);
        }
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui
                .button(RichText::new("Delete everything").color(PALETTE.error))
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
                let (rect, _) =
                    ui.allocate_exact_size(egui::vec2(px, px), egui::Sense::hover());
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
            if ui.button(if last { "Get started" } else { "Next" }).clicked() {
                actions.push(if last {
                    UiAction::OnboardingDone
                } else {
                    UiAction::OnboardingNext
                });
            }
            ui.label(
                RichText::new(format!("{}/{}", cursor + 1, ONBOARDING_PAGES.len()))
                    .small()
                    .color(PALETTE.text_dim),
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
                .color(PALETTE.text_dim),
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
        ui.label(RichText::new(format!("with {}", fmt::display_id(&partner))).color(PALETTE.text_dim));
        ui.add_space(12.0);
        match &mut s.stage {
            SasStage::Waiting => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("waiting for the other side…");
                });
            }
            SasStage::Comparing { words, decimal, our_matched } => {
                ui.label("compare these with your partner out of band:");
                ui.add_space(8.0);
                ui.label(RichText::new(decimal.clone()).heading().monospace().color(PALETTE.accent));
                ui.label(RichText::new(words.clone()).color(PALETTE.text));
                ui.add_space(12.0);
                if *our_matched {
                    ui.label(RichText::new("waiting for your partner to confirm…").color(PALETTE.text_dim));
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
            RichText::new("share this out of band. For encrypted rooms, share the passphrase separately.")
                .small()
                .color(PALETTE.text_dim),
        );
        ui.add_space(8.0);
        egui::ScrollArea::vertical().max_height(120.0).show(ui, |ui| {
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
            ui.colored_label(PALETTE.error, e);
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
                .color(PALETTE.text_dim),
        );
        if s.invite.signature_b64.is_none() {
            ui.add_space(4.0);
            ui.colored_label(PALETTE.warn, "⚠ this invite is unsigned");
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
        egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
            if s.searched && s.results.is_empty() {
                ui.label(RichText::new("no matches").color(PALETTE.text_dim));
            }
            for m in &s.results {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(fmt::hhmm(m.sent_at))
                            .small()
                            .monospace()
                            .color(PALETTE.text_dim),
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
            RichText::new("everyone re-derives the key from a new passphrase — share it out of band.")
                .small()
                .color(PALETTE.text_dim),
        );
        ui.add_space(8.0);
        ui.label("new passphrase");
        ui.add(TextEdit::singleline(&mut s.passphrase).password(true).desired_width(f32::INFINITY));
        if let Some(e) = &s.error {
            ui.add_space(6.0);
            ui.colored_label(PALETTE.error, e);
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
            .color(PALETTE.text_dim),
        );
        ui.add_space(8.0);
        ui.label("new passphrase");
        ui.add(TextEdit::singleline(&mut s.passphrase).password(true).desired_width(f32::INFINITY));
        if let Some(e) = &s.error {
            ui.add_space(6.0);
            ui.colored_label(PALETTE.error, e);
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
        ui.label(RichText::new(&s.address).small().color(PALETTE.text_dim));
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
            ui.colored_label(PALETTE.error, e);
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
            ui.colored_label(PALETTE.error, e);
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
            ui.label(RichText::new("this room is public (no passphrase)").color(PALETTE.text_dim));
        }
        if let Some(e) = &s.error {
            ui.add_space(6.0);
            ui.colored_label(PALETTE.error, e);
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
