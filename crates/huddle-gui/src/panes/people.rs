//! The Contacts pane: the durable, fingerprint-keyed address book plus
//! Requests / Known / Verified / Blocked sublists with per-row actions
//! (message, rename, block/unblock, remove, accept/decline).

use egui::RichText;

use crate::fmt;
use crate::model::{PeopleTab, UiAction, ViewModel};
use crate::theme::palette;
use crate::widgets;

pub fn render(ui: &mut egui::Ui, vm: &ViewModel, actions: &mut Vec<UiAction>) {
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.heading("Contacts");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .button(RichText::new("+ Add by HD-ID").color(palette().accent))
                .clicked()
            {
                actions.push(UiAction::OpenAddContact);
            }
        });
    });
    ui.add_space(4.0);
    // Requests folds both inbound relay contact requests and legacy libp2p
    // friend requests into one badge.
    let request_count = vm.contact_requests.len() + vm.pending_requests.len();
    ui.horizontal(|ui| {
        for tab in [
            PeopleTab::Contacts,
            PeopleTab::Requests,
            PeopleTab::Known,
            PeopleTab::Verified,
            PeopleTab::Blocked,
        ] {
            let count = match tab {
                PeopleTab::Contacts => vm.contacts.len(),
                PeopleTab::Requests => request_count,
                PeopleTab::Known => vm.known_peers.len(),
                PeopleTab::Verified => vm.verified_peers.len(),
                PeopleTab::Blocked => vm.blocked.len(),
            };
            let label = if count > 0 {
                format!("{} ({count})", tab.label())
            } else {
                tab.label().to_string()
            };
            // Draw an unread-style emphasis on Requests when any are waiting.
            let rich = if tab == PeopleTab::Requests && request_count > 0 {
                RichText::new(label).color(palette().warn)
            } else {
                RichText::new(label)
            };
            if ui.selectable_label(vm.people_tab == tab, rich).clicked() {
                actions.push(UiAction::SelectPeopleTab(tab));
            }
        }
    });
    ui.separator();
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| match vm.people_tab {
            PeopleTab::Contacts => contacts(ui, vm, actions),
            PeopleTab::Requests => requests(ui, vm, actions),
            PeopleTab::Known => known(ui, vm, actions),
            PeopleTab::Verified => verified(ui, vm, actions),
            PeopleTab::Blocked => blocked(ui, vm, actions),
        });
}

fn empty_hint(ui: &mut egui::Ui, text: &str) {
    ui.add_space(8.0);
    ui.label(RichText::new(text).color(palette().text_dim));
}

/// One reachability badge per contact: a live LAN connection, relay-reachable,
/// or offline. Mirrors the per-chat transport language (lan / relay / offline).
fn reachability(ui: &mut egui::Ui, lan_connected: bool, reachable: bool) {
    let (glyph, label, color) = if lan_connected {
        ("●", "lan", palette().success)
    } else if reachable {
        ("◈", "relay", palette().accent)
    } else {
        ("○", "offline", palette().text_dim)
    };
    ui.label(RichText::new(glyph).color(color));
    ui.label(RichText::new(label).small().color(color));
}

fn contacts(ui: &mut egui::Ui, vm: &ViewModel, actions: &mut Vec<UiAction>) {
    if vm.contacts.is_empty() {
        empty_hint(
            ui,
            "no contacts yet — “+ Add by HD-ID” to send a contact request, \
             or accept one from the Requests tab",
        );
        return;
    }
    for c in &vm.contacts {
        let name = vm.peer_label(&c.fingerprint);
        ui.horizontal(|ui| {
            widgets::avatar::show(ui, 30.0, &c.fingerprint, &name);
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&name).strong());
                    if c.verified {
                        widgets::verified_tick(ui);
                    }
                    reachability(ui, c.lan_connected, c.reachable);
                });
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(fmt::display_id(&c.fingerprint))
                            .monospace()
                            .small()
                            .color(palette().text_dim),
                    );
                    ui.label(
                        RichText::new(format!("· {}", c.source))
                            .small()
                            .color(palette().text_dim),
                    );
                });
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Remove").clicked() {
                    actions.push(UiAction::RemoveContact(c.fingerprint.clone()));
                }
                if ui.button("Block").clicked() {
                    actions.push(UiAction::PersonBlock(c.fingerprint.clone()));
                }
                if ui.button("Rename").clicked() {
                    actions.push(UiAction::OpenEditAlias(c.fingerprint.clone()));
                }
                if ui.button("Message").clicked() {
                    actions.push(UiAction::PersonStartDm(c.fingerprint.clone()));
                }
            });
        });
        ui.separator();
    }
}

fn requests(ui: &mut egui::Ui, vm: &ViewModel, actions: &mut Vec<UiAction>) {
    if vm.contact_requests.is_empty() && vm.pending_requests.is_empty() {
        empty_hint(ui, "no pending requests");
        return;
    }
    // Inbound contact requests over the relay inbox (the "add by HD-ID over the
    // internet" path).
    for req in &vm.contact_requests {
        let name = req
            .display_name
            .clone()
            .unwrap_or_else(|| vm.peer_label(&req.fingerprint));
        ui.horizontal(|ui| {
            widgets::avatar::show(ui, 28.0, &req.fingerprint, &name);
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&name).strong());
                    ui.label(RichText::new("via relay").small().color(palette().accent));
                });
                ui.label(
                    RichText::new(fmt::display_id(&req.fingerprint))
                        .monospace()
                        .small()
                        .color(palette().text_dim),
                );
                if let Some(note) = req.note.as_deref().filter(|n| !n.is_empty()) {
                    ui.label(RichText::new(format!("“{note}”")).italics().small());
                }
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Decline").clicked() {
                    actions.push(UiAction::RejectContactRequest(req.fingerprint.clone()));
                }
                if ui.button("Accept").clicked() {
                    actions.push(UiAction::AcceptContactRequest(req.fingerprint.clone()));
                }
            });
        });
        ui.separator();
    }
    // Legacy libp2p friend requests (same-LAN / direct dial).
    for req in &vm.pending_requests {
        ui.horizontal(|ui| {
            widgets::avatar::show(ui, 28.0, &req.fingerprint, &vm.peer_label(&req.fingerprint));
            ui.vertical(|ui| {
                ui.label(RichText::new(vm.peer_label(&req.fingerprint)).strong());
                ui.label(
                    RichText::new(fmt::display_id(&req.fingerprint))
                        .monospace()
                        .small()
                        .color(palette().text_dim),
                );
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Reject").clicked() {
                    actions.push(UiAction::RejectRequest(req.fingerprint.clone()));
                }
                if ui.button("Accept").clicked() {
                    actions.push(UiAction::AcceptRequest(req.fingerprint.clone()));
                }
            });
        });
        ui.separator();
    }
}

fn known(ui: &mut egui::Ui, vm: &ViewModel, actions: &mut Vec<UiAction>) {
    if vm.known_peers.is_empty() {
        empty_hint(ui, "no known peers yet — paste an invite or start a DM");
        return;
    }
    for p in &vm.known_peers {
        let online = p.connected_peer_id.is_some();
        let label = match &p.fingerprint {
            Some(fp) => vm.peer_label(fp),
            None => p.label.clone().unwrap_or_else(|| p.address.clone()),
        };
        ui.horizontal(|ui| {
            widgets::status_dot(ui, online);
            ui.vertical(|ui| {
                ui.label(RichText::new(label).strong());
                ui.label(
                    RichText::new(&p.address)
                        .monospace()
                        .small()
                        .color(palette().text_dim),
                );
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Forget").clicked() {
                    actions.push(UiAction::PersonForget(p.address.clone()));
                }
                if let Some(fp) = &p.fingerprint {
                    if ui.button("Block").clicked() {
                        actions.push(UiAction::PersonBlock(fp.clone()));
                    }
                }
                if ui.button("Reconnect").clicked() {
                    actions.push(UiAction::PersonRedial(p.address.clone()));
                }
                if let Some(fp) = &p.fingerprint {
                    if ui.button("Message").clicked() {
                        actions.push(UiAction::PersonStartDm(fp.clone()));
                    }
                }
            });
        });
        ui.separator();
    }
}

fn verified(ui: &mut egui::Ui, vm: &ViewModel, actions: &mut Vec<UiAction>) {
    if vm.verified_peers.is_empty() {
        empty_hint(ui, "no SAS-verified peers yet");
        return;
    }
    for fp in &vm.verified_peers {
        ui.horizontal(|ui| {
            widgets::avatar::show(ui, 28.0, fp, &vm.peer_label(fp));
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(vm.peer_label(fp)).strong());
                    widgets::verified_tick(ui);
                });
                ui.label(
                    RichText::new(fmt::display_id(fp))
                        .monospace()
                        .small()
                        .color(palette().text_dim),
                );
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Message").clicked() {
                    actions.push(UiAction::PersonStartDm(fp.clone()));
                }
            });
        });
        ui.separator();
    }
}

fn blocked(ui: &mut egui::Ui, vm: &ViewModel, actions: &mut Vec<UiAction>) {
    if vm.blocked.is_empty() {
        empty_hint(ui, "no blocked peers");
        return;
    }
    for fp in &vm.blocked {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(fmt::display_id(fp))
                    .monospace()
                    .color(palette().text_dim),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Unblock").clicked() {
                    actions.push(UiAction::PersonUnblock(fp.clone()));
                }
            });
        });
        ui.separator();
    }
}
