//! The People pane: Requests / Known / Verified / Blocked sublists with
//! per-row actions (start DM, reconnect, forget, block/unblock, accept/reject).

use egui::RichText;

use crate::fmt;
use crate::model::{PeopleTab, UiAction, ViewModel};
use crate::theme::PALETTE;
use crate::widgets;

pub fn render(ui: &mut egui::Ui, vm: &ViewModel, actions: &mut Vec<UiAction>) {
    ui.add_space(6.0);
    ui.heading("People");
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        for tab in [
            PeopleTab::Pending,
            PeopleTab::Known,
            PeopleTab::Verified,
            PeopleTab::Blocked,
        ] {
            let count = match tab {
                PeopleTab::Pending => vm.pending_requests.len(),
                PeopleTab::Known => vm.known_peers.len(),
                PeopleTab::Verified => vm.verified_peers.len(),
                PeopleTab::Blocked => vm.blocked.len(),
            };
            let label = if count > 0 {
                format!("{} ({count})", tab.label())
            } else {
                tab.label().to_string()
            };
            if ui.selectable_label(vm.people_tab == tab, label).clicked() {
                actions.push(UiAction::SelectPeopleTab(tab));
            }
        }
    });
    ui.separator();
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| match vm.people_tab {
            PeopleTab::Pending => pending(ui, vm, actions),
            PeopleTab::Known => known(ui, vm, actions),
            PeopleTab::Verified => verified(ui, vm, actions),
            PeopleTab::Blocked => blocked(ui, vm, actions),
        });
}

fn empty_hint(ui: &mut egui::Ui, text: &str) {
    ui.add_space(8.0);
    ui.label(RichText::new(text).color(PALETTE.text_dim));
}

fn pending(ui: &mut egui::Ui, vm: &ViewModel, actions: &mut Vec<UiAction>) {
    if vm.pending_requests.is_empty() {
        empty_hint(ui, "no pending friend requests");
        return;
    }
    for req in &vm.pending_requests {
        ui.horizontal(|ui| {
            widgets::avatar::show(ui, 28.0, &req.fingerprint, &vm.peer_label(&req.fingerprint));
            ui.vertical(|ui| {
                ui.label(RichText::new(vm.peer_label(&req.fingerprint)).strong());
                ui.label(RichText::new(fmt::display_id(&req.fingerprint)).monospace().small().color(PALETTE.text_dim));
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
                ui.label(RichText::new(&p.address).monospace().small().color(PALETTE.text_dim));
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
                ui.label(RichText::new(fmt::display_id(fp)).monospace().small().color(PALETTE.text_dim));
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
            ui.label(RichText::new(fmt::display_id(fp)).monospace().color(PALETTE.text_dim));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Unblock").clicked() {
                    actions.push(UiAction::PersonUnblock(fp.clone()));
                }
            });
        });
        ui.separator();
    }
}
