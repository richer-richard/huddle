//! The Settings pane: Account / Network / Privacy tabs.

use egui::RichText;
use huddle_core::network::NetworkMode;

use crate::model::{SettingsTab, UiAction, ViewModel};
use crate::theme::PALETTE;

pub fn render(ui: &mut egui::Ui, vm: &ViewModel, actions: &mut Vec<UiAction>) {
    ui.add_space(6.0);
    ui.heading("Settings");
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        for tab in [SettingsTab::Account, SettingsTab::Network, SettingsTab::Privacy] {
            if ui.selectable_label(vm.settings_tab == tab, tab.label()).clicked() {
                actions.push(UiAction::SelectSettingsTab(tab));
            }
        }
    });
    ui.separator();
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| match vm.settings_tab {
            SettingsTab::Account => account(ui, vm, actions),
            SettingsTab::Network => network(ui, vm, actions),
            SettingsTab::Privacy => privacy(ui, vm, actions),
        });
}

fn copy_row(ui: &mut egui::Ui, actions: &mut Vec<UiAction>, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("{label}:")).color(PALETTE.text_dim));
        ui.monospace(value);
        if ui.small_button("copy").clicked() {
            actions.push(UiAction::Copy(value.to_string()));
        }
    });
}

fn account(ui: &mut egui::Ui, vm: &ViewModel, actions: &mut Vec<UiAction>) {
    let name = vm
        .display_name
        .clone()
        .unwrap_or_else(|| "[anonymous]".into());
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("username:").color(PALETTE.text_dim));
        ui.strong(&name);
        if ui.button("Edit").clicked() {
            actions.push(UiAction::OpenEditUsername);
        }
    });
    copy_row(ui, actions, "HD-ID", &vm.our_id);
    copy_row(ui, actions, "Safety Code", &vm.safety_code);
    copy_row(ui, actions, "Fingerprint", &vm.our_fp);
    ui.add_space(8.0);
    if ui.button("Show QR code").clicked() {
        actions.push(UiAction::OpenQr);
    }
}

fn network(ui: &mut egui::Ui, vm: &ViewModel, actions: &mut Vec<UiAction>) {
    ui.add_space(6.0);
    ui.label(
        RichText::new(
            "huddle runs LAN discovery and the relay together by default — messages \
             ride whichever reaches the peer (always end-to-end encrypted).",
        )
        .small()
        .color(PALETTE.text_dim),
    );
    ui.add_space(8.0);

    // Relay status + the live transport door.
    ui.horizontal(|ui| {
        ui.label(RichText::new("Relay").strong());
        if !vm.server_enabled {
            ui.label(RichText::new("off (--no-server)").color(PALETTE.warn));
        } else if vm.server_connected {
            ui.label(RichText::new("●").color(PALETTE.success));
            ui.label("connected");
            if let Some(t) = vm.active_transport {
                ui.label(
                    RichText::new(format!("· via {}", t.label())).color(PALETTE.text_dim),
                );
            }
        } else {
            ui.label(RichText::new("○").color(PALETTE.text_dim));
            ui.label(
                RichText::new("connecting… (Tor down? try a clearnet door)")
                    .color(PALETTE.text_dim),
            );
        }
    });

    // LAN status — runs alongside, never instead of, the relay.
    ui.horizontal(|ui| {
        ui.label(RichText::new("LAN").strong());
        if vm.mode != NetworkMode::Server {
            ui.label(RichText::new("●").color(PALETTE.success));
            ui.label(format!("on · {}", vm.mode.as_str()));
        } else {
            ui.label(RichText::new("○").color(PALETTE.text_dim));
            ui.label(RichText::new("off · enable below").color(PALETTE.text_dim));
        }
    });

    // Transport "doors" onto the relay + their anti-censorship tradeoffs, so
    // the effort of reaching the relay under censorship is legible.
    ui.add_space(10.0);
    ui.label(RichText::new("Transport doors").strong());
    ui.label(
        RichText::new("anti-censorship paths onto the relay — huddle picks the first that works:")
            .small()
            .color(PALETTE.text_dim),
    );
    ui.add_space(2.0);
    for p in &vm.transport_profiles {
        let (mark, mcolor) = if Some(p.id) == vm.active_transport {
            ("● active", PALETTE.success)
        } else if p.available() {
            ("· ready", PALETTE.text_dim)
        } else {
            ("  off", PALETTE.text_dim)
        };
        ui.horizontal(|ui| {
            ui.label(RichText::new(mark).color(mcolor).monospace().small());
            ui.label(RichText::new(p.id.label()).strong());
            if !p.available() {
                if let Some(r) = p.reason {
                    ui.label(
                        RichText::new(format!("({r})")).small().color(PALETTE.text_dim),
                    );
                }
            }
        });
        ui.label(
            RichText::new(p.id.description())
                .small()
                .color(PALETTE.text_dim),
        );
        ui.add_space(4.0);
    }

    // The mDNS toggle drives the NEXT launch's transport (relay-only vs relay +
    // LAN together) — the only network "choice", and it's additive, not a mode.
    ui.add_space(6.0);
    let mut mdns = vm.mdns_enabled;
    if ui
        .checkbox(&mut mdns, "Run LAN discovery (mDNS) alongside the relay")
        .changed()
    {
        actions.push(UiAction::ToggleMdns(mdns));
    }
    ui.label(
        RichText::new(
            "When on, huddle runs the relay AND LAN mDNS together — peers on \
             your network connect directly. Applies on the next launch.",
        )
        .small()
        .color(PALETTE.text_dim),
    );
    // Pending-change hint + one-click restart (skip for explicit `--mode direct`).
    let running_mdns = vm.mode == NetworkMode::Mdns;
    if vm.mdns_enabled != running_mdns && vm.mode != NetworkMode::Direct {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("change pending — restart to apply").color(PALETTE.warn));
            if ui.button("Restart now").clicked() {
                actions.push(UiAction::RestartApp);
            }
        });
    }
    if !vm.listen_addresses.is_empty() {
        ui.add_space(8.0);
        ui.label(RichText::new("listen addresses").strong());
        for a in &vm.listen_addresses {
            ui.monospace(a);
        }
    }
}

fn privacy(ui: &mut egui::Ui, vm: &ViewModel, actions: &mut Vec<UiAction>) {
    ui.add_space(6.0);
    let mut n = vm.notifications_enabled;
    if ui
        .checkbox(&mut n, "desktop notifications when the window isn't focused")
        .changed()
    {
        actions.push(UiAction::ToggleNotifications(n));
    }
    let mut vo = vm.verified_only_inbound;
    if ui
        .checkbox(&mut vo, "accept inbound connections only from verified peers")
        .changed()
    {
        actions.push(UiAction::ToggleVerifiedOnlyInbound(vo));
    }
    let mut uc = vm.update_check.unwrap_or(false);
    if ui
        .checkbox(&mut uc, "check crates.io for updates once a day")
        .changed()
    {
        actions.push(UiAction::ToggleUpdateCheck(uc));
    }
    ui.add_space(8.0);
    if ui
        .button(format!("Manage blocked peers ({})", vm.blocked.len()))
        .clicked()
    {
        actions.push(UiAction::GoToBlocked);
    }

    ui.add_space(20.0);
    ui.separator();
    ui.label(RichText::new("Danger zone").color(PALETTE.error).strong());
    ui.label(
        RichText::new("Going dark deletes your account and wipes all local data. There is no undo.")
            .small()
            .color(PALETTE.text_dim),
    );
    ui.add_space(4.0);
    if ui
        .button(RichText::new("Go dark — delete everything").color(PALETTE.error))
        .clicked()
    {
        actions.push(UiAction::OpenGoDark);
    }
}
