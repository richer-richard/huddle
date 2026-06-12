//! The Settings pane: Account / Network / Privacy tabs.

use egui::RichText;
use huddle_core::network::NetworkMode;

use crate::model::{SettingsTab, UiAction, ViewModel};
use crate::theme::palette;

pub fn render(ui: &mut egui::Ui, vm: &ViewModel, actions: &mut Vec<UiAction>) {
    ui.add_space(6.0);
    ui.heading("Settings");
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        for tab in [
            SettingsTab::Account,
            SettingsTab::Network,
            SettingsTab::Privacy,
        ] {
            if ui
                .selectable_label(vm.settings_tab == tab, tab.label())
                .clicked()
            {
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
        ui.label(RichText::new(format!("{label}:")).color(palette().text_dim));
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
        ui.label(RichText::new("username:").color(palette().text_dim));
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

    // huddle 2.0.0 (F5/F6): account security — change the master passphrase and
    // back up the identity as a 24-word recovery seed phrase.
    ui.add_space(14.0);
    ui.separator();
    ui.label(RichText::new("Security").strong());
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                vm.has_master_passphrase,
                egui::Button::new("Change master passphrase"),
            )
            .clicked()
        {
            actions.push(UiAction::OpenChangePassphrase);
        }
        if !vm.has_master_passphrase {
            ui.label(
                RichText::new("(started with --no-master-passphrase)")
                    .small()
                    .color(palette().text_dim),
            );
        }
    });
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                vm.has_master_passphrase,
                egui::Button::new("Export recovery seed phrase"),
            )
            .clicked()
        {
            actions.push(UiAction::OpenExportSeed);
        }
    });
    ui.label(
        RichText::new(
            "the 24-word seed phrase backs up your identity. Anyone who has it IS you — \
             store it offline. Restore it on a fresh install via “Import existing identity”.",
        )
        .small()
        .color(palette().text_dim),
    );

    ui.add_space(14.0);
    ui.separator();
    ui.label(RichText::new("Appearance").strong());
    ui.horizontal(|ui| {
        ui.label(RichText::new("Theme:").color(palette().text_dim));
        for t in [
            crate::theme::Theme::System,
            crate::theme::Theme::Dark,
            crate::theme::Theme::Light,
        ] {
            if ui.selectable_label(vm.theme == t, t.label()).clicked() {
                actions.push(UiAction::SetTheme(t));
            }
        }
    });
    ui.label(
        RichText::new(
            "System follows your OS appearance (default). Switches instantly — no restart needed.",
        )
        .small()
        .color(palette().text_dim),
    );

    // huddle 1.2.1: About — version + a link to the source.
    ui.add_space(14.0);
    ui.separator();
    ui.label(RichText::new("About").strong());
    ui.horizontal(|ui| {
        if ui.button("About huddle").clicked() {
            actions.push(UiAction::OpenAbout);
        }
        ui.label(
            RichText::new(format!("version {}", env!("CARGO_PKG_VERSION")))
                .small()
                .color(palette().text_dim),
        );
    });
}

fn network(ui: &mut egui::Ui, vm: &ViewModel, actions: &mut Vec<UiAction>) {
    ui.add_space(6.0);
    ui.label(
        RichText::new(
            "huddle runs LAN discovery and the relay together by default — messages \
             ride whichever reaches the peer (always end-to-end encrypted).",
        )
        .small()
        .color(palette().text_dim),
    );
    ui.add_space(8.0);

    // Relay status + the live transport door.
    ui.horizontal(|ui| {
        ui.label(RichText::new("Relay").strong());
        if !vm.server_enabled {
            ui.label(RichText::new("off (--no-server)").color(palette().warn));
        } else if vm.server_connected {
            ui.label(RichText::new("●").color(palette().success));
            ui.label("connected");
            if let Some(t) = vm.active_transport {
                ui.label(RichText::new(format!("· via {}", t.label())).color(palette().text_dim));
            }
        } else {
            ui.label(RichText::new("○").color(palette().text_dim));
            ui.label(
                RichText::new("connecting… (Tor down? set a clearnet relay below)")
                    .color(palette().text_dim),
            );
        }
    });

    // huddle 1.0: clearnet relay (e.g. a cloudflared tunnel) — a no-Tor door
    // onto the relay backend. Editable here; huddle 2.1.1: applies immediately.
    ui.horizontal(|ui| {
        ui.label(RichText::new("Clearnet relay").strong());
        match &vm.clearnet_relay {
            Some(u) => {
                ui.monospace(u);
            }
            None => {
                ui.label(RichText::new("none (Tor onion default)").color(palette().text_dim));
            }
        }
        if ui.small_button("Set / edit").clicked() {
            actions.push(UiAction::OpenSetRelay);
        }
    });
    ui.label(
        RichText::new(
            "Paste a wss:// URL (e.g. a cloudflared tunnel) to connect without Tor. \
             Selecting one switches priority to clearnet-first and connects now.",
        )
        .small()
        .color(palette().text_dim),
    );

    // huddle 2.1.1: connection priority — which transport family huddle dials
    // first. Applies live (the relay loop re-dials), so a user on a Tor-hostile
    // network can flip to clearnet without relaunching.
    ui.add_space(10.0);
    ui.label(RichText::new("Connection priority").strong());
    ui.label(
        RichText::new("which transport huddle tries first — applies immediately:")
            .small()
            .color(palette().text_dim),
    );
    ui.add_space(2.0);
    let current_preset =
        huddle_core::network::transport::match_priority_preset(&vm.transport_order);
    for preset in huddle_core::network::transport::priority_presets() {
        let selected = preset.key == current_preset;
        if ui.radio(selected, preset.label).clicked() && !selected {
            actions.push(UiAction::SetTransportPriority(preset.order.clone()));
        }
        ui.label(
            RichText::new(preset.detail)
                .small()
                .color(palette().text_dim),
        );
    }
    if current_preset == "custom" {
        ui.label(
            RichText::new("Custom order — set via --transport-order; pick a preset to change it.")
                .small()
                .color(palette().warn),
        );
    }

    // LAN status — runs alongside, never instead of, the relay.
    ui.horizontal(|ui| {
        ui.label(RichText::new("LAN").strong());
        if vm.mode != NetworkMode::Server {
            ui.label(RichText::new("●").color(palette().success));
            ui.label(format!("on · {}", vm.mode.as_str()));
        } else {
            ui.label(RichText::new("○").color(palette().text_dim));
            ui.label(RichText::new("off · enable below").color(palette().text_dim));
        }
    });

    // Transport "doors" onto the relay + their anti-censorship tradeoffs, so
    // the effort of reaching the relay under censorship is legible.
    ui.add_space(10.0);
    ui.label(RichText::new("Transport doors").strong());
    ui.label(
        RichText::new("anti-censorship paths onto the relay — huddle picks the first that works:")
            .small()
            .color(palette().text_dim),
    );
    ui.add_space(2.0);
    for p in &vm.transport_profiles {
        let (mark, mcolor) = if Some(p.id) == vm.active_transport {
            ("● active", palette().success)
        } else if p.available() {
            ("· ready", palette().text_dim)
        } else {
            ("  off", palette().text_dim)
        };
        ui.horizontal(|ui| {
            ui.label(RichText::new(mark).color(mcolor).monospace().small());
            ui.label(RichText::new(p.id.label()).strong());
            if !p.available() {
                if let Some(r) = p.reason {
                    ui.label(
                        RichText::new(format!("({r})"))
                            .small()
                            .color(palette().text_dim),
                    );
                }
            }
        });
        ui.label(
            RichText::new(p.id.description())
                .small()
                .color(palette().text_dim),
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
        .color(palette().text_dim),
    );
    // Pending-change hint + one-click restart (skip for explicit `--mode direct`).
    let running_mdns = vm.mode == NetworkMode::Mdns;
    if vm.mdns_enabled != running_mdns && vm.mode != NetworkMode::Direct {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("change pending — restart to apply").color(palette().warn));
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
        .checkbox(
            &mut n,
            "desktop notifications when the window isn't focused",
        )
        .changed()
    {
        actions.push(UiAction::ToggleNotifications(n));
    }
    let mut vo = vm.verified_only_inbound;
    if ui
        .checkbox(
            &mut vo,
            "accept inbound connections only from verified peers",
        )
        .changed()
    {
        actions.push(UiAction::ToggleVerifiedOnlyInbound(vo));
    }
    let mut ap = vm.attach_via_path;
    if ui
        .checkbox(
            &mut ap,
            "attach by typing a path (instead of the native file dialog)",
        )
        .changed()
    {
        actions.push(UiAction::ToggleAttachViaPath(ap));
    }
    ui.label(
        RichText::new(
            "When on, the chat Attach button opens a box to type a file path \
             instead of the system file picker.",
        )
        .small()
        .color(palette().text_dim),
    );
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
    ui.label(RichText::new("Danger zone").color(palette().error).strong());
    ui.label(
        RichText::new(
            "Going dark deletes your account and wipes all local data. There is no undo.",
        )
        .small()
        .color(palette().text_dim),
    );
    ui.add_space(4.0);
    if ui
        .button(RichText::new("Go dark — delete everything").color(palette().error))
        .clicked()
    {
        actions.push(UiAction::OpenGoDark);
    }
}
