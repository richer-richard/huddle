//! The left rail: profile header, Direct messages, Group rooms (+ Discover),
//! and pane selectors (People / Activity / Settings).

use egui::{Label, RichText, Sense};
use huddle_core::network::NetworkMode;
use huddle_core::storage::repo::RoomKind;

use crate::model::{Pane, Section, UiAction, ViewModel};
use crate::theme::palette;
use crate::widgets;

pub fn render(ui: &mut egui::Ui, vm: &ViewModel, actions: &mut Vec<UiAction>) {
    ui.add_space(6.0);
    profile_header(ui, vm, actions);
    ui.separator();

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            // DIRECT MESSAGES
            section_header(ui, vm, actions, Section::Direct, "DIRECT MESSAGES");
            if vm.expanded.contains(&Section::Direct) {
                if ui
                    .selectable_label(
                        false,
                        RichText::new("  + New message").color(palette().accent),
                    )
                    .clicked()
                {
                    actions.push(UiAction::OpenNewDm);
                }
                if ui
                    .selectable_label(
                        false,
                        RichText::new("  + Paste invite").color(palette().accent),
                    )
                    .clicked()
                {
                    actions.push(UiAction::OpenPasteInvite);
                }
                let dms: Vec<&_> = vm
                    .discovered
                    .iter()
                    .filter(|d| d.kind == RoomKind::Direct)
                    .collect();
                if dms.is_empty() {
                    ui.label(
                        RichText::new("  no direct messages yet")
                            .small()
                            .color(palette().text_dim),
                    );
                }
                for d in dms {
                    room_row(ui, vm, actions, &d.room_id, RoomKind::Direct);
                }
            }
            ui.add_space(8.0);

            // GROUP ROOMS
            section_header(ui, vm, actions, Section::Group, "GROUP ROOMS");
            if vm.expanded.contains(&Section::Group) {
                if ui
                    .selectable_label(false, RichText::new("  + New room").color(palette().accent))
                    .clicked()
                {
                    actions.push(UiAction::OpenNewGroup);
                }
                for d in vm
                    .discovered
                    .iter()
                    .filter(|d| d.kind != RoomKind::Direct && vm.active_ids.contains(&d.room_id))
                {
                    room_row(ui, vm, actions, &d.room_id, RoomKind::Group);
                }
                let discover: Vec<&_> = vm
                    .discovered
                    .iter()
                    .filter(|d| d.kind != RoomKind::Direct && !vm.active_ids.contains(&d.room_id))
                    .collect();
                if !discover.is_empty() {
                    ui.label(
                        RichText::new("  Discover")
                            .small()
                            .color(palette().text_dim),
                    );
                    for d in discover {
                        ui.horizontal(|ui| {
                            let enc = if d.encrypted { "  E" } else { "" };
                            let text = format!("  # {} · {}{}", d.name, d.member_count, enc);
                            if ui.selectable_label(false, text).clicked() {
                                actions.push(UiAction::OpenJoin(d.room_id.clone()));
                            }
                            if d.encrypted && ui.small_button("code").clicked() {
                                actions.push(UiAction::OpenJoinWithCode(d.room_id.clone()));
                            }
                        });
                    }
                }
            }

            ui.add_space(10.0);
            ui.separator();
            pane_row(ui, vm, actions, Pane::People, "Contacts");
            pane_row(ui, vm, actions, Pane::Activity, "Activity");
            pane_row(ui, vm, actions, Pane::Settings, "Settings");
        });
}

fn profile_header(ui: &mut egui::Ui, vm: &ViewModel, actions: &mut Vec<UiAction>) {
    let label = vm
        .display_name
        .clone()
        .unwrap_or_else(|| "[anonymous]".into());
    ui.horizontal(|ui| {
        widgets::avatar::show(ui, 34.0, &vm.our_fp, &label);
        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                if ui
                    .add(Label::new(RichText::new(&label).strong()).sense(Sense::click()))
                    .clicked()
                {
                    actions.push(UiAction::SelectPane(Pane::Profile));
                }
                // Online when ANY path is live — the relay or a LAN swarm. The
                // app doesn't separate Tor from LAN; both count as reachable.
                let reachable = vm.server_connected || vm.mode != NetworkMode::Server;
                widgets::status_dot(ui, reachable);
            });
            ui.label(
                RichText::new(&vm.our_id)
                    .monospace()
                    .small()
                    .color(palette().text_dim),
            );
        });
    });
}

fn section_header(
    ui: &mut egui::Ui,
    vm: &ViewModel,
    actions: &mut Vec<UiAction>,
    section: Section,
    title: &str,
) {
    let arrow = if vm.expanded.contains(&section) {
        "▾"
    } else {
        "▸"
    };
    let text = RichText::new(format!("{arrow} {title}"))
        .strong()
        .small()
        .color(palette().text_dim);
    if ui.add(Label::new(text).sense(Sense::click())).clicked() {
        actions.push(UiAction::ToggleSection(section));
    }
}

fn room_row(
    ui: &mut egui::Ui,
    vm: &ViewModel,
    actions: &mut Vec<UiAction>,
    room_id: &str,
    kind: RoomKind,
) {
    let selected = vm.current_room_id() == Some(room_id);
    let prefix = if kind == RoomKind::Direct {
        "  "
    } else {
        "  # "
    };
    let label = vm.room_label(room_id);
    let unread = vm.unread.get(room_id).copied().unwrap_or(0);
    let badge = if unread > 0 {
        format!("  ({unread})")
    } else {
        String::new()
    };
    let text = format!("{prefix}{label}{badge}");
    let rich = if unread > 0 {
        RichText::new(text).color(palette().warn)
    } else {
        RichText::new(text)
    };
    if ui.selectable_label(selected, rich).clicked() {
        actions.push(UiAction::SwitchRoom(room_id.to_string()));
    }
}

fn pane_row(
    ui: &mut egui::Ui,
    vm: &ViewModel,
    actions: &mut Vec<UiAction>,
    pane: Pane,
    title: &str,
) {
    let selected = vm.pane == pane;
    if ui
        .selectable_label(selected, format!("  {title}"))
        .clicked()
    {
        actions.push(UiAction::SelectPane(pane));
    }
}
