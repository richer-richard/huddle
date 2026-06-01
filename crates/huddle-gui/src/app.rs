//! The eframe application: a `Locked → Connecting → Ready` state machine that
//! bridges the egui main-thread loop to the tokio-backed `AppHandle`.
//!
//! egui 0.34 note: the `App` entry point is `ui(&mut self, ui, frame)`; panels
//! use `Panel::{top,left,bottom,…}(id).show_inside(ui, …)` and the `Context` is
//! reached via `ui.ctx()`.

use std::time::{Duration, Instant};

use egui::{Align, Layout, RichText};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use huddle_core::app::events::AppEvent;
use huddle_core::network::NetworkMode;
use huddle_core::storage::repo::RoomKind;

use crate::bridge::{self, Cmd, Inbox, ReadyParts, ReqOk, ReqTag};
use crate::cli::Cli;
use crate::model::{
    reduce, ConfirmInviteState, EditUsernameState, GoDarkState, JoinState, JoinWithCodeState,
    Modal, NewDmState, NewGroupState, Pane, PasteInviteState, RotateState, SasStage, SasState,
    SearchState, Section, UiAction, VerifyState, ViewModel,
};
use crate::panes;
use crate::theme::PALETTE;

const ERR_RED: egui::Color32 = egui::Color32::from_rgb(0xff, 0x6b, 0x6b);

pub struct HuddleApp {
    #[allow(dead_code)] // owned to keep the runtime + its tasks alive for the process
    rt: tokio::runtime::Runtime,
    rt_handle: tokio::runtime::Handle,
    ctx: egui::Context,
    cli: Cli,
    state: AppState,
}

enum AppState {
    Fatal(String),
    Locked(LockedForm),
    Connecting(tokio::sync::oneshot::Receiver<Result<ReadyParts, String>>),
    Ready(Box<Ready>),
}

#[derive(Default)]
pub struct LockedForm {
    pub first_launch: bool,
    pub username: String,
    pub passphrase: String,
    pub confirm: String,
    pub error: Option<String>,
}

enum Transition {
    Build(bridge::AuthChoice, Option<String>),
    Ready(ReadyParts),
    FailedAuth(String),
}

impl HuddleApp {
    pub fn new(cc: &eframe::CreationContext<'_>, rt: tokio::runtime::Runtime, cli: Cli) -> Self {
        crate::theme::install(&cc.egui_ctx);
        let ctx = cc.egui_ctx.clone();
        let rt_handle = rt.handle().clone();
        let mut me = Self {
            rt,
            rt_handle,
            ctx,
            cli,
            state: AppState::Fatal(String::new()),
        };
        me.init_state();
        me
    }

    fn init_state(&mut self) {
        if self.cli.no_master_passphrase {
            self.begin_build(bridge::AuthChoice::NoPassphrase, self.cli.name.clone());
            return;
        }
        let salt_exists = huddle_core::storage::keychain::keychain_salt_path().exists();
        let db_exists = huddle_core::config::db_path().exists();
        if !salt_exists && db_exists {
            self.state = AppState::Fatal(format!(
                "found an existing database with no keychain salt — it was created with \
                 --no-master-passphrase and is unencrypted. Re-run with --no-master-passphrase, \
                 or move {} aside to start fresh.",
                huddle_core::config::db_path().display()
            ));
            return;
        }
        self.state = AppState::Locked(LockedForm {
            first_launch: !salt_exists,
            ..Default::default()
        });
    }

    fn begin_build(&mut self, auth: bridge::AuthChoice, name: Option<String>) {
        let params = bridge::BuildParams {
            explicit_mode: self.cli.mode,
            port: self.cli.port,
            relays: self.cli.resolve_relays(),
            server_url: self.cli.resolve_server_url(),
            tor_socks: self.cli.resolve_tor_socks(),
            auth,
            name,
        };
        let rx = bridge::spawn_build(&self.rt_handle, self.ctx.clone(), params);
        self.state = AppState::Connecting(rx);
    }

    fn apply_transition(&mut self, t: Transition) {
        match t {
            Transition::Build(auth, name) => self.begin_build(auth, name),
            Transition::Ready(parts) => {
                let cmd = Cmd::new(
                    self.rt_handle.clone(),
                    parts.handle.clone(),
                    parts.inbox_tx.clone(),
                    self.ctx.clone(),
                );
                let mut vm = ViewModel::from_handle(&parts.handle);
                // First-launch onboarding, then the update-check opt-in.
                if !parts.handle.onboarding_seen() {
                    vm.modal = Modal::Onboarding { cursor: 0 };
                } else if parts.handle.update_check_enabled().is_none() {
                    vm.modal = Modal::UpdateOptIn;
                }
                self.state = AppState::Ready(Box::new(Ready {
                    handle: parts.handle,
                    inbox_rx: parts.inbox_rx,
                    cmd,
                    ctx: self.ctx.clone(),
                    vm,
                    last_refresh: Instant::now(),
                    request_close: false,
                }));
            }
            Transition::FailedAuth(e) => {
                let first_launch =
                    !huddle_core::storage::keychain::keychain_salt_path().exists();
                self.state = AppState::Locked(LockedForm {
                    first_launch,
                    error: Some(e),
                    ..Default::default()
                });
            }
        }
    }
}

impl eframe::App for HuddleApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let close_requested = ui.ctx().input(|i| i.viewport().close_requested());
        let mut transition: Option<Transition> = None;
        let mut do_close = false;
        match &mut self.state {
            AppState::Fatal(msg) => render_fatal(ui, msg),
            AppState::Locked(form) => {
                if let Some((pass, name)) = render_locked(ui, form) {
                    transition = Some(Transition::Build(bridge::AuthChoice::Passphrase(pass), name));
                }
            }
            AppState::Connecting(rx) => {
                use tokio::sync::oneshot::error::TryRecvError;
                match rx.try_recv() {
                    Ok(Ok(parts)) => transition = Some(Transition::Ready(parts)),
                    Ok(Err(e)) => transition = Some(Transition::FailedAuth(e)),
                    Err(TryRecvError::Empty) => render_connecting(ui),
                    Err(TryRecvError::Closed) => {
                        transition = Some(Transition::FailedAuth("startup task aborted".into()))
                    }
                }
            }
            AppState::Ready(ready) => do_close = ready.update(ui, close_requested),
        }
        if do_close {
            // Best-effort shutdown notice already fired on confirm; let the
            // window close now.
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if let Some(t) = transition {
            self.apply_transition(t);
        }
    }
}

/// The connected application.
struct Ready {
    handle: huddle_core::app::AppHandle,
    inbox_rx: crossbeam_channel::Receiver<Inbox>,
    cmd: Cmd,
    ctx: egui::Context,
    vm: ViewModel,
    last_refresh: Instant,
    request_close: bool,
}

impl Ready {
    /// Returns `true` when the window should actually close.
    fn update(&mut self, ui: &mut egui::Ui, close_requested: bool) -> bool {
        let focused = ui.ctx().input(|i| i.focused);
        while let Ok(msg) = self.inbox_rx.try_recv() {
            if let Inbox::Event(ev) = &msg {
                if let Some((title, body)) = self.maybe_notify(ev, focused) {
                    crate::notifier::notify(&title, &body);
                }
            }
            reduce(&mut self.vm, &self.handle, msg);
        }
        self.vm.server_connected = self.handle.server_connected();
        if self.last_refresh.elapsed() > Duration::from_secs(1) {
            self.vm.refresh(&self.handle);
            self.vm.refresh_attachments(&self.handle);
            self.last_refresh = Instant::now();
        }

        let mut actions: Vec<UiAction> = Vec::new();
        self.render(ui, &mut actions);
        for a in actions {
            self.apply(a);
        }
        ui.ctx().request_repaint_after(Duration::from_millis(500));

        // Lifecycle: go-dark farewell → exit; window-close → confirm first.
        if self.vm.should_exit() {
            return true;
        }
        if close_requested {
            if self.request_close {
                return true;
            }
            if !matches!(self.vm.modal, Modal::QuitConfirm) {
                self.vm.replace_modal_if_idle(Modal::QuitConfirm);
            }
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
        false
    }

    /// Decide whether an event warrants a desktop notification (window
    /// unfocused + notifications on + an inbound message).
    fn maybe_notify(&self, ev: &AppEvent, focused: bool) -> Option<(String, String)> {
        if focused || !self.vm.notifications_enabled {
            return None;
        }
        if let AppEvent::MessageReceived { room_id, sender_fingerprint, body, .. } = ev {
            let room = self.vm.room_label(room_id);
            let sender = self.vm.peer_label(sender_fingerprint);
            return Some((
                format!("huddle · {room}"),
                format!("{sender}: {}", crate::notifier::preview(body)),
            ));
        }
        None
    }

    fn render(&mut self, ui: &mut egui::Ui, actions: &mut Vec<UiAction>) {
        egui::Panel::top("header").show_inside(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading("huddle");
                ui.label(RichText::new(format!("v{}", env!("CARGO_PKG_VERSION"))).weak());
                ui.separator();
                ui.monospace(&self.vm.our_id);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    relay_indicator(ui, &self.vm);
                    ui.label(
                        RichText::new(self.vm.mode.as_str())
                            .small()
                            .color(PALETTE.text_dim),
                    );
                });
            });
            ui.add_space(4.0);
        });

        egui::Panel::left("rail")
            .resizable(true)
            .default_size(264.0)
            .min_size(200.0)
            .show_inside(ui, |ui| {
                panes::sidebar::render(ui, &self.vm, actions);
            });

        egui::Panel::bottom("status").show_inside(ui, |ui| {
            ui.add_space(2.0);
            match self.vm.current_status() {
                Some(s) => ui.label(RichText::new(s).color(PALETTE.text_dim)),
                None => ui.label(RichText::new(" ").small()),
            };
            ui.add_space(2.0);
        });

        egui::CentralPanel::default().show_inside(ui, |ui| match self.vm.pane.clone() {
            Pane::Dm(id) | Pane::Group(id) => {
                panes::chat::render(ui, &mut self.vm, &self.handle, &id, actions);
            }
            Pane::Profile => profile_pane(ui, &self.vm, actions),
            Pane::People => panes::people::render(ui, &self.vm, actions),
            Pane::Activity => activity_pane(ui, &self.vm),
            Pane::Settings => panes::settings::render(ui, &self.vm, actions),
            Pane::Welcome => welcome_pane(ui),
        });

        crate::modals::render(ui.ctx(), &mut self.vm.modal, &self.vm.our_id, actions);
    }

    fn apply(&mut self, a: UiAction) {
        match a {
            UiAction::SwitchRoom(id) => self.vm.switch_to_room(&self.handle, &id),
            UiAction::SelectPane(p) => self.vm.pane = p,
            UiAction::ToggleSection(s) => toggle_section(&mut self.vm, s),
            UiAction::SendMessage { room_id, body } => {
                self.cmd
                    .fire(move |h| async move { h.send_room_message(&room_id, &body).await });
            }
            UiAction::TypingPing(room_id) => {
                self.cmd.fire(move |h| async move {
                    h.broadcast_typing(&room_id).await;
                    Ok::<(), std::convert::Infallible>(())
                });
            }
            UiAction::Copy(s) => self.ctx.copy_text(s),
            UiAction::OpenNewGroup => self.vm.modal = Modal::NewGroup(NewGroupState::default()),
            UiAction::OpenNewDm => self.vm.modal = Modal::NewDm(NewDmState::default()),
            UiAction::OpenJoin(room_id) => {
                let (room_name, encrypted) = self
                    .vm
                    .discovered
                    .iter()
                    .find(|d| d.room_id == room_id)
                    .map(|d| (d.name.clone(), d.encrypted))
                    .unwrap_or_else(|| (room_id.clone(), false));
                self.vm.modal = Modal::Join(JoinState {
                    room_id,
                    room_name,
                    encrypted,
                    passphrase: String::new(),
                    error: None,
                });
            }
            UiAction::CloseModal => self.vm.close_modal(),
            UiAction::SubmitNewGroup { name, encrypted, passphrase } => {
                let pass = if encrypted { Some(passphrase) } else { None };
                self.cmd.request(ReqTag::StartRoom, move |h| async move {
                    h.start_room(name.trim(), encrypted, pass.as_deref(), RoomKind::Group)
                        .await
                        .map(ReqOk::RoomId)
                        .map_err(|e| e.to_string())
                });
                self.vm.modal = Modal::None;
            }
            UiAction::SubmitNewDm { target } => {
                let resolved = huddle_core::app::normalize_to_fingerprint(&target).or_else(|| {
                    let m = self.handle.peers_with_username(&target);
                    (m.len() == 1).then(|| m[0].clone())
                });
                match resolved {
                    Some(fp) if fp == self.vm.our_fp => {
                        if let Modal::NewDm(s) = &mut self.vm.modal {
                            s.error = Some("that's your own ID".into());
                        }
                    }
                    Some(fp) => {
                        self.cmd.request(ReqTag::StartDirect, move |h| async move {
                            h.start_direct(&fp)
                                .await
                                .map(ReqOk::RoomId)
                                .map_err(|e| e.to_string())
                        });
                        self.vm.modal = Modal::None;
                    }
                    None => {
                        if let Modal::NewDm(s) = &mut self.vm.modal {
                            s.error =
                                Some("unknown peer — use their HD-ID or paste an invite".into());
                        }
                    }
                }
            }
            UiAction::SubmitJoin { room_id, passphrase } => {
                self.cmd.fire(move |h| async move {
                    h.join_room(&room_id, passphrase.as_deref()).await
                });
                self.vm.modal = Modal::None;
            }

            // ---- Phase 5: people + inbound-dial gate ----
            UiAction::SelectPeopleTab(tab) => {
                self.vm.people_tab = tab;
                self.vm.pane = Pane::People;
            }
            UiAction::PersonStartDm(fp) => {
                self.cmd.request(ReqTag::StartDirect, move |h| async move {
                    h.start_direct(&fp).await.map(ReqOk::RoomId).map_err(|e| e.to_string())
                });
            }
            UiAction::PersonRedial(addr) => {
                self.cmd.fire(move |h| async move { h.redial(&addr).await });
            }
            UiAction::PersonForget(addr) => {
                self.cmd.fire(move |h| async move { h.forget_peer(&addr).await });
            }
            UiAction::PersonBlock(fp) => {
                if let Err(e) = self.handle.block_peer(&fp) {
                    self.vm.set_status(format!("block failed: {e}"));
                } else {
                    self.vm.refresh(&self.handle);
                }
            }
            UiAction::PersonUnblock(fp) => {
                if let Err(e) = self.handle.unblock_peer(&fp) {
                    self.vm.set_status(format!("unblock failed: {e}"));
                } else {
                    self.vm.refresh(&self.handle);
                }
            }
            UiAction::AcceptRequest(fp) => {
                self.cmd.fire(move |h| async move { h.accept_pending_friend_request(&fp).await });
            }
            UiAction::RejectRequest(fp) => {
                if let Err(e) = self.handle.reject_pending_friend_request(&fp) {
                    self.vm.set_status(format!("reject failed: {e}"));
                } else {
                    self.vm.refresh(&self.handle);
                }
            }
            UiAction::InboundAccept { peer_id, address } => {
                self.cmd.fire(move |h| async move {
                    h.accept_inbound(peer_id, &address).await;
                    Ok::<(), std::convert::Infallible>(())
                });
                self.vm.close_modal();
            }
            UiAction::InboundReject { peer_id, fingerprint } => {
                self.cmd.fire(move |h| async move { h.reject_inbound(peer_id, &fingerprint).await });
                self.vm.close_modal();
            }
            UiAction::InboundTrust { peer_id, fingerprint, address } => {
                self.cmd.fire(move |h| async move {
                    h.trust_inbound(peer_id, &fingerprint, &address).await
                });
                self.vm.close_modal();
            }

            // ---- Phase 6: verify + moderation + rotation ----
            UiAction::ToggleMemberPanel => self.vm.show_member_panel = !self.vm.show_member_panel,
            UiAction::LeaveRoom(room_id) => {
                self.cmd
                    .fire(move |h| async move { h.leave_room(&room_id).await.map(|_| ()) });
            }
            UiAction::OpenVerify(room_id) => {
                let me = self.vm.our_fp.clone();
                let verified: std::collections::HashSet<String> =
                    self.handle.verified_fingerprints(&room_id).into_iter().collect();
                let members = self
                    .handle
                    .room_members(&room_id)
                    .into_iter()
                    .filter(|f| f != &me)
                    .map(|f| {
                        let v = verified.contains(&f);
                        (f, v)
                    })
                    .collect();
                self.vm.modal = Modal::Verify(VerifyState { room_id, members });
            }
            UiAction::ToggleMemberVerified { room_id, fingerprint, verified } => {
                if let Err(e) = self.handle.set_member_verified(&room_id, &fingerprint, verified) {
                    self.vm.set_status(format!("verify failed: {e}"));
                }
            }
            UiAction::StartSas { room_id, fingerprint } => {
                self.vm.modal = Modal::Sas(SasState {
                    partner_fingerprint: fingerprint.clone(),
                    tx_id: String::new(),
                    stage: SasStage::Waiting,
                });
                self.cmd.request(
                    ReqTag::SasStart { room_id: room_id.clone(), partner: fingerprint.clone() },
                    move |h| async move {
                        h.sas_start(&room_id, &fingerprint)
                            .await
                            .map(ReqOk::TxId)
                            .map_err(|e| e.to_string())
                    },
                );
            }
            UiAction::SasMatch(tx) => {
                self.cmd.fire(move |h| async move { h.sas_match(&tx).await });
            }
            UiAction::SasCancel(tx) => {
                self.handle.sas_cancel(&tx);
                self.vm.close_modal();
            }
            UiAction::DoKick { room_id, fingerprint } => {
                self.cmd.fire(move |h| async move {
                    h.kick_member(&room_id, &fingerprint).await.map(|_| ())
                });
            }
            UiAction::DoGrant { room_id, fingerprint } => {
                self.cmd
                    .fire(move |h| async move { h.grant_owner(&room_id, &fingerprint).await });
            }
            UiAction::OpenRotate(room_id) => {
                self.vm.modal = Modal::Rotate(RotateState {
                    room_id,
                    passphrase: String::new(),
                    error: None,
                });
            }
            UiAction::SubmitRotate { room_id, passphrase } => {
                self.cmd
                    .fire(move |h| async move { h.rotate_room(&room_id, &passphrase).await });
                self.vm.modal = Modal::None;
            }
            UiAction::SubmitAcceptRotation { room_id, new_salt, passphrase } => {
                self.cmd.fire(move |h| async move {
                    h.accept_rotation(&room_id, &new_salt, &passphrase).await
                });
                self.vm.modal = Modal::None;
            }
            UiAction::ToggleRoomVerifiedOnly { room_id, on } => {
                if let Err(e) = self.handle.set_room_verified_only(&room_id, on) {
                    self.vm.set_status(format!("{e}"));
                }
            }
            UiAction::OpenSearch(room_id) => {
                self.vm.modal = Modal::Search(SearchState {
                    room_id,
                    query: String::new(),
                    results: Vec::new(),
                    searched: false,
                });
            }
            UiAction::RunSearch { room_id, query } => {
                if query.trim().is_empty() {
                    if let Modal::Search(s) = &mut self.vm.modal {
                        s.results.clear();
                        s.searched = false;
                    }
                } else {
                    let results = self
                        .handle
                        .search_room_messages(&room_id, &query, 50)
                        .unwrap_or_default();
                    if let Modal::Search(s) = &mut self.vm.modal {
                        s.results = results;
                        s.searched = true;
                    }
                }
            }

            // ---- Phase 7: files + invites + codes ----
            UiAction::AttachFile(room_id) => {
                if let Some(path) = rfd::FileDialog::new().set_title("Attach a file").pick_file() {
                    self.cmd.fire(move |h| async move {
                        h.send_file(&room_id, &path).await.map(|_| ())
                    });
                }
            }
            UiAction::SaveAttachment { room_id, file_id } => {
                self.cmd.request(
                    ReqTag::SaveDownload { file_id: file_id.clone() },
                    move |h| async move {
                        h.save_to_downloads(&room_id, &file_id)
                            .await
                            .map(ReqOk::SavedPath)
                            .map_err(|e| e.to_string())
                    },
                );
            }
            UiAction::CancelAttachment { room_id, file_id } => {
                self.cmd
                    .fire(move |h| async move { h.cancel_transfer(&room_id, &file_id).await });
            }
            UiAction::OpenAttachment { room_id, file_id } => {
                if let Err(e) = self.handle.open_saved(&room_id, &file_id) {
                    self.vm.set_status(format!("open failed: {e}"));
                }
            }
            UiAction::GenerateInvite(room_id) => self.generate_invite(&room_id),
            UiAction::OpenPasteInvite => {
                self.vm.modal = Modal::PasteInvite(PasteInviteState::default())
            }
            UiAction::SubmitPasteInvite(url) => match huddle_core::invite::decode(&url) {
                Ok(invite) => {
                    let summary = match &invite.room {
                        Some(r) => format!(
                            "Join room “{}”{}",
                            r.name,
                            if r.encrypted { " (encrypted)" } else { "" }
                        ),
                        None => "Connect to this peer".to_string(),
                    };
                    self.vm.modal = Modal::ConfirmInvite(ConfirmInviteState { invite, summary });
                }
                Err(e) => {
                    if let Modal::PasteInvite(s) = &mut self.vm.modal {
                        s.error = Some(format!("invalid invite: {e}"));
                    }
                }
            },
            UiAction::ConfirmInvite => self.confirm_invite(),
            UiAction::GenerateJoinCode(room_id) => match self.handle.generate_join_code(&room_id) {
                Ok(code) => {
                    self.vm.modal = Modal::Info(format!("Join code (valid ~10 min):\n\n{code}"))
                }
                Err(e) => self.vm.set_status(format!("can't generate code: {e}")),
            },
            UiAction::OpenJoinWithCode(room_id) => {
                let room_name = self.vm.room_label(&room_id);
                self.vm.modal = Modal::JoinWithCode(JoinWithCodeState {
                    room_id,
                    room_name,
                    code: String::new(),
                });
            }
            UiAction::SubmitJoinWithCode { room_id, code } => {
                self.cmd
                    .fire(move |h| async move { h.join_room_with_code(&room_id, &code).await });
                self.vm.modal = Modal::None;
            }

            // ---- Phase 8: settings + lifecycle ----
            UiAction::SelectSettingsTab(tab) => {
                self.vm.settings_tab = tab;
                self.vm.pane = Pane::Settings;
            }
            UiAction::OpenEditUsername => {
                self.vm.modal = Modal::EditUsername(EditUsernameState {
                    input: self.vm.display_name.clone().unwrap_or_default(),
                });
            }
            UiAction::SubmitUsername(name) => {
                self.cmd
                    .fire(move |h| async move { h.set_username(name.as_deref()).await });
                self.vm.modal = Modal::None;
            }
            UiAction::OpenQr => self.vm.modal = Modal::Qr,
            UiAction::ToggleNotifications(on) => {
                let _ = self.handle.set_notifications_enabled(on);
                self.vm.notifications_enabled = on;
            }
            UiAction::ToggleMdns(on) => {
                let _ = self.handle.set_mdns_enabled(on);
                self.vm.mdns_enabled = on;
            }
            UiAction::ToggleVerifiedOnlyInbound(on) => {
                let _ = self.handle.set_verified_only_inbound(on);
                self.vm.verified_only_inbound = on;
            }
            UiAction::ToggleUpdateCheck(on) => {
                let _ = self.handle.set_update_check_enabled(on);
                self.vm.update_check = Some(on);
            }
            UiAction::GoToBlocked => {
                self.vm.pane = Pane::People;
                self.vm.people_tab = crate::model::PeopleTab::Blocked;
            }
            UiAction::OpenGoDark => {
                self.vm.modal = Modal::GoDark(GoDarkState {
                    input: String::new(),
                    requires_passphrase: self.vm.has_master_passphrase,
                    error: None,
                });
            }
            UiAction::SubmitGoDark(input) => {
                let requires = self.vm.has_master_passphrase;
                if !requires && input != crate::model::GO_DARK_CONFIRM_PHRASE {
                    if let Modal::GoDark(s) = &mut self.vm.modal {
                        s.error = Some(format!(
                            "type `{}` exactly to confirm",
                            crate::model::GO_DARK_CONFIRM_PHRASE
                        ));
                        s.input.clear();
                    }
                } else {
                    let pass = if requires { input } else { String::new() };
                    self.cmd.fire(move |h| async move { h.go_dark(&pass).await });
                }
            }
            UiAction::OnboardingNext => {
                if let Modal::Onboarding { cursor } = &mut self.vm.modal {
                    *cursor += 1;
                }
            }
            UiAction::OnboardingDone => {
                let _ = self.handle.mark_onboarding_seen();
                let _ = self
                    .handle
                    .set_last_seen_onboarding_version(env!("CARGO_PKG_VERSION"));
                self.vm.modal = if self.handle.update_check_enabled().is_none() {
                    Modal::UpdateOptIn
                } else {
                    Modal::None
                };
            }
            UiAction::UpdateOptInSet(on) => {
                let _ = self.handle.set_update_check_enabled(on);
                self.vm.update_check = Some(on);
                self.vm.modal = Modal::None;
            }
            UiAction::RequestShutdown => {
                self.cmd.fire(|h| async move {
                    h.shutdown().await;
                    Ok::<(), std::convert::Infallible>(())
                });
                self.request_close = true;
                self.vm.modal = Modal::None;
            }
            UiAction::CancelQuit => self.vm.close_modal(),
            UiAction::RestartApp => {
                // Re-exec ourselves with the same args, then exit — the new
                // process re-reads the mDNS toggle and picks up the new mode.
                if let Ok(exe) = std::env::current_exe() {
                    let args: Vec<String> = std::env::args().skip(1).collect();
                    let _ = std::process::Command::new(exe).args(args).spawn();
                }
                self.cmd.fire(|h| async move {
                    h.shutdown().await;
                    Ok::<(), std::convert::Infallible>(())
                });
                self.request_close = true;
                self.vm.modal = Modal::None;
            }
        }
    }

    /// Build + sign + encode a room invite (mirrors the TUI's `GenerateInvite`).
    fn generate_invite(&mut self, room_id: &str) {
        let our_peer = self.handle.peer_id().to_string();
        let our_fp = self.handle.fingerprint().to_string();
        let host_multiaddr = if self.vm.mode != NetworkMode::Server {
            self.handle
                .dialable_addrs()
                .into_iter()
                .next()
                .map(|a| {
                    if a.contains(&our_peer) {
                        a
                    } else {
                        format!("{a}/p2p/{our_peer}")
                    }
                })
                .unwrap_or_default()
        } else {
            String::new()
        };
        let room = self.handle.active_room_info(room_id).map(|info| {
            let salt_b64 = info.passphrase_salt.as_ref().map(|s| B64.encode(s));
            huddle_core::invite::InviteRoom {
                id: info.id,
                name: info.name,
                encrypted: info.encrypted,
                salt_b64,
                creator_fingerprint: info.creator_fingerprint,
                owner_fingerprints: self.handle.room_owners(room_id),
            }
        });
        let unsigned = huddle_core::invite::InviteLink {
            v: 1,
            host_multiaddr,
            fingerprint: our_fp,
            room,
            creator_pubkey_b64: None,
            signed_at_ms: 0,
            signature_b64: None,
        };
        let invite = self.handle.sign_invite(unsigned.clone()).unwrap_or(unsigned);
        match huddle_core::invite::encode(&invite) {
            Ok(url) => self.vm.modal = Modal::ShowInvite(url),
            Err(e) => self.vm.set_status(format!("encode invite: {e}")),
        }
    }

    /// Accept a pasted invite (mirrors the TUI's `ConfirmInviteAccept`).
    fn confirm_invite(&mut self) {
        let invite = match &self.vm.modal {
            Modal::ConfirmInvite(s) => s.invite.clone(),
            _ => return,
        };
        self.vm.modal = Modal::None;
        if !invite.host_multiaddr.trim().is_empty() {
            let addr = invite.host_multiaddr.clone();
            let fp = invite.fingerprint.clone();
            self.cmd
                .fire(move |h| async move { h.dial_invite(&addr, &fp).await });
        }
        if let Some(room) = invite.room {
            self.handle.seed_invite_room(&room);
            if room.encrypted {
                self.vm.modal = Modal::Join(JoinState {
                    room_id: room.id,
                    room_name: room.name,
                    encrypted: true,
                    passphrase: String::new(),
                    error: None,
                });
            } else {
                let rid = room.id.clone();
                self.cmd
                    .fire(move |h| async move { h.join_room(&rid, None).await });
            }
        }
    }
}

fn toggle_section(vm: &mut ViewModel, s: Section) {
    if !vm.expanded.remove(&s) {
        vm.expanded.insert(s);
    }
}

fn relay_indicator(ui: &mut egui::Ui, vm: &ViewModel) {
    if !vm.server_enabled {
        return;
    }
    let (glyph, color, label) = if vm.server_connected {
        ("●", PALETTE.success, "relay")
    } else {
        ("○", PALETTE.text_dim, "connecting")
    };
    ui.label(RichText::new(label).small().color(PALETTE.text_dim));
    ui.label(RichText::new(glyph).color(color));
}

fn welcome_pane(ui: &mut egui::Ui) {
    ui.add_space(80.0);
    ui.vertical_centered(|ui| {
        ui.heading("welcome to huddle");
        ui.add_space(8.0);
        ui.label(
            RichText::new("pick a conversation on the left, or start a new one.")
                .color(PALETTE.text_dim),
        );
    });
}

fn activity_pane(ui: &mut egui::Ui, vm: &ViewModel) {
    ui.add_space(6.0);
    ui.heading("Activity");
    ui.separator();
    egui::ScrollArea::vertical()
        .stick_to_bottom(true)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for line in &vm.log {
                ui.label(RichText::new(line).monospace().small());
            }
        });
}

fn profile_pane(ui: &mut egui::Ui, vm: &ViewModel, actions: &mut Vec<UiAction>) {
    ui.add_space(8.0);
    let name = vm
        .display_name
        .clone()
        .unwrap_or_else(|| "[anonymous]".into());
    ui.horizontal(|ui| {
        crate::widgets::avatar::show(ui, 48.0, &vm.our_fp, &name);
        ui.vertical(|ui| {
            ui.heading(&name);
            ui.label(RichText::new(&vm.our_id).monospace().color(PALETTE.text_dim));
        });
    });
    ui.separator();
    copy_row(ui, actions, "HD-ID", &vm.our_id);
    copy_row(ui, actions, "Safety Code", &vm.safety_code);
    copy_row(ui, actions, "Fingerprint", &vm.our_fp);
    if !vm.listen_addresses.is_empty() {
        ui.add_space(8.0);
        ui.label(RichText::new("listen addresses").strong());
        for a in &vm.listen_addresses {
            copy_row(ui, actions, "addr", a);
        }
    }
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

/// Render the unlock / sign-up screen. Returns `(passphrase, name)` on submit.
fn render_locked(ui: &mut egui::Ui, form: &mut LockedForm) -> Option<(String, Option<String>)> {
    let mut submit = false;
    egui::CentralPanel::default().show_inside(ui, |ui| {
        ui.add_space(56.0);
        ui.vertical_centered(|ui| {
            ui.heading(if form.first_launch {
                "welcome to huddle"
            } else {
                "unlock huddle"
            });
            ui.add_space(8.0);
            ui.label(if form.first_launch {
                "pick a username and a passphrase that encrypts your local database.\n\
                 forget the passphrase and your data is unrecoverable."
            } else {
                "enter your passphrase to unlock the database."
            });
            ui.add_space(20.0);

            let w = 320.0;
            let enter_pressed = |ui: &egui::Ui, r: &egui::Response| {
                r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
            };

            if form.first_launch {
                ui.label("username");
                let r = ui.add(
                    egui::TextEdit::singleline(&mut form.username)
                        .desired_width(w)
                        .hint_text("display name in chat"),
                );
                submit |= enter_pressed(ui, &r);
                ui.add_space(8.0);
            }

            ui.label("passphrase");
            let r = ui.add(
                egui::TextEdit::singleline(&mut form.passphrase)
                    .password(true)
                    .desired_width(w),
            );
            submit |= enter_pressed(ui, &r);

            if form.first_launch {
                ui.add_space(8.0);
                ui.label("confirm passphrase");
                let r = ui.add(
                    egui::TextEdit::singleline(&mut form.confirm)
                        .password(true)
                        .desired_width(w),
                );
                submit |= enter_pressed(ui, &r);
            }

            ui.add_space(14.0);
            if ui
                .add_sized(
                    [w, 30.0],
                    egui::Button::new(if form.first_launch { "sign up" } else { "unlock" }),
                )
                .clicked()
            {
                submit = true;
            }

            if let Some(err) = &form.error {
                ui.add_space(10.0);
                ui.colored_label(ERR_RED, err);
            }
        });
    });

    if !submit {
        return None;
    }
    if form.first_launch && form.username.trim().is_empty() {
        form.error = Some("username can't be empty".into());
        return None;
    }
    if form.passphrase.is_empty() {
        form.error = Some("passphrase can't be empty".into());
        return None;
    }
    if form.first_launch && form.confirm != form.passphrase {
        form.error = Some("passphrases don't match — try again".into());
        form.confirm.clear();
        return None;
    }
    form.error = None;
    let name = if form.first_launch {
        Some(form.username.trim().to_string())
    } else {
        None
    };
    Some((form.passphrase.clone(), name))
}

fn render_connecting(ui: &mut egui::Ui) {
    egui::CentralPanel::default().show_inside(ui, |ui| {
        ui.add_space(140.0);
        ui.vertical_centered(|ui| {
            ui.spinner();
            ui.add_space(10.0);
            ui.label("starting huddle…");
        });
    });
}

fn render_fatal(ui: &mut egui::Ui, msg: &str) {
    egui::CentralPanel::default().show_inside(ui, |ui| {
        ui.add_space(80.0);
        ui.vertical_centered(|ui| {
            ui.heading("cannot start");
            ui.add_space(10.0);
            ui.colored_label(ERR_RED, msg);
        });
    });
}
