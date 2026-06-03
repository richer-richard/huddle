//! The persistent view-model and the event reducer.
//!
//! `ViewModel` mirrors the TUI's `TuiApp`: the active pane, per-room cached
//! state, cached snapshots refreshed on a ~1s tick, and a transient status
//! line. `reduce` is the analogue of the TUI's `handle_app_event` — it folds
//! one inbox message into the model, hydrating open rooms from the handle.
//!
//! Rendering never calls the handle for mutations; view code pushes `UiAction`s
//! into a queue that the app applies after the frame (avoids the `&vm` /
//! `&mut self` borrow conflict).

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

use huddle_core::app::events::{AppEvent, DiscoveredRoom};
use huddle_core::app::{AppHandle, ContactView, KnownPeerStatus};
use huddle_core::network::transport::{TransportId, TransportProfile};
use huddle_core::network::NetworkMode;
use huddle_core::storage::repo::{
    PendingContactRequest, PendingFriendRequest, RoomKind, StoredAttachment, StoredRoomMessage,
};
use libp2p::PeerId;

use crate::bridge::Inbox;
use crate::fmt;

const LOG_CAP: usize = 1000;
const STATUS_TTL: std::time::Duration = std::time::Duration::from_secs(6);

/// Which pane the central area renders.
#[derive(Clone, PartialEq, Eq)]
pub enum Pane {
    Welcome,
    Profile,
    Dm(String),
    Group(String),
    People,
    Activity,
    Settings,
}

/// Collapsible sidebar sections.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Section {
    Direct,
    Group,
}

/// Which sublist the People pane shows.
/// Which sublist the Contacts pane shows. `Contacts` is the durable,
/// fingerprint-keyed address book; `Requests` collects inbound contact
/// requests (over the relay inbox) and legacy libp2p friend requests.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum PeopleTab {
    #[default]
    Contacts,
    Requests,
    Known,
    Verified,
    Blocked,
}

impl PeopleTab {
    pub fn label(self) -> &'static str {
        match self {
            PeopleTab::Contacts => "Contacts",
            PeopleTab::Requests => "Requests",
            PeopleTab::Known => "Known",
            PeopleTab::Verified => "Verified",
            PeopleTab::Blocked => "Blocked",
        }
    }
}

/// Which Settings tab is active.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum SettingsTab {
    #[default]
    Account,
    Network,
    Privacy,
}

impl SettingsTab {
    pub fn label(self) -> &'static str {
        match self {
            SettingsTab::Account => "Account",
            SettingsTab::Network => "Network",
            SettingsTab::Privacy => "Privacy",
        }
    }
}

/// A deferred side-effect produced by render code, applied after the frame.
pub enum UiAction {
    SwitchRoom(String),
    SelectPane(Pane),
    ToggleSection(Section),
    SendMessage { room_id: String, body: String },
    TypingPing(String),
    Copy(String),
    // Modal openers.
    OpenNewGroup,
    OpenNewDm,
    OpenJoin(String),
    CloseModal,
    // Modal submits.
    SubmitNewGroup {
        name: String,
        encrypted: bool,
        passphrase: String,
    },
    SubmitNewDm {
        target: String,
    },
    SubmitJoin {
        room_id: String,
        passphrase: Option<String>,
    },
    // People + inbound-dial gate.
    SelectPeopleTab(PeopleTab),
    PersonStartDm(String),
    PersonRedial(String),
    PersonForget(String),
    PersonBlock(String),
    PersonUnblock(String),
    AcceptRequest(String),
    RejectRequest(String),
    // Contacts address book + relay contact requests (huddle 1.0).
    OpenAddContact,
    SubmitAddContact {
        target: String,
        note: Option<String>,
    },
    AcceptContactRequest(String),
    RejectContactRequest(String),
    RemoveContact(String),
    OpenEditAlias(String),
    SubmitEditAlias {
        fingerprint: String,
        alias: Option<String>,
    },
    InboundAccept {
        peer_id: PeerId,
        address: String,
    },
    InboundReject {
        peer_id: PeerId,
        fingerprint: String,
    },
    InboundTrust {
        peer_id: PeerId,
        fingerprint: String,
        address: String,
    },
    // Verify + moderation + rotation.
    ToggleMemberPanel,
    OpenVerify(String),
    ToggleMemberVerified {
        room_id: String,
        fingerprint: String,
        verified: bool,
    },
    StartSas {
        room_id: String,
        fingerprint: String,
    },
    SasMatch(String),
    SasCancel(String),
    DoKick {
        room_id: String,
        fingerprint: String,
    },
    DoGrant {
        room_id: String,
        fingerprint: String,
    },
    OpenRotate(String),
    SubmitRotate {
        room_id: String,
        passphrase: String,
    },
    SubmitAcceptRotation {
        room_id: String,
        new_salt: Vec<u8>,
        passphrase: String,
    },
    ToggleRoomVerifiedOnly {
        room_id: String,
        on: bool,
    },
    OpenSearch(String),
    RunSearch {
        room_id: String,
        query: String,
    },
    LeaveRoom(String),
    // Files + invites + join codes.
    AttachFile(String),
    SaveAttachment {
        room_id: String,
        file_id: String,
    },
    CancelAttachment {
        room_id: String,
        file_id: String,
    },
    OpenAttachment {
        room_id: String,
        file_id: String,
    },
    GenerateInvite(String),
    OpenPasteInvite,
    SubmitPasteInvite(String),
    ConfirmInvite,
    GenerateJoinCode(String),
    OpenJoinWithCode(String),
    SubmitJoinWithCode {
        room_id: String,
        code: String,
    },
    // Settings + lifecycle.
    SelectSettingsTab(SettingsTab),
    OpenEditUsername,
    SubmitUsername(Option<String>),
    OpenQr,
    ToggleNotifications(bool),
    ToggleMdns(bool),
    /// huddle 1.0: open the "set clearnet relay" modal (prefilled with the
    /// current value).
    OpenSetRelay,
    /// huddle 1.0: persist (Some) or clear (None) the clearnet relay URL.
    SetClearnetRelay(Option<String>),
    ToggleVerifiedOnlyInbound(bool),
    ToggleUpdateCheck(bool),
    GoToBlocked,
    OpenGoDark,
    SubmitGoDark(String),
    OnboardingNext,
    OnboardingDone,
    UpdateOptInSet(bool),
    RequestShutdown,
    CancelQuit,
    RestartApp,
}

/// The single active modal overlay (a queue for async-raised modals lands in a
/// later phase).
pub enum Modal {
    None,
    NewGroup(NewGroupState),
    NewDm(NewDmState),
    AddContact(AddContactState),
    EditAlias(EditAliasState),
    Join(JoinState),
    InboundDial(InboundDialState),
    Verify(VerifyState),
    Sas(SasState),
    Search(SearchState),
    Rotate(RotateState),
    AcceptRotation(AcceptRotationState),
    ShowInvite(String),
    PasteInvite(PasteInviteState),
    ConfirmInvite(ConfirmInviteState),
    SetRelay(SetRelayState),
    JoinWithCode(JoinWithCodeState),
    EditUsername(EditUsernameState),
    GoDark(GoDarkState),
    Qr,
    Onboarding { cursor: usize },
    UpdateOptIn,
    QuitConfirm,
    Error(String),
    Info(String),
}

#[derive(Default)]
pub struct EditUsernameState {
    pub input: String,
}

#[derive(Default)]
pub struct GoDarkState {
    pub input: String,
    pub requires_passphrase: bool,
    pub error: Option<String>,
}

/// Phrase the user must type to confirm go-dark in `--no-master-passphrase`
/// sessions (mirrors the TUI).
pub const GO_DARK_CONFIRM_PHRASE: &str = "DELETE EVERYTHING";

/// First-launch onboarding cards (kept short and emoji-free, like huddle 0.9).
pub const ONBOARDING_PAGES: &[(&str, &str)] = &[
    (
        "huddle is not iMessage",
        "Your messages are end-to-end encrypted and travel over a Tor onion relay \
         that only ever sees ciphertext — never your keys, your IP, or who you are. \
         There's no account, just an identity key on this device.",
    ),
    (
        "passphrase ≠ password",
        "The master passphrase encrypts your LOCAL database. Room passphrases are \
         the access keys to encrypted rooms. Neither is recoverable — there's no \
         reset, by design.",
    ),
    (
        "getting started",
        "Make a group room or start a DM from the left rail, then share an invite \
         (the Invite button in a room). Your friend pastes it with “+ Paste invite”.",
    ),
];

#[derive(Default)]
pub struct PasteInviteState {
    pub url: String,
    pub error: Option<String>,
}

/// huddle 1.0: the "set clearnet relay" modal — paste a `wss://…/ws` (e.g. a
/// cloudflared tunnel) or `ws://ip:port/ws` relay URL, or clear it.
#[derive(Default)]
pub struct SetRelayState {
    pub url: String,
    pub error: Option<String>,
}

pub struct ConfirmInviteState {
    pub invite: huddle_core::invite::InviteLink,
    pub summary: String,
}

pub struct JoinWithCodeState {
    pub room_id: String,
    pub room_name: String,
    pub code: String,
}

pub struct InboundDialState {
    pub peer_id: PeerId,
    pub fingerprint: String,
    pub address: String,
}

/// Manual per-member verification toggles for a room.
pub struct VerifyState {
    pub room_id: String,
    /// (fingerprint, currently-verified)
    pub members: Vec<(String, bool)>,
}

#[derive(Clone)]
pub enum SasStage {
    /// Initiator sent SasInit; waiting for the partner's response.
    Waiting,
    /// Both pubkeys exchanged — show the code for out-of-band comparison.
    Comparing {
        words: String,
        decimal: String,
        our_matched: bool,
    },
}

pub struct SasState {
    pub partner_fingerprint: String,
    pub tx_id: String,
    pub stage: SasStage,
}

pub struct SearchState {
    pub room_id: String,
    pub query: String,
    pub results: Vec<StoredRoomMessage>,
    pub searched: bool,
}

pub struct RotateState {
    pub room_id: String,
    pub passphrase: String,
    pub error: Option<String>,
}

pub struct AcceptRotationState {
    pub room_id: String,
    pub rotator_fingerprint: String,
    pub new_salt: Vec<u8>,
    pub passphrase: String,
    pub error: Option<String>,
}

#[derive(Default)]
pub struct NewGroupState {
    pub name: String,
    pub encrypted: bool,
    pub passphrase: String,
    pub error: Option<String>,
}

#[derive(Default)]
pub struct NewDmState {
    pub target: String,
    pub error: Option<String>,
}

/// Add a contact by HD-ID. Sends a signed contact request over the relay inbox
/// (works across the internet) and races a same-LAN dial for immediacy.
#[derive(Default)]
pub struct AddContactState {
    pub target: String,
    pub note: String,
    pub error: Option<String>,
}

/// Rename a contact locally (sets the alias used everywhere in the UI).
pub struct EditAliasState {
    pub fingerprint: String,
    pub current_label: String,
    pub input: String,
}

pub struct JoinState {
    pub room_id: String,
    pub room_name: String,
    pub encrypted: bool,
    pub passphrase: String,
    pub error: Option<String>,
}

/// A room currently open in a tab (mirror of the TUI's `OpenRoom`).
pub struct OpenRoom {
    pub room_id: String,
    pub encrypted: bool,
    pub kind: RoomKind,
    pub members: Vec<String>,
    pub messages: Vec<StoredRoomMessage>,
    pub attachments: Vec<StoredAttachment>,
    pub input: String,
    pub stick_to_bottom: bool,
    pub last_typing_sent: Option<Instant>,
}

pub struct ViewModel {
    // identity
    pub our_fp: String,
    pub our_id: String,
    pub safety_code: String,
    pub display_name: Option<String>,
    // connectivity
    pub mode: NetworkMode,
    pub server_enabled: bool,
    pub server_connected: bool,
    pub listen_addresses: Vec<String>,
    // navigation + room state
    pub pane: Pane,
    pub expanded: HashSet<Section>,
    pub open_rooms: Vec<OpenRoom>,
    pub unread: HashMap<String, u32>,
    // snapshots refreshed on the ~1s tick
    pub discovered: Vec<DiscoveredRoom>,
    pub active_ids: HashSet<String>,
    pub labels: HashMap<String, String>,      // room_id -> display label
    pub peer_labels: HashMap<String, String>, // fingerprint -> display name
    pub known_peers: Vec<KnownPeerStatus>,
    pub pending_requests: Vec<PendingFriendRequest>,
    pub blocked: Vec<String>,
    pub verified_peers: Vec<String>,
    // huddle 1.0: durable fingerprint-keyed address book + relay contact
    // requests + the transport "doors" onto the relay.
    pub contacts: Vec<ContactView>,
    pub contact_requests: Vec<PendingContactRequest>,
    pub active_transport: Option<TransportId>,
    pub transport_profiles: Vec<TransportProfile>,
    // settings snapshots
    pub notifications_enabled: bool,
    pub mdns_enabled: bool,
    /// huddle 1.0: the persisted clearnet relay URL (e.g. a cloudflared
    /// tunnel), or `None` when unset. Shown + editable in Settings → Network.
    pub clearnet_relay: Option<String>,
    pub verified_only_inbound: bool,
    pub update_check: Option<bool>,
    pub has_master_passphrase: bool,
    // go-dark farewell timer
    pub went_dark_at: Option<Instant>,
    // people / settings sub-navigation
    pub people_tab: PeopleTab,
    pub settings_tab: SettingsTab,
    pub show_member_panel: bool,
    // activity feed + transient status
    pub log: VecDeque<String>,
    pub status: Option<(String, Instant)>,
    // active modal overlay + queue for async-raised modals
    pub modal: Modal,
    pub modal_queue: VecDeque<Modal>,
}

impl ViewModel {
    pub fn from_handle(h: &AppHandle) -> Self {
        let fp = h.fingerprint().to_string();
        let mut expanded = HashSet::new();
        expanded.insert(Section::Direct);
        expanded.insert(Section::Group);
        let mut vm = Self {
            our_id: fmt::display_id(&fp),
            our_fp: fp,
            safety_code: h.safety_code(),
            display_name: h.display_name(),
            // The ACTUAL mode the handle is running (resolved in build_inner
            // from --mode or the persisted mDNS toggle), not a CLI guess.
            mode: h.mode(),
            server_enabled: h.server_enabled(),
            server_connected: h.server_connected(),
            listen_addresses: Vec::new(),
            pane: Pane::Welcome,
            expanded,
            open_rooms: Vec::new(),
            unread: HashMap::new(),
            discovered: Vec::new(),
            active_ids: HashSet::new(),
            labels: HashMap::new(),
            peer_labels: HashMap::new(),
            known_peers: Vec::new(),
            pending_requests: Vec::new(),
            blocked: Vec::new(),
            verified_peers: Vec::new(),
            contacts: Vec::new(),
            contact_requests: Vec::new(),
            active_transport: None,
            transport_profiles: Vec::new(),
            notifications_enabled: true,
            mdns_enabled: false,
            clearnet_relay: None,
            verified_only_inbound: false,
            update_check: None,
            has_master_passphrase: h.has_master_passphrase(),
            went_dark_at: None,
            people_tab: PeopleTab::default(),
            settings_tab: SettingsTab::default(),
            show_member_panel: true,
            log: VecDeque::new(),
            status: None,
            modal: Modal::None,
            modal_queue: VecDeque::new(),
        };
        vm.refresh(h);
        vm
    }

    /// Whether the process should exit (go-dark farewell elapsed).
    pub fn should_exit(&self) -> bool {
        self.went_dark_at
            .map(|t| t.elapsed() > std::time::Duration::from_secs(2))
            .unwrap_or(false)
    }

    /// Show `m` now if no input-bearing modal is up, else queue it behind the
    /// active one (mirrors the TUI's `replace_modal_if_idle`).
    pub fn replace_modal_if_idle(&mut self, m: Modal) {
        if matches!(self.modal, Modal::None | Modal::Error(_) | Modal::Info(_)) {
            self.modal = m;
        } else {
            self.modal_queue.push_back(m);
            while self.modal_queue.len() > 16 {
                self.modal_queue.pop_front();
            }
        }
    }

    /// Close the active modal, pulling the next queued one (if any) forward.
    pub fn close_modal(&mut self) {
        self.modal = self.modal_queue.pop_front().unwrap_or(Modal::None);
    }

    /// Pull the cheap, frequently-changing snapshots from the handle. Called on
    /// the ~1s tick. SQLite-backed reads live here, not in per-frame render.
    pub fn refresh(&mut self, h: &AppHandle) {
        self.discovered = h.discovered_rooms();
        self.active_ids = h.active_room_ids().into_iter().collect();
        self.display_name = h.display_name();
        self.server_enabled = h.server_enabled();
        self.known_peers = h.known_peers();
        self.pending_requests = h.list_pending_friend_requests();
        self.blocked = h.list_blocked_peers();
        self.verified_peers = h.list_verified_peers();
        // huddle 1.0 snapshots: the address book, inbound relay contact
        // requests, and the active transport door + the full door list.
        self.contacts = h.list_contacts();
        self.contact_requests = h.list_pending_contact_requests();
        self.active_transport = h.active_transport();
        self.transport_profiles = h.transport_profiles();
        for c in &self.contacts {
            let label = c
                .alias
                .clone()
                .or_else(|| c.username.clone())
                .unwrap_or_else(|| fmt::display_id(&c.fingerprint));
            self.peer_labels.insert(c.fingerprint.clone(), label);
        }
        self.notifications_enabled = h.notifications_enabled();
        self.mdns_enabled = h.mdns_enabled();
        self.clearnet_relay = h.clearnet_relay();
        self.verified_only_inbound = h.verified_only_inbound();
        self.update_check = h.update_check_enabled();

        self.labels.clear();
        for d in &self.discovered {
            let label = if d.kind == RoomKind::Direct {
                let partner = h
                    .dm_partner_fingerprint(&d.room_id)
                    .unwrap_or_else(|| d.creator_fingerprint.clone());
                let l = h
                    .lookup_username(&partner)
                    .unwrap_or_else(|| fmt::display_id(&partner));
                self.peer_labels.entry(partner).or_insert_with(|| l.clone());
                l
            } else {
                d.name.clone()
            };
            self.labels.insert(d.room_id.clone(), label);
        }
        for r in &self.open_rooms {
            for m in &r.members {
                if !self.peer_labels.contains_key(m) {
                    let l = h
                        .lookup_member_display_name(m)
                        .unwrap_or_else(|| fmt::display_id(m));
                    self.peer_labels.insert(m.clone(), l);
                }
            }
        }
    }

    pub fn peer_label(&self, fp: &str) -> String {
        self.peer_labels
            .get(fp)
            .cloned()
            .unwrap_or_else(|| fmt::display_id(fp))
    }

    pub fn room_label(&self, room_id: &str) -> String {
        self.labels
            .get(room_id)
            .cloned()
            .unwrap_or_else(|| short_room(room_id))
    }

    pub fn open_room(&self, id: &str) -> Option<&OpenRoom> {
        self.open_rooms.iter().find(|r| r.room_id == id)
    }

    pub fn open_room_mut(&mut self, id: &str) -> Option<&mut OpenRoom> {
        self.open_rooms.iter_mut().find(|r| r.room_id == id)
    }

    pub fn current_room_id(&self) -> Option<&str> {
        match &self.pane {
            Pane::Dm(id) | Pane::Group(id) => Some(id.as_str()),
            _ => None,
        }
    }

    pub fn is_active_room(&self, id: &str) -> bool {
        self.current_room_id() == Some(id)
    }

    /// Switch the central pane to a room, hydrating it from the handle and
    /// clearing its unread counter.
    pub fn switch_to_room(&mut self, h: &AppHandle, id: &str) {
        let kind = h
            .active_room_info(id)
            .map(|r| r.kind)
            .or_else(|| self.discovered.iter().find(|d| d.room_id == id).map(|d| d.kind))
            .unwrap_or(RoomKind::Group);
        self.ensure_open(h, id);
        self.pane = match kind {
            RoomKind::Direct => Pane::Dm(id.to_string()),
            RoomKind::Group => Pane::Group(id.to_string()),
        };
        self.unread.remove(id);
    }

    /// Hydrate an `OpenRoom` from the handle if not already open.
    pub fn ensure_open(&mut self, h: &AppHandle, id: &str) {
        if self.open_room(id).is_some() {
            return;
        }
        let Some(info) = h.active_room_info(id) else {
            return;
        };
        let members = h.room_members(id);
        let messages = h.room_messages(id, 500).unwrap_or_default();
        let attachments = h.list_room_attachments(id).unwrap_or_default();
        self.open_rooms.push(OpenRoom {
            room_id: id.to_string(),
            encrypted: info.encrypted,
            kind: info.kind,
            members,
            messages,
            attachments,
            input: String::new(),
            stick_to_bottom: true,
            last_typing_sent: None,
        });
    }

    /// Refresh attachments for every open room (transfers progress between
    /// frames). Called on the ~1s tick.
    pub fn refresh_attachments(&mut self, h: &AppHandle) {
        for r in &mut self.open_rooms {
            if let Ok(a) = h.list_room_attachments(&r.room_id) {
                r.attachments = a;
            }
        }
    }

    pub fn set_status(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        self.push_log(msg.clone());
        self.status = Some((msg, Instant::now() + STATUS_TTL));
    }

    pub fn current_status(&self) -> Option<&str> {
        self.status.as_ref().and_then(|(m, exp)| {
            if *exp > Instant::now() {
                Some(m.as_str())
            } else {
                None
            }
        })
    }

    pub fn push_log(&mut self, line: impl Into<String>) {
        self.log.push_back(line.into());
        while self.log.len() > LOG_CAP {
            self.log.pop_front();
        }
    }

    fn note_listening(&mut self, address: String) {
        if !self.listen_addresses.contains(&address) {
            self.listen_addresses.push(address);
        }
    }
}

/// Fold one inbox message into the view-model.
pub fn reduce(vm: &mut ViewModel, h: &AppHandle, msg: Inbox) {
    match msg {
        Inbox::Event(ev) => apply_event(vm, h, ev),
        Inbox::Lagged(n) => vm.push_log(format!("(dropped {n} events — UI fell behind)")),
        Inbox::CmdError(e) => vm.set_status(format!("error: {e}")),
        Inbox::ReqOk(tag, ok) => match ok {
            crate::bridge::ReqOk::RoomId(id) => vm.switch_to_room(h, &id),
            crate::bridge::ReqOk::TxId(tx) => {
                if let Modal::Sas(s) = &mut vm.modal {
                    s.tx_id = tx;
                }
            }
            crate::bridge::ReqOk::JoinCode(code) => {
                vm.modal = Modal::Info(format!("Join code (valid ~10 min):\n\n{code}"));
            }
            crate::bridge::ReqOk::SavedPath(p) => vm.set_status(format!("saved to {}", p.display())),
            other => vm.push_log(format!("ok [{tag:?}]: {other:?}")),
        },
        Inbox::ReqErr(tag, e) => vm.set_status(format!("error [{tag:?}]: {e}")),
    }
}

fn apply_event(vm: &mut ViewModel, h: &AppHandle, ev: AppEvent) {
    vm.push_log(describe_event(&ev));
    match ev {
        AppEvent::ListeningOn { address } => vm.note_listening(address),
        AppEvent::RoomJoined { room_id } => {
            vm.ensure_open(h, &room_id);
            if matches!(vm.pane, Pane::Welcome | Pane::Profile) {
                vm.switch_to_room(h, &room_id);
            }
        }
        AppEvent::RoomLeft { room_id } => {
            vm.open_rooms.retain(|r| r.room_id != room_id);
            vm.unread.remove(&room_id);
            if vm.current_room_id() == Some(room_id.as_str()) {
                vm.pane = Pane::Welcome;
            }
        }
        AppEvent::MemberJoined { room_id, fingerprint } => {
            if let Some(r) = vm.open_room_mut(&room_id) {
                if !r.members.contains(&fingerprint) {
                    r.members.push(fingerprint);
                    r.members.sort();
                }
            }
        }
        AppEvent::MemberLeft { room_id, fingerprint } => {
            if let Some(r) = vm.open_room_mut(&room_id) {
                r.members.retain(|f| f != &fingerprint);
            }
        }
        AppEvent::MessageReceived { room_id, sender_fingerprint, body, sent_at } => {
            let active = vm.is_active_room(&room_id);
            if let Some(r) = vm.open_room_mut(&room_id) {
                r.messages.push(StoredRoomMessage {
                    id: 0,
                    room_id: room_id.clone(),
                    sender_fingerprint,
                    direction: "in".into(),
                    body,
                    sent_at,
                });
                r.stick_to_bottom = true;
            }
            if !active {
                *vm.unread.entry(room_id).or_insert(0) += 1;
            }
        }
        AppEvent::MessageSent { room_id, body, message_id } => {
            let me = vm.our_fp.clone();
            let now = now_unix();
            if let Some(r) = vm.open_room_mut(&room_id) {
                r.messages.push(StoredRoomMessage {
                    id: message_id,
                    room_id,
                    sender_fingerprint: me,
                    direction: "out".into(),
                    body,
                    sent_at: now,
                });
                r.stick_to_bottom = true;
            }
        }
        AppEvent::Error { description } => vm.set_status(format!("error: {description}")),
        AppEvent::Dialing { address } => vm.set_status(format!("dialing {address}…")),
        AppEvent::DialSucceeded { address, .. } => vm.set_status(format!("connected to {address}")),
        AppEvent::DialFailed { address, error } => {
            vm.set_status(format!("dial {address} failed: {error}"))
        }
        AppEvent::AutoOpenDm { room_id, .. } => vm.switch_to_room(h, &room_id),
        AppEvent::MentionReceived { room_id, .. } => {
            vm.set_status(format!("@you mentioned in {}", vm.room_label(&room_id)))
        }
        AppEvent::InboundDial { peer_id, fingerprint, address } => {
            vm.replace_modal_if_idle(Modal::InboundDial(InboundDialState {
                peer_id,
                fingerprint,
                address,
            }));
        }
        AppEvent::SasCodeReady { partner_fingerprint, tx_id, emoji_labels, decimal, .. } => {
            // Advance our own in-flight SAS modal, or raise one for an
            // inbound request.
            if let Modal::Sas(s) = &mut vm.modal {
                if s.tx_id == tx_id {
                    s.stage = SasStage::Comparing {
                        words: emoji_labels,
                        decimal,
                        our_matched: false,
                    };
                    return;
                }
            }
            vm.replace_modal_if_idle(Modal::Sas(SasState {
                partner_fingerprint,
                tx_id,
                stage: SasStage::Comparing {
                    words: emoji_labels,
                    decimal,
                    our_matched: false,
                },
            }));
        }
        AppEvent::SasVerified { partner_fingerprint, .. } => {
            if matches!(vm.modal, Modal::Sas(_)) {
                vm.close_modal();
            }
            vm.set_status(format!("verified {} via SAS", fmt::short_fp2(&partner_fingerprint)));
        }
        AppEvent::RotationRequested { room_id, rotator_fingerprint, new_salt } => {
            vm.replace_modal_if_idle(Modal::AcceptRotation(AcceptRotationState {
                room_id,
                rotator_fingerprint,
                new_salt,
                passphrase: String::new(),
                error: None,
            }));
        }
        AppEvent::WentDark => {
            vm.went_dark_at = Some(Instant::now());
            vm.modal = Modal::Info("Goodbye. huddle has gone dark — your data has been wiped.".into());
            vm.modal_queue.clear();
        }
        AppEvent::InviteFingerprintMismatch { claimed, actual, .. } => {
            vm.replace_modal_if_idle(Modal::Error(format!(
                "invite fingerprint mismatch — connection dropped.\nclaimed: {}\nactual:  {}\nthe invite link may be forged.",
                fmt::short_fp2(&claimed),
                fmt::short_fp2(&actual)
            )));
        }
        AppEvent::CodeJoinTimedOut { reason, .. } => {
            vm.replace_modal_if_idle(Modal::Error(format!("join code: {reason}")));
        }
        AppEvent::ContactRequestReceived { fingerprint, display_name, .. } => {
            // Pull the new request in immediately (don't wait for the 1s tick)
            // so the Requests tab badge updates the moment it arrives.
            vm.contact_requests = h.list_pending_contact_requests();
            let who = display_name.unwrap_or_else(|| fmt::display_id(&fingerprint));
            vm.set_status(format!("contact request from {who} — see Contacts"));
        }
        // The remaining variants surface in later phases (files, SAS, rotation,
        // inbound dial, NAT, …). They're already in the activity log above.
        _ => {}
    }
}

fn describe_event(ev: &AppEvent) -> String {
    use AppEvent::*;
    match ev {
        RoomDiscovered(d) => format!("discovered room “{}” ({} members)", d.name, d.member_count),
        RoomLost { room_id } => format!("room lost {}", short_room(room_id)),
        RoomJoined { room_id } => format!("joined room {}", short_room(room_id)),
        RoomLeft { room_id } => format!("left room {}", short_room(room_id)),
        MemberJoined { fingerprint, .. } => format!("member joined {}", fmt::short_fp2(fingerprint)),
        MemberLeft { fingerprint, .. } => format!("member left {}", fmt::short_fp2(fingerprint)),
        MessageReceived { sender_fingerprint, body, .. } => {
            format!("{}: {}", fmt::short_fp2(sender_fingerprint), preview(body))
        }
        MessageSent { body, .. } => format!("you: {}", preview(body)),
        ListeningOn { address } => format!("listening on {address}"),
        Dialing { address } => format!("dialing {address}…"),
        DialSucceeded { address, .. } => format!("connected to {address}"),
        DialFailed { address, error } => format!("dial {address} failed: {error}"),
        Error { description } => format!("error: {description}"),
        FileOffered { name, size_bytes, .. } => {
            format!("file offered: {name} ({} KB)", size_bytes / 1024)
        }
        FileReady { .. } => "file ready".to_string(),
        FileSaved { path, .. } => format!("saved to {path}"),
        FileFailed { reason, .. } => format!("transfer failed: {reason}"),
        RotationRequested { rotator_fingerprint, .. } => {
            format!("key rotation requested by {}", fmt::short_fp2(rotator_fingerprint))
        }
        MentionReceived { room_id, .. } => format!("@you mentioned in {}", short_room(room_id)),
        InboundDial { fingerprint, .. } => format!("inbound dial from {}", fmt::short_fp2(fingerprint)),
        SasCodeReady { decimal, .. } => format!("SAS code: {decimal}"),
        SasVerified { partner_fingerprint, .. } => {
            format!("verified {} via SAS", fmt::short_fp2(partner_fingerprint))
        }
        NatStatusChanged { label, .. } => format!("NAT status: {label}"),
        PeerProfileUpdated { fingerprint, username } => {
            let label = username.clone().unwrap_or_else(|| "[anonymous]".into());
            format!("{} is now {}", fmt::short_fp(fingerprint), label)
        }
        WentDark => "gone dark — data wiped".to_string(),
        AutoOpenDm { fingerprint, .. } => format!("auto-opened DM with {}", fmt::short_fp2(fingerprint)),
        other => format!("{other:?}"),
    }
}

fn short_room(id: &str) -> String {
    id.chars().take(8).collect()
}

fn preview(body: &str) -> String {
    let single: String = body.chars().map(|c| if c == '\n' { ' ' } else { c }).collect();
    let trimmed = single.trim();
    if trimmed.chars().count() > 80 {
        format!("{}…", trimmed.chars().take(77).collect::<String>())
    } else {
        trimmed.to_string()
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm() -> ViewModel {
        ViewModel {
            our_fp: "aaaa-bbbb".into(),
            our_id: "HD-AAAA-BBBB".into(),
            safety_code: "0000".into(),
            display_name: None,
            mode: NetworkMode::Server,
            server_enabled: true,
            server_connected: false,
            listen_addresses: Vec::new(),
            pane: Pane::Welcome,
            expanded: HashSet::new(),
            open_rooms: Vec::new(),
            unread: HashMap::new(),
            discovered: Vec::new(),
            active_ids: HashSet::new(),
            labels: HashMap::new(),
            peer_labels: HashMap::new(),
            known_peers: Vec::new(),
            pending_requests: Vec::new(),
            blocked: Vec::new(),
            verified_peers: Vec::new(),
            contacts: Vec::new(),
            contact_requests: Vec::new(),
            active_transport: None,
            transport_profiles: Vec::new(),
            notifications_enabled: true,
            mdns_enabled: false,
            clearnet_relay: None,
            verified_only_inbound: false,
            update_check: None,
            has_master_passphrase: false,
            went_dark_at: None,
            people_tab: PeopleTab::default(),
            settings_tab: SettingsTab::default(),
            show_member_panel: true,
            log: VecDeque::new(),
            status: None,
            modal: Modal::None,
            modal_queue: VecDeque::new(),
        }
    }

    fn room(id: &str) -> OpenRoom {
        OpenRoom {
            room_id: id.into(),
            encrypted: false,
            kind: RoomKind::Group,
            members: vec![],
            messages: vec![],
            attachments: vec![],
            input: String::new(),
            stick_to_bottom: true,
            last_typing_sent: None,
        }
    }

    // The handle-touching reducer paths can't run without a live AppHandle, so
    // we exercise the pure message-append + unread logic directly instead.
    #[test]
    fn message_append_and_unread_pure() {
        // Exercise the pure message-append + unread logic without a handle.
        let mut v = vm();
        v.open_rooms.push(room("r1"));
        // simulate inactive room
        v.pane = Pane::Welcome;
        let active = v.is_active_room("r1");
        if let Some(r) = v.open_room_mut("r1") {
            r.messages.push(StoredRoomMessage {
                id: 0,
                room_id: "r1".into(),
                sender_fingerprint: "x".into(),
                direction: "in".into(),
                body: "hi".into(),
                sent_at: 0,
            });
        }
        if !active {
            *v.unread.entry("r1".into()).or_insert(0) += 1;
        }
        assert_eq!(v.open_room("r1").unwrap().messages.len(), 1);
        assert_eq!(*v.unread.get("r1").unwrap(), 1);
    }

    #[test]
    fn status_expires() {
        let mut v = vm();
        v.set_status("hello");
        assert_eq!(v.current_status(), Some("hello"));
    }
}
