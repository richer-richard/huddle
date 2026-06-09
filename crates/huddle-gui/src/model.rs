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

use zeroize::Zeroizing;

use huddle_core::app::events::{AppEvent, DiscoveredRoom};
use huddle_core::app::{AppHandle, ContactView, KnownPeerStatus};
use huddle_core::network::transport::{TransportId, TransportProfile};
use huddle_core::network::NetworkMode;
use huddle_core::storage::repo::{
    PendingContactRequest, PendingFriendRequest, RoomKind, StoredAttachment, StoredReaction,
    StoredRoomMessage,
};
use libp2p::PeerId;

use crate::bridge::Inbox;
use crate::fmt;

const LOG_CAP: usize = 1000;
const STATUS_TTL: std::time::Duration = std::time::Duration::from_secs(6);

/// huddle 1.3.4: cap on messages retained in an open room's in-memory buffer.
/// A room loads ~500 from the DB on open, then every received/sent message was
/// pushed without bound — a peer spamming a busy room would grow this Vec
/// indefinitely on the GUI client. Oldest are dropped past the cap (history
/// stays in the DB); generous enough for normal scrollback.
const OPEN_ROOM_MSG_CAP: usize = 2000;

/// Push a message and drop the oldest if the buffer exceeds [`OPEN_ROOM_MSG_CAP`].
fn push_capped(messages: &mut Vec<StoredRoomMessage>, m: StoredRoomMessage) {
    messages.push(m);
    if messages.len() > OPEN_ROOM_MSG_CAP {
        let excess = messages.len() - OPEN_ROOM_MSG_CAP;
        messages.drain(0..excess);
    }
}

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
    SendMessage {
        room_id: String,
        body: String,
    },
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
    // huddle 1.2.1: short-lived "connect code" — generate one to share, or
    // redeem one a friend shared (handled inside SubmitAddContact).
    GenerateConnectCode,
    // huddle 1.2.1: open the About window (version + GitHub link).
    OpenAbout,
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
    /// Toggle the Settings option that switches Attach between the native rfd
    /// file dialog (off) and a manual file-path text-entry modal (on).
    ToggleAttachViaPath(bool),
    /// Submit the manually typed attach path from the AttachPath modal.
    SubmitAttachPath {
        room_id: String,
        path: String,
    },
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
    /// huddle 1.1.3: switch the GUI theme (System/Dark/Light) — applied live +
    /// persisted. `System` follows the OS appearance.
    SetTheme(crate::theme::Theme),
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
    // ---- huddle 2.0.0 (F5): master passphrase change ----
    OpenChangePassphrase,
    SubmitChangePassphrase {
        current: String,
        new: String,
    },
    // ---- huddle 2.0.0 (F6): BIP39 seed-phrase export (show-once + verify) ----
    OpenExportSeed,
    /// Verify the re-typed phrase against our identity before declaring the
    /// backup good (drives the export modal's `Verify` → `Done` step).
    ExportSeedVerify {
        reentry: String,
    },
    // ---- huddle 2.0.0 (F9): per-room disappearing-messages TTL ----
    OpenDisappearing(String),
    SetDisappearing {
        room_id: String,
        ttl_secs: Option<u32>,
    },
    // ---- huddle 2.0.0 (F10): reactions / replies / edits / deletes ----
    OpenEmojiPicker {
        room_id: String,
        target_msg_id: String,
    },
    SendReaction {
        room_id: String,
        target_msg_id: String,
        emoji: String,
        removed: bool,
    },
    StartReply {
        room_id: String,
        target_msg_id: String,
        preview: String,
    },
    CancelReply(String),
    SendReply {
        room_id: String,
        body: String,
        reply_to: String,
    },
    StartEdit {
        room_id: String,
        target_msg_id: String,
        body: String,
    },
    CancelEdit(String),
    SendEdit {
        room_id: String,
        target_msg_id: String,
        new_body: String,
    },
    OpenConfirmDelete {
        room_id: String,
        target_msg_id: String,
        preview: String,
    },
    SendDelete {
        room_id: String,
        target_msg_id: String,
    },
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
    /// Manual file-path entry for Attach (alternative to the native rfd dialog).
    AttachPath(AttachPathState),
    JoinWithCode(JoinWithCodeState),
    EditUsername(EditUsernameState),
    GoDark(GoDarkState),
    Qr,
    /// huddle 1.2.1: About window — version + a link to the GitHub repo.
    About,
    Onboarding {
        cursor: usize,
    },
    UpdateOptIn,
    QuitConfirm,
    /// huddle 2.0.0 (F5): change the master passphrase + re-key the DB at rest.
    ChangePassphrase(ChangePassphraseState),
    /// huddle 2.0.0 (F6): show the 24-word BIP39 identity seed once and verify
    /// the user transcribed it before relying on it for recovery.
    ExportSeed(ExportSeedState),
    /// huddle 2.0.0 (F3): a pinned peer key changed mid-session (TOFU drift) —
    /// prompt to re-verify (SAS), or block the peer.
    SafetyNumberChanged(SafetyNumberChangedState),
    /// huddle 2.0.0 (F9): pick a per-room disappearing-messages TTL.
    Disappearing(DisappearingState),
    /// huddle 2.0.0 (F10): pick an emoji to react to a message with.
    EmojiPicker(EmojiPickerState),
    /// huddle 2.0.0 (F10): confirm a permanent (for-everyone) message delete.
    ConfirmDelete(ConfirmDeleteState),
    Error(String),
    Info(String),
}

/// huddle 2.0.0 (F5): the change-master-passphrase modal's fields. The actual
/// re-key + verification of `current` happens in the core; this only collects
/// input and surfaces the result.
#[derive(Default)]
pub struct ChangePassphraseState {
    pub current: String,
    pub new: String,
    pub confirm: String,
    pub error: Option<String>,
}

/// huddle 2.0.0 (F6): the show-once / re-entry-verified seed export flow.
pub struct ExportSeedState {
    /// The 24-word phrase (held only while the modal is open).
    pub phrase: String,
    /// Whether the phrase is currently revealed (hidden behind dots by default).
    pub revealed: bool,
    pub step: ExportSeedStep,
    /// The user's re-typed phrase in the verify step. Wrapped in `Zeroizing` so
    /// the re-entered secret is scrubbed from the heap when the modal closes
    /// (F6) — unlike `phrase`, which is deliberately shown for paper backup.
    pub reentry: Zeroizing<String>,
    pub error: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ExportSeedStep {
    /// Bold warning + the (hidden-by-default) phrase.
    Reveal,
    /// Re-type the phrase to confirm it was written down correctly.
    Verify,
    /// Verified — the backup is good.
    Done,
}

/// huddle 2.0.0 (F3): everything the safety-number-change alert needs.
pub struct SafetyNumberChangedState {
    pub room_id: String,
    pub fingerprint: String,
    pub old_pubkey_b64: String,
    pub new_pubkey_b64: String,
    pub display_name: Option<String>,
}

/// huddle 2.0.0 (F9): TTL picker state — `current` is the room's live setting so
/// the selector opens on the active choice.
pub struct DisappearingState {
    pub room_id: String,
    pub current: Option<u32>,
}

/// huddle 2.0.0 (F9): the TTL options the picker offers, as
/// `(label, ttl_secs)`. `None` is "off".
pub const DISAPPEARING_OPTIONS: &[(&str, Option<u32>)] = &[
    ("Off", None),
    ("5 minutes", Some(300)),
    ("1 hour", Some(3600)),
    ("1 day", Some(86_400)),
    ("1 week", Some(604_800)),
];

/// huddle 2.0.0 (F9): render a TTL in seconds as a short human label for the
/// room header indicator.
pub fn ttl_label(secs: u32) -> String {
    match secs {
        300 => "5m".into(),
        3600 => "1h".into(),
        86_400 => "1d".into(),
        604_800 => "1w".into(),
        s if s % 86_400 == 0 => format!("{}d", s / 86_400),
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

/// huddle 2.0.0 (F10): which message the emoji picker is reacting to.
pub struct EmojiPickerState {
    pub room_id: String,
    pub target_msg_id: String,
}

/// huddle 2.0.0 (F10): the delete-confirmation modal's target + a preview of the
/// body being removed.
pub struct ConfirmDeleteState {
    pub room_id: String,
    pub target_msg_id: String,
    pub preview: String,
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

/// Manual file-path entry for the Attach button when "Attach by typing a path"
/// is enabled in Settings (instead of the native rfd file dialog).
#[derive(Default, Clone)]
pub struct AttachPathState {
    pub room_id: String,
    pub path: String,
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
    /// huddle 1.2.1: a connect code we minted to share (code, expiry-epoch-secs),
    /// shown inside this modal once the relay returns it.
    pub code: Option<(String, i64)>,
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
    /// huddle 2.0.0 (F10): every reaction stored for this room (refreshed on the
    /// ~1s tick and on `ReactionAdded`). Rendered grouped per
    /// `target_client_msg_id` into per-emoji counts under each message.
    pub reactions: Vec<StoredReaction>,
    /// huddle 2.0.0 (F9): the room's disappearing-messages TTL in seconds, or
    /// `None` when expiry is OFF. Drives the room-header indicator.
    pub ttl_secs: Option<u32>,
    /// huddle 2.0.0 (F10): the message currently being replied to in the
    /// composer, as `(client_msg_id, one-line preview)`. `None` = top-level
    /// message. Set by `StartReply`, cleared by `CancelReply` / on send.
    pub reply_to: Option<(String, String)>,
    /// huddle 2.0.0 (F10): the `client_msg_id` of the message being edited
    /// inline (the composer holds the draft body). `None` = composing a new
    /// message. Set by `StartEdit`, cleared by `CancelEdit` / on send.
    pub edit_target: Option<String>,
}

impl OpenRoom {
    /// huddle 2.0.0 (F10): the reactions on one message, grouped into
    /// `(emoji, count, we_reacted)` tuples in first-seen order. `our_fp` is the
    /// local fingerprint, used to flag which badges we can toggle off.
    pub fn reactions_for(&self, client_msg_id: &str, our_fp: &str) -> Vec<(String, usize, bool)> {
        let mut order: Vec<String> = Vec::new();
        let mut counts: HashMap<String, (usize, bool)> = HashMap::new();
        for r in self
            .reactions
            .iter()
            .filter(|r| r.target_client_msg_id == client_msg_id)
        {
            let e = counts.entry(r.emoji.clone()).or_insert_with(|| {
                order.push(r.emoji.clone());
                (0, false)
            });
            e.0 += 1;
            if r.sender_fingerprint == our_fp {
                e.1 = true;
            }
        }
        order
            .into_iter()
            .map(|emoji| {
                let (n, mine) = counts[&emoji];
                (emoji, n, mine)
            })
            .collect()
    }
}

/// huddle 2.0.0 (F10): the emoji palette offered by the reaction picker. Kept
/// short and conventional; a sender can only carry one of these per message.
pub const REACTION_EMOJIS: &[&str] = &["👍", "❤️", "😂", "🎉", "🔥", "😮", "😢", "🙏"];

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
    pub labels: HashMap<String, String>, // room_id -> display label
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
    /// When on, the chat Attach button opens a manual file-path text-entry
    /// modal instead of the native rfd file dialog. Persisted (default false).
    pub attach_via_path: bool,
    /// huddle 1.1.3: the user's GUI theme CHOICE (System/Dark/Light; `System`
    /// default, follows the OS). Persisted as `theme`; resolved to an effective
    /// Dark/Light at render time. Drives the Settings selector highlight.
    pub theme: crate::theme::Theme,
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
    /// huddle 1.2.1: the most recently minted connect code + its expiry (epoch
    /// secs), shown in the Add-contact modal so the user can share it. Cleared
    /// when it expires or a new one is minted.
    pub connect_code: Option<(String, i64)>,
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
            attach_via_path: h.attach_via_path(),
            theme: crate::theme::Theme::from_str(&h.theme()),
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
            connect_code: None,
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
        self.attach_via_path = h.attach_via_path();
        self.theme = crate::theme::Theme::from_str(&h.theme());
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
            .or_else(|| {
                self.discovered
                    .iter()
                    .find(|d| d.room_id == id)
                    .map(|d| d.kind)
            })
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
            // huddle 2.0.0 (F10/F9): hydrate reactions + disappearing TTL so the
            // first frame already shows badges and the header indicator.
            reactions: h.room_reactions(id),
            ttl_secs: h.room_disappearing_ttl(id),
            reply_to: None,
            edit_target: None,
        });
    }

    /// huddle 2.0.0 (F10): reload one open room's message history + reactions
    /// from the DB. The live append-on-event path shows new messages instantly
    /// but can't carry their sender-minted `client_msg_id` (the event omits it);
    /// this pulls the full rows so reactions / replies / edits / deletes can
    /// target them. Called on the ~1s tick and on every F10 content event.
    pub fn reload_room_history(&mut self, h: &AppHandle, room_id: &str) {
        let messages = h.room_messages(room_id, 500).unwrap_or_default();
        let reactions = h.room_reactions(room_id);
        let ttl = h.room_disappearing_ttl(room_id);
        if let Some(r) = self.open_room_mut(room_id) {
            r.messages = messages;
            r.reactions = reactions;
            r.ttl_secs = ttl;
        }
    }

    /// Reload every open room's history (F10 reactions/edits/deletes + F9
    /// expiry). Mirrors [`refresh_attachments`]; runs on the ~1s tick.
    pub fn reload_open_rooms_history(&mut self, h: &AppHandle) {
        let ids: Vec<String> = self.open_rooms.iter().map(|r| r.room_id.clone()).collect();
        for id in ids {
            self.reload_room_history(h, &id);
        }
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
            crate::bridge::ReqOk::SavedPath(p) => {
                vm.set_status(format!("saved to {}", p.display()))
            }
            other => vm.push_log(format!("ok [{tag:?}]: {other:?}")),
        },
        Inbox::ReqErr(tag, e) => match tag {
            // huddle 2.0.0 (F5): surface a wrong-current-passphrase inline in the
            // change-passphrase modal instead of the transient status line.
            crate::bridge::ReqTag::ChangePassphrase => {
                if let Modal::ChangePassphrase(s) = &mut vm.modal {
                    s.error = Some(e);
                } else {
                    vm.set_status(format!("passphrase change failed: {e}"));
                }
            }
            _ => vm.set_status(format!("error [{tag:?}]: {e}")),
        },
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
        AppEvent::MemberJoined {
            room_id,
            fingerprint,
        } => {
            if let Some(r) = vm.open_room_mut(&room_id) {
                if !r.members.contains(&fingerprint) {
                    r.members.push(fingerprint);
                    r.members.sort();
                }
            }
        }
        AppEvent::MemberLeft {
            room_id,
            fingerprint,
        } => {
            if let Some(r) = vm.open_room_mut(&room_id) {
                r.members.retain(|f| f != &fingerprint);
            }
        }
        AppEvent::MessageReceived {
            room_id,
            sender_fingerprint,
            body,
            sent_at,
        } => {
            let active = vm.is_active_room(&room_id);
            if let Some(r) = vm.open_room_mut(&room_id) {
                push_capped(
                    &mut r.messages,
                    StoredRoomMessage {
                        id: 0,
                        room_id: room_id.clone(),
                        sender_fingerprint,
                        direction: "in".into(),
                        body,
                        sent_at,
                        // The event omits the sender-minted id; the ~1s history
                        // reload (and F10 content events) backfill the full row
                        // so reactions / replies / edits can target it.
                        client_msg_id: None,
                        reply_to: None,
                        edited_at: None,
                        deleted_at: None,
                    },
                );
                r.stick_to_bottom = true;
            }
            if !active {
                // huddle 1.3.4: saturating, matching the TUI — never panic/wrap
                // the unread counter on overflow.
                let c = vm.unread.entry(room_id).or_insert(0);
                *c = c.saturating_add(1);
            }
        }
        AppEvent::MessageSent {
            room_id,
            body,
            message_id,
        } => {
            let me = vm.our_fp.clone();
            let now = now_unix();
            if let Some(r) = vm.open_room_mut(&room_id) {
                push_capped(
                    &mut r.messages,
                    StoredRoomMessage {
                        id: message_id,
                        room_id,
                        sender_fingerprint: me,
                        direction: "out".into(),
                        body,
                        sent_at: now,
                        client_msg_id: None,
                        reply_to: None,
                        edited_at: None,
                        deleted_at: None,
                    },
                );
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
        AppEvent::InboundDial {
            peer_id,
            fingerprint,
            address,
        } => {
            vm.replace_modal_if_idle(Modal::InboundDial(InboundDialState {
                peer_id,
                fingerprint,
                address,
            }));
        }
        AppEvent::SasCodeReady {
            partner_fingerprint,
            tx_id,
            emoji_labels,
            decimal,
            ..
        } => {
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
        AppEvent::SasVerified {
            partner_fingerprint,
            ..
        } => {
            if matches!(vm.modal, Modal::Sas(_)) {
                vm.close_modal();
            }
            vm.set_status(format!(
                "verified {} via SAS",
                fmt::short_fp2(&partner_fingerprint)
            ));
        }
        AppEvent::RotationRequested {
            room_id,
            rotator_fingerprint,
            new_salt,
        } => {
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
            vm.modal =
                Modal::Info("Goodbye. huddle has gone dark — your data has been wiped.".into());
            vm.modal_queue.clear();
        }
        AppEvent::InviteFingerprintMismatch {
            claimed, actual, ..
        } => {
            vm.replace_modal_if_idle(Modal::Error(format!(
                "invite fingerprint mismatch — connection dropped.\nclaimed: {}\nactual:  {}\nthe invite link may be forged.",
                fmt::short_fp2(&claimed),
                fmt::short_fp2(&actual)
            )));
        }
        AppEvent::CodeJoinTimedOut { reason, .. } => {
            vm.replace_modal_if_idle(Modal::Error(format!("join code: {reason}")));
        }
        AppEvent::ContactRequestReceived {
            fingerprint,
            display_name,
            ..
        } => {
            // Pull the new request in immediately (don't wait for the 1s tick)
            // so the Requests tab badge updates the moment it arrives.
            vm.contact_requests = h.list_pending_contact_requests();
            let who = display_name.unwrap_or_else(|| fmt::display_id(&fingerprint));
            vm.set_status(format!("contact request from {who} — see Contacts"));
        }
        AppEvent::ConnectCodeCreated { code, expires_at } => {
            // huddle 1.2.1: surface the minted code in the open Add-contact
            // modal (with a Copy button + countdown), and record it on the vm.
            vm.set_status(format!("connect code ready: {code}"));
            if let Modal::AddContact(s) = &mut vm.modal {
                s.code = Some((code.clone(), expires_at));
            }
            vm.connect_code = Some((code, expires_at));
        }
        AppEvent::ConnectCodeRedeemed { fingerprint } => {
            let who = fmt::display_id(&fingerprint);
            vm.set_status(format!("connect code accepted — request sent to {who}"));
        }
        AppEvent::ConnectCodeFailed { reason } => {
            vm.set_status(format!("connect code: {reason}"));
        }
        // huddle 2.0.0 (F3): a pinned peer key changed mid-session. Surface the
        // alert without clobbering a modal the user is mid-way through; the
        // offending message was already dropped by the core.
        AppEvent::SafetyNumberChanged {
            room_id,
            fingerprint,
            old_pubkey_b64,
            new_pubkey_b64,
            display_name,
        } => {
            vm.replace_modal_if_idle(Modal::SafetyNumberChanged(SafetyNumberChangedState {
                room_id,
                fingerprint,
                old_pubkey_b64,
                new_pubkey_b64,
                display_name,
            }));
        }
        // huddle 2.0.0 (F5): the master passphrase change + DB re-key succeeded.
        AppEvent::PassphraseChanged => {
            if matches!(vm.modal, Modal::ChangePassphrase(_)) {
                vm.close_modal();
            }
            vm.set_status("passphrase updated");
        }
        // huddle 2.0.0 (F10): reactions / edits / deletes — re-read the affected
        // room from the DB so badges, `[edited]`, and `[deleted]` reflect at once.
        AppEvent::ReactionAdded { room_id, .. }
        | AppEvent::MessageEdited { room_id, .. }
        | AppEvent::MessageDeleted { room_id, .. } => {
            if vm.open_room(&room_id).is_some() {
                vm.reload_room_history(h, &room_id);
            }
        }
        // huddle 2.0.0 (F9): the per-room TTL changed (locally or via a signed
        // owner broadcast) — refresh the header indicator.
        AppEvent::RoomTtlChanged { room_id, ttl_secs } => {
            if let Some(r) = vm.open_room_mut(&room_id) {
                r.ttl_secs = ttl_secs;
            }
            vm.set_status(match ttl_secs {
                Some(s) => format!("disappearing messages: on ({})", ttl_label(s)),
                None => "disappearing messages: off".to_string(),
            });
        }
        // huddle 2.0.0 (F9): the pruner deleted expired messages — drop the
        // vanished rows from every open room's view.
        AppEvent::MessagesExpired { count } => {
            if count > 0 {
                vm.reload_open_rooms_history(h);
            }
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
        MemberJoined { fingerprint, .. } => {
            format!("member joined {}", fmt::short_fp2(fingerprint))
        }
        MemberLeft { fingerprint, .. } => format!("member left {}", fmt::short_fp2(fingerprint)),
        MessageReceived {
            sender_fingerprint,
            body,
            ..
        } => {
            format!("{}: {}", fmt::short_fp2(sender_fingerprint), preview(body))
        }
        MessageSent { body, .. } => format!("you: {}", preview(body)),
        ListeningOn { address } => format!("listening on {address}"),
        Dialing { address } => format!("dialing {address}…"),
        DialSucceeded { address, .. } => format!("connected to {address}"),
        DialFailed { address, error } => format!("dial {address} failed: {error}"),
        Error { description } => format!("error: {description}"),
        FileOffered {
            name, size_bytes, ..
        } => {
            format!("file offered: {name} ({} KB)", size_bytes / 1024)
        }
        FileReady { .. } => "file ready".to_string(),
        FileSaved { path, .. } => format!("saved to {path}"),
        FileFailed { reason, .. } => format!("transfer failed: {reason}"),
        RotationRequested {
            rotator_fingerprint,
            ..
        } => {
            format!(
                "key rotation requested by {}",
                fmt::short_fp2(rotator_fingerprint)
            )
        }
        MentionReceived { room_id, .. } => format!("@you mentioned in {}", short_room(room_id)),
        InboundDial { fingerprint, .. } => {
            format!("inbound dial from {}", fmt::short_fp2(fingerprint))
        }
        SasCodeReady { decimal, .. } => format!("SAS code: {decimal}"),
        SasVerified {
            partner_fingerprint,
            ..
        } => {
            format!("verified {} via SAS", fmt::short_fp2(partner_fingerprint))
        }
        NatStatusChanged { label, .. } => format!("NAT status: {label}"),
        PeerProfileUpdated {
            fingerprint,
            username,
        } => {
            let label = username.clone().unwrap_or_else(|| "[anonymous]".into());
            format!("{} is now {}", fmt::short_fp(fingerprint), label)
        }
        WentDark => "gone dark — data wiped".to_string(),
        AutoOpenDm { fingerprint, .. } => {
            format!("auto-opened DM with {}", fmt::short_fp2(fingerprint))
        }
        other => format!("{other:?}"),
    }
}

fn short_room(id: &str) -> String {
    id.chars().take(8).collect()
}

fn preview(body: &str) -> String {
    let single: String = body
        .chars()
        .map(|c| if c == '\n' { ' ' } else { c })
        .collect();
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
            attach_via_path: false,
            theme: crate::theme::Theme::System,
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
            connect_code: None,
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
            reactions: vec![],
            ttl_secs: None,
            reply_to: None,
            edit_target: None,
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
                client_msg_id: None,
                reply_to: None,
                edited_at: None,
                deleted_at: None,
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

    fn reaction(target: &str, sender: &str, emoji: &str) -> StoredReaction {
        StoredReaction {
            id: 0,
            room_id: "r1".into(),
            target_client_msg_id: target.into(),
            sender_fingerprint: sender.into(),
            emoji: emoji.into(),
            reacted_at: 0,
        }
    }

    #[test]
    fn reactions_group_by_emoji_with_counts_and_self_flag() {
        let mut r = room("r1");
        r.reactions = vec![
            reaction("m1", "me", "👍"),
            reaction("m1", "bob", "👍"),
            reaction("m1", "carol", "❤️"),
            reaction("m2", "bob", "🔥"),
        ];
        let grouped = r.reactions_for("m1", "me");
        // first-seen order: 👍 then ❤️
        assert_eq!(grouped[0], ("👍".to_string(), 2, true));
        assert_eq!(grouped[1], ("❤️".to_string(), 1, false));
        // a different message's reactions don't leak in
        assert_eq!(
            r.reactions_for("m2", "me"),
            vec![("🔥".to_string(), 1, false)]
        );
        // an un-reacted message is empty
        assert!(r.reactions_for("m3", "me").is_empty());
    }

    #[test]
    fn ttl_label_renders_common_buckets() {
        assert_eq!(ttl_label(300), "5m");
        assert_eq!(ttl_label(3600), "1h");
        assert_eq!(ttl_label(86_400), "1d");
        assert_eq!(ttl_label(604_800), "1w");
        assert_eq!(ttl_label(7200), "2h");
        assert_eq!(ttl_label(45), "45s");
    }
}
