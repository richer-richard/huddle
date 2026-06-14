use std::cell::Cell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::{
    event::{
        self, poll, DisableBracketedPaste, DisableFocusChange, DisableMouseCapture,
        EnableBracketedPaste, EnableFocusChange, EnableMouseCapture, Event, KeyCode, KeyEvent,
        KeyModifiers, MouseButton, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::prelude::*;
use ratatui::Terminal;

use base64::Engine;
use zeroize::Zeroizing;

use huddle_core::app::events::{AppEvent, DiscoveredRoom};
use huddle_core::app::{AppHandle, KnownPeerStatus};
use huddle_core::network::NetworkMode;
use huddle_core::storage::repo::{StoredAttachment, StoredRoomMessage};
use libp2p::PeerId;

use crate::input::{self, Action};

mod actions;
use actions::handle_action;
mod runtime;
pub use runtime::{
    install_panic_hook, prompt_import_seed, prompt_master_passphrase, run_tui, show_welcome,
};

/// Default lifetime for transient status-bar messages.
const STATUS_TTL: Duration = Duration::from_secs(6);

/// Maximum entries kept in the status history ring buffer.
pub const STATUS_HISTORY_CAP: usize = 100;

/// Maximum modals we queue behind the active one. Beyond this we drop
/// the oldest — see `enqueue_modal`.
pub const PENDING_MODAL_CAP: usize = 16;

/// huddle 2.0.0 (F9): the TTL the disappearing-messages toggle arms when a
/// room currently has expiry OFF — one hour. Toggling again turns it back off.
pub const DEFAULT_DISAPPEARING_TTL_SECS: u32 = 3600;

/// huddle 0.6: an onboarding page tagged with the version it was
/// introduced in. Users only see pages whose `min_version` is newer
/// than their last_seen_onboarding_version, so a version bump
/// surfaces only the new "what's new" page — not the foundational
/// cards from before.
pub struct OnboardingPage {
    pub title: &'static str,
    pub body: &'static [&'static str],
    /// Pages with `min_version` greater than the user's last-seen
    /// onboarding version are surfaced. "0.0.0" = foundational pages
    /// shown only on true first launch.
    pub min_version: &'static str,
}

/// Phase H + huddle 0.6: onboarding pages. The mental-model and
/// passphrase pages are foundational (min_version="0.0.0"); each
/// release that ships a user-visible change adds one "what's new"
/// page tagged with its release version.
pub const ONBOARDING_PAGES: &[OnboardingPage] = &[
    OnboardingPage {
        title: "huddle is not iMessage",
        body: &[
            "your messages are end-to-end encrypted, and everything",
            "travels over a Tor onion relay that only ever sees",
            "ciphertext — never your keys, your IP, or who you are.",
            "there's no account, just an identity key on this device.",
            "",
            "rooms outlive whoever made them: anyone with the room",
            "passphrase can join, post, and rotate the key.",
            "",
            "press Enter, Tab, Space, or → to continue.",
        ],
        min_version: "0.0.0",
    },
    OnboardingPage {
        title: "passphrase ≠ password",
        body: &[
            "the master passphrase encrypts your LOCAL database (rooms,",
            "messages, members, Megolm sessions, attachments).",
            "room passphrases are the access keys to encrypted rooms.",
            "neither is recoverable — there's no reset, by design.",
            "",
            "for sharing access without leaking your passphrase, use",
            "  ^J  generate a 10-min single-use join code",
            "  ^V→s  SAS-verify a member's fingerprint",
            "  Shift+I  produce an invite link (passphrase still OOB)",
        ],
        min_version: "0.0.0",
    },
    OnboardingPage {
        title: "what's new in 0.5",
        body: &[
            "  a    add friend by HD ID or username — races LAN / IP / relay",
            "  ,→u  set / clear your username (signed broadcast)",
            "  Alt+Shift+1  delete account + wipe data dir (go dark)",
            "  ✓    green tag next to SAS-verified peers in chat",
            "  HD-  branded ID, shown alongside username everywhere",
        ],
        min_version: "0.5.0",
    },
    OnboardingPage {
        title: "what's new in 0.6 — UX overhaul",
        body: &[
            "  Ctrl+P  command palette — fuzzy-search every action",
            "  Ctrl+H  notification history (last 100 events)",
            "  Shift+? reopen this card   ·   ? help (scroll j/k)",
            "  R       (lobby) mark every room read",
            "",
            "Also: version + clock in the header, per-tab unread",
            "counts, day separators in chat, and a `huddle doctor`",
            "CLI subcommand for bug reports.",
        ],
        min_version: "0.6.0",
    },
    OnboardingPage {
        title: "what's new in 0.7 — TUI 2.0",
        body: &[
            "huddle 0.7 rewrote the TUI around a sidebar:",
            "  Profile · Direct messages · Group rooms ·",
            "  People · Activity · Settings",
            "",
            "Keys:  m  DM     g  group room     p  People",
            "       ,  Settings    Tab/Shift+Tab  switch section",
            "       Space / ← / →  expand or collapse a section",
            "",
            "DMs and group chats are visually distinct; DMs stay 1-1.",
        ],
        min_version: "0.7.0",
    },
    OnboardingPage {
        title: "what's new in 0.7.1 — E2E DMs",
        body: &[
            "DMs are end-to-end encrypted on the room layer.",
            "",
            "Each DM derives a Megolm wrap key from an Ed25519→",
            "X25519 ECDH between the two parties' identity keys,",
            "bound to the room_id via HKDF-SHA256 — no shared",
            "passphrase, no extra prompt. `m` starts a DM and it's",
            "E2E from the first wrapped session key onward.",
        ],
        min_version: "0.7.1",
    },
    OnboardingPage {
        title: "what's new in 0.7.4 — desktop notifications",
        body: &[
            "You'll get a desktop notification when a message arrives",
            "and the terminal isn't focused — switch apps or lock your",
            "screen and you won't miss it. When huddle is focused,",
            "nothing pops up; you're already looking at it.",
            "",
            "Reopening huddle rolls anything you missed in the first",
            "few seconds into a single \"N new messages\" summary.",
            "",
            "Going dark is now Alt+Shift+1 — the extra modifier is",
            "there so a stray keystroke can't wipe your account.",
        ],
        min_version: "0.7.4",
    },
    OnboardingPage {
        title: "what's new in 0.8 — Tor onion relay",
        body: &[
            "huddle now talks over a Tor onion relay by default —",
            "no more flaky NAT hole-punching, and still fully",
            "end-to-end encrypted (the relay only sees ciphertext).",
            "",
            "  · the dot by your name: ● connected, ○ connecting",
            "  · needs Tor running locally (SOCKS5 127.0.0.1:9050)",
            "  · LAN/libp2p is now opt-in: --mode mdns | direct",
            "",
            "To get started, make a group room (g) and share the",
            "invite (Shift+I) — your friend pastes it and you're in.",
        ],
        min_version: "0.8.0",
    },
];

/// huddle 0.6: pages that should be shown to a user with the given
/// last-seen onboarding version. Brand-new users see everything;
/// upgrading users see only the pages tagged with versions newer
/// than their last_seen.
pub fn pages_to_show(last_seen: Option<&str>, legacy_onboarding_seen: bool) -> Vec<usize> {
    let baseline = match (last_seen, legacy_onboarding_seen) {
        (Some(v), _) => v.to_string(),
        // Legacy user from before version tracking: they already saw
        // the 0.5 foundational + "what's new" cards. Treat them as
        // having last_seen=0.5.2 so only newer pages surface.
        (None, true) => "0.5.2".to_string(),
        // Brand-new user: every page.
        (None, false) => "0.0.0".to_string(),
    };
    ONBOARDING_PAGES
        .iter()
        .enumerate()
        .filter(|(_, p)| semver_lt(&baseline, p.min_version))
        .map(|(i, _)| i)
        .collect()
}

/// Tiny numeric semver compare — splits on '.' and parses each segment
/// as a u32, treating missing or non-numeric trailers as 0. Enough for
/// our 0.X.Y release numbering; we never ship pre-release tags.
fn semver_lt(a: &str, b: &str) -> bool {
    parse_semver(a) < parse_semver(b)
}

fn parse_semver(s: &str) -> (u32, u32, u32) {
    let mut it = s.split('.');
    let major = it.next().unwrap_or("0").parse().unwrap_or(0);
    let minor = it.next().unwrap_or("0").parse().unwrap_or(0);
    let patch_raw = it.next().unwrap_or("0");
    let patch_num: String = patch_raw
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let patch = patch_num.parse().unwrap_or(0);
    (major, minor, patch)
}

/// huddle 0.7: which pane the right side of the layout renders.
/// Replaces the legacy `Screen::{Lobby, InRoom}` binary. Selection
/// happens via the sidebar (or jump-shortcuts like `,` for Settings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pane {
    Welcome,
    Profile,
    Dm(String),
    Group(String),
    People,
    Activity,
    Settings,
}

/// huddle 0.7: sidebar section identifiers. Section order is fixed at
/// render time so this enum mirrors the visual order top-to-bottom.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SidebarSection {
    Profile,
    Direct,
    Group,
    People,
    Activity,
    Settings,
}

/// huddle 0.7: a single addressable row in the sidebar. `Section(s)` is
/// the section header itself (clickable to expand/collapse); the other
/// variants are children rendered under an expanded section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidebarItem {
    Section(SidebarSection),
    Profile,
    /// huddle 0.7.8: pinned "+ Add Friend" row at the top of an
    /// expanded Direct messages section. Selecting fires
    /// `Action::OpenComposeDm`.
    DirectAddFriend,
    Dm(String),
    /// huddle 0.7.8: pinned "+ New Group" row at the top of an
    /// expanded Group rooms section. Selecting fires
    /// `Action::OpenStartRoom`.
    GroupNew,
    Group(String),
    GroupDiscover,
    /// huddle 0.7.8: pinned "! N friend requests" badge row when the
    /// People section is expanded and `pending_requests` is non-empty.
    /// Selecting jumps to `Pane::People` with `PeopleFocus::Pending`.
    PeoplePendingBadge,
    Person(String),
    Activity,
    Settings,
}

/// huddle 0.7.8: which tab the Settings pane shows. Account = identity
/// (mirrors Profile's read-only view + edit affordances). Network = mDNS
/// toggle, listen addrs, relays, connectivity. Appearance = theme
/// placeholder. Privacy = verified-only inbound, notifications, update
/// check, blocked peers, go-dark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsTab {
    Account,
    Network,
    Appearance,
    Privacy,
}

impl Default for SettingsTab {
    fn default() -> Self {
        SettingsTab::Account
    }
}

impl SettingsTab {
    pub fn label(self) -> &'static str {
        match self {
            SettingsTab::Account => "Account",
            SettingsTab::Network => "Network",
            SettingsTab::Appearance => "Appearance",
            SettingsTab::Privacy => "Privacy",
        }
    }

    pub fn next(self) -> Self {
        match self {
            SettingsTab::Account => SettingsTab::Network,
            SettingsTab::Network => SettingsTab::Appearance,
            SettingsTab::Appearance => SettingsTab::Privacy,
            SettingsTab::Privacy => SettingsTab::Account,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            SettingsTab::Account => SettingsTab::Privacy,
            SettingsTab::Network => SettingsTab::Account,
            SettingsTab::Appearance => SettingsTab::Network,
            SettingsTab::Privacy => SettingsTab::Appearance,
        }
    }
}

/// huddle 0.7: keyboard focus is either on the sidebar (j/k navigates
/// rows) or on the pane (typing in chat, scrolling messages). Tab/Esc
/// toggles between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidebarFocus {
    Sidebar,
    Pane,
}

/// huddle 0.7: sidebar state — which item is selected, which sections
/// are expanded, and whether keyboard focus is on the sidebar or the
/// pane. Owns sidebar navigation; the pane router is purely read-only
/// for this state.
#[derive(Debug, Clone)]
pub struct SidebarState {
    pub selection: SidebarItem,
    pub expanded: HashSet<SidebarSection>,
    pub focus: SidebarFocus,
}

impl Default for SidebarState {
    fn default() -> Self {
        let mut expanded = HashSet::new();
        expanded.insert(SidebarSection::Profile);
        expanded.insert(SidebarSection::Direct);
        expanded.insert(SidebarSection::Group);
        expanded.insert(SidebarSection::People);
        Self {
            selection: SidebarItem::Section(SidebarSection::Profile),
            expanded,
            focus: SidebarFocus::Sidebar,
        }
    }
}

/// huddle 0.7: which sublist has focus inside the People pane —
/// Known peers, Verified, or Blocked. Tab cycles. Used for per-row
/// action targeting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeopleFocus {
    /// huddle 1.0: inbound relay-inbox contact requests ("add by HD-ID over
    /// the internet"). First tab so a fresh request is the first thing the
    /// user sees on landing in People.
    ContactRequests,
    /// huddle 0.7.7: pending inbound friend requests, spilled to disk
    /// when their 15s modal window times out.
    Pending,
    Known,
    Verified,
    Blocked,
}

impl Default for PeopleFocus {
    fn default() -> Self {
        PeopleFocus::Known
    }
}

/// Modal overlays (mutually exclusive).
#[derive(Debug, Clone)]
pub enum Modal {
    None,
    StartRoom(StartRoomState),
    JoinRoom(JoinRoomState),
    DialPeer(DialPeerState),
    AttachPicker(AttachPickerState),
    /// Manual POSIX file-path entry — an alternative to the tree picker
    /// (`AttachPicker`). Reachable from inside the picker (`p`) and from
    /// the command palette ("attach a file by path").
    AttachPath(AttachPathState),
    /// "Rotate the current room's key" — entered with ^R.
    RotateRoom(RotateRoomState),
    /// Someone else rotated our room's key; ask the user for the new
    /// passphrase so we can continue receiving messages.
    AcceptRotation(AcceptRotationState),
    /// Verify member fingerprints (^V).
    Verify(VerifyState),
    /// Search room history (^F).
    Search(SearchState),
    /// QR code of our identity, scannable for fingerprint comparison.
    QrIdentity,
    /// Phase A: an unknown peer dialed us. User chooses accept/reject/
    /// trust-and-accept. Dismiss without choosing (Esc, 15s timeout) =
    /// auto-reject — anything more permissive would defeat the gate.
    InboundDial(InboundDialState),
    /// Phase B: owner-only picker for kick / grant-owner on a member.
    MemberAction(MemberActionState),
    /// Phase G: SAS verification in progress — initial waiting state
    /// before the partner's ephemeral pubkey arrives, then code-display
    /// + match-confirm.
    Sas(SasState),
    /// huddle 0.5: single-field text editor for the local user's
    /// self-declared username. Empty input clears (None) and the user
    /// renders as `[anonymous]` to themselves and peers. On confirm,
    /// triggers a signed ProfileUpdate broadcast to every joined room.
    EditUsername(EditUsernameState),
    /// huddle 0.5: irreversible account-delete modal. Two fields:
    /// master passphrase + a `DELETE EVERYTHING` confirmation phrase.
    /// Hitting Confirm with both filled calls `AppHandle::go_dark`.
    GoDark(GoDarkState),
    /// huddle 0.5.1: "add friend by HD ID or username" — single-field
    /// text input. On confirm, resolves the input to a fingerprint
    /// (HD-prefix / bare hex / username lookup) and dials via the
    /// usual flow.
    AddFriend(AddFriendState),
    /// huddle 1.2.1: shows a freshly minted connect code for the user to share
    /// (the short-lived DM "add by code" alternative to typing a full HD-ID).
    ConnectCode(ConnectCodeState),
    /// huddle 0.7: "message who?" — Compose-DM modal. Single field
    /// with inline autocomplete; on confirm, resolves to a fingerprint
    /// and starts a DM via `AppHandle::start_direct`. Falls back to
    /// the AddFriend morph (same modal recycled) when input is
    /// unrecognized — no modal-on-modal.
    ComposeDm(ComposeDmState),
    /// Phase F: an owner just generated a short-lived join code for
    /// the current encrypted room. The modal shows it big so the
    /// owner can read it aloud / copy it / pass it OOB.
    ShowJoinCode(ShowJoinCodeState),
    /// Phase F: joiner enters a code shared by an owner of an
    /// encrypted room. On confirm, sends a signed CodeJoinRequest;
    /// the room opens read-only on the owner's response.
    JoinWithCode(JoinWithCodeState),
    /// Phase C: show a freshly-generated invite link (URL form),
    /// optionally room-scoped, so the user can copy + share.
    ShowInvite(ShowInviteState),
    /// Phase C: paste-an-invite text field.
    PasteInvite(PasteInviteState),
    /// Phase C: parsed invite — confirm before dialing.
    ConfirmInvite(ConfirmInviteState),
    /// Phase H + huddle 0.6: onboarding card. `pages` is a filtered
    /// index list into `ONBOARDING_PAGES` so a version bump can show
    /// only the new "what's new" page without re-walking the
    /// foundational cards.
    Onboarding {
        pages: Vec<usize>,
        cursor: usize,
    },
    /// huddle 0.6: scrollable list of the last `STATUS_HISTORY_CAP`
    /// status-bar messages. Opens on Ctrl+H. Doubles as a notification
    /// center.
    StatusHistory {
        scroll: u16,
    },
    /// huddle 0.6: command palette — fuzzy-search every action that
    /// has a `palette_label` in `crate::keybindings::BINDINGS`. Opens
    /// on Ctrl+P. Type to filter, Enter to execute.
    CommandPalette(CommandPaletteState),
    /// huddle 0.6: first-launch opt-in for the update check. Shown
    /// when `handle.update_check_enabled().is_none()`. Yes records
    /// the user opted in and triggers the first poll; No disables.
    UpdateCheckOptIn,
    /// huddle 0.7.7: pick known peers and auto-DM them an invite to
    /// the current group room. Tiered candidate list (Verified → DM
    /// partners → Known peers), multi-select with `/` filter and a
    /// soft-cap. `Shift+I` keeps the OOB link flow; this is the
    /// in-band picker.
    InvitePicker(InvitePickerState),
    QuitConfirm,
    /// huddle 0.7.11: confirmation before wiping the entire blocklist.
    /// Pre-0.7.11 the bare `c` keystroke on Settings → Privacy cleared
    /// the blocklist instantly — one keystroke from data loss, and the
    /// same `c` opened the join-code modal in the lobby so muscle
    /// memory was destructive. Now `c` opens this modal and the user
    /// must press Enter or `y` to actually clear.
    ConfirmClearBlocked,
    /// huddle 2.0.0 (F3): a pinned peer's Ed25519 key changed mid-session
    /// (TOFU drift). The offending message was already dropped; this modal
    /// surfaces the alarm and lets the user re-verify out-of-band (SAS) or
    /// block the peer.
    SafetyNumberChanged(SafetyNumberChangedState),
    /// huddle 2.0.0 (F5): change the master passphrase, re-keying the DB +
    /// Megolm session pickles. Three masked fields (current / new / confirm).
    ChangePassphrase(ChangePassphraseState),
    /// huddle 2.0.0 (F6): export this identity's seed as a 24-word BIP39
    /// phrase. Show-once, then re-entry-verified so the user proves they
    /// transcribed it before relying on it for recovery.
    ExportSeed(ExportSeedState),
    /// huddle 2.0.0 (F10): pick an emoji to react to the selected message.
    EmojiPicker(EmojiPickerState),
    /// huddle 2.0.0 (F10): confirm before deleting (tombstoning) a message.
    ConfirmDelete(ConfirmDeleteState),
    Help,
    Error(String),
    Info(String),
}

/// huddle 2.0.0 (F3): state for the safety-number-change alarm modal. The
/// `focus` walks the two backed responses (0 = Verify via SAS, 1 = Block);
/// Esc dismisses (the pinned key is left unchanged, so the user stays
/// protected — the drift message was already dropped before this fired).
#[derive(Debug, Clone)]
pub struct SafetyNumberChangedState {
    pub room_id: String,
    pub fingerprint: String,
    pub old_pubkey_b64: String,
    pub new_pubkey_b64: String,
    pub display_name: Option<String>,
    /// 0 = Verify (SAS), 1 = Block.
    pub focus: u8,
}

/// huddle 2.0.0 (F5): which field of the change-passphrase modal has focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassField {
    Current,
    New,
    Confirm,
}

/// huddle 2.0.0 (F5): change-master-passphrase modal state. All three fields
/// are masked; `Tab` cycles them and `Enter` confirms once all are filled.
#[derive(Debug, Clone)]
pub struct ChangePassphraseState {
    pub current: String,
    pub new_pass: String,
    pub confirm: String,
    pub focus: PassField,
    pub error: Option<String>,
}

impl Default for ChangePassphraseState {
    fn default() -> Self {
        Self {
            current: String::new(),
            new_pass: String::new(),
            confirm: String::new(),
            focus: PassField::Current,
            error: None,
        }
    }
}

/// huddle 2.0.0 (F6): the export-seed modal walks two steps: first it shows
/// the phrase (reveal/hide toggle), then it asks the user to type it back to
/// prove they saved it correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportStep {
    /// Showing the phrase; Space toggles reveal, Enter advances to re-entry.
    Reveal,
    /// Re-entry verification; the user re-types the full phrase.
    Reentry,
    /// Verified — a brief confirmation before the modal closes.
    Done,
}

/// huddle 2.0.0 (F6): export-seed modal state.
#[derive(Debug, Clone)]
pub struct ExportSeedState {
    /// The 24-word phrase, fetched once from `AppHandle::export_seed_phrase`.
    pub phrase: String,
    /// When false the phrase is rendered as dots — it starts hidden so a
    /// shoulder-surfer doesn't catch it the instant the modal opens.
    pub revealed: bool,
    /// What the user types back during the re-entry step.
    pub reentry: String,
    pub error: Option<String>,
    pub step: ExportStep,
}

/// huddle 2.0.0 (F10): emoji-picker modal for reacting to a message.
#[derive(Debug, Clone)]
pub struct EmojiPickerState {
    pub room_id: String,
    /// `client_msg_id` of the message being reacted to.
    pub target_msg_id: String,
    pub selected: usize,
}

/// huddle 2.0.0 (F10): the common emoji palette offered by the picker.
pub const REACTION_EMOJIS: &[&str] = &["👍", "❤️", "😂", "🎉", "😮", "😢", "🙏", "🔥", "👀", "✅"];

/// huddle 2.0.0 (F10): confirm-delete modal state.
#[derive(Debug, Clone)]
pub struct ConfirmDeleteState {
    pub room_id: String,
    /// `client_msg_id` of the message to tombstone.
    pub target_msg_id: String,
}

#[derive(Debug, Clone, Default)]
pub struct CommandPaletteState {
    pub query: String,
    /// Full list of (label, keys, action_id) for every palette-eligible
    /// binding plus a few synthetic entries (e.g. "toggle update check"
    /// that doesn't have a keybinding). Filtered by `query` at render.
    pub selected: usize,
}

#[derive(Debug, Clone, Default)]
pub struct EditUsernameState {
    pub input: String,
}

/// huddle 0.7.6: single-field Go Dark modal. Mode is fixed at open time:
/// if the user has a master passphrase, `requires_passphrase = true` and
/// the single field is the passphrase itself; otherwise the field is the
/// typed `DELETE EVERYTHING` confirmation (since there's no passphrase
/// to compare against in `--no-master-passphrase` sessions).
///
/// Replaced the two-field (passphrase + typed phrase) flow from 0.5: the
/// Tab-between-fields UX made it easy to fill only one and bounce off a
/// silent inline error, leaving "looks like nothing happened" reports.
#[derive(Debug, Clone, Default)]
pub struct GoDarkState {
    pub input: String,
    pub requires_passphrase: bool,
    /// Set after a wrong-passphrase / wrong-phrase attempt so the modal
    /// can flash an inline error without dismissing.
    pub last_error: Option<String>,
}

/// Confirmation phrase for `--no-master-passphrase` sessions (the only
/// gate they have, since there's no persisted key to compare against).
/// Sessions with a master passphrase use the passphrase itself.
pub const GO_DARK_CONFIRM_PHRASE: &str = "DELETE EVERYTHING";

#[derive(Debug, Clone, Default)]
pub struct AddFriendState {
    pub input: String,
}

/// huddle 1.2.1: state for the "your connect code" modal — the minted code and
/// the epoch-seconds instant it expires (so the UI can show a countdown).
#[derive(Debug, Clone, Default)]
pub struct ConnectCodeState {
    pub code: String,
    pub expires_at: i64,
}

/// huddle 0.7: Compose-DM modal state. Single-field input; autocomplete
/// surfaces inline (rendered from `known_peers` + `peer_profiles` cache).
#[derive(Debug, Clone, Default)]
pub struct ComposeDmState {
    pub input: String,
}

#[derive(Debug, Clone)]
pub struct ShowJoinCodeState {
    /// Room identifier so the modal can render a short hash next to
    /// the room name — useful when two rooms share a name (e.g.
    /// multiple "general"s discovered across networks).
    pub room_id: String,
    pub room_name: String,
    pub code: String,
}

#[derive(Debug, Clone)]
pub struct JoinWithCodeState {
    pub room_id: String,
    pub room_name: String,
    pub code: String,
}

#[derive(Debug, Clone)]
pub struct ShowInviteState {
    pub url: String,
    pub includes_room: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PasteInviteState {
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct ConfirmInviteState {
    pub invite: huddle_core::invite::InviteLink,
}

/// Phase G: stages of an in-flight SAS verification. The state advances
/// from `Waiting` (just started, no code yet) → `Comparing` (both sides
/// have the code, user is deciding) on `AppEvent::SasCodeReady`.
#[derive(Debug, Clone)]
pub enum SasStage {
    /// Initiator only — we sent SasInit, waiting for the partner's
    /// SasResponse to arrive so we can derive the code.
    Waiting,
    /// Both ephemeral pubkeys exchanged; the SAS code is shown for
    /// OOB comparison.
    Comparing {
        emoji_labels: String,
        decimal: String,
        /// True once we've broadcast our SasConfirm. Used to hide the
        /// "Match" button after pressing it (avoid double-fire).
        our_matched: bool,
    },
}

#[derive(Debug, Clone)]
pub struct SasState {
    /// Room the SAS exchange started in. Surfaced in the modal title
    /// ("SAS · #room-name") so the user knows which conversation
    /// they're verifying — important when multiple rooms are open.
    pub room_id: String,
    pub partner_fingerprint: String,
    pub tx_id: String,
    pub stage: SasStage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberActionKind {
    Kick,
    Grant,
}

#[derive(Debug, Clone)]
pub struct MemberActionState {
    pub room_id: String,
    pub kind: MemberActionKind,
    /// (fingerprint, is_already_owner). For Grant, owners are filtered
    /// out at open-time so the list only shows promotable members.
    pub members: Vec<(String, bool)>,
    pub selected: usize,
}

#[derive(Debug, Clone)]
pub struct InboundDialState {
    pub peer_id: PeerId,
    pub fingerprint: String,
    pub address: String,
    /// When the modal opened. Used to auto-reject after 15s — the
    /// network connection stays in our `pending_inbound` map all that
    /// time, so a user who never sees the modal won't accidentally
    /// keep an unknown peer attached forever.
    pub opened_at: Instant,
}

/// huddle 0.7.7: tier label for an `InviteCandidate`. Drives section
/// headers in the picker and sort order (Verified at the top, then DM
/// partners, then plain Known peers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InviteTier {
    /// SAS-verified peer. Safest to in-band-DM an invite — we have
    /// strong, OOB-confirmed assurance this peer is who they claim.
    Verified,
    /// We already have a DM open with this peer. Implies prior trust
    /// (we initiated the DM, they accepted, or vice versa).
    DmPartner,
    /// A known dial peer with a learned fingerprint. Trust is weaker —
    /// we just have proof they own the Ed25519 key behind this address.
    Known,
}

#[derive(Debug, Clone)]
pub struct InviteCandidate {
    pub fingerprint: String,
    pub username: Option<String>,
    pub tier: InviteTier,
}

/// huddle 0.7.7: maximum number of peers selectable per send. Beyond
/// this we surface a hint and refuse to add more. Two-fold purpose:
/// (a) gently discourage spam-blasting, (b) keep the auto-send batch
/// snappy — every `start_direct` + `send_room_message` is a sequential
/// gossipsub publish.
pub const INVITE_PICKER_SOFT_CAP: usize = 20;

#[derive(Debug, Clone, Default)]
pub struct InvitePickerState {
    /// Room we're inviting *into*. Captured at open time so the
    /// generated invite stays consistent if the user switches panes
    /// while the modal is open (modals survive pane changes).
    pub room_id: String,
    pub room_name: String,
    /// All deduped candidates, pre-sorted by tier. Filter narrows the
    /// rendered slice but never mutates this list.
    pub candidates: Vec<InviteCandidate>,
    /// Fingerprints currently checked. Insertion-order isn't visible,
    /// but capped at `INVITE_PICKER_SOFT_CAP`.
    pub selected: HashSet<String>,
    /// Live filter input. Matches case-insensitively against username
    /// AND short HD-ID prefix.
    pub filter: String,
    /// Cursor in the *filtered* slice. Reset to 0 every time the
    /// filter changes.
    pub cursor: usize,
    /// Non-fatal user-feedback line shown above the hint bar. Cleared
    /// on the next keystroke. Used for "20-selection cap reached" and
    /// post-send status.
    pub status_line: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RotateRoomState {
    pub room_id: String,
    pub passphrase: String,
}

#[derive(Debug, Clone)]
pub struct AcceptRotationState {
    pub room_id: String,
    pub rotator_fingerprint: String,
    pub new_salt: Vec<u8>,
    pub passphrase: String,
}

#[derive(Debug, Clone)]
pub struct SearchState {
    pub room_id: String,
    pub query: String,
    pub results: Vec<StoredRoomMessage>,
    pub selected: usize,
    pub searched: bool,
}

#[derive(Debug, Clone)]
pub struct VerifyState {
    pub room_id: String,
    pub our_fingerprint: String,
    /// (fingerprint, currently-verified)
    pub members: Vec<(String, bool)>,
    pub selected: usize,
}

/// Rows of the attach picker visible at once. The renderer and the
/// scroll-clamp logic must agree on this, so it lives here and is
/// imported by `ui::modal`.
pub const ATTACH_VISIBLE_ROWS: usize = 14;

/// Soft cap on entries read per directory. Keeps `rebuild_flat` cheap and
/// the picker responsive even if someone expands a pathologically large
/// directory; the overflow is silently dropped (rare in practice).
const ATTACH_MAX_CHILDREN: usize = 5000;

/// One node in the lazily-loaded attach tree. Collapsed children are
/// retained so re-expanding a directory is instant (no re-read).
#[derive(Debug, Clone)]
pub struct TreeNode {
    /// Display name (`to_string_lossy`). Never used for filesystem access.
    pub name: String,
    /// Authoritative absolute path — safe for non-UTF8 names.
    pub path: std::path::PathBuf,
    pub is_dir: bool,
    pub expanded: bool,
    /// Children fetched yet? Directories load lazily on first expand.
    pub loaded: bool,
    /// Set when the directory could not be read (permissions, IO). We
    /// still mark it `loaded` so we never re-hammer it.
    pub load_error: Option<String>,
    pub children: Vec<TreeNode>,
}

/// A flattened, currently-visible tree row. The flat list is the cursor
/// index space and the render surface; it is rebuilt on every structural
/// change. `path` is the stable identity used to keep the cursor pinned
/// to the same node across rebuilds.
#[derive(Debug, Clone)]
pub struct FlatRow {
    pub path: std::path::PathBuf,
    pub name: String,
    pub is_dir: bool,
    pub expanded: bool,
    pub depth: usize,
    /// Directory that failed to load — render as "(no access)".
    pub has_error: bool,
    /// Expanded directory with no children — render as "(empty)".
    pub is_empty_dir: bool,
}

#[derive(Debug, Clone)]
pub struct AttachPickerState {
    /// Starting directory; the tree is rooted here and cannot ascend above it.
    pub root: std::path::PathBuf,
    pub roots: Vec<TreeNode>,
    pub flat: Vec<FlatRow>,
    pub selected: usize,
    pub scroll: usize,
    pub show_hidden: bool,
    pub error: Option<String>,
}

impl AttachPickerState {
    pub fn new() -> Self {
        let start = dirs::download_dir()
            .or_else(dirs::home_dir)
            .unwrap_or_else(|| std::path::PathBuf::from("/"));
        let mut s = Self {
            root: start,
            roots: Vec::new(),
            flat: Vec::new(),
            selected: 0,
            scroll: 0,
            show_hidden: false,
            error: None,
        };
        s.load_root();
        s
    }

    /// (Re)read the root directory and rebuild the visible list. Used on
    /// open and whenever `show_hidden` toggles.
    fn load_root(&mut self) {
        match Self::read_children(&self.root, self.show_hidden) {
            Ok(nodes) => {
                self.roots = nodes;
                self.error = None;
            }
            Err(e) => {
                self.roots.clear();
                self.error = Some(format!("cannot read {}: {}", self.root.display(), e));
            }
        }
        self.selected = 0;
        self.scroll = 0;
        // Cursor anchoring in rebuild_flat keys off the prior flat list,
        // which we've intentionally discarded here (full reset).
        self.flat.clear();
        self.rebuild_flat();
    }

    /// Read one directory's immediate children into unexpanded nodes.
    /// `metadata()` (not `file_type()`) is used so symlinks-to-dirs are
    /// navigable. Dirs sort first, then case-insensitive by name.
    fn read_children(dir: &std::path::Path, show_hidden: bool) -> std::io::Result<Vec<TreeNode>> {
        let rd = std::fs::read_dir(dir)?;
        let mut tmp: Vec<TreeNode> = Vec::new();
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !show_hidden && name.starts_with('.') {
                continue;
            }
            let path = entry.path();
            let is_dir = std::fs::metadata(&path)
                .map(|m| m.is_dir())
                .unwrap_or(false);
            tmp.push(TreeNode {
                name,
                path,
                is_dir,
                expanded: false,
                loaded: false,
                load_error: None,
                children: Vec::new(),
            });
            if tmp.len() >= ATTACH_MAX_CHILDREN {
                break;
            }
        }
        tmp.sort_by(|a, b| match (a.is_dir, b.is_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
        });
        Ok(tmp)
    }

    /// Recompute the flat visible-row list from the tree, then re-pin the
    /// cursor to the node it was on (by path) and clamp the scroll window.
    fn rebuild_flat(&mut self) {
        let keep = self.flat.get(self.selected).map(|r| r.path.clone());
        let mut flat: Vec<FlatRow> = Vec::new();
        Self::flatten_into(&self.roots, 0, &mut flat);
        self.flat = flat;
        match keep.and_then(|p| self.flat.iter().position(|r| r.path == p)) {
            Some(idx) => self.selected = idx,
            None => self.selected = self.selected.min(self.flat.len().saturating_sub(1)),
        }
        self.clamp_scroll();
    }

    fn flatten_into(nodes: &[TreeNode], depth: usize, out: &mut Vec<FlatRow>) {
        for n in nodes {
            let is_empty_dir = n.is_dir
                && n.expanded
                && n.loaded
                && n.load_error.is_none()
                && n.children.is_empty();
            out.push(FlatRow {
                path: n.path.clone(),
                name: n.name.clone(),
                is_dir: n.is_dir,
                expanded: n.expanded,
                depth,
                has_error: n.load_error.is_some(),
                is_empty_dir,
            });
            if n.is_dir && n.expanded {
                Self::flatten_into(&n.children, depth + 1, out);
            }
        }
    }

    /// Locate a node by path, descending only through expanded directories
    /// (the focused path is always visible, so its ancestors are expanded).
    fn find_node_mut<'a>(
        nodes: &'a mut [TreeNode],
        path: &std::path::Path,
    ) -> Option<&'a mut TreeNode> {
        for n in nodes.iter_mut() {
            if n.path == path {
                return Some(n);
            }
            if n.is_dir && n.expanded {
                if let Some(found) = Self::find_node_mut(&mut n.children, path) {
                    return Some(found);
                }
            }
        }
        None
    }

    /// Space / Enter-on-dir: expand or collapse the focused directory,
    /// lazily reading its children the first time it opens.
    pub fn toggle_expand(&mut self) {
        let path = match self.flat.get(self.selected) {
            Some(r) if r.is_dir => r.path.clone(),
            _ => return,
        };
        let show_hidden = self.show_hidden;
        if let Some(node) = Self::find_node_mut(&mut self.roots, &path) {
            if !node.expanded && !node.loaded {
                match Self::read_children(&node.path, show_hidden) {
                    Ok(children) => {
                        node.children = children;
                        node.loaded = true;
                        node.load_error = None;
                    }
                    Err(e) => {
                        node.loaded = true;
                        node.load_error = Some(e.to_string());
                        node.children.clear();
                    }
                }
            }
            node.expanded = !node.expanded;
        }
        self.rebuild_flat();
    }

    pub fn move_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
        self.clamp_scroll();
    }

    pub fn move_down(&mut self) {
        if self.selected + 1 < self.flat.len() {
            self.selected += 1;
        }
        self.clamp_scroll();
    }

    /// Keep `selected` inside the visible window and `scroll` in range.
    fn clamp_scroll(&mut self) {
        let visible = ATTACH_VISIBLE_ROWS;
        if self.selected < self.scroll {
            self.scroll = self.selected;
        } else if self.selected >= self.scroll + visible {
            self.scroll = self.selected + 1 - visible;
        }
        let max_scroll = self.flat.len().saturating_sub(visible);
        if self.scroll > max_scroll {
            self.scroll = max_scroll;
        }
    }

    /// Right: open a collapsed dir, or step into an already-open one.
    pub fn expand(&mut self) {
        match self.flat.get(self.selected) {
            Some(r) if r.is_dir && !r.expanded => self.toggle_expand(),
            Some(r) if r.is_dir && r.expanded => self.move_down(),
            _ => {}
        }
    }

    /// Left / Backspace: collapse an open dir, else jump to the parent row.
    pub fn collapse_or_parent(&mut self) {
        match self.flat.get(self.selected) {
            Some(r) if r.is_dir && r.expanded => self.toggle_expand(),
            Some(r) => {
                let depth = r.depth;
                if depth > 0 {
                    let mut i = self.selected;
                    while i > 0 {
                        i -= 1;
                        if self.flat[i].depth < depth {
                            self.selected = i;
                            break;
                        }
                    }
                    self.clamp_scroll();
                }
            }
            None => {}
        }
    }

    /// `.`: toggle dotfiles. Simplest correct approach — collapse all and
    /// re-read the root, avoiding inconsistent per-directory hidden state.
    pub fn toggle_hidden(&mut self) {
        self.show_hidden = !self.show_hidden;
        self.load_root();
    }

    /// The path to attach: `Some` only when a regular file is focused.
    pub fn selected_path(&self) -> Option<std::path::PathBuf> {
        let r = self.flat.get(self.selected)?;
        if r.is_dir {
            None
        } else {
            Some(r.path.clone())
        }
    }
}

#[cfg(test)]
mod attach_picker_tests {
    use super::{AttachPickerState, TreeNode};
    use std::path::PathBuf;

    fn dir(name: &str, children: Vec<TreeNode>) -> TreeNode {
        TreeNode {
            name: name.into(),
            path: PathBuf::from(name),
            is_dir: true,
            expanded: false,
            loaded: true, // pre-loaded so toggling never touches the FS
            load_error: None,
            children,
        }
    }
    fn file(name: &str) -> TreeNode {
        TreeNode {
            name: name.into(),
            path: PathBuf::from(name),
            is_dir: false,
            expanded: false,
            loaded: true,
            load_error: None,
            children: vec![],
        }
    }
    fn state(roots: Vec<TreeNode>) -> AttachPickerState {
        let mut s = AttachPickerState {
            root: PathBuf::from("/"),
            roots,
            flat: vec![],
            selected: 0,
            scroll: 0,
            show_hidden: false,
            error: None,
        };
        s.rebuild_flat();
        s
    }

    #[test]
    fn expand_collapse_preserves_cursor() {
        // roots: a/ (contains x), b
        let mut s = state(vec![dir("a", vec![file("x")]), file("b")]);
        assert_eq!(s.flat.len(), 2);

        // expand `a` in place: child `x` appears, cursor stays on `a`.
        s.selected = 0;
        s.toggle_expand();
        assert_eq!(s.flat.len(), 3);
        assert_eq!(s.flat[s.selected].name, "a");
        assert_eq!(s.flat[1].name, "x");
        assert_eq!(s.flat[1].depth, 1);

        // navigate down to `b`, then collapse `a` and confirm cursor pins
        // back to `a` and the child disappears.
        s.move_down();
        s.move_down();
        assert_eq!(s.flat[s.selected].name, "b");
        s.selected = 0;
        s.toggle_expand();
        assert_eq!(s.flat.len(), 2);
        assert_eq!(s.flat[s.selected].name, "a");
    }

    #[test]
    fn selected_path_is_none_for_dirs() {
        let mut s = state(vec![dir("a", vec![file("x")]), file("b")]);
        s.selected = 0; // on `a` (dir)
        assert!(s.selected_path().is_none());
        s.selected = 1; // on `b` (file)
        assert_eq!(s.selected_path(), Some(PathBuf::from("b")));
    }
}

#[derive(Debug, Clone, Default)]
pub struct DialPeerState {
    pub address: String,
    pub status: Option<String>,
}

/// State for the manual attach-by-path modal (`Modal::AttachPath`). A
/// single text field holding the POSIX path the user is typing.
#[derive(Debug, Clone, Default)]
pub struct AttachPathState {
    pub input: String,
    /// Inline validation error (e.g. no file at the typed path). Shown in the
    /// modal so a typo doesn't discard what the user typed — mirrors the attach
    /// picker's `error` and the GUI sibling.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartField {
    Name,
    Encrypted,
    Passphrase,
}

#[derive(Debug, Clone)]
pub struct StartRoomState {
    pub name: String,
    pub encrypted: bool,
    pub passphrase: String,
    pub focus: StartField,
}

impl StartRoomState {
    pub fn new() -> Self {
        Self {
            name: String::new(),
            encrypted: false,
            passphrase: String::new(),
            focus: StartField::Name,
        }
    }
}

#[derive(Debug, Clone)]
pub struct JoinRoomState {
    pub room_id: String,
    pub room_name: String,
    pub encrypted: bool,
    pub passphrase: String,
}

/// Minimum gap between successive Typing broadcasts per room.
const TYPING_DEBOUNCE: Duration = Duration::from_millis(800);

/// A room we're currently in (a tab in the in-room view).
/// huddle 1.3.4: cap on messages retained in an open room's in-memory buffer.
/// A room loads ~200 from the DB on open, then every received/sent message was
/// pushed without bound — a peer spamming a busy room would grow this Vec
/// indefinitely on the client. When the cap is exceeded the oldest are dropped
/// (history still lives in the DB / is scrollable via re-open); generous enough
/// for normal scrollback.
const OPEN_ROOM_MSG_CAP: usize = 2000;

/// Push a message and drop the oldest if the buffer exceeds [`OPEN_ROOM_MSG_CAP`].
fn push_capped(messages: &mut Vec<StoredRoomMessage>, m: StoredRoomMessage) {
    messages.push(m);
    if messages.len() > OPEN_ROOM_MSG_CAP {
        let excess = messages.len() - OPEN_ROOM_MSG_CAP;
        messages.drain(0..excess);
    }
}

pub struct OpenRoom {
    pub room_id: String,
    pub name: String,
    pub encrypted: bool,
    pub members: Vec<String>,
    pub messages: Vec<StoredRoomMessage>,
    /// Attachments currently in this room, in chronological order.
    /// Refreshed from the AppHandle on render and on file events.
    pub attachments: Vec<StoredAttachment>,
    pub input: String,
    pub input_active: bool,
    /// Number of lines skipped from the top of the wrapped message
    /// buffer. Bounded by `last_max_scroll` at render time.
    pub scroll: u16,
    /// Last time we broadcast a Typing pulse for this room; used to
    /// debounce ChatTypeChar so we don't spam gossipsub.
    pub last_typing_sent: Option<Instant>,
    /// When true, render anchors to the bottom regardless of `scroll` —
    /// new messages stay visible. Any ScrollUp / PgUp / Home disables it.
    pub follow_mode: bool,
    /// Last-rendered maximum scroll value (total_lines − visible_height).
    /// Updated by `render_messages` so action handlers can clamp / detect
    /// "we just hit the bottom" without re-running the wrap.
    pub last_max_scroll: Cell<u16>,
    /// When true and input is blurred, j/k navigate file cards instead
    /// of scrolling. Enter activates the focused card.
    pub card_focus: bool,
    /// Index into the visible cards (filtered from `attachments`).
    pub focused_card_idx: usize,
    /// huddle 0.6: number of unread messages since the tab was last
    /// focused. Reset to 0 on tab activation. Replaces the old bool
    /// flag — gives users an "exact count" instead of a vague star.
    pub unread: u32,
    /// huddle 2.0.0 (F10): index into `messages` of the message the
    /// react/reply/edit/delete keybindings target. `None` means "the newest
    /// message that carries a `client_msg_id`" (resolved lazily by
    /// `target_message`). `[` / `]` move it; it's only meaningful in nav mode.
    pub selected_msg: Option<usize>,
    /// huddle 2.0.0 (F10): when `Some(client_msg_id)` the composer is editing
    /// that existing message instead of sending a new one — `ChatSend` routes
    /// to `edit_message` and the input is pre-filled with the old body.
    pub editing_msg: Option<String>,
    /// huddle 2.0.0 (F10): when `Some(client_msg_id)` the next message sent is
    /// a reply to it — `ChatSend` routes to `send_reply` and the composer
    /// shows a reply-context line.
    pub reply_to: Option<String>,
}

// LobbyFocus removed in huddle 0.7: sidebar focus model replaces it.
// `SidebarState::focus` is the new source of truth.

/// huddle 0.6: a single entry in the status-history ring buffer.
/// `timestamp` is wall-clock seconds since UNIX epoch (so the
/// notification overlay renders absolute time, not "12s ago").
#[derive(Debug, Clone)]
pub struct StatusEntry {
    pub message: String,
    pub timestamp: i64,
}

pub struct TuiApp {
    pub handle: AppHandle,
    pub mode: NetworkMode,
    /// huddle 0.7: which pane the right side of the layout renders.
    /// Driven by sidebar selection + jump-shortcuts.
    pub pane: Pane,
    /// huddle 0.7: sidebar state (selection, expansion, focus). The
    /// pane router is read-only on this — sidebar owns its model.
    pub sidebar: SidebarState,
    /// huddle 0.7: centralized color/style palette. All renderers take
    /// a `&Theme`. Default = dark.
    pub theme: crate::ui::theme::Theme,
    /// huddle 1.1.4: which palette `theme` currently holds. Loaded from the
    /// persisted `theme` setting at startup and flipped live from
    /// Settings → Appearance (the `T` chord).
    pub theme_kind: crate::ui::theme::ThemeKind,
    /// huddle 0.7: unread counts keyed by room_id. Increments on
    /// `MessageReceived` for rooms that aren't the current pane;
    /// clears when that room becomes the active pane.
    pub unread: HashMap<String, u32>,
    /// huddle 0.7: toggle the right-margin member list in Group panes.
    /// Default on; Ctrl+I toggles.
    pub show_member_margin: bool,
    /// huddle 0.7: which People-pane sublist has focus (Known/Verified/
    /// Blocked). Tab cycles.
    pub people_focus: PeopleFocus,
    /// huddle 0.7: cursor inside the People pane's Known sublist.
    pub selected_known_idx: usize,
    /// huddle 0.7: cursor inside the People pane's Blocked sublist.
    pub selected_blocked_idx: usize,
    /// huddle 0.7.7: cursor inside the People pane's Pending sublist.
    pub selected_pending_idx: usize,
    /// huddle 1.0: cursor inside the People pane's Contact-requests sublist.
    pub selected_contact_request_idx: usize,
    /// huddle 0.7.7: cached snapshot of `pending_friend_requests` rows
    /// rendered in the People pane. Refreshed on People focus, after
    /// accept/reject, and after the 15s spill.
    pub pending_requests: Vec<huddle_core::storage::repo::PendingFriendRequest>,
    /// huddle 1.0: inbound contact requests that arrived over the relay
    /// inbox ("add by HD-ID over the internet"). Rendered in the Contacts
    /// pane's Requests section; refreshed on a `ContactRequestReceived`
    /// event and after accept/decline.
    pub pending_contact_requests: Vec<huddle_core::storage::repo::PendingContactRequest>,
    pub modal: Modal,
    /// huddle 0.6: a FIFO queue of async-event modals (errors, rotation
    /// requests, inbound dials) that arrived while another modal held
    /// the foreground. Replaces the single-slot Option<Modal> — events
    /// no longer get silently dropped past the second. Capped at
    /// `PENDING_MODAL_CAP`; oldest is shed on overflow.
    pub pending_modals: VecDeque<Modal>,
    pub discovered_rooms: Vec<DiscoveredRoom>,
    pub known_peers: Vec<KnownPeerStatus>,
    pub open_rooms: Vec<OpenRoom>,
    pub listen_addresses: Vec<String>,
    /// Bottom-bar status: text + expiry instant. After expiry, treated
    /// as None by the renderer.
    pub status_message: Option<(String, Instant)>,
    /// huddle 0.6: every status-bar message that's ever been displayed
    /// in this session, capped at `STATUS_HISTORY_CAP`. Opens on
    /// Ctrl+H. Replaces the "goldfish" status bar where two events in
    /// quick succession overwrote each other.
    pub status_history: VecDeque<StatusEntry>,
    /// huddle 0.6: scroll offset of the Help modal. Lives on TuiApp
    /// (not Modal) so the Modal enum stays simple.
    pub help_scroll: u16,
    /// huddle 0.6: latest crates.io poll result. `Some(version)`
    /// renders a banner under the lobby header; `None` hides it.
    /// Set by the spawned update-check task via `update_check_slot`.
    pub update_banner: Option<String>,
    /// huddle 0.6: shared mailbox between the spawned update-check
    /// task (writer) and the main loop (reader). The task writes a
    /// detected newer version here; the main loop drains it once
    /// per tick and copies into `update_banner`. Stays empty when
    /// the user hasn't opted in.
    pub update_check_slot: Arc<Mutex<Option<String>>>,
    /// Phase D follow-up: the lobby header renders this as a
    /// reachability badge. `None` until AutoNAT delivers its first
    /// transition; `Some("reachable")` once any external address
    /// passes a probe; `Some("private")` if a reachable address
    /// later disappears (all probes failing). The TUI maps this to
    /// a 'reachable' / 'private' text badge in the Profile/Settings panes.
    pub nat_status: Option<String>,
    /// huddle 0.5: set to `Instant::now()` when `AppEvent::WentDark`
    /// arrives. The main loop polls this and quits the process once
    /// `GO_DARK_FAREWELL` has elapsed so the goodbye modal stays
    /// visible for a beat.
    pub went_dark_at: Option<Instant>,
    /// huddle 0.7.4: count of inbound messages observed during the
    /// startup catch-up window. After `STARTUP_GRACE` elapses, the
    /// main loop emits ONE summary desktop notification and resets
    /// this counter to zero. After that, individual unfocused-window
    /// notifications fire one-per-message.
    pub startup_catchup_count: u32,
    /// huddle 0.7.4: when `Some`, the main loop is still inside the
    /// catch-up grace window; messages accumulate into
    /// `startup_catchup_count` instead of triggering per-message
    /// notifications. Cleared (set to `None`) the first tick after
    /// the deadline passes.
    pub startup_grace_until: Option<Instant>,
    /// huddle 0.7.5: absolute deadline beyond which we stop sliding
    /// the catch-up window forward. Prevents a sustained-traffic
    /// room from indefinitely suppressing live notifications.
    pub startup_grace_cap: Instant,
    /// huddle 0.7.8: which tab is active in the Settings pane.
    pub settings_tab: SettingsTab,
    /// huddle 0.7.8: which row is highlighted in the Profile pane for
    /// copy-to-clipboard. 0 = username, 1 = HD-ID, 2 = Safety Code,
    /// 3 = fingerprint, 4..N = listen addresses (clamped at render).
    pub profile_cursor: usize,
}

/// huddle 0.5: how long the goodbye modal stays on screen after
/// `WentDark` before the process exits.
pub const GO_DARK_FAREWELL: Duration = Duration::from_secs(2);

/// huddle 0.7.4: how long after startup we batch inbound messages into
/// a single "N new messages while you were away" notification instead
/// of firing per-message notifications. 5s comfortably covers libp2p
/// dial + gossipsub catch-up on a healthy LAN; longer would risk
/// missing live messages.
pub const STARTUP_GRACE: Duration = Duration::from_secs(5);

/// huddle 0.7.5: each MessageReceived during the grace window pushes
/// the deadline forward by this much, so a slow catch-up (large
/// backlog or sluggish gossipsub) still batches correctly instead of
/// firing per-message notifications. Bounded by `STARTUP_GRACE_MAX`.
pub const STARTUP_GRACE_EXTEND: Duration = Duration::from_secs(2);

/// huddle 0.7.5: absolute cap on the catch-up window from
/// `started_at`. Once we cross this, the grace ends and any further
/// inbound messages route through the live notification path —
/// otherwise a sustained-traffic room could indefinitely silence
/// per-message alerts.
pub const STARTUP_GRACE_MAX: Duration = Duration::from_secs(30);

impl TuiApp {
    pub fn new(handle: AppHandle) -> Self {
        let mode = handle.mode();
        let known_peers = handle.known_peers();
        // huddle 0.7.7: capture the pending-request snapshot before
        // `handle` is moved into Self so we don't pay a clone.
        let pending_requests = handle.list_pending_friend_requests();
        let pending_contact_requests = handle.list_pending_contact_requests();
        // huddle 0.6: onboarding-pages-to-show is now version-driven.
        // First-launch users see every page; upgrading users see only
        // the "what's new in X.Y" page for releases newer than their
        // last_seen_onboarding_version.
        let last_seen = handle.last_seen_onboarding_version();
        let legacy_seen = handle.onboarding_seen();
        let pages = pages_to_show(last_seen.as_deref(), legacy_seen);
        let mut pending_modals: VecDeque<Modal> = VecDeque::new();
        if !pages.is_empty() {
            pending_modals.push_back(Modal::Onboarding { pages, cursor: 0 });
        }
        // huddle 0.6: ask first-launch users to opt in to the update
        // check. If they've already answered (Some(true) or Some(false))
        // we skip the modal. The prompt sits behind onboarding so new
        // users see the welcome card first.
        if handle.update_check_enabled().is_none() && legacy_seen {
            pending_modals.push_back(Modal::UpdateCheckOptIn);
        }
        // huddle 1.1.4: honor the persisted theme (shared with the GUI). A
        // fresh DB returns "dark", and `from_str` falls back to Dark for any
        // unknown value, so this is the dark default with no special-casing.
        let theme_kind = crate::ui::theme::ThemeKind::from_str(&handle.theme());
        Self {
            handle,
            mode,
            pane: Pane::Welcome,
            sidebar: SidebarState::default(),
            theme: theme_kind.palette(),
            theme_kind,
            unread: HashMap::new(),
            show_member_margin: true,
            people_focus: PeopleFocus::default(),
            selected_known_idx: 0,
            selected_blocked_idx: 0,
            selected_pending_idx: 0,
            selected_contact_request_idx: 0,
            pending_requests,
            pending_contact_requests,
            modal: Modal::None,
            pending_modals,
            discovered_rooms: Vec::new(),
            known_peers,
            open_rooms: Vec::new(),
            listen_addresses: Vec::new(),
            status_message: None,
            status_history: VecDeque::new(),
            help_scroll: 0,
            update_banner: None,
            update_check_slot: Arc::new(Mutex::new(None)),
            nat_status: None,
            went_dark_at: None,
            startup_catchup_count: 0,
            startup_grace_until: Some(Instant::now() + STARTUP_GRACE),
            startup_grace_cap: Instant::now() + STARTUP_GRACE_MAX,
            settings_tab: SettingsTab::default(),
            profile_cursor: 0,
        }
    }

    /// huddle 0.7: lookup an `OpenRoom` by its `room_id`. Replaces the
    /// old `active_room()` access pattern which keyed by `active_tab`.
    /// The Vec storage is kept for now; this method abstracts the
    /// lookup so pane/sidebar code doesn't depend on the storage shape.
    pub fn open_room(&self, room_id: &str) -> Option<&OpenRoom> {
        self.open_rooms.iter().find(|r| r.room_id == room_id)
    }

    pub fn open_room_mut(&mut self, room_id: &str) -> Option<&mut OpenRoom> {
        self.open_rooms.iter_mut().find(|r| r.room_id == room_id)
    }

    /// huddle 0.7: returns the room_id of the currently-active chat
    /// pane (`Pane::Dm(id) | Pane::Group(id)`); `None` for non-chat
    /// panes.
    pub fn current_pane_room_id(&self) -> Option<&str> {
        match &self.pane {
            Pane::Dm(id) | Pane::Group(id) => Some(id.as_str()),
            _ => None,
        }
    }

    pub fn mode_str(&self) -> &'static str {
        match self.mode {
            NetworkMode::Server => "Tor onion (relay-only)",
            NetworkMode::Mdns => "LAN (mDNS) + relay",
            NetworkMode::Direct => "Direct dial + relay",
        }
    }

    /// huddle 0.8: true when a libp2p swarm is running (i.e. not the
    /// onion-relay-only default). The NAT-reachability badge and peer
    /// counters are libp2p concepts, so the UI hides them otherwise.
    pub fn libp2p_active(&self) -> bool {
        self.mode != NetworkMode::Server
    }

    /// huddle 0.7: clear unread for a room. Called when that room
    /// becomes the active pane. (huddle 0.7.11: removed unused
    /// `unread_count` accessor — `app.unread.get(...)` is used
    /// directly at every call site.)
    pub fn clear_unread(&mut self, room_id: &str) {
        self.unread.remove(room_id);
    }

    /// huddle 0.7: switch the active pane to a given room id. Routes
    /// `Direct` rooms to `Pane::Dm`, anything else to `Pane::Group`.
    /// Also clears the unread counter for that room.
    pub fn switch_to_room(&mut self, room_id: &str) {
        let kind = self
            .handle
            .active_room_info(room_id)
            .map(|r| r.kind)
            .or_else(|| {
                self.handle
                    .discovered_rooms()
                    .into_iter()
                    .find(|d| d.room_id == room_id)
                    .map(|d| d.kind)
            })
            .unwrap_or(huddle_core::storage::repo::RoomKind::Group);
        self.pane = match kind {
            huddle_core::storage::repo::RoomKind::Direct => Pane::Dm(room_id.to_string()),
            huddle_core::storage::repo::RoomKind::Group => Pane::Group(room_id.to_string()),
        };
        self.clear_unread(room_id);
        self.sidebar.focus = SidebarFocus::Pane;
    }

    pub fn refresh_known_peers(&mut self) {
        self.known_peers = self.handle.known_peers();
        if self.selected_known_idx >= self.known_peers.len() && !self.known_peers.is_empty() {
            self.selected_known_idx = self.known_peers.len() - 1;
        }
    }

    /// huddle 0.7.7: re-snapshot the pending-requests list from disk.
    /// Called on People focus, after accept/reject, and after the 15s
    /// spill. Re-clamps the cursor so it doesn't dangle past the last
    /// row when the list shrinks.
    pub fn refresh_pending_requests(&mut self) {
        self.pending_requests = self.handle.list_pending_friend_requests();
        if self.selected_pending_idx >= self.pending_requests.len()
            && !self.pending_requests.is_empty()
        {
            self.selected_pending_idx = self.pending_requests.len() - 1;
        }
    }

    /// huddle 1.0: re-snapshot the relay-inbox contact requests.
    pub fn refresh_pending_contact_requests(&mut self) {
        self.pending_contact_requests = self.handle.list_pending_contact_requests();
    }

    /// Set the bottom status line with the default 6s TTL. Also
    /// appends to the status history ring buffer (huddle 0.6) so the
    /// Ctrl+H overlay can show a backlog even when events fire faster
    /// than the TTL.
    pub fn set_status(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        self.record_status(&msg);
        self.status_message = Some((msg, Instant::now() + STATUS_TTL));
    }

    /// Set the status line with an explicit TTL. Used for transient
    /// notifications worth a longer dwell than the default 6 s — e.g.
    /// DCUtR upgrade success ("direct connection to <peer>") which we
    /// want the user to actually see before it scrolls.
    pub fn set_status_for(&mut self, msg: impl Into<String>, ttl: Duration) {
        let msg = msg.into();
        self.record_status(&msg);
        self.status_message = Some((msg, Instant::now() + ttl));
    }

    /// huddle 0.6: append to the status history ring buffer. Dedupes
    /// adjacent duplicates so a re-render of the same message (which
    /// happens because tick_status calls set_status indirectly via
    /// app events) doesn't fill the buffer with the same line.
    fn record_status(&mut self, msg: &str) {
        if let Some(last) = self.status_history.back() {
            if last.message == msg {
                return;
            }
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.status_history.push_back(StatusEntry {
            message: msg.to_string(),
            timestamp: now,
        });
        while self.status_history.len() > STATUS_HISTORY_CAP {
            self.status_history.pop_front();
        }
    }

    /// Returns the current status text if it hasn't expired.
    pub fn current_status(&self) -> Option<&str> {
        self.status_message.as_ref().and_then(|(msg, exp)| {
            if *exp > Instant::now() {
                Some(msg.as_str())
            } else {
                None
            }
        })
    }

    /// Drop the stored status if it's already past its expiry. Cheap; safe
    /// to call every tick.
    pub fn tick_status(&mut self) {
        if let Some((_, exp)) = &self.status_message {
            if *exp <= Instant::now() {
                self.status_message = None;
            }
        }
    }

    pub fn active_room(&self) -> Option<&OpenRoom> {
        let id = self.current_pane_room_id()?;
        self.open_room(id)
    }

    pub fn active_room_mut(&mut self) -> Option<&mut OpenRoom> {
        let id = self.current_pane_room_id()?.to_string();
        self.open_room_mut(&id)
    }

    pub fn refresh_discovered(&mut self) {
        self.discovered_rooms = self.handle.discovered_rooms();
    }

    /// huddle 2.0.0 (F10/F9): re-read `room_id`'s message history from the
    /// (authoritative) DB into its open-room cache, picking up sender-minted
    /// `client_msg_id`s, edit / delete markers, and reply links. Only overwrites
    /// on a successful, non-empty read so a transient DB error can't blank a
    /// chat the user is looking at.
    pub fn refresh_room_messages(&mut self, room_id: &str) {
        if self.open_room(room_id).is_none() {
            return;
        }
        match self.handle.room_messages(room_id, 200) {
            Ok(msgs) if !msgs.is_empty() => {
                if let Some(r) = self.open_room_mut(room_id) {
                    r.messages = msgs;
                    // Keep the F10 selection cursor in range after the swap.
                    if let Some(idx) = r.selected_msg {
                        if idx >= r.messages.len() {
                            r.selected_msg = None;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// huddle 2.0.0 (F10): resolve the message the react/reply/edit/delete
    /// keybindings act on for the active room. Honours an explicit
    /// `selected_msg` cursor when it points at a still-targetable (has a
    /// `client_msg_id`, not deleted) message, otherwise falls back to the most
    /// recent targetable message. Returns its `client_msg_id`.
    pub fn active_target_msg_id(&self) -> Option<String> {
        self.active_target_message()
            .and_then(|m| m.client_msg_id.clone())
    }

    /// huddle 2.0.0 (F10): the active room's currently-targeted message, if any
    /// — used by the edit flow (it needs the body + ownership) and the renderer
    /// (to draw the selection marker).
    pub fn active_target_message(&self) -> Option<&StoredRoomMessage> {
        let r = self.active_room()?;
        if let Some(idx) = r.selected_msg {
            if let Some(m) = r.messages.get(idx) {
                if m.client_msg_id.is_some() && m.deleted_at.is_none() {
                    return Some(m);
                }
            }
        }
        r.messages
            .iter()
            .rev()
            .find(|m| m.client_msg_id.is_some() && m.deleted_at.is_none())
    }

    /// huddle 2.0.0 (F10): move the message-selection cursor to the previous
    /// (`delta < 0`, older) or next (`delta > 0`, newer) targetable message in
    /// the active room. Seeds from the resolved default the first time.
    pub fn move_selected_msg(&mut self, delta: i32) {
        let r = match self.active_room_mut() {
            Some(r) => r,
            None => return,
        };
        if r.messages.is_empty() {
            return;
        }
        // Resolve the current anchor index (explicit cursor, else newest
        // targetable, else last).
        let anchor = match r.selected_msg {
            Some(idx) => idx,
            None => r
                .messages
                .iter()
                .rposition(|m| m.client_msg_id.is_some() && m.deleted_at.is_none())
                .unwrap_or(r.messages.len().saturating_sub(1)),
        };
        let len = r.messages.len();
        let mut idx = anchor as i64;
        loop {
            idx += delta as i64;
            if idx < 0 || idx >= len as i64 {
                // No further targetable message in this direction — keep anchor.
                return;
            }
            let m = &r.messages[idx as usize];
            if m.client_msg_id.is_some() && m.deleted_at.is_none() {
                r.selected_msg = Some(idx as usize);
                return;
            }
        }
    }

    /// Refresh attachments for every open room from the AppHandle. Called
    /// on tick so card state stays in sync with chunks arriving.
    pub fn refresh_attachments(&mut self) {
        let handle = self.handle.clone();
        for room in &mut self.open_rooms {
            room.attachments = handle
                .list_room_attachments(&room.room_id)
                .unwrap_or_default();
            if room.attachments.is_empty() {
                room.focused_card_idx = 0;
                room.card_focus = false;
            } else if room.focused_card_idx >= room.attachments.len() {
                room.focused_card_idx = room.attachments.len() - 1;
            }
        }
    }

    /// Show `m` now if the user isn't mid-interaction with a modal,
    /// otherwise enqueue it. Dismissible modals (None / Error / Info)
    /// are pure output and safe to displace; input modals hold
    /// unsaved user state and must not be clobbered by an async event.
    ///
    /// huddle 0.6: the queue is now a `VecDeque` (was a single Option)
    /// — concurrent inbound dials / errors no longer drop the second.
    /// Bounded at `PENDING_MODAL_CAP`; oldest shed on overflow so a
    /// runaway error storm can't grow without bound.
    fn replace_modal_if_idle(&mut self, m: Modal) {
        if matches!(self.modal, Modal::None | Modal::Error(_) | Modal::Info(_)) {
            self.modal = m;
        } else {
            self.enqueue_modal(m);
        }
    }

    /// huddle 0.6: append a modal to the pending queue with overflow
    /// protection. Caller usually goes through `replace_modal_if_idle`.
    pub fn enqueue_modal(&mut self, m: Modal) {
        self.pending_modals.push_back(m);
        while self.pending_modals.len() > PENDING_MODAL_CAP {
            self.pending_modals.pop_front();
        }
    }

    // huddle 0.7.11: removed `pending_count` — the modal-queue badge
    // ended up not shipping in 0.6 and no caller uses the accessor.
    // `pending_modals` is still tracked internally.

    pub fn handle_app_event(&mut self, ev: AppEvent) {
        match ev {
            AppEvent::RoomDiscovered(_) | AppEvent::RoomLost { .. } => {
                self.refresh_discovered();
            }
            AppEvent::RoomJoined { room_id } => {
                let info = self.handle.active_room_info(&room_id);
                let members = self.handle.room_members(&room_id);
                let messages = self.handle.room_messages(&room_id, 200).unwrap_or_default();
                let already_open = self.open_rooms.iter().any(|r| r.room_id == room_id);
                if !already_open {
                    if let Some(info) = info {
                        let attachments = self
                            .handle
                            .list_room_attachments(&room_id)
                            .unwrap_or_default();
                        self.open_rooms.push(OpenRoom {
                            room_id: room_id.clone(),
                            name: info.name,
                            encrypted: info.encrypted,
                            members,
                            messages,
                            attachments,
                            input: String::new(),
                            input_active: false,
                            last_typing_sent: None,
                            scroll: 0,
                            follow_mode: true,
                            last_max_scroll: Cell::new(0),
                            card_focus: false,
                            focused_card_idx: 0,
                            unread: 0,
                            selected_msg: None,
                            editing_msg: None,
                            reply_to: None,
                        });
                    }
                }
                // huddle 0.7 focus-steal policy: auto-switch the pane
                // to the freshly-joined room only if the user is on
                // Welcome / Profile (a "soft" pane). Don't steal focus
                // away from another active chat — surface the new
                // room in the sidebar (it'll appear via discovered_rooms)
                // and let the user pick it.
                let soft_pane = matches!(self.pane, Pane::Welcome | Pane::Profile);
                if soft_pane {
                    self.switch_to_room(&room_id);
                }
            }
            AppEvent::RoomLeft { room_id } => {
                if let Some(idx) = self.open_rooms.iter().position(|r| r.room_id == room_id) {
                    self.open_rooms.remove(idx);
                    if self.current_pane_room_id() == Some(room_id.as_str()) {
                        self.pane = Pane::Welcome;
                    }
                    self.unread.remove(&room_id);
                }
            }
            AppEvent::MemberJoined {
                room_id,
                fingerprint,
            } => {
                if let Some(r) = self.open_rooms.iter_mut().find(|r| r.room_id == room_id) {
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
                if let Some(r) = self.open_rooms.iter_mut().find(|r| r.room_id == room_id) {
                    r.members.retain(|f| f != &fingerprint);
                }
            }
            AppEvent::MessageReceived {
                room_id,
                sender_fingerprint,
                body,
                sent_at,
            } => {
                let is_active = self.current_pane_room_id() == Some(room_id.as_str());
                // Snapshot fields needed for the notification before
                // we move body/sender into the stored message.
                let sender_for_notify = sender_fingerprint.clone();
                let body_for_notify = body.clone();
                if let Some(r) = self.open_room_mut(&room_id) {
                    push_capped(
                        &mut r.messages,
                        StoredRoomMessage {
                            id: 0,
                            room_id: room_id.clone(),
                            sender_fingerprint,
                            direction: "in".into(),
                            body,
                            sent_at,
                            // huddle 2.0.0 (F10): the event doesn't carry the
                            // sender-minted id; the refresh below pulls the
                            // authoritative row (with `client_msg_id` etc.) from
                            // the DB so reactions / replies can target it.
                            client_msg_id: None,
                            reply_to: None,
                            edited_at: None,
                            deleted_at: None,
                        },
                    );
                }
                // huddle 2.0.0 (F10): the core inserts the row before emitting
                // this event, so re-reading history gives us the persisted
                // `client_msg_id` / `reply_to` / edit + delete markers for the
                // message we just optimistically rendered.
                self.refresh_room_messages(&room_id);
                if !is_active {
                    let count = self.unread.entry(room_id.clone()).or_insert(0);
                    *count = count.saturating_add(1);
                }
                // huddle 0.7.4: desktop notification routing.
                // * during startup grace → silent batch; the main loop
                //   drains it into one summary notification.
                // * after grace, fire per-message *only* when the
                //   terminal isn't focused. A focused terminal already
                //   shows the message; an unread badge is enough.
                if self.startup_grace_until.is_some() {
                    self.startup_catchup_count = self.startup_catchup_count.saturating_add(1);
                    // huddle 0.7.5: extend the grace deadline so a
                    // slow gossipsub backlog still batches into the
                    // single summary notification instead of leaking
                    // into per-message alerts. Capped by
                    // `startup_grace_cap` so a hot room can't keep
                    // the grace open indefinitely.
                    let extended = Instant::now() + STARTUP_GRACE_EXTEND;
                    let new_deadline = extended.min(self.startup_grace_cap);
                    self.startup_grace_until =
                        self.startup_grace_until.map(|d| d.max(new_deadline));
                } else if !crate::notifier::is_focused() && self.handle.notifications_enabled() {
                    let room_name = self
                        .open_room(&room_id)
                        .map(|r| r.name.clone())
                        .or_else(|| self.handle.active_room_info(&room_id).map(|r| r.name))
                        .unwrap_or_else(|| short_room(&room_id));
                    let sender_name = self
                        .handle
                        .lookup_member_display_name(&sender_for_notify)
                        .unwrap_or_else(|| short_fp(&sender_for_notify));
                    let title = format!("huddle · {}", room_name);
                    let body = format!(
                        "{}: {}",
                        sender_name,
                        crate::notifier::preview(&body_for_notify)
                    );
                    crate::notifier::notify(&title, &body);
                }
            }
            AppEvent::MessageSent {
                room_id,
                body,
                message_id,
            } => {
                if let Some(r) = self.open_rooms.iter_mut().find(|r| r.room_id == room_id) {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;
                    push_capped(
                        &mut r.messages,
                        StoredRoomMessage {
                            id: message_id,
                            room_id: room_id.clone(),
                            sender_fingerprint: self.handle.fingerprint().to_string(),
                            direction: "out".into(),
                            body,
                            sent_at: now,
                            // huddle 2.0.0 (F10): pulled in by the refresh below.
                            client_msg_id: None,
                            reply_to: None,
                            edited_at: None,
                            deleted_at: None,
                        },
                    );
                }
                // huddle 2.0.0 (F10): re-read so our own just-sent message
                // carries its `client_msg_id` (the core persists it before
                // emitting), making it immediately reactable / editable.
                self.refresh_room_messages(&room_id);
            }
            AppEvent::ListeningOn { address } => {
                if !self.listen_addresses.contains(&address) {
                    self.listen_addresses.push(address);
                }
            }
            AppEvent::PeerDiscovered { .. } => {}
            AppEvent::PeerExpired { .. } => {
                self.refresh_known_peers();
            }
            AppEvent::Dialing { address } => {
                self.set_status(format!("dialing {}…", address));
                if let Modal::DialPeer(s) = &mut self.modal {
                    s.status = Some(format!("dialing {}…", address));
                }
            }
            AppEvent::DialSucceeded { address, .. } => {
                self.set_status(format!("connected to {}", address));
                if matches!(self.modal, Modal::DialPeer(_)) {
                    self.modal = Modal::None;
                }
                self.refresh_known_peers();
            }
            AppEvent::DialFailed { address, error } => {
                let msg = format!("dial {} failed: {}", address, error);
                self.set_status(msg.clone());
                if matches!(self.modal, Modal::DialPeer(_)) {
                    self.modal = Modal::Error(msg);
                }
                self.refresh_known_peers();
            }
            AppEvent::Error { description } => {
                self.replace_modal_if_idle(Modal::Error(description));
            }
            AppEvent::FileOffered {
                room_id,
                file_id: _,
                name,
                size_bytes,
                sender_fingerprint: _,
            } => {
                let on_active = self.current_pane_room_id() == Some(room_id.as_str());
                if !on_active {
                    let count = self.unread.entry(room_id.clone()).or_insert(0);
                    *count = count.saturating_add(1);
                }
                let _ = room_id;
                self.set_status(format!("file offered: {} ({} KB)", name, size_bytes / 1024));
            }
            AppEvent::FileProgress { .. } => {
                // Progress is read on render from the attachments list;
                // no state change here.
            }
            AppEvent::FileReady { file_id: _ } => {
                self.set_status("file ready — press Enter to save");
            }
            AppEvent::FileSaved { file_id: _, path } => {
                self.set_status(format!("saved to {}", path));
            }
            AppEvent::FileFailed { file_id: _, reason } => {
                self.set_status(format!("transfer failed: {}", reason));
            }
            AppEvent::TypingChanged { .. } => {
                // The UI re-reads typers per-frame via handle.typers_in_room;
                // nothing else to do here.
            }
            AppEvent::MentionReceived { room_id, body } => {
                // BEL (0x07): most terminals beep or flash on this.
                use std::io::Write;
                let _ = write!(std::io::stdout(), "\x07");
                let _ = std::io::stdout().flush();
                self.set_status(format!("@you mentioned in #{}", short_room(&room_id)));
                let _ = body;
            }
            AppEvent::RotationRequested {
                room_id,
                rotator_fingerprint,
                new_salt,
            } => {
                self.replace_modal_if_idle(Modal::AcceptRotation(AcceptRotationState {
                    room_id,
                    rotator_fingerprint,
                    new_salt,
                    passphrase: String::new(),
                }));
            }
            AppEvent::InboundDial {
                peer_id,
                fingerprint,
                address,
            } => {
                self.replace_modal_if_idle(Modal::InboundDial(InboundDialState {
                    peer_id,
                    fingerprint,
                    address,
                    opened_at: Instant::now(),
                }));
            }
            AppEvent::SasCodeReady {
                room_id,
                partner_fingerprint,
                tx_id,
                emoji_labels,
                decimal,
            } => {
                // If our SAS modal already targets this tx_id, advance
                // it to Comparing. Otherwise this is a fresh inbound
                // SAS request — surface a new modal.
                let advanced = if let Modal::Sas(s) = &mut self.modal {
                    if s.tx_id == tx_id {
                        s.stage = SasStage::Comparing {
                            emoji_labels: emoji_labels.clone(),
                            decimal: decimal.clone(),
                            our_matched: false,
                        };
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };
                if !advanced {
                    self.replace_modal_if_idle(Modal::Sas(SasState {
                        room_id,
                        partner_fingerprint,
                        tx_id,
                        stage: SasStage::Comparing {
                            emoji_labels,
                            decimal,
                            our_matched: false,
                        },
                    }));
                }
            }
            AppEvent::SasVerified {
                partner_fingerprint,
                ..
            } => {
                if matches!(self.modal, Modal::Sas(_)) {
                    self.modal = Modal::None;
                }
                self.set_status(format!(
                    "✓ verified {} via SAS",
                    short_fp(&partner_fingerprint)
                ));
            }
            AppEvent::CodeJoinTimedOut { room_id: _, reason } => {
                // The placeholder tab from `join_room_with_code` stays
                // open (the user might retry) — we just surface the
                // failure via the modal queue so it doesn't clobber
                // anything the user happens to be typing.
                self.replace_modal_if_idle(Modal::Error(format!("code join: {reason}")));
            }
            AppEvent::InviteFingerprintMismatch {
                address: _,
                claimed,
                actual,
            } => {
                // The connection has already been dropped by the app
                // handle; we just inform the user via the modal queue.
                let msg = format!(
                    "invite fingerprint mismatch — connection dropped.\nclaimed: {}\nactual:  {}\nthe invite link may be forged.",
                    short_fp(&claimed),
                    short_fp(&actual)
                );
                self.replace_modal_if_idle(Modal::Error(msg));
            }
            AppEvent::NatStatusChanged {
                label,
                reachable: _,
            } => {
                // The lobby renders this as an emoji badge via
                // `nat_status_badge()`; we just stash the raw label.
                self.nat_status = Some(label);
            }
            AppEvent::DcutrSucceeded { peer_label } => {
                self.set_status_for(
                    format!("direct connection to …{}", peer_label),
                    Duration::from_secs(10),
                );
            }
            AppEvent::PeerProfileUpdated {
                fingerprint,
                username,
            } => {
                // huddle 0.5: a peer set / changed / cleared their
                // username. The chat + member list pull from the DB
                // every render, so a redraw is enough — but show a
                // transient hint so the user notices the rename live.
                let new_label = match &username {
                    Some(n) if !n.is_empty() => n.clone(),
                    _ => "[anonymous]".into(),
                };
                let short: String = fingerprint.chars().take(4).collect();
                self.set_status_for(
                    format!("{}… is now {}", short, new_label),
                    Duration::from_secs(4),
                );
            }
            AppEvent::WentDark => {
                // huddle 0.5: go_dark wiped everything. Show the final
                // farewell, then schedule a quit. The status TTL also
                // serves as the visibility window before exit.
                self.modal =
                    Modal::Info("Goodbye. huddle has gone dark. Restart to begin fresh.".into());
                self.went_dark_at = Some(std::time::Instant::now());
            }
            AppEvent::AutoOpenDm {
                room_id,
                fingerprint,
            } => {
                // huddle 0.7.7: a user-initiated dial connected and
                // Identify landed. Switch into the DM pane so the user
                // can immediately chat without manually navigating.
                // Username (if cached) goes in the status hint so a
                // first-time peer with no profile still gets a clear
                // breadcrumb.
                let label = self
                    .handle
                    .lookup_username(&fingerprint)
                    .unwrap_or_else(|| format!("HD-{}", short_fp(&fingerprint).to_uppercase()));
                self.refresh_known_peers();
                self.switch_to_room(&room_id);
                self.set_status(format!("connected — chatting with {}", label));
            }
            AppEvent::ContactRequestReceived {
                fingerprint,
                display_name,
                ..
            } => {
                // huddle 1.0: a relay-inbox "add by HD-ID" request arrived.
                // Refresh the Contacts pane's Requests section and flag it in
                // the status line so it's never silently buried.
                self.refresh_pending_contact_requests();
                let who = display_name
                    .unwrap_or_else(|| format!("HD-{}", short_fp(&fingerprint).to_uppercase()));
                self.set_status(format!("contact request from {} — see Contacts", who));
            }
            AppEvent::ConnectCodeCreated { code, expires_at } => {
                // huddle 1.2.1: the relay minted our connect code — show it so
                // the user can share it (don't clobber an in-progress modal).
                self.replace_modal_if_idle(Modal::ConnectCode(crate::app::ConnectCodeState {
                    code,
                    expires_at,
                }));
            }
            AppEvent::ConnectCodeRedeemed { fingerprint } => {
                self.set_status(format!(
                    "connect code accepted — request sent to HD-{}, opens a DM when they accept",
                    short_fp(&fingerprint).to_uppercase()
                ));
            }
            AppEvent::ConnectCodeFailed { reason } => {
                self.set_status(format!("connect code: {reason}"));
            }
            // huddle 2.0.0 (F3): a pinned peer's identity key changed mid
            // session. The drift message was already dropped by the core; we
            // raise a prominent alarm (routed through the modal queue so it
            // never clobbers what the user is typing).
            AppEvent::SafetyNumberChanged {
                room_id,
                fingerprint,
                old_pubkey_b64,
                new_pubkey_b64,
                display_name,
            } => {
                let who = display_name
                    .clone()
                    .unwrap_or_else(|| format!("HD-{}", short_fp(&fingerprint).to_uppercase()));
                self.set_status(format!("⚠ safety number changed for {who} — see the alert"));
                self.replace_modal_if_idle(Modal::SafetyNumberChanged(SafetyNumberChangedState {
                    room_id,
                    fingerprint,
                    old_pubkey_b64,
                    new_pubkey_b64,
                    display_name,
                    focus: 0,
                }));
            }
            // huddle 2.0.0 (F5): the master passphrase change + DB re-key
            // committed. Close the modal if it's still up and confirm.
            AppEvent::PassphraseChanged => {
                if matches!(self.modal, Modal::ChangePassphrase(_)) {
                    self.modal = Modal::None;
                }
                self.set_status("master passphrase updated — database re-keyed");
            }
            // huddle 2.0.0 (F10): a reaction landed (ours or a peer's). Re-read
            // the room so the badges under the message refresh.
            AppEvent::ReactionAdded { room_id, .. } => {
                self.refresh_room_messages(&room_id);
            }
            // huddle 2.0.0 (F10): a message body was edited. Re-read so the
            // new body + `[edited]` marker render.
            AppEvent::MessageEdited { room_id, .. } => {
                self.refresh_room_messages(&room_id);
            }
            // huddle 2.0.0 (F10): a message was tombstoned. Re-read so it
            // renders as `[deleted]`.
            AppEvent::MessageDeleted { room_id, .. } => {
                self.refresh_room_messages(&room_id);
            }
            // huddle 2.0.0 (F9): the per-room disappearing-messages TTL changed
            // (locally or via a signed owner broadcast). The header indicator
            // reads the live value each render; surface a transient hint.
            AppEvent::RoomTtlChanged { room_id, ttl_secs } => {
                let label = match ttl_secs {
                    Some(secs) => format!(
                        "messages in #{} now disappear after {}",
                        short_room(&room_id),
                        crate::ui::pane::chat_common::format_ttl(secs)
                    ),
                    None => format!("disappearing messages off in #{}", short_room(&room_id)),
                };
                self.set_status(label);
            }
            // huddle 2.0.0 (F9): the pruner physically deleted expired rows.
            // Re-read every open room so vanished messages leave the view.
            AppEvent::MessagesExpired { count } => {
                if count > 0 {
                    let ids: Vec<String> =
                        self.open_rooms.iter().map(|r| r.room_id.clone()).collect();
                    for rid in ids {
                        self.refresh_room_messages(&rid);
                    }
                }
            }
        }
    }
}

fn short_room(room_id: &str) -> String {
    room_id.chars().take(8).collect()
}

/// First chunk of a fingerprint for compact display — the first 4-4
/// groups of the `xxxx-xxxx-xxxx-...` form, which gives ~32 bits of
/// collision resistance, plenty for a status line.
fn short_fp(fp: &str) -> String {
    fp.split('-').take(2).collect::<Vec<_>>().join("-")
}

/// Phase B: gather a member list for the kick / grant picker. Filters:
/// - excludes ourselves (you can't kick yourself, granting yourself is
///   a no-op since `start_room` already made you an owner)
/// - for Grant, hides current owners so the picker only shows
///   promotable members
/// - returns None if we aren't an owner of the active room (gates the
///   feature in one place)
fn owner_action_members(
    app: &TuiApp,
    kind: MemberActionKind,
) -> Option<(String, Vec<(String, bool)>)> {
    let room_id = app.active_room()?.room_id.clone();
    let our_fp = app.handle.fingerprint().to_string();
    if !app.handle.is_owner(&room_id, &our_fp) {
        // Status message is set by the caller's wrapper if we'd like;
        // returning None here just makes the keybinding a no-op for
        // non-owners, which is the intended UX.
        return None;
    }
    let owners: std::collections::HashSet<String> =
        app.handle.room_owners(&room_id).into_iter().collect();
    let members: Vec<(String, bool)> = app
        .active_room()?
        .members
        .iter()
        .filter(|fp| *fp != &our_fp)
        .filter(|fp| match kind {
            MemberActionKind::Kick => true,
            // Already an owner → nothing to grant
            MemberActionKind::Grant => !owners.contains(*fp),
        })
        .map(|fp| (fp.clone(), owners.contains(fp)))
        .collect();
    if members.is_empty() {
        return None;
    }
    Some((room_id, members))
}

/// huddle 0.7: move the sidebar selection up (`delta < 0`) or down
/// (`delta > 0`). Wraps within the ordered item list. Section headers
/// are skipped over when the move would land on one and the original
/// selection wasn't a section header — keeps j/k navigation snappy.
fn sidebar_move(app: &mut TuiApp, delta: i32) {
    let items = crate::ui::sidebar::ordered_items(app);
    if items.is_empty() {
        return;
    }
    let mut idx = items
        .iter()
        .position(|it| *it == app.sidebar.selection)
        .unwrap_or(0) as i32;
    idx += delta;
    if idx < 0 {
        idx = 0;
    }
    if idx as usize >= items.len() {
        idx = items.len() as i32 - 1;
    }
    app.sidebar.selection = items[idx as usize].clone();
    sync_pane_from_selection(app);
}

/// huddle 0.7: jump to the next/prev sidebar section (`delta = ±1`).
/// Used by Tab / Shift+Tab. Lands on the section header (which the user
/// can then j/k into).
fn sidebar_jump_section(app: &mut TuiApp, delta: i32) {
    use SidebarSection::*;
    let order = [Profile, Direct, Group, People, Activity, Settings];
    let current = match &app.sidebar.selection {
        SidebarItem::Section(s) => *s,
        SidebarItem::Profile => Profile,
        SidebarItem::Dm(_) | SidebarItem::DirectAddFriend => Direct,
        SidebarItem::Group(_) | SidebarItem::GroupDiscover | SidebarItem::GroupNew => Group,
        SidebarItem::Person(_) | SidebarItem::PeoplePendingBadge => People,
        SidebarItem::Activity => Activity,
        SidebarItem::Settings => Settings,
    };
    let cur_idx = order.iter().position(|s| *s == current).unwrap_or(0) as i32;
    let mut next = cur_idx + delta;
    if next < 0 {
        next = order.len() as i32 - 1;
    } else if next as usize >= order.len() {
        next = 0;
    }
    app.sidebar.selection = SidebarItem::Section(order[next as usize]);
}

/// huddle 0.7: expand / collapse the currently-selected section.
fn sidebar_toggle_expand(app: &mut TuiApp) {
    let section = match &app.sidebar.selection {
        SidebarItem::Section(s) => *s,
        SidebarItem::Profile => SidebarSection::Profile,
        SidebarItem::Dm(_) | SidebarItem::DirectAddFriend => SidebarSection::Direct,
        SidebarItem::Group(_) | SidebarItem::GroupDiscover | SidebarItem::GroupNew => {
            SidebarSection::Group
        }
        SidebarItem::Person(_) | SidebarItem::PeoplePendingBadge => SidebarSection::People,
        SidebarItem::Activity => SidebarSection::Activity,
        SidebarItem::Settings => SidebarSection::Settings,
    };
    if app.sidebar.expanded.contains(&section) {
        app.sidebar.expanded.remove(&section);
    } else {
        app.sidebar.expanded.insert(section);
    }
}

/// huddle 0.7: side-effect of moving the sidebar — if the selection is
/// addressable (DM / Group / People / etc.), switch the pane to match
/// so live preview is always available as the cursor moves. The dual
/// "Enter to commit" model is unnecessary in a TUI with no mouse.
fn sync_pane_from_selection(app: &mut TuiApp) {
    if let Some(pane) = crate::ui::sidebar::pane_for_item(&app.sidebar.selection) {
        match &pane {
            Pane::Dm(id) | Pane::Group(id) => {
                let id = id.clone();
                app.clear_unread(&id);
                if app.handle.active_room_info(&id).is_some() {
                    open_existing_room_tab_quiet(app, &id);
                }
                app.pane = pane;
            }
            _ => app.pane = pane,
        }
    }
}

/// huddle 0.7.8: the labeled identity rows shown in Profile pane, in
/// fixed visual order. Tuple is (label-for-status-message, value-to-
/// copy). Listen addresses are spread across rows so each address is
/// individually yankable. Order MUST match `pane/profile.rs` rendering
/// so `profile_cursor` indices into the right thing.
pub fn profile_fields(app: &TuiApp) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let username = app
        .handle
        .display_name()
        .unwrap_or_else(|| "[anonymous]".into());
    out.push(("username".into(), username));
    let hd = crate::ui::display_id(app.handle.fingerprint());
    out.push(("HD-ID".into(), hd));
    out.push(("Safety Code".into(), app.handle.safety_code()));
    out.push(("fingerprint".into(), app.handle.fingerprint().to_string()));
    // huddle 0.7.12: expose the libp2p peer-id and render each listen
    // address as a complete, copy-paste dialable multiaddr (with the
    // /p2p/<peer-id> suffix the dial flow + MANUAL_TESTING §6 ask you to
    // append). Pre-0.7.12 the pane showed bare listen addrs and no
    // peer-id anywhere, so the documented "dial B's multiaddr with
    // peer-id appended" step was impossible from the UI.
    let peer_id = app.handle.peer_id().to_string();
    out.push(("peer-id".into(), peer_id.clone()));
    for (i, addr) in app.listen_addresses.iter().take(6).enumerate() {
        let dial = if addr.contains(&peer_id) {
            addr.clone()
        } else {
            format!("{addr}/p2p/{peer_id}")
        };
        out.push((format!("dial address {}", i + 1), dial));
    }
    out
}

pub fn profile_field_count(app: &TuiApp) -> usize {
    profile_fields(app).len()
}

pub fn profile_field_at(app: &TuiApp, idx: usize) -> Option<(String, String)> {
    profile_fields(app).into_iter().nth(idx)
}

/// huddle 0.7: list of room ids in sidebar order (DMs first, then
/// groups). Used by `switch_chat_relative` and `switch_chat_absolute`.
fn chat_room_ids(app: &TuiApp) -> Vec<String> {
    let discovered = app.handle.discovered_rooms();
    let mut dms: Vec<_> = discovered
        .iter()
        .filter(|r| r.kind == huddle_core::storage::repo::RoomKind::Direct)
        .map(|r| r.room_id.clone())
        .collect();
    let mut groups: Vec<_> = discovered
        .iter()
        .filter(|r| r.kind != huddle_core::storage::repo::RoomKind::Direct)
        .map(|r| r.room_id.clone())
        .collect();
    dms.append(&mut groups);
    dms
}

/// huddle 0.7: switch to the next / previous chat (DM or Group) in
/// sidebar order, wrapping at the ends.
fn switch_chat_relative(app: &mut TuiApp, delta: i32) {
    let chats = chat_room_ids(app);
    if chats.is_empty() {
        return;
    }
    let current = app
        .current_pane_room_id()
        .and_then(|id| chats.iter().position(|c| c == id));
    let next = match current {
        Some(i) => {
            let mut n = i as i32 + delta;
            if n < 0 {
                n = chats.len() as i32 - 1;
            }
            n as usize % chats.len()
        }
        None => 0,
    };
    let id = chats[next].clone();
    app.switch_to_room(&id);
}

/// huddle 0.7: jump to the N-th chat (zero-based) in sidebar order.
fn switch_chat_absolute(app: &mut TuiApp, n: usize) {
    let chats = chat_room_ids(app);
    if let Some(id) = chats.get(n).cloned() {
        app.switch_to_room(&id);
    }
}

/// huddle 0.7: hydrate OpenRoom if missing, without changing pane or
/// stealing focus. Used by `sync_pane_from_selection` to ensure the
/// chat pane has data on first sight.
fn open_existing_room_tab_quiet(app: &mut TuiApp, room_id: &str) {
    if app.open_room(room_id).is_some() {
        return;
    }
    let info = match app.handle.active_room_info(room_id) {
        Some(i) => i,
        None => return,
    };
    let members = app.handle.room_members(room_id);
    let messages = app.handle.room_messages(room_id, 200).unwrap_or_default();
    let attachments = app
        .handle
        .list_room_attachments(room_id)
        .unwrap_or_default();
    app.open_rooms.push(OpenRoom {
        room_id: room_id.to_string(),
        name: info.name,
        encrypted: info.encrypted,
        members,
        messages,
        attachments,
        input: String::new(),
        input_active: false,
        last_typing_sent: None,
        scroll: 0,
        follow_mode: true,
        last_max_scroll: Cell::new(0),
        card_focus: false,
        focused_card_idx: 0,
        unread: 0,
        selected_msg: None,
        editing_msg: None,
        reply_to: None,
    });
}

/// Scroll the active room by `delta` lines (negative = up). Maintains
/// `follow_mode` semantics: scrolling up disables it, reaching the bottom
/// enables it.
fn scroll_by(app: &mut TuiApp, delta: i32) {
    let r = match app.active_room_mut() {
        Some(r) => r,
        None => return,
    };
    let max = r.last_max_scroll.get();
    let current = if r.follow_mode { max } else { r.scroll };
    let next = if delta < 0 {
        current.saturating_sub(delta.unsigned_abs() as u16)
    } else {
        current.saturating_add(delta as u16).min(max)
    };
    r.scroll = next;
    r.follow_mode = next >= max;
}

/// huddle 0.7: hydrate an OpenRoom for `room_id` if we're subscribed but
/// don't have it open yet, then switch the active pane to it. Mirrors
/// what the `AppEvent::RoomJoined` handler does, minus the actual join
/// call.
fn open_existing_room_tab(app: &mut TuiApp, room_id: &str) {
    let info = match app.handle.active_room_info(room_id) {
        Some(i) => i,
        None => return,
    };
    if app.open_room(room_id).is_none() {
        let members = app.handle.room_members(room_id);
        let messages = app.handle.room_messages(room_id, 200).unwrap_or_default();
        let attachments = app
            .handle
            .list_room_attachments(room_id)
            .unwrap_or_default();
        app.open_rooms.push(OpenRoom {
            room_id: room_id.to_string(),
            name: info.name,
            encrypted: info.encrypted,
            members,
            messages,
            attachments,
            input: String::new(),
            input_active: false,
            last_typing_sent: None,
            scroll: 0,
            follow_mode: true,
            last_max_scroll: Cell::new(0),
            card_focus: false,
            focused_card_idx: 0,
            unread: 0,
            // huddle 2.0 (F10): message-selection + reply/edit composer state.
            selected_msg: None,
            editing_msg: None,
            reply_to: None,
        });
    }
    app.switch_to_room(room_id);
}

/// Restores the terminal on drop — raw mode off, alternate screen left,
/// mouse capture disabled. Holding one of these guarantees cleanup on
/// every exit path (normal return, early `?`, or a panic unwind), not
/// just the happy path.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            io::stdout(),
            LeaveAlternateScreen,
            DisableMouseCapture,
            DisableFocusChange,
            DisableBracketedPaste
        );
    }
}

/// huddle 0.7: resolve user-typed compose-DM input to a fingerprint.
/// Accepts:
///   - exact HD-... ID (branded)
///   - bare 24-char hex
///   - any peer username (from `peer_profiles`) — first match wins
///   - any known-peer label
fn resolve_dm_target(app: &TuiApp, input: &str) -> Option<String> {
    let trimmed = input.trim();
    // Reuse the dial-by-id-or-username normalizer for HD/hex paths.
    if let Some(fp) = huddle_core::app::normalize_to_fingerprint(trimmed) {
        return Some(fp);
    }
    // Username → fingerprint via the signed-ProfileUpdate cache
    // (`peer_profiles`). huddle 0.7.12: previously this iterated
    // `known_peers` and fed `p.label` (always `None`, and a label is
    // not a fingerprint) to `lookup_username`, so the branch was dead
    // and every typed username fell through to the dial path — which
    // hard-fails for a peer we share a room with but have no dialable
    // address for. Now we resolve over every peer whose name we've
    // learned, whether or not we've ever dialed them. Resolve only on
    // an unambiguous single match; an ambiguous or unknown name returns
    // `None` so the caller's AddFriend fallback can surface the proper
    // "ambiguous — use their HD- ID" / "no peer named X" guidance.
    let matches = app.handle.peers_with_username(trimmed);
    if matches.len() == 1 {
        return matches.into_iter().next();
    }
    None
}

/// Extract (room_id, file_id, status, encrypted) for the active room's
/// focused card. Returns None when no card is focused / available.
fn focused_card_info(
    app: &TuiApp,
) -> Option<(
    String,
    String,
    huddle_core::storage::repo::AttachmentStatus,
    bool,
)> {
    let r = app.active_room()?;
    let a = r.attachments.get(r.focused_card_idx)?;
    Some((r.room_id.clone(), a.file_id.clone(), a.status, a.encrypted))
}

// =========================================================================
// huddle 0.7.7: InvitePicker helpers
// =========================================================================

/// Build the tiered candidate list for the invite picker. Ordering:
///   1. Verified peers — SAS-completed; safest to in-band-DM.
///   2. DM partners — we already have a DM open with them.
///   3. Known peers — dialed at some point; weakest trust signal.
///
/// Dedup is fp-keyed: a peer who's both verified AND a DM partner
/// shows once at the highest tier. We filter out:
///   - our own fingerprint
///   - peers already in the room (no point inviting them)
///   - blocked peers (would silently fail anyway, and confusing UX)
///   - peers we don't have a username/profile cached for AND no
///     fingerprint (can't render or address them)
pub fn gather_invite_candidates(app: &TuiApp, room_id: &str) -> Vec<InviteCandidate> {
    let our_fp = app.handle.fingerprint().to_string();
    let in_room: HashSet<String> = app.handle.room_members(room_id).into_iter().collect();
    let blocked: HashSet<String> = app.handle.list_blocked_peers().into_iter().collect();

    let mut out: Vec<InviteCandidate> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let push = |list: &mut Vec<InviteCandidate>,
                seen: &mut HashSet<String>,
                fp: String,
                tier: InviteTier,
                username: Option<String>| {
        if seen.insert(fp.clone()) {
            list.push(InviteCandidate {
                fingerprint: fp,
                username,
                tier,
            });
        }
    };

    // Tier 1: Verified (highest trust). lookup_username falls back to None
    // for peers that haven't broadcast a ProfileUpdate yet.
    for fp in app.handle.list_verified_peers() {
        if fp == our_fp || in_room.contains(&fp) || blocked.contains(&fp) {
            continue;
        }
        let name = app.handle.lookup_username(&fp);
        push(&mut out, &mut seen, fp, InviteTier::Verified, name);
    }

    // Tier 2: DM partners. Iterate active rooms; pick out those whose
    // `kind` is Direct, then ask for the other member's fingerprint.
    for rid in app.handle.active_room_ids() {
        let info = match app.handle.active_room_info(&rid) {
            Some(i) => i,
            None => continue,
        };
        if info.kind != huddle_core::storage::repo::RoomKind::Direct {
            continue;
        }
        if let Some(partner) = app.handle.dm_partner_fingerprint(&rid) {
            if partner == our_fp || in_room.contains(&partner) || blocked.contains(&partner) {
                continue;
            }
            let name = app.handle.lookup_username(&partner);
            push(&mut out, &mut seen, partner, InviteTier::DmPartner, name);
        }
    }

    // Tier 3: Known peers with a learned fingerprint. Skip peers
    // we couldn't dedup-skip earlier (already verified or in DM).
    for p in &app.known_peers {
        if let Some(fp) = &p.fingerprint {
            if fp == &our_fp || in_room.contains(fp) || blocked.contains(fp) {
                continue;
            }
            let name = app.handle.lookup_username(fp);
            push(&mut out, &mut seen, fp.clone(), InviteTier::Known, name);
        }
    }

    out
}

/// Apply the picker's filter to its candidate slice. Match is
/// case-insensitive against the cached username AND the short HD-ID
/// prefix. Empty filter returns every candidate in tier order.
/// Returns owned clones so the caller can use it across mutable
/// borrows of the modal state.
pub fn filtered_invite_candidates(state: &InvitePickerState) -> Vec<InviteCandidate> {
    if state.filter.is_empty() {
        return state.candidates.clone();
    }
    let needle = state.filter.to_lowercase();
    state
        .candidates
        .iter()
        .filter(|c| {
            if let Some(u) = &c.username {
                if u.to_lowercase().contains(&needle) {
                    return true;
                }
            }
            let short = crate::ui::short_fp(&c.fingerprint).to_lowercase();
            short.starts_with(&needle)
                || needle.starts_with("hd-") && {
                    let after = needle.trim_start_matches("hd-").to_lowercase();
                    short.starts_with(&after)
                }
        })
        .cloned()
        .collect()
}

/// huddle 0.7.12: pick the best host address to embed in an invite.
/// Prefers addresses meant for the wire — relay-circuit reservations /
/// AutoNAT-confirmed external addresses (`dialable_addrs`), which work
/// across NAT — then the first routable listen address. Only falls back
/// to a loopback / unspecified-bind address (`127.0.0.1`, `0.0.0.0`,
/// `::1`, `::`) when that's literally all we have, since those are
/// useless to a remote peer. Pre-0.7.12 the invite builders grabbed
/// `listen_addresses.first()`, which is frequently `127.0.0.1`.
fn pick_invite_host_addr(app: &TuiApp) -> Option<String> {
    if let Some(a) = app.handle.dialable_addrs().into_iter().next() {
        return Some(a);
    }
    if let Some(a) = app
        .listen_addresses
        .iter()
        .find(|a| !is_unspecified_or_loopback(a))
    {
        return Some(a.clone());
    }
    // Nothing routable yet — last resort so the user at least gets a
    // (hand-editable) link instead of an error.
    app.listen_addresses.first().cloned()
}

/// True for multiaddrs a remote peer can't reach us on: IPv4/IPv6
/// loopback and the unspecified bind addresses.
fn is_unspecified_or_loopback(addr: &str) -> bool {
    addr.contains("/ip4/127.")
        || addr.contains("/ip4/0.0.0.0")
        || addr.contains("/ip6/::1/")
        || addr.contains("/ip6/::/")
}

/// huddle 0.8: the invite's libp2p `host_multiaddr`, or an empty string
/// when there's no usable address (the relay-only default, where no swarm
/// is listening). An empty value is valid: the recipient ignores the dial
/// and joins purely over the onion relay. When libp2p is running we embed
/// the best routable address with the `/p2p/<peer-id>` suffix so a direct
/// dial can still short-circuit the relay on a LAN.
fn build_host_multiaddr(app: &TuiApp, our_peer: &str) -> String {
    if !app.libp2p_active() {
        return String::new();
    }
    match pick_invite_host_addr(app) {
        Some(listen) if listen.contains(our_peer) => listen,
        Some(listen) => format!("{}/p2p/{}", listen, our_peer),
        None => String::new(),
    }
}

/// Build a room-scoped invite link the same way `Action::GenerateInvite`
/// does — but reusable so the InvitePicker can call it without
/// duplicating the listen-address / encode dance. Errors when we don't
/// have a listen address yet (transient startup state).
pub fn build_room_invite_link(app: &TuiApp, room_id: &str) -> anyhow::Result<String> {
    use anyhow::anyhow;
    let our_peer = app.handle.peer_id().to_string();
    let our_fp = app.handle.fingerprint().to_string();
    // huddle 0.8: optional libp2p address (empty in the relay-only
    // default). The recipient joins over the onion relay regardless; see
    // `build_host_multiaddr`.
    let host_multiaddr = build_host_multiaddr(app, &our_peer);

    let info = app
        .handle
        .active_room_info(room_id)
        .ok_or_else(|| anyhow!("room not active locally"))?;
    let salt_b64 = info
        .passphrase_salt
        .as_ref()
        .map(|s| base64::engine::general_purpose::STANDARD.encode(s));
    let room = huddle_core::invite::InviteRoom {
        id: info.id,
        name: info.name,
        encrypted: info.encrypted,
        salt_b64,
        creator_fingerprint: info.creator_fingerprint,
        owner_fingerprints: app.handle.room_owners(room_id),
    };
    let unsigned = huddle_core::invite::InviteLink {
        v: 1,
        host_multiaddr,
        fingerprint: our_fp,
        room: Some(room),
        creator_pubkey_b64: None,
        signed_at_ms: 0,
        signature_b64: None,
        // huddle 1.0: carry our configured clearnet relay (v3 invite).
        relay_url: app.handle.clearnet_relay(),
        // huddle 2.0 (F1): None keeps this a v2/v3 invite (back-compatible).
        mlkem_ek_b64: None,
    };
    let invite = app.handle.sign_invite(unsigned.clone()).unwrap_or(unsigned);
    huddle_core::invite::encode(&invite).map_err(|e| anyhow!("encode failed: {e}"))
}

// =========================================================================
// huddle 0.6: command palette
// =========================================================================

/// One entry surfaced by the command palette. `label` is the
/// human-readable description shown to the user; `keys` is the
/// keybinding to display alongside. Confirm dispatches by matching
/// `label`.
#[derive(Debug, Clone, Copy)]
pub struct PaletteEntry {
    pub label: &'static str,
    pub keys: &'static str,
}

/// Static list of "extra" palette entries that don't have a normal
/// keybinding — toggles and settings rows reachable only via the
/// palette.
const EXTRA_PALETTE_ENTRIES: &[PaletteEntry] = &[
    PaletteEntry {
        label: "toggle update check (crates.io)",
        keys: "",
    },
    PaletteEntry {
        label: "dismiss update banner",
        keys: "",
    },
    PaletteEntry {
        label: "clear notification history",
        keys: "Ctrl+H · c",
    },
    PaletteEntry {
        label: "invite peers to room…",
        keys: "Alt+I",
    },
];

/// Build the palette entry list filtered by `query`. Each character
/// of the query must appear in order in the label (subsequence
/// match — the standard "fuzzy" pattern). Empty query returns all.
pub fn palette_filtered(query: &str) -> Vec<PaletteEntry> {
    use crate::keybindings::palette_entries;
    let entries: Vec<PaletteEntry> = palette_entries()
        .map(|(label, keys)| PaletteEntry { label, keys })
        .chain(EXTRA_PALETTE_ENTRIES.iter().copied())
        .collect();
    if query.trim().is_empty() {
        return entries;
    }
    let q_lower: String = query.to_lowercase();
    entries
        .into_iter()
        .filter(|e| fuzzy_match(&e.label.to_lowercase(), &q_lower))
        .collect()
}

fn fuzzy_match(haystack: &str, needle: &str) -> bool {
    let mut it = haystack.chars();
    'outer: for nc in needle.chars() {
        for hc in it.by_ref() {
            if hc == nc {
                continue 'outer;
            }
        }
        return false;
    }
    true
}

/// Dispatch a confirmed palette pick to the actual app action. Each
/// arm mirrors what the corresponding keybinding would do. Some
/// actions are no-ops in some contexts (e.g. "kick member" when not
/// in a room as owner) — they surface a status note instead of
/// throwing an error.
pub async fn run_palette_action(label: &str, app: &mut TuiApp) -> Result<bool> {
    match label {
        // === Lobby-style ===
        "start a new room" => {
            app.modal = Modal::StartRoom(StartRoomState::new());
        }
        "add friend by HD ID or username" => {
            app.modal = Modal::AddFriend(AddFriendState::default());
        }
        "dial peer by address" => {
            app.modal = Modal::DialPeer(DialPeerState::default());
        }
        "show your QR identity" => {
            app.modal = Modal::QrIdentity;
        }
        "open settings" => {
            app.pane = Pane::Settings;
            app.settings_tab = SettingsTab::Account;
            app.sidebar.selection = SidebarItem::Section(SidebarSection::Settings);
        }
        "join with code" => {
            app.set_status("select an encrypted room in the lobby first, then press c");
        }
        "generate invite link" | "generate invite for this room" => {
            return Box::pin(handle_action(Action::GenerateInvite, app)).await;
        }
        "paste invite link" => {
            app.modal = Modal::PasteInvite(PasteInviteState { url: String::new() });
        }
        "mark all rooms read" => {
            return Box::pin(handle_action(Action::MarkAllRead, app)).await;
        }
        "refresh rooms" => {
            app.refresh_discovered();
            app.refresh_known_peers();
            app.set_status("refreshed");
        }
        // === Global ===
        "show help" => {
            app.help_scroll = 0;
            app.modal = Modal::Help;
        }
        "show what's new / onboarding" => {
            let pages: Vec<usize> = (0..ONBOARDING_PAGES.len()).collect();
            app.modal = Modal::Onboarding { pages, cursor: 0 };
        }
        "show notification history" => {
            app.modal = Modal::StatusHistory { scroll: 0 };
        }
        "quit huddle" => {
            app.modal = Modal::QuitConfirm;
        }
        // === Room-context ===
        "switch to next room" => {
            return Box::pin(handle_action(Action::TabNext, app)).await;
        }
        "leave current room" => {
            return Box::pin(handle_action(Action::LeaveRoom, app)).await;
        }
        "back to lobby" => {
            app.pane = Pane::Welcome;
            app.sidebar.focus = SidebarFocus::Sidebar;
        }
        "search room history" => {
            return Box::pin(handle_action(Action::OpenSearch, app)).await;
        }
        "verify members" => {
            return Box::pin(handle_action(Action::OpenVerify, app)).await;
        }
        "rotate room key" => {
            return Box::pin(handle_action(Action::OpenRotateRoom, app)).await;
        }
        "attach a file" => {
            return Box::pin(handle_action(Action::OpenAttachmentPicker, app)).await;
        }
        "attach a file by path" => {
            return Box::pin(handle_action(Action::OpenAttachByPath, app)).await;
        }
        "toggle room mute" => {
            return Box::pin(handle_action(Action::ToggleMute, app)).await;
        }
        "kick member" => {
            return Box::pin(handle_action(Action::OpenKickPicker, app)).await;
        }
        "grant owner" => {
            return Box::pin(handle_action(Action::OpenGrantPicker, app)).await;
        }
        "toggle verified-only joins" => {
            return Box::pin(handle_action(Action::ToggleRoomVerifiedOnly, app)).await;
        }
        "generate join code" => {
            return Box::pin(handle_action(Action::OpenGenerateJoinCode, app)).await;
        }
        "show room bans" => {
            return Box::pin(handle_action(Action::ShowRoomBans, app)).await;
        }
        "toggle room message expiry" => {
            return Box::pin(handle_action(Action::ToggleDisappearingMessages, app)).await;
        }
        // === Identity / security (huddle 2.0.0) ===
        "change master passphrase" => {
            return Box::pin(handle_action(Action::OpenChangePassphrase, app)).await;
        }
        "export seed phrase" => {
            return Box::pin(handle_action(Action::OpenExportSeed, app)).await;
        }
        // === Extras ===
        "toggle update check (crates.io)" => {
            return Box::pin(handle_action(Action::ToggleUpdateCheck, app)).await;
        }
        "dismiss update banner" => {
            return Box::pin(handle_action(Action::DismissUpdateBanner, app)).await;
        }
        "clear notification history" => {
            return Box::pin(handle_action(Action::ClearStatusHistory, app)).await;
        }
        "invite peers to room…" => {
            return Box::pin(handle_action(Action::OpenInvitePicker, app)).await;
        }
        other => {
            app.set_status(format!("no dispatch for '{}'", other));
        }
    }
    Ok(false)
}

// =========================================================================
// huddle 0.6: update detection (Tier 1 — passive banner, opt-in)
// =========================================================================

/// 24h between crates.io pings. The user opts in once; subsequent
/// launches respect this cache so we don't hammer the API.
const UPDATE_CHECK_INTERVAL_SECS: i64 = 24 * 60 * 60;

/// Spawn a tokio task that — only if the cache is older than 24h —
/// fetches crates.io's `huddle` crate metadata, extracts the
/// `max_stable_version`, and writes it into the app's shared
/// `update_check_slot` if it's newer than `CARGO_PKG_VERSION`. Safe
/// to call multiple times; the cache check serializes work.
pub fn spawn_update_check(app: &TuiApp) {
    let handle = app.handle.clone();
    let slot = app.update_check_slot.clone();
    tokio::spawn(async move {
        let result = tokio::task::spawn_blocking(move || run_update_check(&handle))
            .await
            .ok()
            .flatten();
        if let Some(v) = result {
            if let Ok(mut s) = slot.lock() {
                *s = Some(v);
            }
        }
    });
}

fn run_update_check(handle: &huddle_core::app::AppHandle) -> Option<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    let cached_at = handle.last_update_check_at();
    let cached_version = handle.last_known_remote_version();
    if now - cached_at < UPDATE_CHECK_INTERVAL_SECS {
        // Fresh cache: just compare the stored value.
        return cached_version.filter(|v| is_version_newer(v, env!("CARGO_PKG_VERSION")));
    }
    // Stale cache → fetch. huddle 1.1.4: route the request through the local
    // Tor SOCKS5 proxy so enabling the (opt-in) update check never leaks the
    // client's clearnet IP to crates.io — consistent with huddle's
    // onion-by-default posture. If Tor isn't reachable the request simply
    // fails and we skip this cycle rather than fall back to a direct
    // clearnet fetch (privacy over feature).
    let proxy = ureq::Proxy::new(&format!("socks5://{}", handle.tor_socks())).ok()?;
    let agent = ureq::AgentBuilder::new()
        .proxy(proxy)
        .timeout(std::time::Duration::from_secs(15))
        .build();
    let body = agent
        .get("https://crates.io/api/v1/crates/huddle")
        .set(
            "User-Agent",
            &format!("huddle/{}", env!("CARGO_PKG_VERSION")),
        )
        .call()
        .ok()?
        .into_string()
        .ok()?;
    // Extract "max_stable_version":"X.Y.Z" by hand to avoid a
    // serde_json dependency. Crates.io returns this field at the
    // top of the JSON; substring-finding it is robust.
    let version = parse_max_stable_version(&body)?;
    let _ = handle.set_last_update_check_at(now);
    let _ = handle.set_last_known_remote_version(&version);
    if is_version_newer(&version, env!("CARGO_PKG_VERSION")) {
        Some(version)
    } else {
        None
    }
}

/// Extract `"max_stable_version":"X.Y.Z"` from a crates.io API body
/// by substring match. Returns the value, or None if the field is
/// absent / malformed.
fn parse_max_stable_version(body: &str) -> Option<String> {
    let needle = "\"max_stable_version\":\"";
    let start = body.find(needle)? + needle.len();
    let rest = &body[start..];
    let end = rest.find('"')?;
    let v = &rest[..end];
    // Guard against accidentally matching an empty or non-numeric
    // value.
    if v.is_empty() || !v.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(v.to_string())
}

/// Reuse the same semver-tuple compare from `parse_semver`. Returns
/// true iff `remote > current`.
fn is_version_newer(remote: &str, current: &str) -> bool {
    parse_semver(remote) > parse_semver(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    // huddle 0.7.12 — guards Bug E: an invite must never embed a
    // loopback / unspecified host the recipient can't reach.
    #[test]
    fn is_unspecified_or_loopback_filters_useless_addrs() {
        assert!(is_unspecified_or_loopback("/ip4/127.0.0.1/tcp/9000"));
        assert!(is_unspecified_or_loopback("/ip4/0.0.0.0/tcp/9000"));
        assert!(is_unspecified_or_loopback("/ip6/::1/tcp/9000"));
        assert!(is_unspecified_or_loopback("/ip6/::/tcp/9000"));
    }

    #[test]
    fn is_unspecified_or_loopback_passes_routable_addrs() {
        assert!(!is_unspecified_or_loopback("/ip4/192.168.1.5/tcp/9000"));
        assert!(!is_unspecified_or_loopback("/ip4/10.0.0.5/tcp/9000"));
        assert!(!is_unspecified_or_loopback("/ip4/8.8.8.8/tcp/9000"));
        assert!(!is_unspecified_or_loopback("/ip6/2001:db8::1/tcp/9000"));
        // A relay-circuit address must pass through untouched.
        assert!(!is_unspecified_or_loopback(
            "/ip4/1.2.3.4/tcp/4001/p2p/12D3KooRelay/p2p-circuit"
        ));
    }
}
