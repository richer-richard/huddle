use std::cell::Cell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::{
    event::{
        self, poll, DisableFocusChange, DisableMouseCapture, EnableFocusChange,
        EnableMouseCapture, Event, MouseButton, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::prelude::*;
use ratatui::Terminal;

use base64::Engine;
use huddle_core::app::events::{AppEvent, DiscoveredRoom};
use huddle_core::app::{AppHandle, KnownPeerStatus};
use huddle_core::network::NetworkMode;
use huddle_core::storage::repo::{StoredAttachment, StoredRoomMessage};
use libp2p::PeerId;

use crate::input::{self, Action};

/// Default lifetime for transient status-bar messages.
const STATUS_TTL: Duration = Duration::from_secs(6);

/// Maximum entries kept in the status history ring buffer.
pub const STATUS_HISTORY_CAP: usize = 100;

/// Maximum modals we queue behind the active one. Beyond this we drop
/// the oldest — see `enqueue_modal`.
pub const PENDING_MODAL_CAP: usize = 16;

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
            "every member is a peer — no host, no central server.",
            "rooms outlive whoever created them.",
            "anyone with the room passphrase can join, send, rotate the key.",
            "leaderless + persistent mesh; the protocol has no admin tier",
            "by default, only the soft 'owner' role you can grant per room.",
            "",
            "press → / Tab / Enter / Space to continue.",
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
            "  ^I  produce an invite link (passphrase still OOB)",
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
            "  Ctrl+P  command palette — fuzzy search every action",
            "  Ctrl+H  notification history (last 100 status events)",
            "  Shift+? re-open this card anytime ('show what's new')",
            "  ?       help screen is now generated from input.rs —",
            "          every key is documented, scroll with j/k.",
            "  R       (lobby) mark every room read",
            "",
            "  · version + clock in the lobby header",
            "  · live peer counter next to the NAT badge",
            "  · per-tab unread counts (instead of '*')",
            "  · scroll indicator + day separators in chat",
            "  · '[N pending]' badge when a modal event was queued",
            "  · update banner (opt-in) — checks crates.io every 24h",
            "  · `huddle doctor` CLI subcommand for bug reports",
        ],
        min_version: "0.6.0",
    },
    OnboardingPage {
        title: "what's new in 0.7 — TUI 2.0",
        body: &[
            "huddle 0.7 rewrites the TUI around a sidebar:",
            "",
            "  Profile        you, your HD-ID, NAT badge",
            "  Direct messages  1-1 DMs (encrypted, 2-people-forever)",
            "  Group rooms      every multi-peer room you've joined",
            "  People           known peers + verified + blocked",
            "  Activity         status history + transfers",
            "  Settings         toggles + go-dark",
            "",
            "New keys:",
            "  m   start a DM (Compose-DM modal)",
            "  g   start a group room",
            "  p   jump to People pane",
            "  ,   jump to Settings pane",
            "  Tab/Shift+Tab   jump between sidebar sections",
            "  Space/←/→       expand/collapse a section",
            "  Alt+M           toggle the member margin in a Group",
            "",
            "Retired: tab-bar, Ctrl+B (back-to-lobby), numeric tab jump.",
            "Direct chats and group chats are now visually distinct;",
            "DMs land in the Direct messages section and stay 1-1.",
            "",
            "Note: v1 DMs aren't end-to-end encrypted on the room layer",
            "(visibility-filter + topic-ID obscurity); v0.8 will add E2E.",
        ],
        min_version: "0.7.0",
    },
    OnboardingPage {
        title: "what's new in 0.7.1 — E2E DMs",
        body: &[
            "DMs are now end-to-end encrypted on the room layer.",
            "",
            "Each DM derives a Megolm wrap key from an Ed25519→X25519",
            "ECDH between you and the other party's identity keys,",
            "bound to the canonical room_id via HKDF-SHA256. No shared",
            "passphrase, no extra prompt — `m` starts a DM and it's",
            "E2E from the first wrapped session key onward.",
            "",
            "The wire shape didn't change: DMs ride the same MemberAnnounce",
            "+ wrapped-Megolm-session-key flow as encrypted group rooms.",
            "Only the derivation of the wrap key changed.",
            "",
            "DMs created on 0.7.0 stay in their original (encrypted=false)",
            "mode for back-compat; new DMs created on 0.7.1 are E2E.",
        ],
        min_version: "0.7.1",
    },
    OnboardingPage {
        title: "what's new in 0.7.4 — desktop notifications",
        body: &[
            "huddle now fires native desktop notifications when a",
            "message arrives and the terminal isn't focused. Switch to",
            "another app, lock your screen, drag the window off-display —",
            "you'll still get pinged. When the terminal IS focused, no",
            "notification fires (the message is right in front of you).",
            "",
            "Catch-up summary: when you reopen huddle, any messages that",
            "arrived during the 5-second initial sync window are batched",
            "into one notification — \"N new messages while you were away\".",
            "",
            "Go dark moved to Alt+Shift+1 (Option+Shift+1 on macOS,",
            "Alt+Shift+1 on Linux/Windows). Plain `!` was one keystroke",
            "away from nuking your account — the extra modifier is a",
            "deliberate friction. The Settings pane row and the modal",
            "prompt both render `Alt+Shift+1` now.",
            "",
            "macOS only: the first notification triggers a one-time",
            "permission prompt for Script Editor / Terminal — click Allow.",
        ],
        min_version: "0.7.4",
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
    let patch_num: String = patch_raw.chars().take_while(|c| c.is_ascii_digit()).collect();
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
    /// huddle 0.7.8: pinned "📩 N friend requests" badge row when the
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
    /// huddle 0.7.7: pending inbound friend requests, spilled to disk
    /// when their 15s modal window times out. First tab so a forgotten
    /// request from earlier is the first thing the user sees on
    /// landing in People.
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
    Help,
    Error(String),
    Info(String),
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
        emoji_string: String,
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

#[derive(Debug, Clone)]
pub struct AttachEntry {
    pub name: String,
    pub is_dir: bool,
}

#[derive(Debug, Clone)]
pub struct AttachPickerState {
    pub cwd: std::path::PathBuf,
    pub entries: Vec<AttachEntry>,
    pub selected: usize,
    pub error: Option<String>,
}

impl AttachPickerState {
    pub fn new() -> Self {
        let start = dirs::download_dir()
            .or_else(dirs::home_dir)
            .unwrap_or_else(|| std::path::PathBuf::from("/"));
        let mut s = Self {
            cwd: start,
            entries: Vec::new(),
            selected: 0,
            error: None,
        };
        s.reload();
        s
    }

    pub fn reload(&mut self) {
        self.error = None;
        self.entries.clear();
        self.selected = 0;
        match std::fs::read_dir(&self.cwd) {
            Ok(rd) => {
                let mut tmp: Vec<AttachEntry> = Vec::new();
                for entry in rd.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.starts_with('.') {
                        continue;
                    }
                    let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
                    tmp.push(AttachEntry { name, is_dir });
                }
                tmp.sort_by(|a, b| match (a.is_dir, b.is_dir) {
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                });
                self.entries = tmp;
            }
            Err(e) => {
                self.error = Some(format!("cannot read {}: {}", self.cwd.display(), e));
            }
        }
    }

    pub fn descend(&mut self) {
        if let Some(e) = self.entries.get(self.selected) {
            if e.is_dir {
                self.cwd.push(&e.name);
                self.reload();
            }
        }
    }

    pub fn ascend(&mut self) {
        if let Some(parent) = self.cwd.parent() {
            self.cwd = parent.to_path_buf();
            self.reload();
        }
    }

    pub fn selected_path(&self) -> Option<std::path::PathBuf> {
        let e = self.entries.get(self.selected)?;
        if e.is_dir {
            None
        } else {
            Some(self.cwd.join(&e.name))
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DialPeerState {
    pub address: String,
    pub status: Option<String>,
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
    /// huddle 0.7.7: cached snapshot of `pending_friend_requests` rows
    /// rendered in the People pane. Refreshed on People focus, after
    /// accept/reject, and after the 15s spill.
    pub pending_requests: Vec<huddle_core::storage::repo::PendingFriendRequest>,
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
    /// '🌐 reachable' / '🏠 private' emoji in `lobby::render_status`.
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
        Self {
            handle,
            mode,
            pane: Pane::Welcome,
            sidebar: SidebarState::default(),
            theme: crate::ui::theme::Theme::dark(),
            unread: HashMap::new(),
            show_member_margin: true,
            people_focus: PeopleFocus::default(),
            selected_known_idx: 0,
            selected_blocked_idx: 0,
            selected_pending_idx: 0,
            pending_requests,
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
            NetworkMode::Mdns => "LAN (mDNS)",
            NetworkMode::Direct => "Direct (manual dial)",
        }
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

    /// Refresh attachments for every open room from the AppHandle. Called
    /// on tick so card state stays in sync with chunks arriving.
    pub fn refresh_attachments(&mut self) {
        let handle = self.handle.clone();
        for room in &mut self.open_rooms {
            room.attachments = handle.list_room_attachments(&room.room_id).unwrap_or_default();
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
            AppEvent::MemberJoined { room_id, fingerprint } => {
                if let Some(r) = self.open_rooms.iter_mut().find(|r| r.room_id == room_id) {
                    if !r.members.contains(&fingerprint) {
                        r.members.push(fingerprint);
                        r.members.sort();
                    }
                }
            }
            AppEvent::MemberLeft { room_id, fingerprint } => {
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
                    r.messages.push(StoredRoomMessage {
                        id: 0,
                        room_id: room_id.clone(),
                        sender_fingerprint,
                        direction: "in".into(),
                        body,
                        sent_at,
                    });
                }
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
                    self.startup_catchup_count =
                        self.startup_catchup_count.saturating_add(1);
                    // huddle 0.7.5: extend the grace deadline so a
                    // slow gossipsub backlog still batches into the
                    // single summary notification instead of leaking
                    // into per-message alerts. Capped by
                    // `startup_grace_cap` so a hot room can't keep
                    // the grace open indefinitely.
                    let extended = Instant::now() + STARTUP_GRACE_EXTEND;
                    let new_deadline = extended.min(self.startup_grace_cap);
                    self.startup_grace_until = self
                        .startup_grace_until
                        .map(|d| d.max(new_deadline));
                } else if !crate::notifier::is_focused()
                    && self.handle.notifications_enabled()
                {
                    let room_name = self
                        .open_room(&room_id)
                        .map(|r| r.name.clone())
                        .or_else(|| {
                            self.handle.active_room_info(&room_id).map(|r| r.name)
                        })
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
                    r.messages.push(StoredRoomMessage {
                        id: message_id,
                        room_id: room_id.clone(),
                        sender_fingerprint: self.handle.fingerprint().to_string(),
                        direction: "out".into(),
                        body,
                        sent_at: now,
                    });
                }
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
                self.set_status(format!(
                    "file offered: {} ({} KB)",
                    name,
                    size_bytes / 1024
                ));
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
                emoji_string,
                emoji_labels,
                decimal,
            } => {
                // If our SAS modal already targets this tx_id, advance
                // it to Comparing. Otherwise this is a fresh inbound
                // SAS request — surface a new modal.
                let advanced = if let Modal::Sas(s) = &mut self.modal {
                    if s.tx_id == tx_id {
                        s.stage = SasStage::Comparing {
                            emoji_string: emoji_string.clone(),
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
                            emoji_string,
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
            AppEvent::NatStatusChanged { label, reachable: _ } => {
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
            AppEvent::PeerProfileUpdated { fingerprint, username } => {
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
                self.modal = Modal::Info(
                    "Goodbye. huddle has gone dark. Restart to begin fresh.".into(),
                );
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
    for (i, addr) in app.listen_addresses.iter().take(6).enumerate() {
        out.push((format!("listen address {}", i + 1), addr.clone()));
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
    let attachments = app.handle.list_room_attachments(room_id).unwrap_or_default();
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
        let attachments = app.handle.list_room_attachments(room_id).unwrap_or_default();
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
            DisableFocusChange
        );
    }
}

/// Install a panic hook that restores the terminal *before* the default
/// hook prints the panic message. Without this, a panic inside the TUI
/// prints into the alternate screen, which is then torn down — losing the
/// message. Call once at startup.
pub fn install_panic_hook() {
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(
            io::stdout(),
            LeaveAlternateScreen,
            DisableMouseCapture,
            DisableFocusChange
        );
        original(info);
    }));
}

pub async fn run_tui(handle: AppHandle) -> Result<()> {
    enable_raw_mode()?;
    // From here on, every exit path restores the terminal.
    let _guard = TerminalGuard;
    let mut stdout = io::stdout();
    execute!(
        stdout,
        EnterAlternateScreen,
        EnableMouseCapture,
        EnableFocusChange
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = TuiApp::new(handle);
    // huddle 0.6: if the user already opted in to update checks
    // (Some(true) on a prior launch), kick the once-per-24h poll.
    if matches!(app.handle.update_check_enabled(), Some(true)) {
        spawn_update_check(&app);
    }
    let mut event_rx = app.handle.subscribe();

    let result = main_loop(&mut terminal, &mut app, &mut event_rx).await;

    app.handle.shutdown().await;
    result
}

/// What `prompt_master_passphrase` hands back. An empty `passphrase`
/// means the user pressed Esc / Ctrl-C — caller should exit cleanly.
pub struct AuthPrompt {
    pub passphrase: String,
    /// Only populated on first-launch (sign-up) flow.
    pub username: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthField {
    Username,
    Passphrase,
    Confirm,
}

/// Prompt for the master passphrase before bringing up `AppHandle`.
/// First-launch (`is_new=true`) collects username + passphrase + confirm;
/// returning users only enter their passphrase. Tab cycles between
/// fields; Enter advances or submits.
pub fn prompt_master_passphrase(is_new: bool) -> Result<AuthPrompt> {
    use crossterm::event::{KeyCode, KeyModifiers};
    use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph};

    enable_raw_mode()?;
    let _guard = TerminalGuard;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut username = String::new();
    let mut passphrase = String::new();
    let mut confirm = String::new();
    let mut field = if is_new {
        AuthField::Username
    } else {
        AuthField::Passphrase
    };
    let mut error: Option<String> = None;
    let mut outcome: Option<AuthPrompt> = None;

    while outcome.is_none() {
        terminal.draw(|f| {
            let height: u16 = if is_new { 18 } else { 12 };
            let area = crate::ui::centered_rect(64, height, f.area());
            f.render_widget(Clear, area);
            let block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .padding(Padding::uniform(1))
                .title(Span::styled(
                    if is_new {
                        " welcome to huddle — sign up "
                    } else {
                        " unlock huddle "
                    },
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ));

            let masked = |s: &str| -> String { s.chars().map(|_| '•').collect() };
            let label_style = |is_focused: bool| {
                if is_focused {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::DarkGray)
                }
            };
            let value_style = Style::default().fg(Color::White);
            let cursor = Span::styled("_", Style::default().fg(Color::DarkGray));

            let mut lines: Vec<Line> = Vec::new();
            lines.push(Line::from(""));
            if is_new {
                lines.push(Line::from(Span::styled(
                    "  pick a username (display name in chat — you can change it later)",
                    Style::default().fg(Color::DarkGray),
                )));
                lines.push(Line::from(Span::styled(
                    "  and a passphrase that encrypts your local database.",
                    Style::default().fg(Color::DarkGray),
                )));
                lines.push(Line::from(Span::styled(
                    "  forget the passphrase and your data is unrecoverable.",
                    Style::default().fg(Color::DarkGray),
                )));
                lines.push(Line::from(""));

                let u_focused = field == AuthField::Username;
                lines.push(Line::from(vec![
                    Span::styled("  username:    ", label_style(u_focused)),
                    Span::styled(username.clone(), value_style),
                    if u_focused {
                        cursor.clone()
                    } else {
                        Span::raw("")
                    },
                ]));
                let p_focused = field == AuthField::Passphrase;
                lines.push(Line::from(vec![
                    Span::styled("  passphrase:  ", label_style(p_focused)),
                    Span::styled(masked(&passphrase), value_style),
                    if p_focused {
                        cursor.clone()
                    } else {
                        Span::raw("")
                    },
                ]));
                let c_focused = field == AuthField::Confirm;
                lines.push(Line::from(vec![
                    Span::styled("  confirm:     ", label_style(c_focused)),
                    Span::styled(masked(&confirm), value_style),
                    if c_focused {
                        cursor.clone()
                    } else {
                        Span::raw("")
                    },
                ]));
            } else {
                lines.push(Line::from(Span::styled(
                    "  enter your passphrase to unlock the database.",
                    Style::default().fg(Color::DarkGray),
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("  passphrase: ", label_style(true)),
                    Span::styled(masked(&passphrase), value_style),
                    cursor.clone(),
                ]));
            }

            if let Some(err) = &error {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    format!("  ! {}", err),
                    Style::default().fg(Color::Red),
                )));
            }
            lines.push(Line::from(""));
            let hint_label = if is_new {
                if field == AuthField::Confirm {
                    " sign up   "
                } else {
                    " next field   "
                }
            } else {
                " unlock   "
            };
            lines.push(Line::from(vec![
                Span::styled(" Enter", Style::default().fg(Color::Yellow)),
                Span::styled(hint_label, Style::default().fg(Color::DarkGray)),
                Span::styled("Tab", Style::default().fg(Color::Yellow)),
                Span::styled(" cycle fields   ", Style::default().fg(Color::DarkGray)),
                Span::styled("Esc", Style::default().fg(Color::Yellow)),
                Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
            ]));
            f.render_widget(Paragraph::new(lines).block(block), area);
        })?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && matches!(key.code, KeyCode::Char('c'))
                {
                    outcome = Some(AuthPrompt {
                        passphrase: String::new(),
                        username: None,
                    });
                    break;
                }
                match key.code {
                    KeyCode::Esc => {
                        outcome = Some(AuthPrompt {
                            passphrase: String::new(),
                            username: None,
                        });
                    }
                    KeyCode::Tab if is_new => {
                        field = match field {
                            AuthField::Username => AuthField::Passphrase,
                            AuthField::Passphrase => AuthField::Confirm,
                            AuthField::Confirm => AuthField::Username,
                        };
                    }
                    KeyCode::Backspace => match field {
                        AuthField::Username => {
                            username.pop();
                        }
                        AuthField::Passphrase => {
                            passphrase.pop();
                        }
                        AuthField::Confirm => {
                            confirm.pop();
                        }
                    },
                    KeyCode::Enter => {
                        if is_new {
                            match field {
                                AuthField::Username => {
                                    if username.trim().is_empty() {
                                        error = Some("username can't be empty".into());
                                    } else {
                                        error = None;
                                        field = AuthField::Passphrase;
                                    }
                                }
                                AuthField::Passphrase => {
                                    if passphrase.is_empty() {
                                        error = Some("passphrase can't be empty".into());
                                    } else {
                                        error = None;
                                        field = AuthField::Confirm;
                                    }
                                }
                                AuthField::Confirm => {
                                    if confirm != passphrase {
                                        error = Some("passphrases don't match — try again".into());
                                        confirm.clear();
                                    } else {
                                        outcome = Some(AuthPrompt {
                                            passphrase: passphrase.clone(),
                                            username: Some(username.trim().to_string()),
                                        });
                                    }
                                }
                            }
                        } else if passphrase.is_empty() {
                            error = Some("passphrase can't be empty".into());
                        } else {
                            outcome = Some(AuthPrompt {
                                passphrase: passphrase.clone(),
                                username: None,
                            });
                        }
                    }
                    KeyCode::Char(c) => match field {
                        AuthField::Username => username.push(c),
                        AuthField::Passphrase => passphrase.push(c),
                        AuthField::Confirm => confirm.push(c),
                    },
                    _ => {}
                }
            }
        }
    }

    Ok(outcome.unwrap_or(AuthPrompt {
        passphrase: String::new(),
        username: None,
    }))
}

/// Show the welcome card before bringing up `AppHandle`. Returns `Ok(true)`
/// when the user is ready to continue or `Ok(false)` if they pressed
/// Ctrl-C / q (caller exits without starting the app).
pub fn show_welcome() -> Result<bool> {
    use crossterm::event::{KeyCode, KeyModifiers};

    enable_raw_mode()?;
    let _guard = TerminalGuard;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let outcome = loop {
        terminal.draw(crate::ui::picker::render_welcome)?;
        if poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && matches!(key.code, KeyCode::Char('c'))
                {
                    break false;
                }
                match key.code {
                    KeyCode::Char('q') => break false,
                    _ => break true,
                }
            }
        }
    };
    Ok(outcome)
}

async fn main_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut TuiApp,
    event_rx: &mut tokio::sync::broadcast::Receiver<AppEvent>,
) -> Result<()> {
    let mut should_quit = false;
    let mut last_refresh = std::time::Instant::now();

    while !should_quit {
        terminal.draw(|f| crate::ui::render(f, app))?;

        // Drain any pending app events.
        while let Ok(ev) = event_rx.try_recv() {
            app.handle_app_event(ev);
        }

        // Refresh discovered rooms every second (covers TTL pruning).
        if last_refresh.elapsed() > Duration::from_secs(1) {
            app.refresh_discovered();
            app.refresh_attachments();
            last_refresh = std::time::Instant::now();
        }

        // Drop expired status-bar messages.
        app.tick_status();

        // huddle 0.7.4: end of the startup catch-up window. Drain the
        // accumulated counter into one summary desktop notification
        // ("N new messages while you were away") and disarm the gate
        // so future messages route through the per-message path.
        if let Some(deadline) = app.startup_grace_until {
            if Instant::now() >= deadline {
                let n = app.startup_catchup_count;
                app.startup_catchup_count = 0;
                app.startup_grace_until = None;
                if n > 0 && app.handle.notifications_enabled() {
                    let body = if n == 1 {
                        "1 new message while you were away".to_string()
                    } else {
                        format!("{} new messages while you were away", n)
                    };
                    crate::notifier::notify("huddle", &body);
                }
            }
        }

        // huddle 0.6: drain the update-check slot. The poll task
        // writes here when a newer version is detected; we copy
        // into `update_banner` once so the lobby renders the banner.
        if app.update_banner.is_none() {
            if let Ok(mut slot) = app.update_check_slot.lock() {
                if let Some(v) = slot.take() {
                    app.update_banner = Some(v);
                }
            }
        }

        // huddle 0.5: if go_dark fired, hold the goodbye modal on
        // screen for `GO_DARK_FAREWELL`, then quit. The data dir is
        // already wiped at this point; the network task is down.
        if let Some(t) = app.went_dark_at {
            if t.elapsed() >= GO_DARK_FAREWELL {
                should_quit = true;
                continue;
            }
        }

        // Phase A: an inbound-dial modal that's been ignored for 15s
        // gets spilled to the persistent `pending_friend_requests`
        // table (huddle 0.7.7). The live libp2p connection is closed
        // so we don't leave an unknown peer attached — but the
        // *request* lives on for up to 3 days, viewable + acceptable
        // from the People pane. A startup sweep removes rows older
        // than the TTL so the table stays bounded.
        let auto_reject_state: Option<InboundDialState> =
            if let Modal::InboundDial(s) = &app.modal {
                if s.opened_at.elapsed() >= Duration::from_secs(15) {
                    Some(s.clone())
                } else {
                    None
                }
            } else {
                None
            };
        if let Some(s) = auto_reject_state {
            // Persist first so a failed reject_inbound doesn't drop
            // the request on the floor.
            if let Err(e) =
                app.handle
                    .spill_pending_friend_request(s.peer_id, &s.fingerprint, &s.address)
            {
                tracing::warn!(%e, "failed to spill pending friend request");
            }
            // Disconnect-only — do NOT block_peer. The user hasn't
            // decided yet; reject_inbound's block was appropriate for
            // a transient 15s timeout but blocks a peer permanently,
            // which contradicts "remember the request for 3 days".
            app.handle.disconnect_peer(s.peer_id).await;
            app.set_status(format!(
                "saved request from {} — review in People → Pending",
                short_fp(&s.fingerprint)
            ));
            app.modal = Modal::None;
            app.refresh_pending_requests();
        }

        if poll(Duration::from_millis(33))? {
            match event::read()? {
                Event::Key(key) => {
                    let action = input::map_key(key, app);
                    should_quit = handle_action(action, app).await?;
                }
                Event::Mouse(m) => {
                    if matches!(m.kind, MouseEventKind::Down(MouseButton::Left))
                        && app.current_pane_room_id().is_some()
                    {
                        // Click-to-toggle: clicking anywhere inside the
                        // chat area while we're in a room enters card
                        // focus mode if there are cards. Precise hit-
                        // testing per-card requires Rect tracking from
                        // render — left as a follow-up.
                        if let Some(r) = app.active_room() {
                            if !r.attachments.is_empty() && !r.card_focus {
                                handle_action(input::Action::ToggleCardFocus, app).await?;
                            }
                        }
                    }
                }
                Event::FocusGained => crate::notifier::set_focused(true),
                Event::FocusLost => crate::notifier::set_focused(false),
                _ => {}
            }
        }

        // An async-event modal queued while the user was mid-interaction
        // (see `replace_modal_if_idle`) surfaces once the foreground modal
        // is dismissed — by any path, not just `Action::CloseModal`. The
        // queue is FIFO (huddle 0.6); we drain one per tick so the user
        // sees them in arrival order.
        if matches!(app.modal, Modal::None) {
            if let Some(m) = app.pending_modals.pop_front() {
                app.modal = m;
            }
        }
    }

    Ok(())
}

async fn handle_action(action: Action, app: &mut TuiApp) -> Result<bool> {
    match action {
        Action::Nothing => Ok(false),
        Action::Quit => Ok(true),
        Action::OpenQuitConfirm => {
            app.modal = Modal::QuitConfirm;
            Ok(false)
        }
        Action::OpenClearBlockedConfirm => {
            app.modal = Modal::ConfirmClearBlocked;
            Ok(false)
        }
        Action::CloseModal => {
            app.modal = Modal::None;
            Ok(false)
        }
        Action::OpenStartRoom => {
            app.modal = Modal::StartRoom(StartRoomState::new());
            Ok(false)
        }
        Action::OpenHelp => {
            app.help_scroll = 0;
            app.modal = Modal::Help;
            Ok(false)
        }
        Action::LobbyNavigateUp => {
            sidebar_move(app, -1);
            Ok(false)
        }
        Action::LobbyNavigateDown => {
            sidebar_move(app, 1);
            Ok(false)
        }
        Action::LobbyRefresh => {
            app.refresh_discovered();
            app.refresh_known_peers();
            Ok(false)
        }
        Action::LobbyFocusToggle => {
            // huddle 0.7: Tab now jumps to the next sidebar section
            // (rather than toggling between two flat lists). Acts as
            // pane-focus toggle when on the sidebar and a chat pane.
            sidebar_jump_section(app, 1);
            Ok(false)
        }
        Action::FocusSidebar => {
            // huddle 0.7.2: Ctrl+Left. Blur chat input if active so
            // typing keystrokes route to sidebar nav, not into the
            // last-active chat.
            if let Some(r) = app.active_room_mut() {
                r.input_active = false;
            }
            app.sidebar.focus = SidebarFocus::Sidebar;
            Ok(false)
        }
        Action::FocusPane => {
            // huddle 0.7.2: Ctrl+Right. On chat panes, also focus the
            // input so typing goes straight into the composer.
            app.sidebar.focus = SidebarFocus::Pane;
            if matches!(app.pane, Pane::Dm(_) | Pane::Group(_)) {
                if let Some(r) = app.active_room_mut() {
                    r.input_active = true;
                }
            }
            Ok(false)
        }
        Action::LobbyReconnectPeer => {
            if let Some(p) = app.known_peers.get(app.selected_known_idx).cloned() {
                if let Err(e) = app.handle.redial(&p.address).await {
                    app.modal = Modal::Error(format!("dial failed: {e}"));
                }
            }
            Ok(false)
        }
        Action::LobbyForgetPeer => {
            if let Some(p) = app.known_peers.get(app.selected_known_idx).cloned() {
                if let Err(e) = app.handle.forget_peer(&p.address).await {
                    app.modal = Modal::Error(format!("forget failed: {e}"));
                }
                app.refresh_known_peers();
                if app.selected_known_idx >= app.known_peers.len() && !app.known_peers.is_empty() {
                    app.selected_known_idx = app.known_peers.len() - 1;
                }
            }
            Ok(false)
        }
        Action::OpenDialPeer => {
            app.modal = Modal::DialPeer(DialPeerState::default());
            Ok(false)
        }
        Action::DialPeerTypeChar(c) => {
            if let Modal::DialPeer(s) = &mut app.modal {
                s.address.push(c);
            }
            Ok(false)
        }
        Action::DialPeerBackspace => {
            if let Modal::DialPeer(s) = &mut app.modal {
                s.address.pop();
            }
            Ok(false)
        }
        Action::DialPeerConfirm => {
            let address = match &app.modal {
                Modal::DialPeer(s) => s.address.clone(),
                _ => return Ok(false),
            };
            if address.trim().is_empty() {
                if let Modal::DialPeer(s) = &mut app.modal {
                    s.status = Some("address is empty".into());
                }
                return Ok(false);
            }
            match app.handle.dial(&address).await {
                Ok(()) => {
                    if let Modal::DialPeer(s) = &mut app.modal {
                        s.status = Some(format!("dialing {}…", address));
                    }
                }
                Err(e) => {
                    app.modal = Modal::Error(format!("invalid address: {e}"));
                }
            }
            Ok(false)
        }
        Action::LobbyJoinSelected => {
            // huddle 0.7: Enter on the sidebar commits the selection.
            // For Dm/Group items, switch the pane. For GroupDiscover
            // children, walk the discovered list and join the first
            // unjoined group.
            match app.sidebar.selection.clone() {
                SidebarItem::Dm(room_id) | SidebarItem::Group(room_id) => {
                    if app.handle.active_room_info(&room_id).is_some() {
                        open_existing_room_tab(app, &room_id);
                        return Ok(false);
                    }
                    let room = app
                        .handle
                        .discovered_rooms()
                        .into_iter()
                        .find(|d| d.room_id == room_id);
                    if let Some(room) = room {
                        if room.encrypted {
                            app.modal = Modal::JoinRoom(JoinRoomState {
                                room_id: room.room_id.clone(),
                                room_name: room.name.clone(),
                                encrypted: true,
                                passphrase: String::new(),
                            });
                        } else if let Err(e) = app.handle.join_room(&room.room_id, None).await {
                            app.modal = Modal::Error(format!("join failed: {e}"));
                        }
                    }
                }
                SidebarItem::Section(s) => {
                    // Enter on a section header toggles its expand state.
                    if app.sidebar.expanded.contains(&s) {
                        app.sidebar.expanded.remove(&s);
                    } else {
                        app.sidebar.expanded.insert(s);
                    }
                }
                SidebarItem::Profile => app.pane = Pane::Profile,
                SidebarItem::Person(_) => app.pane = Pane::People,
                SidebarItem::Activity => app.pane = Pane::Activity,
                SidebarItem::Settings => app.pane = Pane::Settings,
                SidebarItem::DirectAddFriend => {
                    // huddle 0.7.8: pinned "+ Add Friend" row → fire the
                    // same flow as the global `m` shortcut.
                    return Box::pin(handle_action(Action::OpenComposeDm, app)).await;
                }
                SidebarItem::GroupNew => {
                    return Box::pin(handle_action(Action::OpenStartRoom, app)).await;
                }
                SidebarItem::PeoplePendingBadge => {
                    return Box::pin(handle_action(Action::JumpToPeoplePane, app)).await;
                }
                SidebarItem::GroupDiscover => {
                    // Find first unjoined group room and open its join modal.
                    if let Some(room) = app
                        .handle
                        .discovered_rooms()
                        .into_iter()
                        .find(|r| {
                            r.kind != huddle_core::storage::repo::RoomKind::Direct
                                && !app
                                    .handle
                                    .active_room_ids()
                                    .iter()
                                    .any(|aid| aid == &r.room_id)
                        })
                    {
                        if room.encrypted {
                            app.modal = Modal::JoinRoom(JoinRoomState {
                                room_id: room.room_id.clone(),
                                room_name: room.name.clone(),
                                encrypted: true,
                                passphrase: String::new(),
                            });
                        } else if let Err(e) = app.handle.join_room(&room.room_id, None).await {
                            app.modal = Modal::Error(format!("join failed: {e}"));
                        }
                    }
                }
            }
            Ok(false)
        }
        Action::StartRoomNextField => {
            if let Modal::StartRoom(s) = &mut app.modal {
                s.focus = match s.focus {
                    StartField::Name => StartField::Encrypted,
                    StartField::Encrypted => {
                        if s.encrypted {
                            StartField::Passphrase
                        } else {
                            StartField::Name
                        }
                    }
                    StartField::Passphrase => StartField::Name,
                };
            }
            Ok(false)
        }
        Action::StartRoomToggleEncrypted => {
            if let Modal::StartRoom(s) = &mut app.modal {
                s.encrypted = !s.encrypted;
                if !s.encrypted {
                    s.passphrase.clear();
                    // The passphrase field is hidden when encryption is
                    // off — don't strand focus on an invisible field.
                    if s.focus == StartField::Passphrase {
                        s.focus = StartField::Encrypted;
                    }
                }
            }
            Ok(false)
        }
        Action::StartRoomTypeChar(c) => {
            if let Modal::StartRoom(s) = &mut app.modal {
                match s.focus {
                    StartField::Name => s.name.push(c),
                    StartField::Passphrase => s.passphrase.push(c),
                    StartField::Encrypted => {}
                }
            }
            Ok(false)
        }
        Action::StartRoomBackspace => {
            if let Modal::StartRoom(s) = &mut app.modal {
                match s.focus {
                    StartField::Name => {
                        s.name.pop();
                    }
                    StartField::Passphrase => {
                        s.passphrase.pop();
                    }
                    StartField::Encrypted => {}
                }
            }
            Ok(false)
        }
        Action::StartRoomConfirm => {
            let (name, encrypted, passphrase) = match &app.modal {
                Modal::StartRoom(s) => (s.name.clone(), s.encrypted, s.passphrase.clone()),
                _ => return Ok(false),
            };
            if name.trim().is_empty() {
                app.modal = Modal::Error("room name cannot be empty".into());
                return Ok(false);
            }
            if encrypted && passphrase.is_empty() {
                app.modal = Modal::Error("encrypted room requires a passphrase".into());
                return Ok(false);
            }
            app.modal = Modal::None;
            let pp = if encrypted { Some(passphrase.as_str()) } else { None };
            if let Err(e) = app
                .handle
                .start_room(&name, encrypted, pp, huddle_core::storage::repo::RoomKind::Group)
                .await
            {
                app.modal = Modal::Error(format!("start failed: {e}"));
            }
            Ok(false)
        }
        Action::JoinRoomTypeChar(c) => {
            if let Modal::JoinRoom(j) = &mut app.modal {
                j.passphrase.push(c);
            }
            Ok(false)
        }
        Action::JoinRoomBackspace => {
            if let Modal::JoinRoom(j) = &mut app.modal {
                j.passphrase.pop();
            }
            Ok(false)
        }
        Action::JoinRoomConfirm => {
            let (room_id, passphrase) = match &app.modal {
                Modal::JoinRoom(j) => (j.room_id.clone(), j.passphrase.clone()),
                _ => return Ok(false),
            };
            app.modal = Modal::None;
            if let Err(e) = app.handle.join_room(&room_id, Some(&passphrase)).await {
                app.modal = Modal::Error(format!("join failed: {e}"));
            }
            Ok(false)
        }
        Action::TabNext => {
            // huddle 0.7: Tab-next now walks DM + Group rooms in
            // sidebar order. Retired the tab-bar concept; sidebar is
            // the navigation source of truth.
            switch_chat_relative(app, 1);
            Ok(false)
        }
        Action::TabPrev => {
            switch_chat_relative(app, -1);
            Ok(false)
        }
        Action::TabSelect(n) => {
            // huddle 0.7: Alt+1..9 jumps to the Nth chat (DM + Group
            // combined, sidebar order).
            switch_chat_absolute(app, n);
            Ok(false)
        }
        Action::BackToLobby => {
            // huddle 0.7: "back to lobby" is now "focus the sidebar".
            // The Welcome pane is the home screen.
            app.sidebar.focus = SidebarFocus::Sidebar;
            if matches!(app.pane, Pane::Dm(_) | Pane::Group(_)) {
                // Don't actually change pane — let the user choose. The
                // explicit way to leave a chat is `Ctrl+L` (LeaveRoom).
            } else {
                app.pane = Pane::Welcome;
            }
            Ok(false)
        }
        Action::LeaveRoom => {
            if let Some(room) = app.active_room() {
                let id = room.room_id.clone();
                match app.handle.leave_room(&id).await {
                    Ok(true) => {}
                    Ok(false) => app.set_status(
                        "left locally — peers may still see you until they time you out",
                    ),
                    Err(e) => app.modal = Modal::Error(format!("leave failed: {e}")),
                }
            }
            Ok(false)
        }
        Action::FocusInput => {
            if let Some(r) = app.active_room_mut() {
                r.input_active = true;
            }
            Ok(false)
        }
        Action::BlurInput => {
            if let Some(r) = app.active_room_mut() {
                r.input_active = false;
            }
            Ok(false)
        }
        Action::ScrollUp => {
            scroll_by(app, -1);
            Ok(false)
        }
        Action::ScrollDown => {
            scroll_by(app, 1);
            Ok(false)
        }
        Action::PageUp => {
            scroll_by(app, -10);
            Ok(false)
        }
        Action::PageDown => {
            scroll_by(app, 10);
            Ok(false)
        }
        Action::JumpTop => {
            if let Some(r) = app.active_room_mut() {
                r.scroll = 0;
                r.follow_mode = false;
            }
            Ok(false)
        }
        Action::JumpBottom => {
            if let Some(r) = app.active_room_mut() {
                r.follow_mode = true;
            }
            Ok(false)
        }
        Action::ChatTypeChar(c) => {
            let (room_id, should_pulse) = {
                let r = match app.active_room_mut() {
                    Some(r) if r.input_active => r,
                    _ => return Ok(false),
                };
                r.input.push(c);
                let pulse = match r.last_typing_sent {
                    Some(t) if t.elapsed() < TYPING_DEBOUNCE => false,
                    _ => true,
                };
                if pulse {
                    r.last_typing_sent = Some(Instant::now());
                }
                (r.room_id.clone(), pulse)
            };
            if should_pulse {
                app.handle.broadcast_typing(&room_id).await;
            }
            Ok(false)
        }
        Action::ChatBackspace => {
            if let Some(r) = app.active_room_mut() {
                if r.input_active {
                    r.input.pop();
                }
            }
            Ok(false)
        }
        Action::ChatSend => {
            let (room_id, body) = {
                match app.active_room_mut() {
                    Some(r) if r.input_active && !r.input.trim().is_empty() => {
                        let body = r.input.clone();
                        r.input.clear();
                        (r.room_id.clone(), body)
                    }
                    _ => return Ok(false),
                }
            };
            if let Err(e) = app.handle.send_room_message(&room_id, &body).await {
                app.modal = Modal::Error(format!("send failed: {e}"));
            }
            Ok(false)
        }
        Action::ChatInsertNewline => {
            if let Some(r) = app.active_room_mut() {
                if r.input_active {
                    r.input.push('\n');
                }
            }
            Ok(false)
        }
        Action::ToggleCardFocus => {
            if let Some(r) = app.active_room_mut() {
                if r.attachments.is_empty() {
                    return Ok(false);
                }
                r.card_focus = !r.card_focus;
                if r.card_focus {
                    r.input_active = false;
                    if r.focused_card_idx >= r.attachments.len() {
                        r.focused_card_idx = 0;
                    }
                }
            }
            Ok(false)
        }
        Action::CardNext => {
            if let Some(r) = app.active_room_mut() {
                if !r.attachments.is_empty() {
                    r.focused_card_idx = (r.focused_card_idx + 1) % r.attachments.len();
                }
            }
            Ok(false)
        }
        Action::CardPrev => {
            if let Some(r) = app.active_room_mut() {
                if !r.attachments.is_empty() {
                    r.focused_card_idx = if r.focused_card_idx == 0 {
                        r.attachments.len() - 1
                    } else {
                        r.focused_card_idx - 1
                    };
                }
            }
            Ok(false)
        }
        Action::ActivateFocusedCard => {
            let (room_id, file_id, status, encrypted) = match focused_card_info(app) {
                Some(t) => t,
                None => return Ok(false),
            };
            use huddle_core::storage::repo::AttachmentStatus;
            match status {
                AttachmentStatus::Offered | AttachmentStatus::Downloading => {
                    // Auto-pulled by gossipsub; just status nudge.
                    app.set_status("waiting for chunks…");
                }
                AttachmentStatus::Ready | AttachmentStatus::Saved => {
                    match app.handle.save_to_downloads(&room_id, &file_id).await {
                        Ok(path) => app.set_status(format!("saved to {}", path.display())),
                        Err(e) => app.modal = Modal::Error(format!("save failed: {e}")),
                    }
                }
                AttachmentStatus::Failed => {
                    app.set_status("retry not yet implemented — ask the sender to resend");
                }
                AttachmentStatus::Cancelled => {
                    app.set_status("transfer was cancelled");
                }
            }
            let _ = encrypted;
            Ok(false)
        }
        Action::OpenFocusedCard => {
            let (room_id, file_id, _, _) = match focused_card_info(app) {
                Some(t) => t,
                None => return Ok(false),
            };
            if let Err(e) = app.handle.open_saved(&room_id, &file_id) {
                app.modal = Modal::Error(format!("open failed: {e}"));
            }
            Ok(false)
        }
        Action::CancelFocusedCard => {
            let (room_id, file_id, _, _) = match focused_card_info(app) {
                Some(t) => t,
                None => return Ok(false),
            };
            if let Err(e) = app.handle.cancel_transfer(&room_id, &file_id).await {
                app.modal = Modal::Error(format!("cancel failed: {e}"));
            }
            Ok(false)
        }
        Action::SaveAgainFocusedCard => {
            let (room_id, file_id, _, _) = match focused_card_info(app) {
                Some(t) => t,
                None => return Ok(false),
            };
            match app.handle.save_to_downloads(&room_id, &file_id).await {
                Ok(path) => app.set_status(format!("saved to {}", path.display())),
                Err(e) => app.modal = Modal::Error(format!("save failed: {e}")),
            }
            Ok(false)
        }
        Action::OpenAttachmentPicker => {
            if app.active_room().is_none() {
                app.set_status("attach is only available inside a room");
                return Ok(false);
            }
            app.modal = Modal::AttachPicker(AttachPickerState::new());
            Ok(false)
        }
        Action::AttachPickerUp => {
            if let Modal::AttachPicker(s) = &mut app.modal {
                if s.selected > 0 {
                    s.selected -= 1;
                }
            }
            Ok(false)
        }
        Action::AttachPickerDown => {
            if let Modal::AttachPicker(s) = &mut app.modal {
                if s.selected + 1 < s.entries.len() {
                    s.selected += 1;
                }
            }
            Ok(false)
        }
        Action::AttachPickerAscend => {
            if let Modal::AttachPicker(s) = &mut app.modal {
                s.ascend();
            }
            Ok(false)
        }
        Action::OpenRotateRoom => {
            let room_id = match app.active_room() {
                Some(r) if r.encrypted => r.room_id.clone(),
                Some(_) => {
                    app.set_status("rotation only applies to encrypted rooms");
                    return Ok(false);
                }
                None => return Ok(false),
            };
            app.modal = Modal::RotateRoom(RotateRoomState {
                room_id,
                passphrase: String::new(),
            });
            Ok(false)
        }
        Action::RotateRoomTypeChar(c) => {
            if let Modal::RotateRoom(s) = &mut app.modal {
                s.passphrase.push(c);
            }
            Ok(false)
        }
        Action::RotateRoomBackspace => {
            if let Modal::RotateRoom(s) = &mut app.modal {
                s.passphrase.pop();
            }
            Ok(false)
        }
        Action::RotateRoomConfirm => {
            let (room_id, pp) = match &app.modal {
                Modal::RotateRoom(s) => (s.room_id.clone(), s.passphrase.clone()),
                _ => return Ok(false),
            };
            if pp.is_empty() {
                app.modal = Modal::Error("new passphrase cannot be empty".into());
                return Ok(false);
            }
            app.modal = Modal::None;
            match app.handle.rotate_room(&room_id, &pp).await {
                Ok(()) => app.set_status("rotation broadcast — share the new passphrase out-of-band"),
                Err(e) => app.modal = Modal::Error(format!("rotate failed: {e}")),
            }
            Ok(false)
        }
        Action::AcceptRotationTypeChar(c) => {
            if let Modal::AcceptRotation(s) = &mut app.modal {
                s.passphrase.push(c);
            }
            Ok(false)
        }
        Action::AcceptRotationBackspace => {
            if let Modal::AcceptRotation(s) = &mut app.modal {
                s.passphrase.pop();
            }
            Ok(false)
        }
        Action::AcceptRotationConfirm => {
            let (room_id, new_salt, pp) = match &app.modal {
                Modal::AcceptRotation(s) => {
                    (s.room_id.clone(), s.new_salt.clone(), s.passphrase.clone())
                }
                _ => return Ok(false),
            };
            if pp.is_empty() {
                return Ok(false);
            }
            app.modal = Modal::None;
            match app.handle.accept_rotation(&room_id, &new_salt, &pp).await {
                Ok(()) => app.set_status("accepted rotation — new key in use"),
                Err(e) => app.modal = Modal::Error(format!("accept rotation failed: {e}")),
            }
            Ok(false)
        }
        Action::OpenQrIdentity => {
            app.modal = Modal::QrIdentity;
            Ok(false)
        }
        Action::ToggleMute => {
            let room_id = match app.active_room() {
                Some(r) => r.room_id.clone(),
                None => return Ok(false),
            };
            let now_muted = app.handle.is_room_muted(&room_id);
            if let Err(e) = app.handle.set_room_muted(&room_id, !now_muted) {
                app.modal = Modal::Error(format!("mute toggle failed: {e}"));
            } else {
                app.set_status(if !now_muted { "muted" } else { "unmuted" });
            }
            Ok(false)
        }
        Action::OpenSearch => {
            let room_id = match app.active_room() {
                Some(r) => r.room_id.clone(),
                None => return Ok(false),
            };
            app.modal = Modal::Search(SearchState {
                room_id,
                query: String::new(),
                results: Vec::new(),
                selected: 0,
                searched: false,
            });
            Ok(false)
        }
        Action::SearchTypeChar(c) => {
            if let Modal::Search(s) = &mut app.modal {
                s.query.push(c);
            }
            Ok(false)
        }
        Action::SearchBackspace => {
            if let Modal::Search(s) = &mut app.modal {
                s.query.pop();
            }
            Ok(false)
        }
        Action::SearchSubmit => {
            let (room_id, query) = match &app.modal {
                Modal::Search(s) => (s.room_id.clone(), s.query.clone()),
                _ => return Ok(false),
            };
            if query.trim().is_empty() {
                return Ok(false);
            }
            let results = app
                .handle
                .search_room_messages(&room_id, &query, 100)
                .unwrap_or_default();
            if let Modal::Search(s) = &mut app.modal {
                s.results = results;
                s.selected = 0;
                s.searched = true;
            }
            Ok(false)
        }
        Action::SearchNext => {
            if let Modal::Search(s) = &mut app.modal {
                if s.selected + 1 < s.results.len() {
                    s.selected += 1;
                }
            }
            Ok(false)
        }
        Action::SearchPrev => {
            if let Modal::Search(s) = &mut app.modal {
                if s.selected > 0 {
                    s.selected -= 1;
                }
            }
            Ok(false)
        }
        Action::OpenVerify => {
            let room_id = match app.active_room() {
                Some(r) => r.room_id.clone(),
                None => return Ok(false),
            };
            let our_fp = app.handle.fingerprint().to_string();
            let verified_set: std::collections::HashSet<String> =
                app.handle.verified_fingerprints(&room_id).into_iter().collect();
            let members: Vec<(String, bool)> = app
                .active_room()
                .map(|r| {
                    r.members
                        .iter()
                        .filter(|fp| **fp != our_fp)
                        .map(|fp| (fp.clone(), verified_set.contains(fp)))
                        .collect()
                })
                .unwrap_or_default();
            if members.is_empty() {
                app.set_status("no other members to verify yet");
                return Ok(false);
            }
            app.modal = Modal::Verify(VerifyState {
                room_id,
                our_fingerprint: our_fp,
                members,
                selected: 0,
            });
            Ok(false)
        }
        Action::VerifyNext => {
            if let Modal::Verify(s) = &mut app.modal {
                if s.selected + 1 < s.members.len() {
                    s.selected += 1;
                }
            }
            Ok(false)
        }
        Action::VerifyPrev => {
            if let Modal::Verify(s) = &mut app.modal {
                if s.selected > 0 {
                    s.selected -= 1;
                }
            }
            Ok(false)
        }
        Action::VerifyToggle => {
            let (room_id, fp, new_state) = match &mut app.modal {
                Modal::Verify(s) => {
                    let m = match s.members.get_mut(s.selected) {
                        Some(x) => x,
                        None => return Ok(false),
                    };
                    m.1 = !m.1;
                    (s.room_id.clone(), m.0.clone(), m.1)
                }
                _ => return Ok(false),
            };
            if let Err(e) = app.handle.set_member_verified(&room_id, &fp, new_state) {
                app.modal = Modal::Error(format!("verify failed: {e}"));
            }
            Ok(false)
        }
        Action::OnboardingNext => {
            if let Modal::Onboarding { pages, cursor } = &mut app.modal {
                if *cursor + 1 < pages.len() {
                    *cursor += 1;
                } else {
                    let _ = app.handle.mark_onboarding_seen();
                    let _ = app
                        .handle
                        .set_last_seen_onboarding_version(env!("CARGO_PKG_VERSION"));
                    app.modal = Modal::None;
                }
            }
            Ok(false)
        }
        Action::OnboardingPrev => {
            if let Modal::Onboarding { cursor, .. } = &mut app.modal {
                if *cursor > 0 {
                    *cursor -= 1;
                }
            }
            Ok(false)
        }
        Action::OnboardingDismiss => {
            // Esc still records last_seen so the same pages don't re-pop
            // on next launch. Users replay via Settings → "Show what's
            // new" or the command palette.
            let _ = app.handle.mark_onboarding_seen();
            let _ = app
                .handle
                .set_last_seen_onboarding_version(env!("CARGO_PKG_VERSION"));
            app.modal = Modal::None;
            Ok(false)
        }
        // huddle 0.6: re-open onboarding regardless of last_seen. Shows
        // every page — gives users a way to revisit the welcome cards.
        Action::OpenWhatsNew => {
            let pages: Vec<usize> = (0..ONBOARDING_PAGES.len()).collect();
            app.modal = Modal::Onboarding { pages, cursor: 0 };
            Ok(false)
        }
        Action::OpenStatusHistory => {
            app.modal = Modal::StatusHistory { scroll: 0 };
            Ok(false)
        }
        Action::StatusHistoryScrollUp => {
            if let Modal::StatusHistory { scroll } = &mut app.modal {
                *scroll = scroll.saturating_sub(1);
            }
            Ok(false)
        }
        Action::StatusHistoryScrollDown => {
            if let Modal::StatusHistory { scroll } = &mut app.modal {
                *scroll = scroll.saturating_add(1);
            }
            Ok(false)
        }
        Action::StatusHistoryPageUp => {
            if let Modal::StatusHistory { scroll } = &mut app.modal {
                *scroll = scroll.saturating_sub(10);
            }
            Ok(false)
        }
        Action::StatusHistoryPageDown => {
            if let Modal::StatusHistory { scroll } = &mut app.modal {
                *scroll = scroll.saturating_add(10);
            }
            Ok(false)
        }
        Action::ClearStatusHistory => {
            app.status_history.clear();
            app.set_status("notification history cleared");
            app.modal = Modal::None;
            Ok(false)
        }
        Action::OpenCommandPalette => {
            app.modal = Modal::CommandPalette(CommandPaletteState::default());
            Ok(false)
        }
        Action::CommandPaletteTypeChar(c) => {
            if let Modal::CommandPalette(s) = &mut app.modal {
                s.query.push(c);
                s.selected = 0;
            }
            Ok(false)
        }
        Action::CommandPaletteBackspace => {
            if let Modal::CommandPalette(s) = &mut app.modal {
                s.query.pop();
                s.selected = 0;
            }
            Ok(false)
        }
        Action::CommandPaletteNext => {
            if let Modal::CommandPalette(s) = &mut app.modal {
                let total = palette_filtered(&s.query).len();
                if s.selected + 1 < total {
                    s.selected += 1;
                }
            }
            Ok(false)
        }
        Action::CommandPalettePrev => {
            if let Modal::CommandPalette(s) = &mut app.modal {
                if s.selected > 0 {
                    s.selected -= 1;
                }
            }
            Ok(false)
        }
        Action::CommandPaletteConfirm => {
            let picked: Option<String> = if let Modal::CommandPalette(s) = &app.modal {
                let filtered = palette_filtered(&s.query);
                filtered.get(s.selected).map(|e| e.label.to_string())
            } else {
                None
            };
            app.modal = Modal::None;
            if let Some(label) = picked {
                return run_palette_action(&label, app).await;
            }
            Ok(false)
        }
        Action::MarkAllRead => {
            let mut n = 0u32;
            for r in &mut app.open_rooms {
                if r.unread > 0 {
                    n = n.saturating_add(r.unread);
                    r.unread = 0;
                }
            }
            app.set_status(if n == 0 {
                "no unread to mark".to_string()
            } else {
                format!("marked {} message(s) read across {} room(s)", n, app.open_rooms.len())
            });
            Ok(false)
        }
        Action::HelpScrollUp => {
            app.help_scroll = app.help_scroll.saturating_sub(1);
            Ok(false)
        }
        Action::HelpScrollDown => {
            app.help_scroll = app.help_scroll.saturating_add(1);
            Ok(false)
        }
        Action::HelpPageUp => {
            app.help_scroll = app.help_scroll.saturating_sub(10);
            Ok(false)
        }
        Action::HelpPageDown => {
            app.help_scroll = app.help_scroll.saturating_add(10);
            Ok(false)
        }
        Action::UpdateCheckOptInYes => {
            let _ = app.handle.set_update_check_enabled(true);
            app.modal = Modal::None;
            app.set_status("update check enabled — polling crates.io once per day");
            // Kick off a check immediately so the user sees the
            // outcome rather than waiting for the 24h timer.
            spawn_update_check(app);
            Ok(false)
        }
        Action::UpdateCheckOptInNo => {
            let _ = app.handle.set_update_check_enabled(false);
            app.modal = Modal::None;
            app.set_status("update check disabled — toggle later in settings");
            Ok(false)
        }
        Action::ToggleUpdateCheck => {
            let cur = app.handle.update_check_enabled().unwrap_or(false);
            let _ = app.handle.set_update_check_enabled(!cur);
            app.set_status(if !cur {
                "update check ON — polling crates.io once per day"
            } else {
                "update check OFF"
            });
            if !cur {
                spawn_update_check(app);
            } else {
                app.update_banner = None;
            }
            Ok(false)
        }
        Action::DismissUpdateBanner => {
            app.update_banner = None;
            Ok(false)
        }
        Action::GenerateInvite => {
            // Build an invite payload from what we know. host_multiaddr
            // comes from the first listen address + our peer_id. Room
            // section is included iff we're in a room view.
            let our_peer = app.handle.peer_id().to_string();
            let our_fp = app.handle.fingerprint().to_string();
            let listen = match app.listen_addresses.first() {
                Some(a) => a.clone(),
                None => {
                    app.set_status("no listen address yet — try again in a sec");
                    return Ok(false);
                }
            };
            // libp2p multiaddrs need /p2p/<peer-id> appended so the
            // dialer's pubkey check fires. Listen addr is usually
            // /ip4/0.0.0.0/tcp/<port> — substitute a real host on the
            // receiver's end isn't ideal but the IP is what the user
            // shared OOB anyway. For LAN we leave the 0.0.0.0 as-is;
            // the user can fix the URL before sharing if their auto-
            // detected addr isn't reachable from outside.
            let host_multiaddr = format!("{}/p2p/{}", listen, our_peer);

            let room = match app.active_room() {
                Some(r) => {
                    if let Some(info) = app.handle.active_room_info(&r.room_id) {
                        let salt_b64 = info.passphrase_salt.as_ref().map(|s| {
                            base64::engine::general_purpose::STANDARD.encode(s)
                        });
                        Some(huddle_core::invite::InviteRoom {
                            id: info.id.clone(),
                            name: info.name.clone(),
                            encrypted: info.encrypted,
                            salt_b64,
                            creator_fingerprint: info.creator_fingerprint.clone(),
                            owner_fingerprints: app.handle.room_owners(&info.id),
                        })
                    } else {
                        None
                    }
                }
                _ => None,
            };

            let unsigned = huddle_core::invite::InviteLink {
                v: 1,
                host_multiaddr,
                fingerprint: our_fp,
                room: room.clone(),
                creator_pubkey_b64: None,
                signed_at_ms: 0,
                signature_b64: None,
            };
            // huddle 0.7.11: sign via AppHandle so the invite is bound
            // to the local Ed25519 identity. Falls back to v=1 only if
            // signing somehow fails — the receiver will then show the
            // "this invite is unsigned" warning.
            let invite = app.handle.sign_invite(unsigned.clone()).unwrap_or(unsigned);
            match huddle_core::invite::encode(&invite) {
                Ok(url) => {
                    app.modal = Modal::ShowInvite(ShowInviteState {
                        url,
                        includes_room: room.map(|r| r.name),
                    });
                }
                Err(e) => app.modal = Modal::Error(format!("encode invite: {e}")),
            }
            Ok(false)
        }
        Action::OpenPasteInvite => {
            app.modal = Modal::PasteInvite(PasteInviteState { url: String::new() });
            Ok(false)
        }
        Action::PasteInviteTypeChar(c) => {
            if let Modal::PasteInvite(s) = &mut app.modal {
                s.url.push(c);
            }
            Ok(false)
        }
        Action::PasteInviteBackspace => {
            if let Modal::PasteInvite(s) = &mut app.modal {
                s.url.pop();
            }
            Ok(false)
        }
        Action::PasteInviteConfirm => {
            let url = match &app.modal {
                Modal::PasteInvite(s) => s.url.clone(),
                _ => return Ok(false),
            };
            match huddle_core::invite::decode(url.trim()) {
                Ok(invite) => {
                    app.modal = Modal::ConfirmInvite(ConfirmInviteState { invite });
                }
                Err(e) => {
                    app.modal = Modal::Error(format!("bad invite link: {e}"));
                }
            }
            Ok(false)
        }
        Action::ConfirmInviteAccept => {
            let invite = match &app.modal {
                Modal::ConfirmInvite(s) => s.invite.clone(),
                _ => return Ok(false),
            };
            app.modal = Modal::None;
            // Dial via the invite-aware path. libp2p enforces the
            // embedded /p2p/<peer-id> check at the transport level
            // (structural MITM defense), AND once Identify lands the
            // app-layer post-dial arm compares the cryptographic fp
            // against `invite.fingerprint`, disconnecting on mismatch.
            // If a room was included, we open Join modal speculatively
            // — the joiner types the passphrase, and the actual
            // join_room call succeeds once the room announcement
            // arrives.
            match app
                .handle
                .dial_invite(&invite.host_multiaddr, &invite.fingerprint)
                .await
            {
                Ok(()) => app.set_status(format!("dialing {} via invite…", short_fp(&invite.fingerprint))),
                Err(e) => {
                    app.modal = Modal::Error(format!("dial failed: {e}"));
                    return Ok(false);
                }
            }
            if let Some(room) = invite.room {
                if room.encrypted {
                    app.modal = Modal::JoinRoom(JoinRoomState {
                        room_id: room.id.clone(),
                        room_name: room.name.clone(),
                        encrypted: true,
                        passphrase: String::new(),
                    });
                } else if let Err(e) = app.handle.join_room(&room.id, None).await {
                    app.modal = Modal::Error(format!("join failed: {e}"));
                }
            }
            Ok(false)
        }
        Action::OpenGenerateJoinCode => {
            let (room_id, room_name) = match app.active_room() {
                Some(r) => (r.room_id.clone(), r.name.clone()),
                None => return Ok(false),
            };
            match app.handle.generate_join_code(&room_id) {
                Ok(code) => {
                    app.modal = Modal::ShowJoinCode(ShowJoinCodeState {
                        room_id,
                        room_name,
                        code,
                    });
                }
                Err(e) => app.set_status(format!("can't generate code: {e}")),
            }
            Ok(false)
        }
        Action::OpenJoinWithCode => {
            // huddle 0.7: meaningful on a Group sidebar item or the
            // GroupDiscover row.
            let room = match &app.sidebar.selection {
                SidebarItem::Group(id) | SidebarItem::Dm(id) => app
                    .handle
                    .discovered_rooms()
                    .into_iter()
                    .find(|d| d.room_id == *id),
                _ => None,
            };
            let room = match room {
                Some(r) => r,
                None => {
                    app.set_status("select an encrypted group in the sidebar first");
                    return Ok(false);
                }
            };
            if !room.encrypted {
                app.set_status("code-join only applies to encrypted rooms");
                return Ok(false);
            }
            app.modal = Modal::JoinWithCode(JoinWithCodeState {
                room_id: room.room_id,
                room_name: room.name,
                code: String::new(),
            });
            Ok(false)
        }
        Action::JoinWithCodeTypeChar(c) => {
            if let Modal::JoinWithCode(s) = &mut app.modal {
                s.code.push(c);
            }
            Ok(false)
        }
        Action::JoinWithCodeBackspace => {
            if let Modal::JoinWithCode(s) = &mut app.modal {
                s.code.pop();
            }
            Ok(false)
        }
        Action::JoinWithCodeConfirm => {
            let (room_id, code) = match &app.modal {
                Modal::JoinWithCode(s) => (s.room_id.clone(), s.code.clone()),
                _ => return Ok(false),
            };
            if code.trim().is_empty() {
                return Ok(false);
            }
            app.modal = Modal::None;
            if let Err(e) = app.handle.join_room_with_code(&room_id, code.trim()).await {
                app.modal = Modal::Error(format!("code join failed: {e}"));
            } else {
                app.set_status("code submitted — waiting for owner (up to 30 s)");
            }
            Ok(false)
        }
        Action::SettingsTabNext => {
            app.settings_tab = app.settings_tab.next();
            Ok(false)
        }
        Action::SettingsTabPrev => {
            app.settings_tab = app.settings_tab.prev();
            Ok(false)
        }
        Action::SettingsTabSelect(tab) => {
            app.settings_tab = tab;
            Ok(false)
        }
        Action::SettingsToggleMdns => {
            let now_on = app.handle.mdns_enabled();
            if let Err(e) = app.handle.set_mdns_enabled(!now_on) {
                app.modal = Modal::Error(format!("save failed: {e}"));
                return Ok(false);
            }
            let new_state = !now_on;
            app.set_status(if new_state {
                "LAN discovery enabled — restart huddle to apply"
            } else {
                "LAN discovery disabled — restart huddle to apply"
            });
            Ok(false)
        }
        Action::SettingsToggleNotifications => {
            let now_on = app.handle.notifications_enabled();
            if let Err(e) = app.handle.set_notifications_enabled(!now_on) {
                app.modal = Modal::Error(format!("save failed: {e}"));
                return Ok(false);
            }
            app.set_status(if !now_on {
                "desktop notifications on (OS-local only)"
            } else {
                "desktop notifications off"
            });
            Ok(false)
        }
        Action::ProfileFieldUp => {
            if app.profile_cursor > 0 {
                app.profile_cursor -= 1;
            }
            Ok(false)
        }
        Action::ProfileFieldDown => {
            let max = profile_field_count(app).saturating_sub(1);
            if app.profile_cursor < max {
                app.profile_cursor += 1;
            }
            Ok(false)
        }
        Action::ProfileFieldYank => {
            let (label, value) = match profile_field_at(app, app.profile_cursor) {
                Some(v) => v,
                None => return Ok(false),
            };
            match crate::clipboard::copy(&value) {
                Ok(()) => app.set_status(format!("copied {} to clipboard", label)),
                Err(e) => app.set_status(format!("copy failed: {}", e)),
            }
            Ok(false)
        }
        Action::OpenEditUsername => {
            // Pre-fill the editor with the current username so the user
            // can tweak rather than retype. Empty submission clears.
            let current = app.handle.display_name().unwrap_or_default();
            app.modal = Modal::EditUsername(EditUsernameState { input: current });
            Ok(false)
        }
        Action::EditUsernameTypeChar(c) => {
            if let Modal::EditUsername(s) = &mut app.modal {
                if s.input.chars().count() < 32 {
                    s.input.push(c);
                }
            }
            Ok(false)
        }
        Action::EditUsernameBackspace => {
            if let Modal::EditUsername(s) = &mut app.modal {
                s.input.pop();
            }
            Ok(false)
        }
        Action::EditUsernameConfirm => {
            let input = match &app.modal {
                Modal::EditUsername(s) => s.input.clone(),
                _ => return Ok(false),
            };
            let trimmed = input.trim();
            let new_name = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
            app.modal = Modal::None;
            if let Err(e) = app.handle.set_username(new_name.as_deref()).await {
                app.modal = Modal::Error(format!("set username failed: {e}"));
            } else {
                app.set_status(match &new_name {
                    Some(n) => format!("username set to {n}"),
                    None => "username cleared — you are now [anonymous]".into(),
                });
            }
            Ok(false)
        }
        Action::OpenGoDarkModal => {
            app.modal = Modal::GoDark(GoDarkState {
                requires_passphrase: app.handle.has_master_passphrase(),
                ..GoDarkState::default()
            });
            Ok(false)
        }
        Action::OpenAddFriend => {
            app.modal = Modal::AddFriend(AddFriendState::default());
            Ok(false)
        }
        Action::AddFriendTypeChar(c) => {
            if let Modal::AddFriend(s) = &mut app.modal {
                if s.input.chars().count() < 64 {
                    s.input.push(c);
                }
            }
            Ok(false)
        }
        Action::AddFriendBackspace => {
            if let Modal::AddFriend(s) = &mut app.modal {
                s.input.pop();
            }
            Ok(false)
        }
        Action::AddFriendConfirm => {
            let input = match &app.modal {
                Modal::AddFriend(s) => s.input.clone(),
                _ => return Ok(false),
            };
            if input.trim().is_empty() {
                return Ok(false);
            }
            app.modal = Modal::None;
            match app.handle.dial_by_id_or_username(input.trim()).await {
                Ok(()) => {
                    // libp2p races every known address (LAN > public IP
                    // > relay-circuit). The status line says "dialing"
                    // generically — actual transport surfaces in the
                    // ListeningOn / connected-peer events afterwards.
                    app.set_status(format!("dialing {} (racing LAN / IP / relay)…", input.trim()));
                }
                Err(e) => {
                    app.modal = Modal::Error(format!("add friend: {e}"));
                }
            }
            Ok(false)
        }
        Action::GoDarkTypeChar(c) => {
            if let Modal::GoDark(s) = &mut app.modal {
                if s.input.chars().count() < 128 {
                    s.input.push(c);
                }
            }
            Ok(false)
        }
        Action::GoDarkBackspace => {
            if let Modal::GoDark(s) = &mut app.modal {
                s.input.pop();
            }
            Ok(false)
        }
        Action::GoDarkConfirm => {
            // Snapshot mode + input before touching the modal again.
            let (input, requires_passphrase) = match &app.modal {
                Modal::GoDark(s) => (s.input.clone(), s.requires_passphrase),
                _ => return Ok(false),
            };
            // huddle 0.7.6: single gate per session mode.
            //   master passphrase mode → passphrase IS the gate; `go_dark`
            //     does the constant-time check internally.
            //   --no-master-passphrase mode → typed `DELETE EVERYTHING`
            //     is the only gate (no key to compare against).
            if !requires_passphrase && input != GO_DARK_CONFIRM_PHRASE {
                if let Modal::GoDark(s) = &mut app.modal {
                    s.last_error = Some(format!(
                        "type `{}` exactly to confirm",
                        GO_DARK_CONFIRM_PHRASE
                    ));
                    s.input.clear();
                }
                return Ok(false);
            }
            // For passphrase mode, pass `input` as the passphrase.
            // For no-master mode, the passphrase argument is ignored
            // by `go_dark` (it short-circuits the check on a zeroed key).
            let passphrase_to_send = if requires_passphrase {
                input
            } else {
                String::new()
            };
            match app.handle.go_dark(&passphrase_to_send).await {
                Ok(()) => {
                    // WentDark event fires from go_dark; the handler
                    // schedules the actual exit so the goodbye modal
                    // is visible for a beat.
                    Ok(false)
                }
                Err(e) => {
                    if let Modal::GoDark(s) = &mut app.modal {
                        s.last_error = Some(format!("{e}"));
                        s.input.clear();
                    }
                    Ok(false)
                }
            }
        }
        Action::SettingsToggleGlobalVerifiedOnly => {
            // huddle 0.7.8: pane-driven toggle. The previous version
            // mutated a per-modal snapshot; the pane reads the live
            // value via `handle.verified_only_inbound()` every render
            // so we just flip and persist.
            let new_state = !app.handle.verified_only_inbound();
            if let Err(e) = app.handle.set_verified_only_inbound(new_state) {
                app.modal = Modal::Error(format!("save failed: {e}"));
                return Ok(false);
            }
            Ok(false)
        }
        Action::ClearBlockedPeers => {
            // Iterate the persisted blocklist and unblock each. We do
            // this in two phases (snapshot, then loop) so the SQLite
            // connection isn't borrowed across the unblock_peer calls.
            let blocked = app.handle.list_blocked_peers();
            let n = blocked.len();
            let mut errors = 0usize;
            for fp in blocked {
                if app.handle.unblock_peer(&fp).is_err() {
                    errors += 1;
                }
            }
            // huddle 0.7.8: the Settings pane reads the live blocklist
            // count on every render, so no snapshot needs updating here.
            let msg = if errors == 0 {
                format!("cleared {} blocked peer(s)", n)
            } else {
                format!(
                    "cleared {} blocked peer(s); {} error(s)",
                    n.saturating_sub(errors),
                    errors
                )
            };
            app.set_status(msg);
            // huddle 0.7.11: ClearBlockedPeers is now reached via the
            // ConfirmClearBlocked modal; close it on success.
            app.modal = Modal::None;
            Ok(false)
        }
        Action::ToggleRoomVerifiedOnly => {
            let room_id = match app.active_room() {
                Some(r) => r.room_id.clone(),
                None => return Ok(false),
            };
            let our_fp = app.handle.fingerprint().to_string();
            if !app.handle.is_owner(&room_id, &our_fp) {
                app.set_status("only an owner can toggle room verified-only");
                return Ok(false);
            }
            let new_state = !app.handle.room_verified_only(&room_id);
            if let Err(e) = app.handle.set_room_verified_only(&room_id, new_state) {
                app.modal = Modal::Error(format!("toggle failed: {e}"));
                return Ok(false);
            }
            app.set_status(if new_state {
                "room is now verified-only — non-SAS-verified joiners refused"
            } else {
                "room verified-only mode off"
            });
            Ok(false)
        }
        Action::VerifyStartSas => {
            // From the Verify modal: kick off an SAS exchange with the
            // focused member. Replaces the Verify modal with the SAS
            // in-progress modal (Waiting → Comparing on response).
            let (room_id, partner_fp) = match &app.modal {
                Modal::Verify(v) => match v.members.get(v.selected) {
                    Some((fp, _)) => (v.room_id.clone(), fp.clone()),
                    None => return Ok(false),
                },
                _ => return Ok(false),
            };
            match app.handle.sas_start(&room_id, &partner_fp).await {
                Ok(tx_id) => {
                    app.modal = Modal::Sas(SasState {
                        room_id,
                        partner_fingerprint: partner_fp,
                        tx_id,
                        stage: SasStage::Waiting,
                    });
                }
                Err(e) => app.modal = Modal::Error(format!("SAS start failed: {e}")),
            }
            Ok(false)
        }
        Action::SasMatch => {
            if let Modal::Sas(s) = &mut app.modal {
                let tx_id = s.tx_id.clone();
                if let SasStage::Comparing {
                    ref mut our_matched,
                    ..
                } = s.stage
                {
                    *our_matched = true;
                }
                if let Err(e) = app.handle.sas_match(&tx_id).await {
                    app.modal = Modal::Error(format!("SAS match failed: {e}"));
                    return Ok(false);
                }
                app.set_status("SAS match sent — waiting for partner to confirm");
            }
            Ok(false)
        }
        Action::SasCancel => {
            if let Modal::Sas(s) = &app.modal {
                app.handle.sas_cancel(&s.tx_id);
            }
            app.modal = Modal::None;
            Ok(false)
        }
        Action::OpenKickPicker => {
            let (room_id, members) = match owner_action_members(app, MemberActionKind::Kick) {
                Some(t) => t,
                None => return Ok(false),
            };
            app.modal = Modal::MemberAction(MemberActionState {
                room_id,
                kind: MemberActionKind::Kick,
                members,
                selected: 0,
            });
            Ok(false)
        }
        Action::OpenGrantPicker => {
            let (room_id, members) = match owner_action_members(app, MemberActionKind::Grant) {
                Some(t) => t,
                None => return Ok(false),
            };
            app.modal = Modal::MemberAction(MemberActionState {
                room_id,
                kind: MemberActionKind::Grant,
                members,
                selected: 0,
            });
            Ok(false)
        }
        Action::ShowRoomBans => {
            // Owners only. We use the same `we_are_owner` gate as
            // kick/grant so the keybinding is silently ignored for
            // non-owners (matching the rest of the moderation surface).
            let room_id = match app.active_room() {
                Some(r) => r.room_id.clone(),
                None => return Ok(false),
            };
            if !app.handle.we_are_owner(&room_id) {
                return Ok(false);
            }
            let bans = app.handle.list_room_bans(&room_id);
            let body = if bans.is_empty() {
                "no bans in this room.".to_string()
            } else {
                let mut s = format!("{} ban(s) in this room:\n\n", bans.len());
                for fp in &bans {
                    s.push_str(&format!("  {}\n", short_fp(fp)));
                }
                s.push_str("\nban is enforced by key rotation (the banned peer can no longer derive the room key). press any key to dismiss.");
                s
            };
            app.replace_modal_if_idle(Modal::Info(body));
            Ok(false)
        }
        Action::MemberActionNext => {
            if let Modal::MemberAction(s) = &mut app.modal {
                if s.selected + 1 < s.members.len() {
                    s.selected += 1;
                }
            }
            Ok(false)
        }
        Action::MemberActionPrev => {
            if let Modal::MemberAction(s) = &mut app.modal {
                if s.selected > 0 {
                    s.selected -= 1;
                }
            }
            Ok(false)
        }
        Action::MemberActionConfirm => {
            let snapshot = if let Modal::MemberAction(s) = &app.modal {
                s.members
                    .get(s.selected)
                    .map(|(fp, _)| (s.room_id.clone(), s.kind, fp.clone()))
            } else {
                None
            };
            let (room_id, kind, target_fp) = match snapshot {
                Some(t) => t,
                None => return Ok(false),
            };
            app.modal = Modal::None;
            match kind {
                MemberActionKind::Grant => {
                    match app.handle.grant_owner(&room_id, &target_fp).await {
                        Ok(()) => app.set_status(format!("granted owner to {}", short_fp(&target_fp))),
                        Err(e) => app.modal = Modal::Error(format!("grant failed: {e}")),
                    }
                }
                MemberActionKind::Kick => {
                    match app.handle.kick_member(&room_id, &target_fp).await {
                        Ok(new_pp) if new_pp.is_empty() => {
                            app.set_status(format!("kicked {}", short_fp(&target_fp)));
                        }
                        Ok(new_pp) => {
                            // Show the new passphrase prominently so the
                            // owner can copy + share OOB with remaining
                            // members. Modal::Info dismisses on any key.
                            app.modal = Modal::Info(format!(
                                "kicked {}. new passphrase (share OOB with remaining members):\n\n  {}",
                                short_fp(&target_fp),
                                new_pp
                            ));
                        }
                        Err(e) => app.modal = Modal::Error(format!("kick failed: {e}")),
                    }
                }
            }
            Ok(false)
        }
        Action::InboundDialAccept => {
            if let Modal::InboundDial(s) = app.modal.clone() {
                app.handle.accept_inbound(s.peer_id, &s.address).await;
                app.set_status(format!("connected to {}", short_fp(&s.fingerprint)));
                app.modal = Modal::None;
                app.refresh_known_peers();
            }
            Ok(false)
        }
        Action::InboundDialReject => {
            if let Modal::InboundDial(s) = app.modal.clone() {
                if let Err(e) = app.handle.reject_inbound(s.peer_id, &s.fingerprint).await {
                    app.modal = Modal::Error(format!("reject failed: {e}"));
                    return Ok(false);
                }
                app.set_status(format!("rejected {}", short_fp(&s.fingerprint)));
                app.modal = Modal::None;
            }
            Ok(false)
        }
        Action::InboundDialTrust => {
            if let Modal::InboundDial(s) = app.modal.clone() {
                if let Err(e) = app
                    .handle
                    .trust_inbound(s.peer_id, &s.fingerprint, &s.address)
                    .await
                {
                    app.modal = Modal::Error(format!("trust failed: {e}"));
                    return Ok(false);
                }
                app.set_status(format!("trusted {} — won't ask again", short_fp(&s.fingerprint)));
                app.modal = Modal::None;
                app.refresh_known_peers();
            }
            Ok(false)
        }
        Action::AttachPickerDescendOrPick => {
            let pick: Option<std::path::PathBuf> = match &mut app.modal {
                Modal::AttachPicker(s) => {
                    if let Some(e) = s.entries.get(s.selected) {
                        if e.is_dir {
                            s.descend();
                            None
                        } else {
                            s.selected_path()
                        }
                    } else {
                        None
                    }
                }
                _ => None,
            };
            if let Some(path) = pick {
                let room_id = match app.active_room() {
                    Some(r) => r.room_id.clone(),
                    None => return Ok(false),
                };
                app.modal = Modal::None;
                match app.handle.send_file(&room_id, &path).await {
                    Ok(file_id) => {
                        app.set_status(format!("sending {} ({})", path.display(), &file_id[..12]));
                    }
                    Err(e) => {
                        app.modal = Modal::Error(format!("send failed: {e}"));
                    }
                }
            }
            Ok(false)
        }
        // huddle 0.7 sidebar/pane helpers
        Action::SidebarSectionPrev => {
            sidebar_jump_section(app, -1);
            Ok(false)
        }
        Action::SidebarToggleExpand => {
            sidebar_toggle_expand(app);
            Ok(false)
        }
        Action::JumpToPeoplePane => {
            app.pane = Pane::People;
            app.sidebar.selection = SidebarItem::Section(SidebarSection::People);
            // huddle 0.7.7: pull fresh pending-request rows so the
            // section count is right + the cursor stays in range. If
            // there are pending requests, land on that tab — that's
            // where the user almost certainly wants to look first.
            app.refresh_pending_requests();
            if !app.pending_requests.is_empty() {
                app.people_focus = PeopleFocus::Pending;
                app.selected_pending_idx = 0;
            }
            Ok(false)
        }
        Action::JumpToSettingsPane => {
            app.pane = Pane::Settings;
            // huddle 0.7.8: reset to Account tab on jump so `,` from
            // anywhere lands on a predictable surface.
            app.settings_tab = SettingsTab::Account;
            app.sidebar.selection = SidebarItem::Section(SidebarSection::Settings);
            Ok(false)
        }
        Action::OpenComposeDm => {
            app.modal = Modal::ComposeDm(ComposeDmState::default());
            Ok(false)
        }
        Action::ComposeDmTypeChar(c) => {
            if let Modal::ComposeDm(s) = &mut app.modal {
                s.input.push(c);
            }
            Ok(false)
        }
        Action::ComposeDmBackspace => {
            if let Modal::ComposeDm(s) = &mut app.modal {
                s.input.pop();
            }
            Ok(false)
        }
        Action::ComposeDmCancel => {
            app.modal = Modal::None;
            Ok(false)
        }
        Action::ComposeDmConfirm => {
            let input = match &app.modal {
                Modal::ComposeDm(s) => s.input.trim().to_string(),
                _ => return Ok(false),
            };
            if input.is_empty() {
                return Ok(false);
            }
            // Resolve input to a fingerprint via lookup helpers, then
            // start the DM. On unresolvable input we morph to AddFriend.
            let resolved = resolve_dm_target(app, &input);
            match resolved {
                Some(fp) => {
                    app.modal = Modal::None;
                    match app.handle.start_direct(&fp).await {
                        Ok(room_id) => {
                            app.switch_to_room(&room_id);
                            app.set_status(format!("DM with {}", short_fp(&fp)));
                        }
                        Err(e) => app.modal = Modal::Error(format!("DM failed: {e}")),
                    }
                }
                None => {
                    // State C: unrecognized text → morph into AddFriend.
                    app.modal = Modal::AddFriend(AddFriendState { input });
                }
            }
            Ok(false)
        }
        Action::ToggleMemberMargin => {
            app.show_member_margin = !app.show_member_margin;
            Ok(false)
        }
        Action::OpenInvitePicker => {
            // Picker only makes sense inside a group room — the
            // generated invite has to scope to *some* room, and DMs
            // can't take a third member by design. From any other
            // pane (Welcome, Profile, People, Activity, Settings) we
            // surface a status hint and bail.
            let (room_id, room_name, is_group) = match app.active_room() {
                Some(r) => {
                    let info = app.handle.active_room_info(&r.room_id);
                    let is_group = info
                        .as_ref()
                        .map(|i| i.kind != huddle_core::storage::repo::RoomKind::Direct)
                        .unwrap_or(false);
                    (
                        r.room_id.clone(),
                        info.map(|i| i.name).unwrap_or_default(),
                        is_group,
                    )
                }
                None => {
                    app.set_status("open a group first — `Shift+I` for OOB or `s` to create");
                    return Ok(false);
                }
            };
            if !is_group {
                app.set_status("DMs are 1-1 by design — open a group to invite peers");
                return Ok(false);
            }
            let candidates = gather_invite_candidates(app, &room_id);
            if candidates.is_empty() {
                app.set_status(
                    "no peers to invite yet — verify someone with Ctrl+V or share `Shift+I` OOB",
                );
                return Ok(false);
            }
            app.modal = Modal::InvitePicker(InvitePickerState {
                room_id,
                room_name,
                candidates,
                selected: HashSet::new(),
                filter: String::new(),
                cursor: 0,
                status_line: None,
            });
            Ok(false)
        }
        Action::InvitePickerCancel => {
            app.modal = Modal::None;
            Ok(false)
        }
        Action::InvitePickerFilterTypeChar(c) => {
            if let Modal::InvitePicker(s) = &mut app.modal {
                s.filter.push(c);
                s.cursor = 0;
                s.status_line = None;
            }
            Ok(false)
        }
        Action::InvitePickerFilterBackspace => {
            if let Modal::InvitePicker(s) = &mut app.modal {
                s.filter.pop();
                s.cursor = 0;
                s.status_line = None;
            }
            Ok(false)
        }
        Action::InvitePickerCursorUp => {
            if let Modal::InvitePicker(s) = &mut app.modal {
                if s.cursor > 0 {
                    s.cursor -= 1;
                }
                s.status_line = None;
            }
            Ok(false)
        }
        Action::InvitePickerCursorDown => {
            if let Modal::InvitePicker(s) = &mut app.modal {
                let visible_len = filtered_invite_candidates(s).len();
                if s.cursor + 1 < visible_len {
                    s.cursor += 1;
                }
                s.status_line = None;
            }
            Ok(false)
        }
        Action::InvitePickerToggleSelected => {
            if let Modal::InvitePicker(s) = &mut app.modal {
                let visible = filtered_invite_candidates(s);
                if let Some(c) = visible.get(s.cursor).cloned() {
                    if s.selected.contains(&c.fingerprint) {
                        s.selected.remove(&c.fingerprint);
                        s.status_line = None;
                    } else if s.selected.len() >= INVITE_PICKER_SOFT_CAP {
                        s.status_line = Some(format!(
                            "selection cap: {} max per send",
                            INVITE_PICKER_SOFT_CAP
                        ));
                    } else {
                        s.selected.insert(c.fingerprint);
                        s.status_line = None;
                    }
                }
            }
            Ok(false)
        }
        Action::InvitePickerSend => {
            let (room_id, selected_fps) = match &app.modal {
                Modal::InvitePicker(s) => {
                    if s.selected.is_empty() {
                        if let Modal::InvitePicker(s2) = &mut app.modal {
                            s2.status_line = Some(
                                "Space to select peers · Enter sends · Esc cancels".into(),
                            );
                        }
                        return Ok(false);
                    }
                    (s.room_id.clone(), s.selected.iter().cloned().collect::<Vec<_>>())
                }
                _ => return Ok(false),
            };
            // Build the invite link exactly once — same code path as
            // `Shift+I` but scoped to the captured room. Failure here
            // is structural (no listen address yet) and shows an error.
            let invite_text = match build_room_invite_link(app, &room_id) {
                Ok(t) => t,
                Err(e) => {
                    if let Modal::InvitePicker(s) = &mut app.modal {
                        s.status_line = Some(format!("invite build failed: {e}"));
                    }
                    return Ok(false);
                }
            };
            let mut sent = 0usize;
            let mut failures: Vec<String> = Vec::new();
            for fp in &selected_fps {
                let dm_room_id = match app.handle.start_direct(fp).await {
                    Ok(rid) => rid,
                    Err(e) => {
                        failures.push(format!("{}: {}", short_fp(fp), e));
                        continue;
                    }
                };
                match app.handle.send_room_message(&dm_room_id, &invite_text).await {
                    Ok(()) => sent += 1,
                    Err(e) => failures.push(format!("{}: {}", short_fp(fp), e)),
                }
            }
            app.modal = Modal::None;
            if failures.is_empty() {
                app.set_status(format!("sent invite to {} peer(s)", sent));
            } else {
                app.set_status(format!(
                    "sent to {}; failed for {}",
                    sent,
                    failures.len()
                ));
                tracing::warn!(?failures, "invite-picker send had partial failures");
            }
            Ok(false)
        }
        Action::PeopleFocusNext => {
            // huddle 0.7.7: Pending joins the rotation. Skipped when
            // empty so the cycle doesn't land on an empty tab the
            // user can't act on. Known is always present (even with
            // zero peers, it shows the "no known peers" hint), so
            // it's the safe fallback at the end.
            app.refresh_pending_requests();
            let has_pending = !app.pending_requests.is_empty();
            app.people_focus = match app.people_focus {
                PeopleFocus::Pending => PeopleFocus::Known,
                PeopleFocus::Known => PeopleFocus::Verified,
                PeopleFocus::Verified => PeopleFocus::Blocked,
                PeopleFocus::Blocked => {
                    if has_pending {
                        PeopleFocus::Pending
                    } else {
                        PeopleFocus::Known
                    }
                }
            };
            Ok(false)
        }
        Action::PendingRequestUp => {
            if app.selected_pending_idx > 0 {
                app.selected_pending_idx -= 1;
            }
            Ok(false)
        }
        Action::PendingRequestDown => {
            if app.selected_pending_idx + 1 < app.pending_requests.len() {
                app.selected_pending_idx += 1;
            }
            Ok(false)
        }
        Action::PendingRequestAccept => {
            let fp = app
                .pending_requests
                .get(app.selected_pending_idx)
                .map(|r| r.fingerprint.clone());
            if let Some(fp) = fp {
                match app.handle.accept_pending_friend_request(&fp).await {
                    Ok(()) => {
                        app.set_status(format!("re-dialing {} …", short_fp(&fp)));
                    }
                    Err(e) => {
                        app.modal = Modal::Error(format!("accept failed: {e}"));
                    }
                }
                app.refresh_pending_requests();
                if app.pending_requests.is_empty() {
                    app.people_focus = PeopleFocus::Known;
                }
            }
            Ok(false)
        }
        Action::PendingRequestReject => {
            let fp = app
                .pending_requests
                .get(app.selected_pending_idx)
                .map(|r| r.fingerprint.clone());
            if let Some(fp) = fp {
                if let Err(e) = app.handle.reject_pending_friend_request(&fp) {
                    app.modal = Modal::Error(format!("reject failed: {e}"));
                } else {
                    app.set_status(format!("rejected + blocked {}", short_fp(&fp)));
                }
                app.refresh_pending_requests();
                if app.pending_requests.is_empty() {
                    app.people_focus = PeopleFocus::Known;
                }
            }
            Ok(false)
        }
        Action::PeoplePersonReconnect => {
            if let Some(p) = app.known_peers.get(app.selected_known_idx).cloned() {
                if let Err(e) = app.handle.redial(&p.address).await {
                    app.modal = Modal::Error(format!("dial failed: {e}"));
                }
            }
            Ok(false)
        }
        Action::PeoplePersonBlock => {
            if let Some(p) = app.known_peers.get(app.selected_known_idx).cloned() {
                // huddle 0.7.7: read from `fingerprint`, not `label`
                // (label is only set on add-by-id / username-resolved
                // peers; plain `d` dial peers leave it as None).
                if let Some(fp) = p.fingerprint.as_deref() {
                    let _ = app.handle.block_peer(fp);
                    app.set_status(format!("blocked {}", short_fp(fp)));
                } else {
                    app.set_status("can't block — fingerprint not learned yet (try after Identify)");
                }
            }
            Ok(false)
        }
        Action::PeoplePersonUnblock => {
            let blocked = app.handle.list_blocked_peers();
            if let Some(fp) = blocked.get(app.selected_blocked_idx).cloned() {
                let _ = app.handle.unblock_peer(&fp);
                app.set_status(format!("unblocked {}", short_fp(&fp)));
            }
            Ok(false)
        }
        Action::PeoplePersonForget => {
            if let Some(p) = app.known_peers.get(app.selected_known_idx).cloned() {
                let _ = app.handle.forget_peer(&p.address).await;
                app.refresh_known_peers();
            }
            Ok(false)
        }
        Action::PeoplePersonStartDm => {
            if let Some(p) = app.known_peers.get(app.selected_known_idx).cloned() {
                // huddle 0.7.7: use `fingerprint` (populated post-Identify
                // for every dialed peer). Previously this used `label`,
                // which is `None` for plain `d` dials — silently no-op'd.
                if let Some(fp) = p.fingerprint.clone() {
                    match app.handle.start_direct(&fp).await {
                        Ok(rid) => app.switch_to_room(&rid),
                        Err(e) => app.modal = Modal::Error(format!("DM failed: {e}")),
                    }
                } else {
                    app.set_status("can't DM yet — peer hasn't identified (try after they connect)");
                }
            }
            Ok(false)
        }
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
    let normalized = huddle_core::app::normalize_to_fingerprint(trimmed);
    if let Some(fp) = normalized {
        return Some(fp);
    }
    // Username lookup — peer_profiles cache keyed by username.
    for p in &app.known_peers {
        if let Some(label) = &p.label {
            if let Some(name) = app.handle.lookup_username(label) {
                if name.eq_ignore_ascii_case(trimmed) {
                    return Some(label.clone());
                }
            }
        }
    }
    None
}

/// Extract (room_id, file_id, status, encrypted) for the active room's
/// focused card. Returns None when no card is focused / available.
fn focused_card_info(
    app: &TuiApp,
) -> Option<(String, String, huddle_core::storage::repo::AttachmentStatus, bool)> {
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
pub fn gather_invite_candidates(
    app: &TuiApp,
    room_id: &str,
) -> Vec<InviteCandidate> {
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
            if partner == our_fp
                || in_room.contains(&partner)
                || blocked.contains(&partner)
            {
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
            short.starts_with(&needle) || needle.starts_with("hd-") && {
                let after = needle.trim_start_matches("hd-").to_lowercase();
                short.starts_with(&after)
            }
        })
        .cloned()
        .collect()
}

/// Build a room-scoped invite link the same way `Action::GenerateInvite`
/// does — but reusable so the InvitePicker can call it without
/// duplicating the listen-address / encode dance. Errors when we don't
/// have a listen address yet (transient startup state).
pub fn build_room_invite_link(app: &TuiApp, room_id: &str) -> anyhow::Result<String> {
    use anyhow::anyhow;
    let our_peer = app.handle.peer_id().to_string();
    let our_fp = app.handle.fingerprint().to_string();
    let listen = app
        .listen_addresses
        .first()
        .ok_or_else(|| anyhow!("no listen address yet — try again in a sec"))?
        .clone();
    let host_multiaddr = format!("{}/p2p/{}", listen, our_peer);

    let info = app
        .handle
        .active_room_info(room_id)
        .ok_or_else(|| anyhow!("room not active locally"))?;
    let salt_b64 = info.passphrase_salt.as_ref().map(|s| {
        base64::engine::general_purpose::STANDARD.encode(s)
    });
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
    };
    let invite = app
        .handle
        .sign_invite(unsigned.clone())
        .unwrap_or(unsigned);
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
    // Stale cache → fetch.
    let body = ureq::get("https://crates.io/api/v1/crates/huddle")
        .set("User-Agent", &format!("huddle/{}", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(10))
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
