use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{Modal, Pane, PeopleFocus, SettingsTab, SidebarFocus, SidebarItem, TuiApp};

#[derive(Debug)]
pub enum Action {
    Nothing,
    Quit,
    OpenQuitConfirm,
    CloseModal,
    OpenStartRoom,
    OpenHelp,
    // Lobby / Sidebar (huddle 0.7 — names retained for back-compat;
    // semantics rewritten to drive the new sidebar widget).
    LobbyNavigateUp,
    LobbyNavigateDown,
    LobbyJoinSelected,
    LobbyRefresh,
    LobbyFocusToggle,
    /// huddle 0.7.2: tmux-style focus jump. Ctrl+Left → sidebar,
    /// Ctrl+Right → pane. Single-stroke, works from any context
    /// (including while typing in chat input).
    FocusSidebar,
    FocusPane,
    LobbyReconnectPeer,
    LobbyForgetPeer,
    OpenDialPeer,
    // huddle 0.7: sidebar-specific helpers
    SidebarSectionPrev,
    SidebarToggleExpand,
    JumpToPeoplePane,
    JumpToSettingsPane,
    OpenComposeDm,
    ComposeDmTypeChar(char),
    ComposeDmBackspace,
    ComposeDmConfirm,
    ComposeDmCancel,
    ToggleMemberMargin,
    PeopleFocusNext,
    PeoplePersonReconnect,
    PeoplePersonBlock,
    PeoplePersonUnblock,
    PeoplePersonForget,
    PeoplePersonStartDm,
    /// huddle 0.7.7: pending-request row navigation + accept/reject.
    PendingRequestUp,
    PendingRequestDown,
    PendingRequestAccept,
    PendingRequestReject,
    /// huddle 0.7.7: InvitePicker actions.
    OpenInvitePicker,
    InvitePickerCursorUp,
    InvitePickerCursorDown,
    InvitePickerToggleSelected,
    InvitePickerFilterTypeChar(char),
    InvitePickerFilterBackspace,
    InvitePickerSend,
    InvitePickerCancel,
    // Start room modal
    StartRoomNextField,
    StartRoomToggleEncrypted,
    StartRoomTypeChar(char),
    StartRoomBackspace,
    StartRoomConfirm,
    // Join room modal
    JoinRoomTypeChar(char),
    JoinRoomBackspace,
    JoinRoomConfirm,
    // Dial peer modal
    DialPeerTypeChar(char),
    DialPeerBackspace,
    DialPeerConfirm,
    // In-room
    TabNext,
    TabPrev,
    TabSelect(usize),
    BackToLobby,
    LeaveRoom,
    FocusInput,
    BlurInput,
    ScrollUp,
    ScrollDown,
    PageUp,
    PageDown,
    JumpTop,
    JumpBottom,
    ChatTypeChar(char),
    ChatBackspace,
    ChatSend,
    ChatInsertNewline,
    // File cards
    ToggleCardFocus,
    CardNext,
    CardPrev,
    ActivateFocusedCard,
    OpenFocusedCard,
    CancelFocusedCard,
    SaveAgainFocusedCard,
    OpenAttachmentPicker,
    // Attach picker modal
    AttachPickerUp,
    AttachPickerDown,
    AttachPickerAscend,
    AttachPickerDescendOrPick,
    // Rotation
    OpenRotateRoom,
    RotateRoomTypeChar(char),
    RotateRoomBackspace,
    RotateRoomConfirm,
    AcceptRotationTypeChar(char),
    AcceptRotationBackspace,
    AcceptRotationConfirm,
    // Verify modal
    OpenVerify,
    VerifyNext,
    VerifyPrev,
    VerifyToggle,
    // Mute
    ToggleMute,
    // QR identity
    OpenQrIdentity,
    // Search
    OpenSearch,
    SearchTypeChar(char),
    SearchBackspace,
    SearchSubmit,
    SearchNext,
    SearchPrev,
    // Phase A: inbound-dial accept gate
    InboundDialAccept,
    InboundDialReject,
    InboundDialTrust,
    // Phase B: soft owner role
    OpenKickPicker,
    OpenGrantPicker,
    MemberActionNext,
    MemberActionPrev,
    MemberActionConfirm,
    /// Phase B follow-up: list bans for the current room (owners only).
    /// Bound to `^B` in the room view; renders an Info modal so it
    /// dismisses on any key.
    ShowRoomBans,
    /// Phase A follow-up: clear every globally-blocked peer. Bound to
    /// `c` in the Settings modal. Sledgehammer for now — finer-grained
    /// per-peer unblock is a future refinement.
    ClearBlockedPeers,
    /// huddle 0.7.11: opens the confirm modal for the "clear all blocked
    /// peers" action. Used to be the bare `c` direct-fire.
    OpenClearBlockedConfirm,
    // Phase G: SAS verification
    VerifyStartSas,
    SasMatch,
    SasCancel,
    // Phase E: verified-only-mode toggles
    SettingsToggleGlobalVerifiedOnly,
    ToggleRoomVerifiedOnly,
    /// huddle 0.7.8: Settings pane tab cycling.
    SettingsTabNext,
    SettingsTabPrev,
    SettingsTabSelect(SettingsTab),
    /// huddle 0.7.8: Settings → Network row toggle (restart-required).
    SettingsToggleMdns,
    /// huddle 0.7.8: Settings → Privacy row toggle.
    SettingsToggleNotifications,
    /// huddle 0.7.8: Profile pane row navigation + yank-to-clipboard.
    ProfileFieldUp,
    ProfileFieldDown,
    ProfileFieldYank,
    // huddle 0.5: optional self-declared username
    OpenEditUsername,
    EditUsernameTypeChar(char),
    EditUsernameBackspace,
    EditUsernameConfirm,
    // huddle 0.5: go-dark account deletion flow
    OpenGoDarkModal,
    GoDarkTypeChar(char),
    GoDarkBackspace,
    GoDarkConfirm,
    // huddle 0.5.1: add friend by HD ID or username
    OpenAddFriend,
    AddFriendTypeChar(char),
    AddFriendBackspace,
    AddFriendConfirm,
    // Phase F: short-lived join codes
    OpenGenerateJoinCode,
    OpenJoinWithCode,
    JoinWithCodeTypeChar(char),
    JoinWithCodeBackspace,
    JoinWithCodeConfirm,
    // Phase C: invite links
    GenerateInvite,
    OpenPasteInvite,
    PasteInviteTypeChar(char),
    PasteInviteBackspace,
    PasteInviteConfirm,
    ConfirmInviteAccept,
    // Phase H: first-launch onboarding card
    OnboardingNext,
    OnboardingPrev,
    OnboardingDismiss,
    // huddle 0.6: notification history overlay (Ctrl+H)
    OpenStatusHistory,
    StatusHistoryScrollUp,
    StatusHistoryScrollDown,
    StatusHistoryPageUp,
    StatusHistoryPageDown,
    ClearStatusHistory,
    // huddle 0.6: command palette (Ctrl+P) — fuzzy action search
    OpenCommandPalette,
    CommandPaletteTypeChar(char),
    CommandPaletteBackspace,
    CommandPaletteNext,
    CommandPalettePrev,
    CommandPaletteConfirm,
    // huddle 0.6: re-open onboarding / "what's new" card (Shift+?)
    OpenWhatsNew,
    // huddle 0.6: mark every room's unread counter back to 0 (R in lobby)
    MarkAllRead,
    // huddle 0.6: help screen scroll
    HelpScrollUp,
    HelpScrollDown,
    HelpPageUp,
    HelpPageDown,
    // huddle 0.6: update-check opt-in
    UpdateCheckOptInYes,
    UpdateCheckOptInNo,
    ToggleUpdateCheck,
    DismissUpdateBanner,
}

/// huddle 0.7.4: detect the "go dark" chord. Bare `!` (Shift+1) is too
/// easy to press accidentally — a single missed keystroke could nuke
/// the user's data — so the global trigger now requires the Option /
/// Alt modifier on top. Terminals report this combo in three shapes
/// depending on the Option-as-Meta setting; accept all of them:
///   * macOS default (Option sends a unicode glyph) → `Char('⁄')` (U+2044)
///   * Option-as-Meta / Linux / Windows Alt+Shift+1 → ALT [+SHIFT] + `!`
///   * some terminals report the bare digit → ALT + SHIFT + `1`
fn is_godark_chord(key: KeyEvent) -> bool {
    if matches!(key.code, KeyCode::Char('⁄')) {
        return true;
    }
    if key.modifiers.contains(KeyModifiers::ALT) {
        if matches!(key.code, KeyCode::Char('!')) {
            return true;
        }
        if key.modifiers.contains(KeyModifiers::SHIFT)
            && matches!(key.code, KeyCode::Char('1'))
        {
            return true;
        }
    }
    false
}

pub fn map_key(key: KeyEvent, app: &TuiApp) -> Action {
    // huddle 0.7.11: Ctrl+C used to unconditionally open QuitConfirm
    // (replacing whatever modal was open). Mid-typing a master
    // passphrase / GoDark confirmation / EditUsername / Onboarding,
    // an accidental Ctrl+C wiped the typed input. Now Ctrl+C only
    // opens the quit prompt when no modal is open; inside a modal it
    // falls through to that modal's own handler, where most modals
    // route Esc to a clean cancel anyway.
    if key.modifiers.contains(KeyModifiers::CONTROL)
        && key.code == KeyCode::Char('c')
        && matches!(app.modal, Modal::None)
    {
        return Action::OpenQuitConfirm;
    }

    // huddle 0.6: global hotkeys that fire regardless of current
    // screen, as long as no modal is open (modal-internal Ctrl chords
    // would conflict otherwise). Ctrl+P = command palette,
    // Ctrl+H = status history, Shift+? = re-open onboarding.
    if matches!(app.modal, Modal::None) {
        // huddle 0.7.11: Shift+? (or bare `?` in a non-typing context)
        // re-opens the "what's new" card. Pre-0.7.11 the cheat sheet
        // advertised this but no handler dispatched it.
        if matches!(key.code, KeyCode::Char('?'))
            && !matches!(app.pane, Pane::Dm(_) | Pane::Group(_))
        {
            // Only when no chat-input is taking the keystroke. In chat
            // panes, `?` still goes to the input handler via the
            // existing in-room logic; from sidebar/Welcome/Profile/
            // People/Activity/Settings, `?` opens the help, and
            // Shift+? opens what's-new. Decide based on the SHIFT
            // modifier when present.
            if key.modifiers.contains(KeyModifiers::SHIFT) {
                return Action::OpenWhatsNew;
            }
        }
        // huddle 0.7.3: Shift+Left / Shift+Right = focus jump between
        // sidebar and pane. Swapped from Ctrl+arrows in 0.7.2 because
        // macOS claims Ctrl+arrows for Mission Control Space-switching
        // and Cmd+arrows for Terminal/iTerm2 tab-switching. Shift+arrows
        // are unclaimed at OS and terminal levels on all three platforms.
        if key.modifiers.contains(KeyModifiers::SHIFT) {
            match key.code {
                KeyCode::Left => return Action::FocusSidebar,
                KeyCode::Right => return Action::FocusPane,
                _ => {}
            }
        }
        // huddle 0.7.4: Option+Shift+1 (Alt+Shift+!) — open Go Dark.
        // See `is_godark_chord` for why this replaced the bare `!`.
        if is_godark_chord(key) {
            return Action::OpenGoDarkModal;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            // Ctrl+H — note: crossterm sometimes delivers this as
            // KeyCode::Backspace on certain terminals because of the
            // ASCII collision. We accept both.
            if matches!(key.code, KeyCode::Char('h') | KeyCode::Char('H')) {
                let input_active = app
                    .active_room()
                    .map(|r| r.input_active)
                    .unwrap_or(false);
                // Suppress when the user is typing — Ctrl+H = Backspace
                // on POSIX terminals and we don't want to eat it.
                if !input_active {
                    return Action::OpenStatusHistory;
                }
            }
            if matches!(key.code, KeyCode::Char('p') | KeyCode::Char('P')) {
                // Ctrl+P is bound to TabPrev inside a room; only override
                // when room input is NOT active so the palette is reachable.
                let input_active = app
                    .active_room()
                    .map(|r| r.input_active)
                    .unwrap_or(false);
                let in_room = matches!(app.pane, Pane::Dm(_) | Pane::Group(_));
                if !(in_room && input_active) {
                    return Action::OpenCommandPalette;
                }
            }
        }
    }

    match &app.modal {
        Modal::QuitConfirm => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => Action::Quit,
            _ => Action::CloseModal,
        },
        Modal::ConfirmClearBlocked => match key.code {
            // Explicit confirm: y / Y / Enter actually clears.
            // Anything else (Esc, n, q, any letter) safely cancels —
            // matches the QuitConfirm shape so users with muscle memory
            // for that pattern aren't surprised.
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                Action::ClearBlockedPeers
            }
            _ => Action::CloseModal,
        },
        Modal::Error(_) => match key.code {
            _ => Action::CloseModal,
        },
        Modal::Help => match key.code {
            KeyCode::Char('j') | KeyCode::Down => Action::HelpScrollDown,
            KeyCode::Char('k') | KeyCode::Up => Action::HelpScrollUp,
            KeyCode::PageDown => Action::HelpPageDown,
            KeyCode::PageUp => Action::HelpPageUp,
            // huddle 0.7.11: require an explicit Esc/Enter/q to close.
            // Pre-0.7.11 *any* key dismissed the modal — reflexive
            // vim-`h` (back), `?` (re-show), or just typing while
            // scanning the list silently nuked the help screen.
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => Action::CloseModal,
            _ => Action::Nothing,
        },
        Modal::StartRoom(_) => match key.code {
            KeyCode::Esc => Action::CloseModal,
            KeyCode::Tab => Action::StartRoomNextField,
            KeyCode::Enter => {
                // On Encrypted field: Enter toggles; otherwise confirms.
                if let Modal::StartRoom(s) = &app.modal {
                    if matches!(s.focus, crate::app::StartField::Encrypted) {
                        return Action::StartRoomToggleEncrypted;
                    }
                }
                Action::StartRoomConfirm
            }
            KeyCode::Char(' ') => {
                if let Modal::StartRoom(s) = &app.modal {
                    if matches!(s.focus, crate::app::StartField::Encrypted) {
                        return Action::StartRoomToggleEncrypted;
                    }
                }
                Action::StartRoomTypeChar(' ')
            }
            KeyCode::Backspace => Action::StartRoomBackspace,
            KeyCode::Char(c) => Action::StartRoomTypeChar(c),
            _ => Action::Nothing,
        },
        Modal::JoinRoom(_) => match key.code {
            KeyCode::Esc => Action::CloseModal,
            KeyCode::Enter => Action::JoinRoomConfirm,
            KeyCode::Backspace => Action::JoinRoomBackspace,
            KeyCode::Char(c) => Action::JoinRoomTypeChar(c),
            _ => Action::Nothing,
        },
        Modal::DialPeer(_) => match key.code {
            KeyCode::Esc => Action::CloseModal,
            KeyCode::Enter => Action::DialPeerConfirm,
            KeyCode::Backspace => Action::DialPeerBackspace,
            KeyCode::Char(c) => Action::DialPeerTypeChar(c),
            _ => Action::Nothing,
        },
        Modal::AttachPicker(_) => match key.code {
            KeyCode::Esc => Action::CloseModal,
            KeyCode::Char('j') | KeyCode::Down => Action::AttachPickerDown,
            KeyCode::Char('k') | KeyCode::Up => Action::AttachPickerUp,
            // huddle 0.7.11: bare `h` no longer ascends — too easy to
            // hit by mistake when scanning a deep directory tree. Use
            // Backspace or Left for ascend, which match the vim/file-
            // browser convention without the typo hazard.
            KeyCode::Backspace | KeyCode::Left => Action::AttachPickerAscend,
            KeyCode::Enter | KeyCode::Right => Action::AttachPickerDescendOrPick,
            _ => Action::Nothing,
        },
        Modal::RotateRoom(_) => match key.code {
            KeyCode::Esc => Action::CloseModal,
            KeyCode::Enter => Action::RotateRoomConfirm,
            KeyCode::Backspace => Action::RotateRoomBackspace,
            KeyCode::Char(c) => Action::RotateRoomTypeChar(c),
            _ => Action::Nothing,
        },
        Modal::AcceptRotation(_) => match key.code {
            KeyCode::Esc => Action::CloseModal,
            KeyCode::Enter => Action::AcceptRotationConfirm,
            KeyCode::Backspace => Action::AcceptRotationBackspace,
            KeyCode::Char(c) => Action::AcceptRotationTypeChar(c),
            _ => Action::Nothing,
        },
        Modal::Verify(_) => match key.code {
            // huddle 0.7.11: bare `q` removed — accidentally typing `q`
            // while reading a member list aloud (q/quill/queue) used
            // to dismiss the modal. Esc still closes.
            KeyCode::Esc => Action::CloseModal,
            KeyCode::Char('j') | KeyCode::Down => Action::VerifyNext,
            KeyCode::Char('k') | KeyCode::Up => Action::VerifyPrev,
            KeyCode::Enter | KeyCode::Char(' ') => Action::VerifyToggle,
            KeyCode::Char('s') => Action::VerifyStartSas,
            _ => Action::Nothing,
        },
        Modal::Sas(_) => match key.code {
            // huddle 0.7.11: bare `c` and `q` removed from the cancel
            // chord set — they used to fire when the user spoke the
            // emoji-words "cat" / "queen" aloud during OOB comparison.
            // Esc remains the explicit cancel; Ctrl+C also reaches
            // here (which we route to the same SasCancel action via
            // the modal-aware Ctrl+C fallthrough at the top of
            // map_key).
            KeyCode::Esc => Action::SasCancel,
            KeyCode::Char('m') | KeyCode::Enter => Action::SasMatch,
            _ => Action::Nothing,
        },
        Modal::EditUsername(_) => match key.code {
            KeyCode::Esc => Action::CloseModal,
            KeyCode::Enter => Action::EditUsernameConfirm,
            KeyCode::Backspace => Action::EditUsernameBackspace,
            KeyCode::Char(c) => Action::EditUsernameTypeChar(c),
            _ => Action::Nothing,
        },
        Modal::GoDark(_) => match key.code {
            KeyCode::Esc => Action::CloseModal,
            KeyCode::Enter => Action::GoDarkConfirm,
            KeyCode::Backspace => Action::GoDarkBackspace,
            KeyCode::Char(c) => Action::GoDarkTypeChar(c),
            _ => Action::Nothing,
        },
        Modal::AddFriend(_) => match key.code {
            KeyCode::Esc => Action::CloseModal,
            KeyCode::Enter => Action::AddFriendConfirm,
            KeyCode::Backspace => Action::AddFriendBackspace,
            KeyCode::Char(c) => Action::AddFriendTypeChar(c),
            _ => Action::Nothing,
        },
        Modal::ShowJoinCode(_) => match key.code {
            // huddle 0.7.11: Esc/Enter/q only. Pre-0.7.11 any key
            // dismissed the join-code modal — accidental typo
            // discarded a code the owner was about to share OOB.
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => Action::CloseModal,
            _ => Action::Nothing,
        },
        Modal::JoinWithCode(_) => match key.code {
            KeyCode::Esc => Action::CloseModal,
            KeyCode::Enter => Action::JoinWithCodeConfirm,
            KeyCode::Backspace => Action::JoinWithCodeBackspace,
            KeyCode::Char(c) => Action::JoinWithCodeTypeChar(c),
            _ => Action::Nothing,
        },
        Modal::ShowInvite(_) => match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => Action::CloseModal,
            _ => Action::Nothing,
        },
        Modal::PasteInvite(_) => match key.code {
            KeyCode::Esc => Action::CloseModal,
            KeyCode::Enter => Action::PasteInviteConfirm,
            KeyCode::Backspace => Action::PasteInviteBackspace,
            KeyCode::Char(c) => Action::PasteInviteTypeChar(c),
            _ => Action::Nothing,
        },
        Modal::ConfirmInvite(_) => match key.code {
            KeyCode::Esc | KeyCode::Char('c') | KeyCode::Char('C') => Action::CloseModal,
            KeyCode::Enter | KeyCode::Char('d') | KeyCode::Char('D') => {
                Action::ConfirmInviteAccept
            }
            _ => Action::Nothing,
        },
        Modal::Onboarding { .. } => match key.code {
            // Esc dismisses early; the user can re-read it via Shift+?
            // or from Settings. We still bump last_seen so it doesn't
            // re-pop next launch on this version.
            KeyCode::Esc | KeyCode::Char('q') => Action::OnboardingDismiss,
            KeyCode::Char('h') | KeyCode::Left | KeyCode::Backspace => Action::OnboardingPrev,
            KeyCode::Enter
            | KeyCode::Char(' ')
            | KeyCode::Char('l')
            | KeyCode::Right
            | KeyCode::Tab => Action::OnboardingNext,
            _ => Action::Nothing,
        },
        Modal::StatusHistory { .. } => match key.code {
            KeyCode::Esc | KeyCode::Char('q') => Action::CloseModal,
            KeyCode::Char('j') | KeyCode::Down => Action::StatusHistoryScrollDown,
            KeyCode::Char('k') | KeyCode::Up => Action::StatusHistoryScrollUp,
            KeyCode::PageDown => Action::StatusHistoryPageDown,
            KeyCode::PageUp => Action::StatusHistoryPageUp,
            KeyCode::Char('c') | KeyCode::Char('C') => Action::ClearStatusHistory,
            KeyCode::Char('G') | KeyCode::End => Action::StatusHistoryPageDown,
            KeyCode::Char('g') | KeyCode::Home => Action::StatusHistoryPageUp,
            _ => Action::Nothing,
        },
        Modal::CommandPalette(_) => match key.code {
            KeyCode::Esc => Action::CloseModal,
            KeyCode::Enter => Action::CommandPaletteConfirm,
            KeyCode::Down => Action::CommandPaletteNext,
            KeyCode::Up => Action::CommandPalettePrev,
            // huddle 0.7.11: Ctrl+N / Ctrl+P navigate inside the palette
            // (Emacs/readline convention). Pre-0.7.11 these inserted
            // literal `n` / `p` into the filter because the Char(c)
            // catch-all didn't check modifiers.
            KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                Action::CommandPaletteNext
            }
            KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                Action::CommandPalettePrev
            }
            KeyCode::Backspace => Action::CommandPaletteBackspace,
            // Other Ctrl chords inside the palette should not be typed
            // into the filter as plain characters. Drop them silently
            // so the user's muscle memory for Ctrl+H / Ctrl+P outside
            // the palette doesn't corrupt their search query.
            KeyCode::Char(_) if key.modifiers.contains(KeyModifiers::CONTROL) => {
                Action::Nothing
            }
            KeyCode::Char(c) => Action::CommandPaletteTypeChar(c),
            _ => Action::Nothing,
        },
        Modal::UpdateCheckOptIn => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                Action::UpdateCheckOptInYes
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => Action::UpdateCheckOptInNo,
            _ => Action::Nothing,
        },
        Modal::Search(_) => match key.code {
            KeyCode::Esc => Action::CloseModal,
            KeyCode::Enter => Action::SearchSubmit,
            KeyCode::Down => Action::SearchNext,
            KeyCode::Up => Action::SearchPrev,
            KeyCode::Backspace => Action::SearchBackspace,
            KeyCode::Char(c) => Action::SearchTypeChar(c),
            _ => Action::Nothing,
        },
        Modal::Info(_) => match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => Action::CloseModal,
            _ => Action::Nothing,
        },
        Modal::QrIdentity => match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => Action::CloseModal,
            _ => Action::Nothing,
        },
        Modal::InboundDial(_) => match key.code {
            // Esc = reject. Anything more permissive would defeat the
            // gate — we always require a positive decision.
            KeyCode::Esc | KeyCode::Char('r') | KeyCode::Char('R') => Action::InboundDialReject,
            KeyCode::Char('a') | KeyCode::Char('A') | KeyCode::Enter => Action::InboundDialAccept,
            KeyCode::Char('t') | KeyCode::Char('T') => Action::InboundDialTrust,
            _ => Action::Nothing,
        },
        Modal::MemberAction(_) => match key.code {
            KeyCode::Esc | KeyCode::Char('q') => Action::CloseModal,
            KeyCode::Char('j') | KeyCode::Down => Action::MemberActionNext,
            KeyCode::Char('k') | KeyCode::Up => Action::MemberActionPrev,
            KeyCode::Enter => Action::MemberActionConfirm,
            _ => Action::Nothing,
        },
        Modal::ComposeDm(_) => match key.code {
            KeyCode::Esc => Action::ComposeDmCancel,
            KeyCode::Enter => Action::ComposeDmConfirm,
            KeyCode::Backspace => Action::ComposeDmBackspace,
            KeyCode::Char(c) => Action::ComposeDmTypeChar(c),
            _ => Action::Nothing,
        },
        Modal::InvitePicker(_) => match key.code {
            KeyCode::Esc => Action::InvitePickerCancel,
            KeyCode::Enter => Action::InvitePickerSend,
            KeyCode::Up | KeyCode::Char('k') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                Action::InvitePickerCursorUp
            }
            KeyCode::Down | KeyCode::Char('j') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                Action::InvitePickerCursorDown
            }
            KeyCode::Up => Action::InvitePickerCursorUp,
            KeyCode::Down => Action::InvitePickerCursorDown,
            KeyCode::Char(' ') => Action::InvitePickerToggleSelected,
            KeyCode::Backspace => Action::InvitePickerFilterBackspace,
            KeyCode::Char(c) => Action::InvitePickerFilterTypeChar(c),
            _ => Action::Nothing,
        },
        Modal::None => map_normal(key, app),
    }
}

fn map_normal(key: KeyEvent, app: &TuiApp) -> Action {
    // huddle 0.7: when the sidebar has focus OR we're on a non-chat pane,
    // we use sidebar navigation. Chat panes (DM/Group) with `pane` focus
    // route through `map_in_room`.
    let sidebar_has_focus = matches!(app.sidebar.focus, SidebarFocus::Sidebar);
    let chat_pane = matches!(app.pane, Pane::Dm(_) | Pane::Group(_));
    if !chat_pane || sidebar_has_focus {
        map_sidebar(key, app)
    } else {
        map_in_room(key, app)
    }
}

fn map_sidebar(key: KeyEvent, app: &TuiApp) -> Action {
    // huddle 0.7.8: Settings is now a tabbed pane. Tab/Shift+Tab cycle
    // the tabs; 1-4 jump directly. Upper-case row chords toggle the
    // setting on that row regardless of which tab is currently visible
    // (consistent muscle memory across tabs).
    if matches!(app.pane, Pane::Settings) {
        match key.code {
            KeyCode::Char('V') => return Action::SettingsToggleGlobalVerifiedOnly,
            KeyCode::Char('U') => return Action::ToggleUpdateCheck,
            KeyCode::Char('E') => return Action::OpenEditUsername,
            KeyCode::Char('W') => return Action::OpenWhatsNew,
            KeyCode::Char('M') => return Action::SettingsToggleMdns,
            KeyCode::Char('N') => return Action::SettingsToggleNotifications,
            // huddle 0.7.8: lowercase `c` in Settings → Privacy clears
            // every blocked peer at once. Only fires from the Privacy
            // tab so a stray `c` on Account/Network/Appearance can't
            // wipe the blocklist by accident.
            KeyCode::Char('c') if matches!(app.settings_tab, SettingsTab::Privacy) => {
                // huddle 0.7.11: opens a confirm modal first. Bare `c`
                // used to dispatch ClearBlockedPeers directly, which
                // was one keystroke from total blocklist loss and
                // shadowed the lobby's `c` = "join with code" binding.
                return Action::OpenClearBlockedConfirm;
            }
            // huddle 0.7.11: digits 1-4 require pane focus, same as
            // Tab/BackTab. Pre-0.7.11 the digits worked from sidebar
            // focus, which was inconsistent with Tab (sidebar focus →
            // sidebar/pane toggle) and let a stray digit jump tabs
            // while the user was navigating sections.
            KeyCode::Char('1') if matches!(app.sidebar.focus, SidebarFocus::Pane) => {
                return Action::SettingsTabSelect(SettingsTab::Account);
            }
            KeyCode::Char('2') if matches!(app.sidebar.focus, SidebarFocus::Pane) => {
                return Action::SettingsTabSelect(SettingsTab::Network);
            }
            KeyCode::Char('3') if matches!(app.sidebar.focus, SidebarFocus::Pane) => {
                return Action::SettingsTabSelect(SettingsTab::Appearance);
            }
            KeyCode::Char('4') if matches!(app.sidebar.focus, SidebarFocus::Pane) => {
                return Action::SettingsTabSelect(SettingsTab::Privacy);
            }
            // huddle 0.7.9: Tab/BackTab cycle Settings tabs ONLY when
            // the pane is focused. With the sidebar focused, Tab keeps
            // its universal "toggle sidebar↔pane focus" meaning so the
            // user can still move into the pane from the sidebar via
            // a single Tab keystroke. (0.7.8 swallowed Tab here
            // regardless of focus, which broke that gesture.)
            KeyCode::Tab if matches!(app.sidebar.focus, SidebarFocus::Pane) => {
                return Action::SettingsTabNext;
            }
            KeyCode::BackTab if matches!(app.sidebar.focus, SidebarFocus::Pane) => {
                return Action::SettingsTabPrev;
            }
            _ => {}
        }
    }
    // Profile pane row navigation + yank — gated on pane focus so j/k
    // can't trap the sidebar when `sync_pane_from_selection` live-
    // previews Profile while the user is still scrolling the sidebar.
    // 0.7.9 dropped the gate citing People's pattern, but People only
    // captures j/k inside the Pending sub-tab (reachable after Tab'ing
    // into the pane). Profile auto-switches the pane on sidebar
    // selection, so ungated j/k made further sidebar nav impossible.
    if matches!(app.pane, Pane::Profile)
        && matches!(app.sidebar.focus, SidebarFocus::Pane)
    {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => return Action::ProfileFieldDown,
            KeyCode::Char('k') | KeyCode::Up => return Action::ProfileFieldUp,
            KeyCode::Char('y') => return Action::ProfileFieldYank,
            _ => {}
        }
    }
    // E / Q stay reachable from either focus — capitalized chords don't
    // conflict with sidebar navigation, and being able to fire them
    // without first Tab'ing into the pane keeps the discovery flow short.
    if matches!(app.pane, Pane::Profile) {
        match key.code {
            KeyCode::Char('E') => return Action::OpenEditUsername,
            KeyCode::Char('Q') => return Action::OpenQrIdentity,
            _ => {}
        }
    }
    // huddle 0.7.11: Activity pane `c` clears the status-history list.
    // Pre-0.7.11 the pane's hint advertised this but no pane-level
    // handler was wired, so `c` fell through to the lobby's
    // OpenJoinWithCode binding — hint contradicted behavior.
    if matches!(app.pane, Pane::Activity) {
        if let KeyCode::Char('c') = key.code {
            return Action::ClearStatusHistory;
        }
    }
    // huddle 0.7.11: Alt+M toggles the member margin in a Group pane.
    // Pre-0.7.11 the help screen and hint bar both advertised Ctrl+I
    // for this, but Ctrl+I == Tab in every terminal we care about, so
    // ToggleMemberMargin was unreachable. Alt+M is unclaimed by macOS
    // Terminal / iTerm2 / kitty / alacritty / wezterm by default.
    if key.modifiers.contains(KeyModifiers::ALT)
        && matches!(key.code, KeyCode::Char('m') | KeyCode::Char('M'))
        && matches!(app.pane, Pane::Group(_))
    {
        return Action::ToggleMemberMargin;
    }
    // huddle 0.7.7: People-pane row bindings. The pane header advertises
    // `m message · r reconnect · b block · u unblock · x forget`, but
    // those keystrokes previously hit the *global* handlers (e.g. `m`
    // opened an empty Compose-DM modal). When a Known-peers row is
    // focused, route them to the selection-aware actions.
    if matches!(app.pane, Pane::People) && app.people_focus == PeopleFocus::Known {
        match key.code {
            KeyCode::Char('m') => return Action::PeoplePersonStartDm,
            KeyCode::Char('r') => return Action::PeoplePersonReconnect,
            KeyCode::Char('b') => return Action::PeoplePersonBlock,
            KeyCode::Char('x') => return Action::PeoplePersonForget,
            _ => {}
        }
    }
    if matches!(app.pane, Pane::People) && app.people_focus == PeopleFocus::Blocked {
        if let KeyCode::Char('u') = key.code {
            return Action::PeoplePersonUnblock;
        }
    }
    // huddle 0.7.7: Pending-requests sublist bindings. `a` Accept (re-
    // dial + trust), `r` Reject (delete + block). Up/Down move the
    // cursor. `a` overlaps the global "add friend" letter — Pane::People
    // + Pending focus disambiguates so the row action wins here only.
    if matches!(app.pane, Pane::People) && app.people_focus == PeopleFocus::Pending {
        match key.code {
            KeyCode::Char('a') | KeyCode::Enter => return Action::PendingRequestAccept,
            KeyCode::Char('r') => return Action::PendingRequestReject,
            KeyCode::Char('j') | KeyCode::Down => return Action::PendingRequestDown,
            KeyCode::Char('k') | KeyCode::Up => return Action::PendingRequestUp,
            _ => {}
        }
    }
    // huddle 0.7.7: Tab inside the People pane cycles the sub-tab
    // (Pending / Known / Verified / Blocked) — the pane header
    // advertises "Tab switches lists" but the action was never
    // wired up. Keeps sidebar-section Tab working everywhere else.
    if matches!(app.pane, Pane::People) && key.code == KeyCode::Tab {
        return Action::PeopleFocusNext;
    }
    // Cross-pane shortcuts — work anywhere the sidebar has focus,
    // including from Welcome/People/Activity/Settings panes. Go Dark
    // lives on the Option+Shift+1 chord (handled globally in
    // `map_key`); a bare `!` here would fire too easily by accident.
    match key.code {
        KeyCode::Char('q') => return Action::OpenQuitConfirm,
        KeyCode::Char('s') | KeyCode::Char('g') => return Action::OpenStartRoom,
        KeyCode::Char('m') => return Action::OpenComposeDm,
        KeyCode::Char('?') => return Action::OpenHelp,
        KeyCode::Char(':') => return Action::OpenCommandPalette,
        KeyCode::Char('a') => return Action::OpenAddFriend,
        KeyCode::Char('d') => return Action::OpenDialPeer,
        KeyCode::Char('i') => return Action::OpenQrIdentity,
        KeyCode::Char(',') => return Action::JumpToSettingsPane,
        KeyCode::Char('p') => return Action::JumpToPeoplePane,
        KeyCode::Char('c') => return Action::OpenJoinWithCode,
        KeyCode::Char('I') => return Action::GenerateInvite,
        KeyCode::Char('v') => return Action::OpenPasteInvite,
        KeyCode::Char('R') => return Action::MarkAllRead,
        _ => {}
    }
    match key.code {
        KeyCode::Tab => Action::LobbyFocusToggle,
        KeyCode::BackTab => Action::SidebarSectionPrev,
        KeyCode::Char('j') | KeyCode::Down => Action::LobbyNavigateDown,
        KeyCode::Char('k') | KeyCode::Up => Action::LobbyNavigateUp,
        KeyCode::Char(' ') | KeyCode::Right | KeyCode::Left => Action::SidebarToggleExpand,
        KeyCode::Char('r') => {
            // Context-sensitive: on a Person, reconnect. On a section
            // header or any item, refresh discovered rooms + peers.
            match &app.sidebar.selection {
                SidebarItem::Person(_) => Action::LobbyReconnectPeer,
                _ => Action::LobbyRefresh,
            }
        }
        KeyCode::Char('x') => match &app.sidebar.selection {
            SidebarItem::Person(_) => Action::LobbyForgetPeer,
            _ => Action::Nothing,
        },
        KeyCode::Enter => Action::LobbyJoinSelected,
        KeyCode::Esc => Action::Nothing,
        _ => Action::Nothing,
    }
}

fn map_in_room(key: KeyEvent, app: &TuiApp) -> Action {
    let input_active = app.active_room().map(|r| r.input_active).unwrap_or(false);

    let card_focus = app.active_room().map(|r| r.card_focus).unwrap_or(false);

    // Ctrl chords first (apply regardless of input focus).
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return match key.code {
            // ^J inserts a newline in the input (the canonical
            // multiline trick; works on every terminal).
            KeyCode::Char('j') if input_active => Action::ChatInsertNewline,
            KeyCode::Char('l') => Action::LeaveRoom,
            KeyCode::Char('b') => Action::BackToLobby,
            KeyCode::Char('n') => Action::TabNext,
            KeyCode::Char('p') => Action::TabPrev,
            KeyCode::Char('a') if !input_active => Action::OpenAttachmentPicker,
            KeyCode::Char('r') if !input_active => Action::OpenRotateRoom,
            KeyCode::Char('v') if !input_active => Action::OpenVerify,
            KeyCode::Char('f') if !input_active => Action::OpenSearch,
            KeyCode::Char('m') if !input_active => Action::ToggleMute,
            KeyCode::Char('k') if !input_active => Action::OpenKickPicker,
            KeyCode::Char('g') if !input_active => Action::OpenGrantPicker,
            KeyCode::Char('o') if !input_active => Action::ToggleRoomVerifiedOnly,
            KeyCode::Char('j') if !input_active => Action::OpenGenerateJoinCode,
            _ => Action::Nothing,
        };
    }
    // huddle 0.7.11: invite chords moved off Ctrl+i / Ctrl+I because
    // both collapse to ASCII Tab in every terminal we ship for, so the
    // pre-0.7.11 chords were unreachable. Now bare `I` (Shift+I) opens
    // the OOB link generator and Alt+I opens the in-band invite
    // picker. Both fire only when the chat input is blurred so they
    // don't fight with text composition.
    if matches!(app.pane, Pane::Group(_) | Pane::Dm(_)) {
        let input_active = app.active_room().map(|r| r.input_active).unwrap_or(false);
        if !input_active {
            if matches!(key.code, KeyCode::Char('I')) && !key.modifiers.contains(KeyModifiers::CONTROL) {
                return Action::GenerateInvite;
            }
            if key.modifiers.contains(KeyModifiers::ALT)
                && matches!(key.code, KeyCode::Char('i') | KeyCode::Char('I'))
            {
                return Action::OpenInvitePicker;
            }
        }
    }

    if key.code == KeyCode::Tab {
        return Action::TabNext;
    }

    // Numeric tab jump (only if input is not active).
    if !input_active {
        if let KeyCode::Char(c @ '1'..='9') = key.code {
            let n = (c as u8 - b'1') as usize;
            return Action::TabSelect(n);
        }
    }

    if input_active {
        // Alt+Enter (Option+Enter on macOS) and Shift+Enter both insert
        // a newline. Plain Enter sends.
        if matches!(key.code, KeyCode::Enter)
            && (key.modifiers.contains(KeyModifiers::ALT)
                || key.modifiers.contains(KeyModifiers::SHIFT))
        {
            return Action::ChatInsertNewline;
        }
        match key.code {
            KeyCode::Enter => Action::ChatSend,
            // Some terminals deliver Option+Enter as a literal LF char.
            KeyCode::Char('\n') => Action::ChatInsertNewline,
            KeyCode::Esc => Action::BlurInput,
            KeyCode::Backspace => Action::ChatBackspace,
            KeyCode::PageUp => Action::PageUp,
            KeyCode::PageDown => Action::PageDown,
            KeyCode::Char(c) => Action::ChatTypeChar(c),
            _ => Action::Nothing,
        }
    } else if card_focus {
        // Card-focus keystrokes when input is blurred and the user has
        // entered card navigation mode (via `f`). Esc / `f` exit.
        match key.code {
            KeyCode::Esc | KeyCode::Char('f') => Action::ToggleCardFocus,
            KeyCode::Char('j') | KeyCode::Down => Action::CardNext,
            KeyCode::Char('k') | KeyCode::Up => Action::CardPrev,
            KeyCode::Enter => Action::ActivateFocusedCard,
            KeyCode::Char('o') => Action::OpenFocusedCard,
            KeyCode::Char('c') => Action::CancelFocusedCard,
            KeyCode::Char('s') => Action::SaveAgainFocusedCard,
            KeyCode::Char('r') => Action::ActivateFocusedCard,
            _ => Action::Nothing,
        }
    } else {
        match key.code {
            KeyCode::Char('q') => Action::OpenQuitConfirm,
            KeyCode::Char('/') => Action::FocusInput,
            KeyCode::Char('?') => Action::OpenHelp,
            // huddle 0.6: vim-style command palette also reachable
            // from in-room chat mode.
            KeyCode::Char(':') => Action::OpenCommandPalette,
            KeyCode::Char('f') => Action::ToggleCardFocus,
            KeyCode::Char('j') | KeyCode::Down => Action::ScrollDown,
            KeyCode::Char('k') | KeyCode::Up => Action::ScrollUp,
            KeyCode::PageDown => Action::PageDown,
            KeyCode::PageUp => Action::PageUp,
            KeyCode::Home | KeyCode::Char('g') => Action::JumpTop,
            KeyCode::End | KeyCode::Char('G') => Action::JumpBottom,
            // Shift+b — owners-only view of bans for the current room.
            // Distinct from ^B (BackToLobby) since terminals collapse
            // Ctrl+Shift+b → Ctrl+b, making the Ctrl-chord ambiguous.
            KeyCode::Char('B') => Action::ShowRoomBans,
            KeyCode::Esc => Action::BackToLobby,
            _ => Action::Nothing,
        }
    }
}
