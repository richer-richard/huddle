use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{Modal, Pane, SidebarFocus, SidebarItem, TuiApp};

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
    // Phase G: SAS verification
    VerifyStartSas,
    SasMatch,
    SasCancel,
    // Phase E: verified-only-mode toggles
    OpenSettings,
    SettingsToggleGlobalVerifiedOnly,
    ToggleRoomVerifiedOnly,
    // huddle 0.5: optional self-declared username
    OpenEditUsername,
    EditUsernameTypeChar(char),
    EditUsernameBackspace,
    EditUsernameConfirm,
    // huddle 0.5: go-dark account deletion flow
    OpenGoDarkModal,
    GoDarkNextField,
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

pub fn map_key(key: KeyEvent, app: &TuiApp) -> Action {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return Action::OpenQuitConfirm;
    }

    // huddle 0.6: global hotkeys that fire regardless of current
    // screen, as long as no modal is open (modal-internal Ctrl chords
    // would conflict otherwise). Ctrl+P = command palette,
    // Ctrl+H = status history, Shift+? = re-open onboarding.
    if matches!(app.modal, Modal::None) {
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
        Modal::Error(_) => match key.code {
            _ => Action::CloseModal,
        },
        Modal::Help => match key.code {
            KeyCode::Char('j') | KeyCode::Down => Action::HelpScrollDown,
            KeyCode::Char('k') | KeyCode::Up => Action::HelpScrollUp,
            KeyCode::PageDown => Action::HelpPageDown,
            KeyCode::PageUp => Action::HelpPageUp,
            _ => Action::CloseModal,
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
            KeyCode::Char('h') | KeyCode::Backspace | KeyCode::Left => Action::AttachPickerAscend,
            KeyCode::Enter | KeyCode::Char('l') | KeyCode::Right => Action::AttachPickerDescendOrPick,
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
            KeyCode::Esc | KeyCode::Char('q') => Action::CloseModal,
            KeyCode::Char('j') | KeyCode::Down => Action::VerifyNext,
            KeyCode::Char('k') | KeyCode::Up => Action::VerifyPrev,
            KeyCode::Enter | KeyCode::Char(' ') => Action::VerifyToggle,
            KeyCode::Char('s') => Action::VerifyStartSas,
            _ => Action::Nothing,
        },
        Modal::Sas(_) => match key.code {
            KeyCode::Esc | KeyCode::Char('c') | KeyCode::Char('q') => Action::SasCancel,
            KeyCode::Char('m') | KeyCode::Enter => Action::SasMatch,
            _ => Action::Nothing,
        },
        Modal::Settings(_) => match key.code {
            KeyCode::Esc | KeyCode::Char('q') => Action::CloseModal,
            KeyCode::Char('v') | KeyCode::Enter | KeyCode::Char(' ') => {
                Action::SettingsToggleGlobalVerifiedOnly
            }
            KeyCode::Char('c') => Action::ClearBlockedPeers,
            KeyCode::Char('u') => Action::OpenEditUsername,
            // huddle 0.6: capital U = toggle update check; lowercase u
            // stays "edit username". The case split keeps both reachable
            // and matches the convention from R (mark all read) in lobby.
            KeyCode::Char('U') => Action::ToggleUpdateCheck,
            // huddle 0.6: W = replay onboarding from inside Settings.
            KeyCode::Char('w') | KeyCode::Char('W') => Action::OpenWhatsNew,
            KeyCode::Char('!') => Action::OpenGoDarkModal,
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
            KeyCode::Tab => Action::GoDarkNextField,
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
            _ => Action::CloseModal,
        },
        Modal::JoinWithCode(_) => match key.code {
            KeyCode::Esc => Action::CloseModal,
            KeyCode::Enter => Action::JoinWithCodeConfirm,
            KeyCode::Backspace => Action::JoinWithCodeBackspace,
            KeyCode::Char(c) => Action::JoinWithCodeTypeChar(c),
            _ => Action::Nothing,
        },
        Modal::ShowInvite(_) => match key.code {
            _ => Action::CloseModal,
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
            KeyCode::Backspace => Action::CommandPaletteBackspace,
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
            _ => Action::CloseModal,
        },
        Modal::QrIdentity => match key.code {
            _ => Action::CloseModal,
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
    // huddle 0.7.3: Settings-pane row bindings. The pane visibly
    // displays "V verified-only / U update check / E username /
    // W replay onboarding / ! go dark" — previously those rows were
    // inert because only the Settings *modal* dispatched them. Now
    // they fire from the pane itself.
    if matches!(app.pane, Pane::Settings) {
        match key.code {
            KeyCode::Char('V') => return Action::SettingsToggleGlobalVerifiedOnly,
            KeyCode::Char('U') => return Action::ToggleUpdateCheck,
            KeyCode::Char('E') => return Action::OpenEditUsername,
            KeyCode::Char('W') => return Action::OpenWhatsNew,
            _ => {}
        }
    }
    // Cross-pane shortcuts — work anywhere the sidebar has focus,
    // including from Welcome/People/Activity/Settings panes. `!` is
    // a global because it's the most consistently advertised
    // go-dark shortcut, and the modal itself enforces the
    // two-factor destructive confirm.
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
        KeyCode::Char('!') => return Action::OpenGoDarkModal,
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
            KeyCode::Char('I') if !input_active => Action::GenerateInvite,
            _ => Action::Nothing,
        };
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
