use std::cell::Cell;
use std::io;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::{
    event::{
        self, poll, DisableMouseCapture, EnableMouseCapture, Event, MouseButton, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::prelude::*;
use ratatui::Terminal;

use huddle_core::app::events::{AppEvent, DiscoveredRoom};
use huddle_core::app::{AppHandle, KnownPeerStatus};
use huddle_core::network::NetworkMode;
use huddle_core::storage::repo::{StoredAttachment, StoredRoomMessage};

use crate::input::{self, Action};

/// Default lifetime for transient status-bar messages.
const STATUS_TTL: Duration = Duration::from_secs(6);

/// Top-level screen — the lobby or the in-room view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Lobby,
    InRoom,
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
    QuitConfirm,
    Help,
    Error(String),
    Info(String),
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
    pub unread: bool,
}

/// Which list the cursor is on in the lobby — known dial peers or
/// discovered rooms. Used for `j/k` navigation and `Enter`/`r`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LobbyFocus {
    KnownPeers,
    Rooms,
}

pub struct TuiApp {
    pub handle: AppHandle,
    pub mode: NetworkMode,
    pub screen: Screen,
    pub modal: Modal,
    pub discovered_rooms: Vec<DiscoveredRoom>,
    pub known_peers: Vec<KnownPeerStatus>,
    pub lobby_focus: LobbyFocus,
    pub selected_room_idx: usize,
    pub selected_peer_idx: usize,
    pub open_rooms: Vec<OpenRoom>,
    pub active_tab: usize,
    pub listen_addresses: Vec<String>,
    /// Bottom-bar status: text + expiry instant. After expiry, treated
    /// as None by the renderer.
    pub status_message: Option<(String, Instant)>,
}

impl TuiApp {
    pub fn new(handle: AppHandle) -> Self {
        let mode = handle.mode();
        let known_peers = handle.known_peers();
        let lobby_focus = if mode == NetworkMode::Direct && !known_peers.is_empty() {
            LobbyFocus::KnownPeers
        } else {
            LobbyFocus::Rooms
        };
        Self {
            handle,
            mode,
            screen: Screen::Lobby,
            modal: Modal::None,
            discovered_rooms: Vec::new(),
            known_peers,
            lobby_focus,
            selected_room_idx: 0,
            selected_peer_idx: 0,
            open_rooms: Vec::new(),
            active_tab: 0,
            listen_addresses: Vec::new(),
            status_message: None,
        }
    }

    pub fn refresh_known_peers(&mut self) {
        self.known_peers = self.handle.known_peers();
        if self.selected_peer_idx >= self.known_peers.len() && !self.known_peers.is_empty() {
            self.selected_peer_idx = self.known_peers.len() - 1;
        }
    }

    /// Set the bottom status line with the default 6s TTL.
    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status_message = Some((msg.into(), Instant::now() + STATUS_TTL));
    }

    /// Set the status line with an explicit TTL.
    pub fn set_status_for(&mut self, msg: impl Into<String>, ttl: Duration) {
        self.status_message = Some((msg.into(), Instant::now() + ttl));
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
        self.open_rooms.get(self.active_tab)
    }

    pub fn active_room_mut(&mut self) -> Option<&mut OpenRoom> {
        self.open_rooms.get_mut(self.active_tab)
    }

    pub fn refresh_discovered(&mut self) {
        self.discovered_rooms = self.handle.discovered_rooms();
        if self.selected_room_idx >= self.discovered_rooms.len() && !self.discovered_rooms.is_empty() {
            self.selected_room_idx = self.discovered_rooms.len() - 1;
        }
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

    pub fn handle_app_event(&mut self, ev: AppEvent) {
        match ev {
            AppEvent::RoomDiscovered(_) | AppEvent::RoomLost { .. } => {
                self.refresh_discovered();
            }
            AppEvent::RoomJoined { room_id } => {
                let info = self.handle.active_room_info(&room_id);
                let members = self.handle.room_members(&room_id);
                let messages = self.handle.room_messages(&room_id, 200).unwrap_or_default();
                if !self.open_rooms.iter().any(|r| r.room_id == room_id) {
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
                            input_active: true,
                            last_typing_sent: None,
                            scroll: 0,
                            follow_mode: true,
                            last_max_scroll: Cell::new(0),
                            card_focus: false,
                            focused_card_idx: 0,
                            unread: false,
                        });
                        self.active_tab = self.open_rooms.len() - 1;
                        self.screen = Screen::InRoom;
                    }
                }
            }
            AppEvent::RoomLeft { room_id } => {
                if let Some(idx) = self.open_rooms.iter().position(|r| r.room_id == room_id) {
                    self.open_rooms.remove(idx);
                    if self.open_rooms.is_empty() {
                        self.screen = Screen::Lobby;
                        self.active_tab = 0;
                    } else if self.active_tab >= self.open_rooms.len() {
                        self.active_tab = self.open_rooms.len() - 1;
                    }
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
                let idx_opt = self.open_rooms.iter().position(|r| r.room_id == room_id);
                if let Some(idx) = idx_opt {
                    let is_active = idx == self.active_tab && self.screen == Screen::InRoom;
                    let r = &mut self.open_rooms[idx];
                    r.messages.push(StoredRoomMessage {
                        id: 0,
                        room_id: room_id.clone(),
                        sender_fingerprint,
                        direction: "in".into(),
                        body,
                        sent_at,
                    });
                    if !is_active {
                        r.unread = true;
                    }
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
                self.modal = Modal::Error(description);
            }
            AppEvent::FileOffered {
                room_id,
                file_id: _,
                name,
                size_bytes,
                sender_fingerprint: _,
            } => {
                let active_id = self
                    .open_rooms
                    .get(self.active_tab)
                    .map(|r| r.room_id.clone());
                let on_active = self.screen == Screen::InRoom && active_id.as_deref() == Some(&room_id);
                if let Some(r) = self.open_rooms.iter_mut().find(|r| r.room_id == room_id) {
                    if !on_active {
                        r.unread = true;
                    }
                }
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
                self.modal = Modal::AcceptRotation(AcceptRotationState {
                    room_id,
                    rotator_fingerprint,
                    new_salt,
                    passphrase: String::new(),
                });
            }
        }
    }

}

fn short_room(room_id: &str) -> String {
    room_id.chars().take(8).collect()
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

/// Open a tab for a room we're already subscribed to in `active_rooms`
/// (e.g. one that was auto-restored at startup). Mirrors what the
/// `AppEvent::RoomJoined` handler does, minus the actual join call.
fn open_existing_room_tab(app: &mut TuiApp, room_id: &str) {
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
        input_active: true,
        last_typing_sent: None,
        scroll: 0,
        follow_mode: true,
        last_max_scroll: Cell::new(0),
        card_focus: false,
        focused_card_idx: 0,
        unread: false,
    });
    app.active_tab = app.open_rooms.len() - 1;
    app.screen = Screen::InRoom;
}

pub async fn run_tui(handle: AppHandle) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = TuiApp::new(handle);
    let mut event_rx = app.handle.subscribe();

    let result = main_loop(&mut terminal, &mut app, &mut event_rx).await;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    app.handle.shutdown().await;
    result
}

/// Show the welcome card before bringing up `AppHandle`. Returns `Ok(true)`
/// when the user is ready to continue or `Ok(false)` if they pressed
/// Ctrl-C / q (caller exits without starting the app).
pub fn show_welcome() -> Result<bool> {
    use crossterm::event::{KeyCode, KeyModifiers};

    enable_raw_mode()?;
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
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
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

        if poll(Duration::from_millis(33))? {
            match event::read()? {
                Event::Key(key) => {
                    let action = input::map_key(key, app);
                    should_quit = handle_action(action, app).await?;
                }
                Event::Mouse(m) => {
                    if matches!(m.kind, MouseEventKind::Down(MouseButton::Left))
                        && app.screen == Screen::InRoom
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
                _ => {}
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
        Action::CloseModal => {
            app.modal = Modal::None;
            Ok(false)
        }
        Action::OpenStartRoom => {
            app.modal = Modal::StartRoom(StartRoomState::new());
            Ok(false)
        }
        Action::OpenHelp => {
            app.modal = Modal::Help;
            Ok(false)
        }
        Action::LobbyNavigateUp => {
            match app.lobby_focus {
                LobbyFocus::Rooms => {
                    if app.selected_room_idx > 0 {
                        app.selected_room_idx -= 1;
                    }
                }
                LobbyFocus::KnownPeers => {
                    if app.selected_peer_idx > 0 {
                        app.selected_peer_idx -= 1;
                    }
                }
            }
            Ok(false)
        }
        Action::LobbyNavigateDown => {
            match app.lobby_focus {
                LobbyFocus::Rooms => {
                    if app.selected_room_idx + 1 < app.discovered_rooms.len() {
                        app.selected_room_idx += 1;
                    }
                }
                LobbyFocus::KnownPeers => {
                    if app.selected_peer_idx + 1 < app.known_peers.len() {
                        app.selected_peer_idx += 1;
                    }
                }
            }
            Ok(false)
        }
        Action::LobbyRefresh => {
            app.refresh_discovered();
            app.refresh_known_peers();
            Ok(false)
        }
        Action::LobbyFocusToggle => {
            app.lobby_focus = match app.lobby_focus {
                LobbyFocus::Rooms => LobbyFocus::KnownPeers,
                LobbyFocus::KnownPeers => LobbyFocus::Rooms,
            };
            Ok(false)
        }
        Action::LobbyReconnectPeer => {
            if let Some(p) = app.known_peers.get(app.selected_peer_idx).cloned() {
                if let Err(e) = app.handle.redial(&p.address).await {
                    app.modal = Modal::Error(format!("dial failed: {e}"));
                }
            }
            Ok(false)
        }
        Action::LobbyForgetPeer => {
            if let Some(p) = app.known_peers.get(app.selected_peer_idx).cloned() {
                if let Err(e) = app.handle.forget_peer(&p.address).await {
                    app.modal = Modal::Error(format!("forget failed: {e}"));
                }
                app.refresh_known_peers();
                if app.selected_peer_idx >= app.known_peers.len() && !app.known_peers.is_empty() {
                    app.selected_peer_idx = app.known_peers.len() - 1;
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
            if let Some(room) = app.discovered_rooms.get(app.selected_room_idx).cloned() {
                // Already have a tab open — just focus it.
                if let Some(idx) = app
                    .open_rooms
                    .iter()
                    .position(|r| r.room_id == room.room_id)
                {
                    app.active_tab = idx;
                    app.screen = Screen::InRoom;
                    return Ok(false);
                }
                // Auto-restored non-encrypted room: we're already subscribed
                // in active_rooms, just need to open a tab without re-joining.
                if !room.encrypted && app.handle.active_room_info(&room.room_id).is_some() {
                    open_existing_room_tab(app, &room.room_id);
                    return Ok(false);
                }
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
            if let Err(e) = app.handle.start_room(&name, encrypted, pp).await {
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
            if !app.open_rooms.is_empty() {
                app.active_tab = (app.active_tab + 1) % app.open_rooms.len();
                if let Some(r) = app.active_room_mut() {
                    r.unread = false;
                }
            }
            Ok(false)
        }
        Action::TabPrev => {
            if !app.open_rooms.is_empty() {
                app.active_tab = if app.active_tab == 0 {
                    app.open_rooms.len() - 1
                } else {
                    app.active_tab - 1
                };
                if let Some(r) = app.active_room_mut() {
                    r.unread = false;
                }
            }
            Ok(false)
        }
        Action::TabSelect(n) => {
            if n < app.open_rooms.len() {
                app.active_tab = n;
                if let Some(r) = app.active_room_mut() {
                    r.unread = false;
                }
            }
            Ok(false)
        }
        Action::BackToLobby => {
            app.screen = Screen::Lobby;
            Ok(false)
        }
        Action::LeaveRoom => {
            if let Some(room) = app.active_room() {
                let id = room.room_id.clone();
                if let Err(e) = app.handle.leave_room(&id).await {
                    app.modal = Modal::Error(format!("leave failed: {e}"));
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
    }
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
