use std::cell::Cell;
use std::io;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::{
    event::{self, poll, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::prelude::*;
use ratatui::Terminal;

use huddle_core::app::events::{AppEvent, DiscoveredRoom};
use huddle_core::app::{AppHandle, KnownPeerStatus};
use huddle_core::network::NetworkMode;
use huddle_core::storage::repo::StoredRoomMessage;

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
    QuitConfirm,
    Help,
    Error(String),
    Info(String),
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

/// A room we're currently in (a tab in the in-room view).
pub struct OpenRoom {
    pub room_id: String,
    pub name: String,
    pub encrypted: bool,
    pub members: Vec<String>,
    pub messages: Vec<StoredRoomMessage>,
    pub input: String,
    pub input_active: bool,
    /// Number of lines skipped from the top of the wrapped message
    /// buffer. Bounded by `last_max_scroll` at render time.
    pub scroll: u16,
    /// When true, render anchors to the bottom regardless of `scroll` —
    /// new messages stay visible. Any ScrollUp / PgUp / Home disables it.
    pub follow_mode: bool,
    /// Last-rendered maximum scroll value (total_lines − visible_height).
    /// Updated by `render_messages` so action handlers can clamp / detect
    /// "we just hit the bottom" without re-running the wrap.
    pub last_max_scroll: Cell<u16>,
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
                        self.open_rooms.push(OpenRoom {
                            room_id: room_id.clone(),
                            name: info.name,
                            encrypted: info.encrypted,
                            members,
                            messages,
                            input: String::new(),
                            input_active: true,
                            scroll: 0,
                            follow_mode: true,
                            last_max_scroll: Cell::new(0),
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
        }
    }

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
    app.open_rooms.push(OpenRoom {
        room_id: room_id.to_string(),
        name: info.name,
        encrypted: info.encrypted,
        members,
        messages,
        input: String::new(),
        input_active: true,
        scroll: 0,
        follow_mode: true,
        last_max_scroll: Cell::new(0),
        unread: false,
    });
    app.active_tab = app.open_rooms.len() - 1;
    app.screen = Screen::InRoom;
}

pub async fn run_tui(handle: AppHandle) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = TuiApp::new(handle);
    let mut event_rx = app.handle.subscribe();

    let result = main_loop(&mut terminal, &mut app, &mut event_rx).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
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
            last_refresh = std::time::Instant::now();
        }

        // Drop expired status-bar messages.
        app.tick_status();

        if poll(Duration::from_millis(33))? {
            if let Event::Key(key) = event::read()? {
                let action = input::map_key(key, app);
                should_quit = handle_action(action, app).await?;
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
            if let Some(r) = app.active_room_mut() {
                if r.input_active {
                    r.input.push(c);
                }
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
    }
}
