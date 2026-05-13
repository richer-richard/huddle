use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::{
    event::{self, poll, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::prelude::*;
use ratatui::Terminal;

use huddle_core::app::events::{AppEvent, DiscoveredRoom};
use huddle_core::app::AppHandle;
use huddle_core::storage::repo::StoredRoomMessage;

use crate::input::{self, Action};

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
    QuitConfirm,
    Help,
    Error(String),
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
    pub scroll: u16,
    pub unread: bool,
}

pub struct TuiApp {
    pub handle: AppHandle,
    pub screen: Screen,
    pub modal: Modal,
    pub discovered_rooms: Vec<DiscoveredRoom>,
    pub selected_room_idx: usize,
    pub open_rooms: Vec<OpenRoom>,
    pub active_tab: usize,
    pub listen_addresses: Vec<String>,
    pub status_message: Option<String>,
}

impl TuiApp {
    pub fn new(handle: AppHandle) -> Self {
        Self {
            handle,
            screen: Screen::Lobby,
            modal: Modal::None,
            discovered_rooms: Vec::new(),
            selected_room_idx: 0,
            open_rooms: Vec::new(),
            active_tab: 0,
            listen_addresses: Vec::new(),
            status_message: None,
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
            AppEvent::Error { description } => {
                self.modal = Modal::Error(description);
            }
        }
    }

    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status_message = Some(msg.into());
    }
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
            if app.selected_room_idx > 0 {
                app.selected_room_idx -= 1;
            }
            Ok(false)
        }
        Action::LobbyNavigateDown => {
            if app.selected_room_idx + 1 < app.discovered_rooms.len() {
                app.selected_room_idx += 1;
            }
            Ok(false)
        }
        Action::LobbyRefresh => {
            app.refresh_discovered();
            Ok(false)
        }
        Action::LobbyJoinSelected => {
            if let Some(room) = app.discovered_rooms.get(app.selected_room_idx).cloned() {
                if app.open_rooms.iter().any(|r| r.room_id == room.room_id) {
                    // Already joined — just switch to that tab.
                    if let Some(idx) = app
                        .open_rooms
                        .iter()
                        .position(|r| r.room_id == room.room_id)
                    {
                        app.active_tab = idx;
                        app.screen = Screen::InRoom;
                    }
                    return Ok(false);
                }
                if room.encrypted {
                    app.modal = Modal::JoinRoom(JoinRoomState {
                        room_id: room.room_id.clone(),
                        room_name: room.name.clone(),
                        encrypted: true,
                        passphrase: String::new(),
                    });
                } else {
                    if let Err(e) = app.handle.join_room(&room.room_id, None).await {
                        app.modal = Modal::Error(format!("join failed: {e}"));
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
            if let Some(r) = app.active_room_mut() {
                r.scroll = r.scroll.saturating_add(1);
            }
            Ok(false)
        }
        Action::ScrollDown => {
            if let Some(r) = app.active_room_mut() {
                r.scroll = r.scroll.saturating_sub(1);
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
                    Some(r) if r.input_active && !r.input.is_empty() => {
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
    }
}
