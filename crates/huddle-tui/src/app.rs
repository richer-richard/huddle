use std::collections::HashMap;
use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::{
    event::{self, poll, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use libp2p::PeerId;
use ratatui::prelude::*;
use ratatui::Terminal;

use huddle_core::app::events::AppEvent;
use huddle_core::app::AppHandle;
use huddle_core::storage::repo::StoredMessage;

use crate::input::{self, TuiAction};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    PeerList,
    Chat,
    Status,
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub fingerprint: String,
    pub online: bool,
    pub has_session: bool,
}

pub struct TuiApp {
    pub handle: AppHandle,
    pub peers: Vec<PeerInfo>,
    pub selected_peer_idx: usize,
    pub active_peer: Option<PeerId>,
    pub messages: HashMap<PeerId, Vec<StoredMessage>>,
    pub input_buffer: String,
    pub input_active: bool,
    pub active_pane: Pane,
    pub listen_addresses: Vec<String>,
    pub connected_peers: usize,
    pub scroll_offset: usize,
}

impl TuiApp {
    pub fn new(handle: AppHandle) -> Self {
        Self {
            handle,
            peers: Vec::new(),
            selected_peer_idx: 0,
            active_peer: None,
            messages: HashMap::new(),
            input_buffer: String::new(),
            input_active: false,
            active_pane: Pane::PeerList,
            listen_addresses: Vec::new(),
            connected_peers: 0,
            scroll_offset: 0,
        }
    }

    pub fn handle_app_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::PeerDiscovered {
                peer_id,
                fingerprint,
            } => {
                if let Some(p) = self.peers.iter_mut().find(|p| p.peer_id == peer_id) {
                    if let Some(fp) = fingerprint {
                        p.fingerprint = fp;
                    }
                    p.online = true;
                } else {
                    self.peers.push(PeerInfo {
                        peer_id,
                        fingerprint: fingerprint.unwrap_or_else(|| "unknown".into()),
                        online: true,
                        has_session: false,
                    });
                }
            }
            AppEvent::PeerExpired { peer_id } => {
                if let Some(p) = self.peers.iter_mut().find(|p| p.peer_id == peer_id) {
                    p.online = false;
                }
            }
            AppEvent::SessionEstablished {
                peer_id,
                fingerprint,
            } => {
                if let Some(p) = self.peers.iter_mut().find(|p| p.peer_id == peer_id) {
                    p.has_session = true;
                    p.fingerprint = fingerprint;
                }
            }
            AppEvent::MessageReceived {
                peer_id,
                body,
                sent_at,
            } => {
                let msg = StoredMessage {
                    id: 0,
                    peer_id: peer_id.to_string(),
                    direction: "in".into(),
                    body,
                    sent_at,
                    delivered_at: None,
                };
                self.messages.entry(peer_id).or_default().push(msg);
            }
            AppEvent::MessageSent {
                peer_id,
                body,
                message_id,
            } => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                let msg = StoredMessage {
                    id: message_id,
                    peer_id: peer_id.to_string(),
                    direction: "out".into(),
                    body,
                    sent_at: now,
                    delivered_at: None,
                };
                self.messages.entry(peer_id).or_default().push(msg);
            }
            AppEvent::ConnectionEstablished { .. } => {
                self.connected_peers += 1;
            }
            AppEvent::ConnectionClosed { .. } => {
                self.connected_peers = self.connected_peers.saturating_sub(1);
            }
            AppEvent::ListeningOn { address } => {
                self.listen_addresses.push(address);
            }
            AppEvent::MessageAcked { .. } | AppEvent::Error { .. } => {}
        }
    }

    pub fn load_messages_for_peer(&mut self, peer_id: &PeerId) {
        if let Ok(msgs) = self.handle.get_messages(peer_id, 200) {
            if !msgs.is_empty() {
                self.messages.insert(*peer_id, msgs);
            }
        }
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

    if let Ok(peers) = app.handle.list_peers() {
        for p in peers {
            if let Ok(peer_id) = p.peer_id.parse::<PeerId>() {
                app.peers.push(PeerInfo {
                    peer_id,
                    fingerprint: p.fingerprint,
                    online: false,
                    has_session: p.olm_session_data.is_some(),
                });
            }
        }
    }

    loop {
        terminal.draw(|f| crate::ui::render_ui(f, &app))?;

        while let Ok(event) = event_rx.try_recv() {
            app.handle_app_event(event);
        }

        if poll(Duration::from_millis(33))? {
            if let Event::Key(key) = event::read()? {
                match input::handle_key(key, &app) {
                    TuiAction::Quit => break,
                    TuiAction::CyclePaneForward => {
                        app.active_pane = match app.active_pane {
                            Pane::PeerList => Pane::Chat,
                            Pane::Chat => Pane::Status,
                            Pane::Status => Pane::PeerList,
                        };
                    }
                    TuiAction::NavigateUp => {
                        if app.active_pane == Pane::PeerList && app.selected_peer_idx > 0 {
                            app.selected_peer_idx -= 1;
                        } else if app.active_pane == Pane::Chat {
                            app.scroll_offset = app.scroll_offset.saturating_add(1);
                        }
                    }
                    TuiAction::NavigateDown => {
                        if app.active_pane == Pane::PeerList
                            && app.selected_peer_idx + 1 < app.peers.len()
                        {
                            app.selected_peer_idx += 1;
                        } else if app.active_pane == Pane::Chat {
                            app.scroll_offset = app.scroll_offset.saturating_sub(1);
                        }
                    }
                    TuiAction::Select => {
                        if app.active_pane == Pane::PeerList && !app.peers.is_empty() {
                            let peer_id = app.peers[app.selected_peer_idx].peer_id;
                            let needs_session = !app.peers[app.selected_peer_idx].has_session;
                            app.active_peer = Some(peer_id);
                            app.load_messages_for_peer(&peer_id);

                            if needs_session {
                                app.handle.initiate_session(peer_id).await.ok();
                            }

                            app.active_pane = Pane::Chat;
                            app.input_active = true;
                        }
                    }
                    TuiAction::FocusInput => {
                        if app.active_peer.is_some() {
                            app.active_pane = Pane::Chat;
                            app.input_active = true;
                        }
                    }
                    TuiAction::BlurInput => {
                        app.input_active = false;
                    }
                    TuiAction::SendMessage => {
                        if app.input_active && !app.input_buffer.is_empty() {
                            if let Some(peer_id) = app.active_peer {
                                let body = app.input_buffer.clone();
                                app.input_buffer.clear();
                                app.handle.send_message(peer_id, &body).await.ok();
                            }
                        }
                    }
                    TuiAction::CharInput(c) => {
                        if app.input_active {
                            app.input_buffer.push(c);
                        }
                    }
                    TuiAction::Backspace => {
                        if app.input_active {
                            app.input_buffer.pop();
                        }
                    }
                    TuiAction::None => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    app.handle.shutdown().await;
    Ok(())
}
