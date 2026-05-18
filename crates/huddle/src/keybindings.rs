// Single source of truth for every keybinding in huddle.
//
// `render_help` (modal.rs), the command palette (modal.rs), and the
// adaptive hint bar all read this table — adding a new key here is the
// only place you have to touch. Keep this in sync with `input.rs`.

use crate::app::{Modal, Pane, TuiApp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Context {
    Lobby,
    LobbyPeers,
    LobbyRooms,
    RoomChat,
    RoomCardFocus,
    RoomInputActive,
    Global,
}

impl Context {
    #[allow(dead_code)]
    pub fn label(self) -> &'static str {
        match self {
            Context::Lobby => "Lobby",
            Context::LobbyPeers => "Lobby (known peers)",
            Context::LobbyRooms => "Lobby (rooms)",
            Context::RoomChat => "In a room",
            Context::RoomCardFocus => "Card focus",
            Context::RoomInputActive => "Typing",
            Context::Global => "Global",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Binding {
    /// Key glyph as shown in help / hints. e.g. "?", "Ctrl+J", "Shift+B".
    pub keys: &'static str,
    pub context: Context,
    pub description: &'static str,
    /// Canonical action name surfaced in the command palette. None means
    /// the key isn't reachable through the palette (e.g. typing modes).
    pub palette_label: Option<&'static str>,
}

pub const BINDINGS: &[Binding] = &[
    // Global
    Binding {
        keys: "Ctrl+C",
        context: Context::Global,
        description: "quit",
        palette_label: Some("quit huddle"),
    },
    Binding {
        keys: "?",
        context: Context::Global,
        description: "help (this screen)",
        palette_label: Some("show help"),
    },
    Binding {
        keys: "Shift+?",
        context: Context::Global,
        description: "re-open onboarding / what's new",
        palette_label: Some("show what's new / onboarding"),
    },
    Binding {
        keys: "Ctrl+H",
        context: Context::Global,
        description: "open notification history",
        palette_label: Some("show notification history"),
    },
    Binding {
        keys: "Ctrl+P",
        context: Context::Global,
        description: "command palette",
        palette_label: None,
    },
    // huddle 0.7.3: tmux-style focus jump between sidebar and pane.
    // Swapped from Ctrl+arrows in 0.7.2 because macOS claims Ctrl+arrows
    // for Mission Control Spaces and Cmd+arrows for terminal tabs.
    // Shift+arrows are unclaimed at every level on Mac/Linux/Windows.
    Binding {
        keys: "Shift+←",
        context: Context::Global,
        description: "focus sidebar",
        palette_label: Some("focus sidebar"),
    },
    Binding {
        keys: "Shift+→",
        context: Context::Global,
        description: "focus pane",
        palette_label: Some("focus pane"),
    },
    // huddle 0.7.4: deliberately-awkward chord. Bare `!` was too easy
    // to fat-finger into the destructive flow. ASCII spelling chosen
    // for universal font support — Mac users will press Option but
    // every keyboard doubles that as "alt".
    Binding {
        keys: "Alt+Shift+1",
        context: Context::Global,
        description: "go dark — delete account, wipe data, exit",
        palette_label: Some("go dark (delete account)"),
    },
    // Lobby
    Binding {
        keys: "s",
        context: Context::Lobby,
        description: "start a new room",
        palette_label: Some("start a new room"),
    },
    Binding {
        keys: "a",
        context: Context::Lobby,
        description: "add a friend by HD ID or username",
        palette_label: Some("add friend by HD ID or username"),
    },
    Binding {
        keys: "d",
        context: Context::Lobby,
        description: "dial a peer by IP:port or multiaddr",
        palette_label: Some("dial peer by address"),
    },
    Binding {
        keys: "i",
        context: Context::Lobby,
        description: "show your QR identity",
        palette_label: Some("show your QR identity"),
    },
    Binding {
        keys: ",",
        context: Context::Lobby,
        description: "open settings",
        palette_label: Some("open settings"),
    },
    Binding {
        keys: "c",
        context: Context::Lobby,
        description: "join encrypted room with a code",
        palette_label: Some("join with code"),
    },
    Binding {
        keys: "Shift+I",
        context: Context::Lobby,
        description: "generate an invite link",
        palette_label: Some("generate invite link"),
    },
    Binding {
        keys: "v",
        context: Context::Lobby,
        description: "paste an invite link",
        palette_label: Some("paste invite link"),
    },
    Binding {
        keys: "Tab",
        context: Context::Lobby,
        description: "switch focus (peers ↔ rooms)",
        palette_label: None,
    },
    Binding {
        keys: "j / k",
        context: Context::Lobby,
        description: "navigate the focused list",
        palette_label: None,
    },
    Binding {
        keys: "R",
        context: Context::Lobby,
        description: "mark every room read",
        palette_label: Some("mark all rooms read"),
    },
    Binding {
        keys: "q",
        context: Context::Lobby,
        description: "quit",
        palette_label: None,
    },
    // Lobby (rooms focus)
    Binding {
        keys: "Enter",
        context: Context::LobbyRooms,
        description: "join the selected room",
        palette_label: None,
    },
    Binding {
        keys: "r",
        context: Context::LobbyRooms,
        description: "refresh discovered rooms",
        palette_label: Some("refresh rooms"),
    },
    // Lobby (known-peers focus)
    Binding {
        keys: "Enter",
        context: Context::LobbyPeers,
        description: "reconnect to highlighted peer",
        palette_label: None,
    },
    Binding {
        keys: "r",
        context: Context::LobbyPeers,
        description: "retry connect",
        palette_label: None,
    },
    Binding {
        keys: "x",
        context: Context::LobbyPeers,
        description: "forget peer",
        palette_label: None,
    },
    // In-room (chat mode)
    Binding {
        keys: "/",
        context: Context::RoomChat,
        description: "focus input (type)",
        palette_label: None,
    },
    Binding {
        keys: "Esc",
        context: Context::RoomChat,
        description: "back to lobby",
        palette_label: None,
    },
    Binding {
        keys: "Tab / Ctrl+N",
        context: Context::RoomChat,
        description: "next tab",
        palette_label: Some("switch to next room"),
    },
    Binding {
        keys: "Ctrl+P",
        context: Context::RoomChat,
        description: "command palette",
        palette_label: None,
    },
    Binding {
        keys: "1..9",
        context: Context::RoomChat,
        description: "jump to tab N",
        palette_label: None,
    },
    Binding {
        keys: "j / k / arrows",
        context: Context::RoomChat,
        description: "scroll messages",
        palette_label: None,
    },
    Binding {
        keys: "PgUp / PgDn",
        context: Context::RoomChat,
        description: "page through history",
        palette_label: None,
    },
    Binding {
        keys: "g / G",
        context: Context::RoomChat,
        description: "jump to top / bottom",
        palette_label: None,
    },
    Binding {
        keys: "Ctrl+L",
        context: Context::RoomChat,
        description: "leave the current room",
        palette_label: Some("leave current room"),
    },
    Binding {
        keys: "Ctrl+B",
        context: Context::RoomChat,
        description: "back to lobby (stay in room)",
        palette_label: Some("back to lobby"),
    },
    Binding {
        keys: "Ctrl+F",
        context: Context::RoomChat,
        description: "search this room's history",
        palette_label: Some("search room history"),
    },
    Binding {
        keys: "Ctrl+V",
        context: Context::RoomChat,
        description: "verify member fingerprints",
        palette_label: Some("verify members"),
    },
    Binding {
        keys: "Ctrl+R",
        context: Context::RoomChat,
        description: "rotate the room key (owner)",
        palette_label: Some("rotate room key"),
    },
    Binding {
        keys: "Ctrl+A",
        context: Context::RoomChat,
        description: "attach a file",
        palette_label: Some("attach a file"),
    },
    Binding {
        keys: "Ctrl+M",
        context: Context::RoomChat,
        description: "mute / unmute room notifications",
        palette_label: Some("toggle room mute"),
    },
    Binding {
        keys: "Ctrl+K",
        context: Context::RoomChat,
        description: "kick a member (owner)",
        palette_label: Some("kick member"),
    },
    Binding {
        keys: "Ctrl+G",
        context: Context::RoomChat,
        description: "grant owner to a member (owner)",
        palette_label: Some("grant owner"),
    },
    Binding {
        keys: "Ctrl+O",
        context: Context::RoomChat,
        description: "toggle verified-only joins (owner)",
        palette_label: Some("toggle verified-only joins"),
    },
    Binding {
        keys: "Ctrl+J",
        context: Context::RoomChat,
        description: "generate a 10-min single-use join code (owner)",
        palette_label: Some("generate join code"),
    },
    Binding {
        keys: "Ctrl+Shift+I",
        context: Context::RoomChat,
        description: "generate an invite link for this room",
        palette_label: Some("generate invite for this room"),
    },
    Binding {
        keys: "Shift+B",
        context: Context::RoomChat,
        description: "show room bans (owner)",
        palette_label: Some("show room bans"),
    },
    Binding {
        keys: "f",
        context: Context::RoomChat,
        description: "focus file cards (when present)",
        palette_label: None,
    },
    Binding {
        keys: "q",
        context: Context::RoomChat,
        description: "quit huddle",
        palette_label: None,
    },
    // Card-focus mode
    Binding {
        keys: "j / k",
        context: Context::RoomCardFocus,
        description: "select next / previous card",
        palette_label: None,
    },
    Binding {
        keys: "Enter",
        context: Context::RoomCardFocus,
        description: "save the focused card",
        palette_label: None,
    },
    Binding {
        keys: "o",
        context: Context::RoomCardFocus,
        description: "open the saved file",
        palette_label: None,
    },
    Binding {
        keys: "c",
        context: Context::RoomCardFocus,
        description: "cancel the transfer",
        palette_label: None,
    },
    Binding {
        keys: "s",
        context: Context::RoomCardFocus,
        description: "save again (to a new path)",
        palette_label: None,
    },
    Binding {
        keys: "Esc / f",
        context: Context::RoomCardFocus,
        description: "exit card focus",
        palette_label: None,
    },
    // Input-active mode
    Binding {
        keys: "Enter",
        context: Context::RoomInputActive,
        description: "send the message",
        palette_label: None,
    },
    Binding {
        keys: "Alt+Enter / Ctrl+J",
        context: Context::RoomInputActive,
        description: "insert a newline (multi-line message)",
        palette_label: None,
    },
    Binding {
        keys: "Esc",
        context: Context::RoomInputActive,
        description: "blur the input (back to nav mode)",
        palette_label: None,
    },
    Binding {
        keys: "PgUp / PgDn",
        context: Context::RoomInputActive,
        description: "scroll messages while typing",
        palette_label: None,
    },
];

/// Bindings filtered by `context`. Used by `render_help` for section
/// headers and by the adaptive hint bar.
#[allow(dead_code)]
pub fn for_context(ctx: Context) -> impl Iterator<Item = &'static Binding> {
    BINDINGS.iter().filter(move |b| b.context == ctx)
}

/// Command palette entries — every binding that exposes a `palette_label`.
pub fn palette_entries() -> impl Iterator<Item = (&'static str, &'static str)> {
    BINDINGS.iter().filter_map(|b| {
        b.palette_label.map(|label| (label, b.keys))
    })
}

/// Adaptive hint bar items for the current app state. Roughly 5-6 items,
/// prioritized by likelihood of being the next action the user wants.
pub fn adaptive_hints(app: &TuiApp) -> Vec<(&'static str, &'static str)> {
    let mut out: Vec<(&'static str, &'static str)> = Vec::new();
    // Only render hints when no modal is open — otherwise the modal
    // hint bar is the relevant thing.
    if !matches!(app.modal, Modal::None) {
        return out;
    }
    let in_chat = matches!(app.pane, Pane::Dm(_) | Pane::Group(_));
    if !in_chat {
        // Sidebar / non-chat pane hints.
        match &app.pane {
            Pane::Welcome => {
                out.push(("m", "DM someone"));
                out.push(("g", "new group"));
                out.push(("a", "add friend"));
                out.push(("v", "paste invite"));
                out.push(("i", "QR"));
                out.push(("Ctrl+P", "palette"));
            }
            Pane::Profile => {
                out.push(("j/k", "select"));
                out.push(("y", "copy"));
                out.push(("E", "edit name"));
                out.push(("Q", "QR"));
                out.push(("Shift+I", "invite"));
            }
            Pane::People => {
                out.push(("Tab", "next list"));
                out.push(("m", "DM"));
                out.push(("r", "reconnect"));
                out.push(("b", "block"));
                out.push(("x", "forget"));
            }
            Pane::Activity => {
                out.push(("c", "clear"));
                out.push(("?", "help"));
            }
            Pane::Settings => {
                // huddle 0.7.8: tab-aware hints — show row chords for
                // the active tab, plus the universal Tab cycle.
                out.push(("Tab", "next tab"));
                match app.settings_tab {
                    crate::app::SettingsTab::Account => {
                        out.push(("E", "username"));
                        out.push(("Q", "QR"));
                        out.push(("W", "what's new"));
                    }
                    crate::app::SettingsTab::Network => {
                        out.push(("M", "toggle mDNS"));
                    }
                    crate::app::SettingsTab::Appearance => {}
                    crate::app::SettingsTab::Privacy => {
                        out.push(("V", "verified-only"));
                        out.push(("N", "notifications"));
                        out.push(("U", "update check"));
                        out.push(("Alt+Shift+1", "go dark"));
                    }
                }
            }
            _ => {}
        }
        out.push(("Shift+→", "pane"));
        out.push(("?", "help"));
        out.push(("q", "quit"));
    } else {
            let r = app.active_room();
        let room = app.active_room();
        let input_active = room.map(|r| r.input_active).unwrap_or(false);
        let card_focus = room.map(|r| r.card_focus).unwrap_or(false);
        let is_group = matches!(app.pane, Pane::Group(_));
        if card_focus {
            out.push(("j/k", "navigate"));
            out.push(("Enter", "save"));
            out.push(("o", "open"));
            out.push(("Esc/f", "exit"));
        } else if input_active {
            out.push(("Enter", "send"));
            out.push(("Alt+↵", "newline"));
            out.push(("Esc", "blur"));
            out.push(("Shift+←", "sidebar"));
            out.push(("Ctrl+P", "palette"));
        } else {
            out.push(("/", "type"));
            out.push(("Ctrl+V", "verify"));
            out.push(("Ctrl+F", "search"));
            out.push(("Ctrl+A", "attach"));
            if is_group {
                out.push(("Ctrl+I", "members"));
            }
            out.push(("Ctrl+L", "leave"));
            out.push(("Shift+←", "sidebar"));
        }
    }
    out
}
