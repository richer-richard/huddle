//! huddle 0.7: centralized color + style palette.
//!
//! Every renderer takes a `&Theme` reference instead of hard-coding
//! `Color::Cyan` / `Style::default().fg(Color::Yellow)` inline. The
//! palette below matches the colors already used across the old
//! `ui/lobby.rs` / `ui/room.rs` / `ui/modal.rs` so the visual identity
//! is preserved. Future themes (`light`, `high_contrast`) plug in by
//! providing alternative `Theme::*` constructors.

use ratatui::style::{Color, Modifier, Style};

#[derive(Debug, Clone)]
pub struct Theme {
    pub accent: Color,
    pub accent_dim: Color,
    pub text: Color,
    pub text_dim: Color,
    pub border: Color,
    pub border_focus: Color,
    pub success: Color,
    pub warn: Color,
    pub error: Color,
    pub bg_select: Color,
    pub unread_badge: Color,
    pub encrypted: Color,
}

impl Theme {
    pub fn dark() -> Self {
        Self {
            accent: Color::Cyan,
            accent_dim: Color::DarkGray,
            text: Color::White,
            text_dim: Color::DarkGray,
            border: Color::DarkGray,
            border_focus: Color::Cyan,
            success: Color::Green,
            warn: Color::Yellow,
            error: Color::Red,
            bg_select: Color::Rgb(40, 40, 60),
            unread_badge: Color::Yellow,
            encrypted: Color::Magenta,
        }
    }

    pub fn accent_bold(&self) -> Style {
        Style::default().fg(self.accent).add_modifier(Modifier::BOLD)
    }
    pub fn text_style(&self) -> Style {
        Style::default().fg(self.text)
    }
    pub fn dim(&self) -> Style {
        Style::default().fg(self.text_dim)
    }
    pub fn ok(&self) -> Style {
        Style::default().fg(self.success).add_modifier(Modifier::BOLD)
    }
    pub fn warn_style(&self) -> Style {
        Style::default().fg(self.warn).add_modifier(Modifier::BOLD)
    }
    pub fn err_style(&self) -> Style {
        Style::default().fg(self.error).add_modifier(Modifier::BOLD)
    }
    pub fn unread(&self) -> Style {
        Style::default()
            .fg(self.unread_badge)
            .add_modifier(Modifier::BOLD)
    }
    pub fn enc(&self) -> Style {
        Style::default()
            .fg(self.encrypted)
            .add_modifier(Modifier::BOLD)
    }
    pub fn select_bg(&self) -> Style {
        Style::default().bg(self.bg_select).fg(self.text)
    }
    pub fn select_bg_focus(&self) -> Style {
        Style::default()
            .bg(self.bg_select)
            .fg(self.accent)
            .add_modifier(Modifier::BOLD)
    }
    pub fn border_style(&self) -> Style {
        Style::default().fg(self.border)
    }
    pub fn border_focus_style(&self) -> Style {
        Style::default()
            .fg(self.border_focus)
            .add_modifier(Modifier::BOLD)
    }
}
