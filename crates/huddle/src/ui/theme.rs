//! huddle 0.7: centralized color + style palette.
//! huddle 1.1.4: runtime Dark (default) + Light themes — parity with the
//! desktop GUI's `huddle-gui::theme`.
//!
//! Every renderer takes a `&Theme` reference instead of hard-coding
//! `Color::Cyan` / `Style::default().fg(Color::Yellow)` inline. `Theme` is a
//! struct of `ratatui::Color` fields plus style helpers; the active palette is
//! swapped at runtime by replacing the `Theme` value the app threads into
//! rendering (see `TuiApp.theme` / `ThemeKind`). Two high-contrast palettes
//! are provided:
//!   * [`Theme::dark`] — bright accents on near-black (the default), and
//!   * [`Theme::light`] — dark, saturated accents intended for a light
//!     terminal background so nothing washes out.
//!
//! Both use `Color::Rgb` rather than the 16 ANSI names so the colors are
//! stable across terminal palettes (an ANSI `Cyan` is whatever the user's
//! theme defines, which would defeat "high-contrast parity"). The chosen
//! palette is persisted via `AppHandle::theme()/set_theme()` — the *same*
//! `theme` setting the GUI uses, so one row drives both front-ends.

use ratatui::style::{Color, Modifier, Style};

/// Which palette is active. `Dark` is the default. Persisted as a string
/// (`"dark"` / `"light"`) via `AppHandle::theme()/set_theme()`, mirroring
/// `huddle_gui::theme::Theme`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThemeKind {
    #[default]
    Dark,
    Light,
}

impl ThemeKind {
    /// Stable string for persistence. Matches the GUI's encoding exactly so a
    /// single `theme` DB row drives both the TUI and the GUI.
    pub fn as_str(self) -> &'static str {
        match self {
            ThemeKind::Dark => "dark",
            ThemeKind::Light => "light",
        }
    }

    /// Parse the persisted value; anything but `light` (incl. blank/unknown)
    /// falls back to the `Dark` default — the same fail-safe rule as the GUI.
    pub fn from_str(s: &str) -> ThemeKind {
        if s.trim().eq_ignore_ascii_case("light") {
            ThemeKind::Light
        } else {
            ThemeKind::Dark
        }
    }

    /// Human label for the Settings toggle.
    pub fn label(self) -> &'static str {
        match self {
            ThemeKind::Dark => "Dark",
            ThemeKind::Light => "Light",
        }
    }

    /// The other kind — used by the live toggle.
    pub fn toggled(self) -> ThemeKind {
        match self {
            ThemeKind::Dark => ThemeKind::Light,
            ThemeKind::Light => ThemeKind::Dark,
        }
    }

    /// Build the concrete palette for this kind.
    pub fn palette(self) -> Theme {
        match self {
            ThemeKind::Dark => Theme::dark(),
            ThemeKind::Light => Theme::light(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Theme {
    pub accent: Color,
    // huddle 0.7.11: dropped unused `accent_dim` field — it was never
    // read after the 0.7 TUI refactor merged the dim accent into
    // `text_dim` for hint chips.
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
    /// High-contrast dark (default): bright accents on near-black. A near-1:1
    /// port of the GUI's DARK palette, tuned slightly for terminals
    /// (`text_dim` lifted from the GUI value, `border` given a concrete RGB —
    /// the old ANSI `DarkGray` was illegibly dim on a true-black background).
    pub fn dark() -> Self {
        Self {
            accent: Color::Rgb(0x4c, 0xc2, 0xff),
            text: Color::Rgb(0xf2, 0xf3, 0xf5),
            text_dim: Color::Rgb(0x9b, 0xa1, 0xb0),
            border: Color::Rgb(0x3a, 0x3f, 0x4c),
            border_focus: Color::Rgb(0x4c, 0xc2, 0xff),
            success: Color::Rgb(0x4a, 0xde, 0x80),
            warn: Color::Rgb(0xfa, 0xcc, 0x15),
            error: Color::Rgb(0xff, 0x6b, 0x6b),
            bg_select: Color::Rgb(0x26, 0x31, 0x4a),
            unread_badge: Color::Rgb(0xfa, 0xcc, 0x15),
            encrypted: Color::Rgb(0xc9, 0x8b, 0xff),
        }
    }

    /// High-contrast light: deliberately DARK, saturated accents so nothing
    /// washes out on a light terminal background. Ports the GUI's LIGHT
    /// palette (which was designed for exactly this). Pick this on a terminal
    /// with a light background; the accents stay legible either way, and
    /// selection rows paint a pale-blue fill behind near-black text.
    pub fn light() -> Self {
        Self {
            accent: Color::Rgb(0x03, 0x69, 0xa1),
            text: Color::Rgb(0x14, 0x15, 0x1a),
            text_dim: Color::Rgb(0x52, 0x55, 0x5e),
            border: Color::Rgb(0x8a, 0x90, 0x9c),
            border_focus: Color::Rgb(0x03, 0x69, 0xa1),
            success: Color::Rgb(0x15, 0x80, 0x3d),
            warn: Color::Rgb(0xb4, 0x53, 0x09),
            error: Color::Rgb(0xb9, 0x1c, 0x1c),
            bg_select: Color::Rgb(0xcf, 0xe4, 0xff),
            unread_badge: Color::Rgb(0xb4, 0x53, 0x09),
            encrypted: Color::Rgb(0x7e, 0x22, 0xce),
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
