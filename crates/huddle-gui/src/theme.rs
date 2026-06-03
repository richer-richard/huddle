//! The huddle palette translated into an egui `Visuals` + `Style`. Mirrors
//! `crates/huddle/src/ui/theme.rs`: cyan accent, magenta = encrypted, green =
//! verified/success, yellow = warn/unread, red = error — with comfortable
//! "messenger" spacing.
//!
//! huddle 1.1.3: three theme choices — **System** (default; follows the OS
//! light/dark setting), high-contrast **Dark**, and high-contrast **Light**.
//! The user's choice (`System`/`Dark`/`Light`) is resolved each frame against
//! the OS theme into an effective Dark/Light via [`resolve`]; the palette is
//! then read at runtime through [`palette()`] (call sites use `palette().accent`
//! etc.), so the active theme is switchable live from Settings → Account →
//! Appearance and `System` tracks the OS instantly. Both palettes are tuned for
//! legibility: Light deliberately uses *dark, saturated* accents so they don't
//! wash out on a white background, and Dark uses bright accents over a
//! near-black background.

use std::sync::atomic::{AtomicU8, Ordering};

use egui::Color32;

/// The user's theme choice. `System` (follow the OS light/dark setting) is the
/// default; `Dark`/`Light` pin the appearance regardless of the OS.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Theme {
    #[default]
    System,
    Dark,
    Light,
}

impl Theme {
    /// Stable string for persistence (the `theme` DB setting).
    pub fn as_str(self) -> &'static str {
        match self {
            Theme::System => "system",
            Theme::Dark => "dark",
            Theme::Light => "light",
        }
    }

    /// Parse the persisted value. `dark`/`light` pin the appearance; anything
    /// else (incl. blank/unknown/`system`) falls back to the `System` default,
    /// which follows the OS. Installs that already persisted `dark`/`light`
    /// keep that exact choice.
    pub fn from_str(s: &str) -> Theme {
        match s.trim().to_ascii_lowercase().as_str() {
            "dark" => Theme::Dark,
            "light" => Theme::Light,
            _ => Theme::System,
        }
    }

    /// Human label for the Settings selector.
    pub fn label(self) -> &'static str {
        match self {
            Theme::System => "System",
            Theme::Dark => "Dark",
            Theme::Light => "Light",
        }
    }
}

pub struct Palette {
    pub accent: Color32,
    pub encrypted: Color32,
    pub success: Color32,
    pub warn: Color32,
    pub error: Color32,
    pub text: Color32,
    pub text_dim: Color32,
    pub bg: Color32,
    pub panel: Color32,
    pub select: Color32,
}

/// High-contrast dark theme: bright accents over a near-black background.
static DARK: Palette = Palette {
    accent: Color32::from_rgb(0x4c, 0xc2, 0xff),
    encrypted: Color32::from_rgb(0xc9, 0x8b, 0xff),
    success: Color32::from_rgb(0x4a, 0xde, 0x80),
    warn: Color32::from_rgb(0xfa, 0xcc, 0x15),
    error: Color32::from_rgb(0xff, 0x6b, 0x6b),
    text: Color32::from_rgb(0xf2, 0xf3, 0xf5),
    text_dim: Color32::from_rgb(0xb4, 0xb8, 0xc4),
    bg: Color32::from_rgb(0x0b, 0x0b, 0x0f),
    panel: Color32::from_rgb(0x15, 0x16, 0x1c),
    select: Color32::from_rgb(0x26, 0x31, 0x4a),
};

/// High-contrast light theme: deliberately DARK, saturated accents so nothing
/// blends into the white background; near-black text on off-white panels.
static LIGHT: Palette = Palette {
    accent: Color32::from_rgb(0x03, 0x69, 0xa1),
    encrypted: Color32::from_rgb(0x7e, 0x22, 0xce),
    success: Color32::from_rgb(0x15, 0x80, 0x3d),
    warn: Color32::from_rgb(0xb4, 0x53, 0x09),
    error: Color32::from_rgb(0xb9, 0x1c, 0x1c),
    text: Color32::from_rgb(0x14, 0x15, 0x1a),
    text_dim: Color32::from_rgb(0x52, 0x55, 0x5e),
    bg: Color32::from_rgb(0xf4, 0xf5, 0xf7),
    panel: Color32::from_rgb(0xff, 0xff, 0xff),
    select: Color32::from_rgb(0xcf, 0xe4, 0xff),
};

// The EFFECTIVE theme — the resolved Dark/Light that `palette()`/`install()`
// render. 0 = Dark, 1 = Light. `System` is never stored here; it is resolved
// into Dark/Light by [`resolve`] using the OS theme. Process-global; the GUI is
// single-window.
static CURRENT: AtomicU8 = AtomicU8::new(0);

// The user's CHOICE: 0 = System, 1 = Dark, 2 = Light. Drives the Settings
// selector and is what gets persisted; `System` is resolved per-frame.
static CHOICE: AtomicU8 = AtomicU8::new(0);

/// The effective theme currently installed (always `Dark` or `Light`).
pub fn current() -> Theme {
    match CURRENT.load(Ordering::Relaxed) {
        1 => Theme::Light,
        _ => Theme::Dark,
    }
}

/// Set the effective Dark/Light theme (what `palette()`/`install()` use).
/// Callers pass the output of [`resolve`], so `System` never reaches here; it is
/// treated as Dark defensively. Call [`install`] afterwards to repaint.
pub fn set_effective(t: Theme) {
    CURRENT.store(if t == Theme::Light { 1 } else { 0 }, Ordering::Relaxed);
}

/// The user's theme choice (System/Dark/Light) — drives the Settings selector.
pub fn choice() -> Theme {
    match CHOICE.load(Ordering::Relaxed) {
        1 => Theme::Dark,
        2 => Theme::Light,
        _ => Theme::System,
    }
}

/// Record the user's theme choice. Follow with [`apply`] (or rely on the
/// per-frame [`resolve`] check) to install the resulting palette.
pub fn set_choice(t: Theme) {
    CHOICE.store(
        match t {
            Theme::System => 0,
            Theme::Dark => 1,
            Theme::Light => 2,
        },
        Ordering::Relaxed,
    );
}

/// Resolve the [`choice`] into an effective Dark/Light, consulting the OS theme
/// (`ctx.system_theme()`) when the choice is `System`. When the OS preference is
/// unknown (`None`), fall back to `Dark` (the historic default); a later
/// [`resolve`] corrects it once egui learns the OS theme.
pub fn resolve(ctx: &egui::Context) -> Theme {
    match choice() {
        Theme::Dark => Theme::Dark,
        Theme::Light => Theme::Light,
        Theme::System => match ctx.system_theme() {
            Some(egui::Theme::Light) => Theme::Light,
            _ => Theme::Dark,
        },
    }
}

/// Resolve the current choice against the OS theme and install the resulting
/// palette. Call after the choice changes, or when the OS theme flips.
pub fn apply(ctx: &egui::Context) {
    set_effective(resolve(ctx));
    install(ctx);
}

/// The active palette. Call sites read fields off this, e.g. `palette().accent`.
/// `current()` only ever returns the effective Dark/Light; the `_` arm falls
/// back to Dark for exhaustiveness.
pub fn palette() -> &'static Palette {
    match current() {
        Theme::Light => &LIGHT,
        _ => &DARK,
    }
}

/// Install the active palette + spacing onto the egui context. Called once at
/// startup and again whenever the theme changes (Settings → Appearance).
pub fn install(ctx: &egui::Context) {
    let theme = current();
    let p = palette();
    let mut v = match theme {
        Theme::Light => egui::Visuals::light(),
        _ => egui::Visuals::dark(),
    };
    v.panel_fill = p.panel;
    v.window_fill = p.panel;
    v.extreme_bg_color = p.bg;
    v.faint_bg_color = match theme {
        Theme::Light => Color32::from_rgb(0xec, 0xee, 0xf2),
        _ => Color32::from_rgb(0x1c, 0x1c, 0x24),
    };
    v.override_text_color = Some(p.text);
    v.hyperlink_color = p.accent;
    v.selection.bg_fill = p.select;
    v.selection.stroke = egui::Stroke::new(1.0, p.accent);
    v.widgets.hovered.bg_fill = match theme {
        Theme::Light => Color32::from_rgb(0xe3, 0xe7, 0xef),
        _ => Color32::from_rgb(0x22, 0x26, 0x33),
    };
    v.widgets.active.bg_fill = p.select;
    ctx.set_visuals(v);

    let mut style = (*ctx.global_style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(8.0, 4.0);
    style.spacing.window_margin = egui::Margin::same(10);
    ctx.set_global_style(style);
}

#[cfg(test)]
mod tests {
    use super::Theme;

    #[test]
    fn default_is_system() {
        assert_eq!(Theme::default(), Theme::System);
    }

    #[test]
    fn from_str_pins_explicit_and_defaults_to_system() {
        assert_eq!(Theme::from_str("dark"), Theme::Dark);
        assert_eq!(Theme::from_str("light"), Theme::Light);
        assert_eq!(Theme::from_str("system"), Theme::System);
        // Blank / unknown / legacy-unset → System (the new default), NOT Dark.
        // This is the trickiest spot: the old parser fell back to Dark.
        assert_eq!(Theme::from_str(""), Theme::System);
        assert_eq!(Theme::from_str("   "), Theme::System);
        assert_eq!(Theme::from_str("nonsense"), Theme::System);
        // Case-insensitive + trims, so a previously persisted value round-trips.
        assert_eq!(Theme::from_str("  DARK "), Theme::Dark);
        assert_eq!(Theme::from_str("Light"), Theme::Light);
    }

    #[test]
    fn as_str_round_trips_and_labels_present() {
        for t in [Theme::System, Theme::Dark, Theme::Light] {
            assert_eq!(Theme::from_str(t.as_str()), t);
            assert!(!t.label().is_empty());
        }
    }
}
