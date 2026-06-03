//! The huddle palette translated into an egui `Visuals` + `Style`. Mirrors
//! `crates/huddle/src/ui/theme.rs`: cyan accent, magenta = encrypted, green =
//! verified/success, yellow = warn/unread, red = error — with comfortable
//! "messenger" spacing.
//!
//! huddle 1.1.2: two themes — a high-contrast **Dark** (default) and a
//! high-contrast **Light**. The palette is resolved at runtime through
//! [`palette()`] (call sites use `palette().accent` etc.), so the active theme
//! is switchable live from Settings → Account → Appearance. Both palettes are
//! tuned for legibility: Light deliberately uses *dark, saturated* accents so
//! they don't wash out on a white background, and Dark uses bright accents over
//! a near-black background.

use std::sync::atomic::{AtomicU8, Ordering};

use egui::Color32;

/// Which theme is active. `Dark` is the default.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Theme {
    #[default]
    Dark,
    Light,
}

impl Theme {
    /// Stable string for persistence (the `theme` DB setting).
    pub fn as_str(self) -> &'static str {
        match self {
            Theme::Dark => "dark",
            Theme::Light => "light",
        }
    }

    /// Parse the persisted value; anything but `light` (incl. blank/unknown)
    /// falls back to the `Dark` default.
    pub fn from_str(s: &str) -> Theme {
        if s.trim().eq_ignore_ascii_case("light") {
            Theme::Light
        } else {
            Theme::Dark
        }
    }

    /// Human label for the Settings toggle.
    pub fn label(self) -> &'static str {
        match self {
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

// 0 = Dark (default), 1 = Light. Process-global; the GUI is single-window.
static CURRENT: AtomicU8 = AtomicU8::new(0);

/// The currently active theme.
pub fn current() -> Theme {
    match CURRENT.load(Ordering::Relaxed) {
        1 => Theme::Light,
        _ => Theme::Dark,
    }
}

/// Set the active theme. Call [`install`] afterwards to repaint with it.
pub fn set_theme(t: Theme) {
    CURRENT.store(
        match t {
            Theme::Dark => 0,
            Theme::Light => 1,
        },
        Ordering::Relaxed,
    );
}

/// The active palette. Call sites read fields off this, e.g. `palette().accent`.
pub fn palette() -> &'static Palette {
    match current() {
        Theme::Dark => &DARK,
        Theme::Light => &LIGHT,
    }
}

/// Install the active palette + spacing onto the egui context. Called once at
/// startup and again whenever the theme changes (Settings → Appearance).
pub fn install(ctx: &egui::Context) {
    let theme = current();
    let p = palette();
    let mut v = match theme {
        Theme::Dark => egui::Visuals::dark(),
        Theme::Light => egui::Visuals::light(),
    };
    v.panel_fill = p.panel;
    v.window_fill = p.panel;
    v.extreme_bg_color = p.bg;
    v.faint_bg_color = match theme {
        Theme::Dark => Color32::from_rgb(0x1c, 0x1c, 0x24),
        Theme::Light => Color32::from_rgb(0xec, 0xee, 0xf2),
    };
    v.override_text_color = Some(p.text);
    v.hyperlink_color = p.accent;
    v.selection.bg_fill = p.select;
    v.selection.stroke = egui::Stroke::new(1.0, p.accent);
    v.widgets.hovered.bg_fill = match theme {
        Theme::Dark => Color32::from_rgb(0x22, 0x26, 0x33),
        Theme::Light => Color32::from_rgb(0xe3, 0xe7, 0xef),
    };
    v.widgets.active.bg_fill = p.select;
    ctx.set_visuals(v);

    let mut style = (*ctx.global_style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(8.0, 4.0);
    style.spacing.window_margin = egui::Margin::same(10);
    ctx.set_global_style(style);
}
