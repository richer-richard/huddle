//! The huddle palette translated into an egui `Visuals` + `Style`. Mirrors
//! `crates/huddle/src/ui/theme.rs`: cyan accent, magenta = encrypted, green =
//! verified/success, yellow = warn/unread, red = error — over a restrained dark
//! background, with comfortable "messenger" spacing.

use egui::Color32;

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

pub const PALETTE: Palette = Palette {
    accent: Color32::from_rgb(0x38, 0xbd, 0xf8),
    encrypted: Color32::from_rgb(0xc0, 0x84, 0xfc),
    success: Color32::from_rgb(0x4c, 0xd9, 0x64),
    warn: Color32::from_rgb(0xf5, 0xc5, 0x42),
    error: Color32::from_rgb(0xff, 0x6b, 0x6b),
    text: Color32::from_rgb(0xe6, 0xe6, 0xea),
    text_dim: Color32::from_rgb(0x8a, 0x8a, 0x99),
    bg: Color32::from_rgb(0x0e, 0x0e, 0x12),
    panel: Color32::from_rgb(0x16, 0x16, 0x1d),
    select: Color32::from_rgb(0x23, 0x29, 0x3a),
};

/// Install the palette + spacing on the egui context (called once at startup).
pub fn install(ctx: &egui::Context) {
    let p = &PALETTE;
    let mut v = egui::Visuals::dark();
    v.panel_fill = p.panel;
    v.window_fill = p.panel;
    v.extreme_bg_color = p.bg;
    v.faint_bg_color = Color32::from_rgb(0x1c, 0x1c, 0x24);
    v.override_text_color = Some(p.text);
    v.hyperlink_color = p.accent;
    v.selection.bg_fill = p.select;
    v.selection.stroke = egui::Stroke::new(1.0, p.accent);
    v.widgets.hovered.bg_fill = Color32::from_rgb(0x20, 0x24, 0x30);
    v.widgets.active.bg_fill = p.select;
    ctx.set_visuals(v);

    let mut style = (*ctx.global_style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(8.0, 4.0);
    style.spacing.window_margin = egui::Margin::same(10);
    ctx.set_global_style(style);
}
