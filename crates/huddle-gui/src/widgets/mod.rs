//! Reusable egui widgets for the huddle look (avatars, status dots, …).

pub mod avatar;

use crate::theme::palette;

/// A small ●/○ connection dot — solid green when online, hollow dim when not.
pub fn status_dot(ui: &mut egui::Ui, online: bool) {
    let (glyph, color) = if online {
        ("●", palette().success)
    } else {
        ("○", palette().text_dim)
    };
    ui.label(egui::RichText::new(glyph).color(color));
}

/// A green ✓ verified badge.
pub fn verified_tick(ui: &mut egui::Ui) {
    ui.label(egui::RichText::new("✓").color(palette().success).strong());
}
