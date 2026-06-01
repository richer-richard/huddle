//! Deterministic, image-free avatars: a colored circle (hue derived from the
//! fingerprint) with up to two initials. Emoji-free, matching huddle 0.9.

use egui::{Color32, FontId, Sense, Ui, Vec2};

/// Deterministic avatar color from a seed (fingerprint): FNV-1a → hue, with a
/// fixed, calm saturation/value so the palette stays restrained.
pub fn color_for(seed: &str) -> Color32 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in seed.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let hue = (hash % 360) as f32 / 360.0;
    Color32::from(egui::ecolor::Hsva::new(hue, 0.45, 0.62, 1.0))
}

/// Up to two uppercase initials from a label (username or HD-id).
pub fn initials(label: &str) -> String {
    let cleaned = label.trim().trim_start_matches("HD-");
    let chars: Vec<char> = cleaned.chars().filter(|c| c.is_alphanumeric()).collect();
    chars.iter().take(2).collect::<String>().to_uppercase()
}

/// Paint a circular avatar with initials, allocating a `diameter`-square cell.
pub fn show(ui: &mut Ui, diameter: f32, seed: &str, label: &str) {
    let (rect, _resp) = ui.allocate_exact_size(Vec2::splat(diameter), Sense::hover());
    let painter = ui.painter();
    let center = rect.center();
    painter.circle_filled(center, diameter / 2.0, color_for(seed));
    painter.text(
        center,
        egui::Align2::CENTER_CENTER,
        initials(label),
        FontId::proportional(diameter * 0.4),
        Color32::from_rgb(0x10, 0x10, 0x14),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn color_is_deterministic() {
        assert_eq!(color_for("abcd-ef01"), color_for("abcd-ef01"));
    }

    #[test]
    fn initials_strip_hd_prefix() {
        assert_eq!(initials("HD-AB12-CD34"), "AB");
        assert_eq!(initials("alice"), "AL");
        assert_eq!(initials(""), "");
    }
}
