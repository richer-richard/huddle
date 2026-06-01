//! Small formatting helpers ported from the TUI
//! (`crates/huddle/src/ui/mod.rs`) so IDs render identically in the GUI.

/// Truncate a fingerprint to its first group (4 hex chars).
pub fn short_fp(fp: &str) -> String {
    fp.split('-').next().unwrap_or(fp).to_string()
}

/// First two 4-char groups of a fingerprint — compact but collision-resistant
/// enough for a status line / log.
pub fn short_fp2(fp: &str) -> String {
    fp.split('-').take(2).collect::<Vec<_>>().join("-")
}

/// Render a full fingerprint as a branded huddle ID:
/// `HD-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`. Tolerant of inputs that are already
/// `HD-`-prefixed, already dash-separated lowercase (the canonical
/// `identity::compute_fingerprint` output), or a bare 24-char hex run.
pub fn display_id(fp: &str) -> String {
    if fp.starts_with("HD-") {
        return fp.to_string();
    }
    let upper = fp.to_ascii_uppercase();
    if upper.contains('-') {
        return format!("HD-{}", upper);
    }
    if upper.len() == 24 && upper.chars().all(|c| c.is_ascii_hexdigit()) {
        let groups: Vec<String> = upper
            .as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap().to_string())
            .collect();
        return format!("HD-{}", groups.join("-"));
    }
    format!("HD-{}", upper)
}

/// UTC `HH:MM` for a unix timestamp.
pub fn hhmm(unix: i64) -> String {
    let secs = unix.rem_euclid(86_400);
    format!("{:02}:{:02}", secs / 3600, (secs % 3600) / 60)
}

/// UTC calendar-day bucket (days since the epoch) — used to detect day changes.
pub fn day_bucket(unix: i64) -> i64 {
    unix.div_euclid(86_400)
}

/// UTC `YYYY-MM-DD` for a unix timestamp (Howard Hinnant's civil-from-days).
pub fn ymd_string(unix: i64) -> String {
    let z = unix.div_euclid(86_400) + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ymd_known_epoch() {
        assert_eq!(ymd_string(0), "1970-01-01");
        // 2021-01-01 00:00:00 UTC = 1609459200
        assert_eq!(ymd_string(1_609_459_200), "2021-01-01");
        assert_eq!(hhmm(1_609_459_200 + 3 * 3600 + 25 * 60), "03:25");
    }

    #[test]
    fn display_id_groups_bare_hex() {
        assert_eq!(
            display_id("0123456789abcdef01234567"),
            "HD-0123-4567-89AB-CDEF-0123-4567"
        );
    }

    #[test]
    fn display_id_passes_through_prefixed() {
        assert_eq!(display_id("HD-ABCD"), "HD-ABCD");
    }

    #[test]
    fn display_id_uppercases_dashed() {
        assert_eq!(display_id("abcd-ef01"), "HD-ABCD-EF01");
    }

    #[test]
    fn short_fp_takes_first_group() {
        assert_eq!(short_fp("abcd-ef01-2345"), "abcd");
        assert_eq!(short_fp2("abcd-ef01-2345"), "abcd-ef01");
    }
}
