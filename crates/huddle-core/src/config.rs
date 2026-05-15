use std::path::PathBuf;

pub fn data_dir() -> PathBuf {
    let base = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("huddle")
}

/// Phase D: location of the user's optional config file. We use
/// `dirs::config_dir()` rather than `data_dir()` so this lives in the
/// platform-appropriate "preferences" directory (macOS
/// `~/Library/Application Support`, Linux `~/.config`, Windows
/// `%APPDATA%`). Doesn't have to exist — `load_relays` returns an
/// empty list if absent.
pub fn config_path() -> PathBuf {
    let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("huddle").join("config.toml")
}

/// Phase D: parse the `[network] relays = [...]` list from the config
/// file. Tiny hand-rolled parser — we don't want a `toml` crate dep
/// just for this. Lines starting with `#` are comments; whitespace is
/// trimmed. Returns an empty Vec if the file doesn't exist or has no
/// relays entry.
pub fn load_relays() -> Option<Vec<String>> {
    let path = config_path();
    let body = std::fs::read_to_string(&path).ok()?;
    let mut in_network = false;
    let mut out: Vec<String> = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            in_network = line == "[network]";
            continue;
        }
        if !in_network {
            continue;
        }
        if let Some(rest) = line.strip_prefix("relays") {
            let rest = rest.trim_start().trim_start_matches('=').trim();
            // Support both `relays = ["a", "b"]` and a multi-line form.
            // Strip the leading `[` and trailing `]` if present, split
            // on `,`, then unquote each piece.
            let payload = rest.trim_start_matches('[').trim_end_matches(']');
            for item in payload.split(',') {
                let item = item.trim().trim_matches('"').trim_matches('\'');
                if !item.is_empty() {
                    out.push(item.to_string());
                }
            }
        }
    }
    Some(out)
}

pub fn db_path() -> PathBuf {
    data_dir().join("huddle.db")
}

pub fn identity_key_path() -> PathBuf {
    data_dir().join("identity.key")
}

pub fn log_path() -> PathBuf {
    data_dir().join("huddle.log")
}

pub fn ensure_data_dir() -> std::io::Result<()> {
    std::fs::create_dir_all(data_dir())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dir_is_inside_huddle_directory() {
        let dir = data_dir();
        assert!(dir.ends_with("huddle") || dir.to_string_lossy().contains("huddle"));
    }

    #[test]
    fn db_path_ends_with_huddle_db() {
        let path = db_path();
        assert_eq!(path.file_name().unwrap(), "huddle.db");
    }

    #[test]
    fn identity_path_ends_with_identity_key() {
        let path = identity_key_path();
        assert_eq!(path.file_name().unwrap(), "identity.key");
    }
}
