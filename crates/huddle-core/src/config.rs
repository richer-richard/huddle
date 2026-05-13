use std::path::PathBuf;

pub fn data_dir() -> PathBuf {
    let base = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("huddle")
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
