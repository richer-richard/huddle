#![no_main]
//! Fuzz the `file_id` validation + cache-path handling.
//!
//! A `file_id` is attacker-controlled wire data used to build a filesystem path
//! under the cache dir. `FileManager::read_cache` rejects anything that isn't a
//! 64-char lowercase-hex digest BEFORE touching disk (the path-traversal guard),
//! so arbitrary input must only ever yield an `Err` — never a panic, and never a
//! read outside the cache directory.

use std::path::PathBuf;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

use huddle_core::files::FileManager;

/// One process-wide `FileManager` rooted at a throwaway temp dir, so each fuzz
/// iteration exercises only the validation + path logic, not repeated setup.
fn manager() -> &'static FileManager {
    static MGR: OnceLock<FileManager> = OnceLock::new();
    MGR.get_or_init(|| {
        let mut dir: PathBuf = std::env::temp_dir();
        dir.push("huddle-core-fuzz-file-id");
        FileManager::new(&dir).expect("create fuzz FileManager")
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = manager().read_cache(s);
    }
});
