//! `huddle-gui doctor` — a plain-text diagnostic dump for bug reports.
//! Runs without a window or network. Ported from the TUI's `run_doctor`.

use anyhow::Result;
use huddle_core::config;
use std::fs;

pub fn run() -> Result<()> {
    println!("huddle-gui {}", env!("CARGO_PKG_VERSION"));
    println!("ui: egui/eframe (native GUI)");
    println!("repository: https://github.com/richer-richard/huddle");
    println!();
    println!("paths:");
    let data_dir = config::data_dir();
    println!("  data dir:   {}", data_dir.display());
    println!("  database:   {}", config::db_path().display());
    println!("  log file:   {}", data_dir.join("huddle-gui.log").display());
    println!("  config:     {}", config::config_path().display());
    println!();

    let exists = |p: &std::path::Path| match fs::metadata(p) {
        Ok(meta) => format!("present ({} KB)", meta.len() / 1024),
        Err(_) => "absent".to_string(),
    };
    println!("data files:");
    for name in &[
        "huddle.db",
        "huddle.db-shm",
        "huddle.db-wal",
        "keychain.salt",
        "identity.key",
        "huddle-gui.log",
    ] {
        let p = data_dir.join(name);
        println!("  {:<16} {}", format!("{name}:"), exists(&p));
    }
    println!();

    match config::load_relays() {
        Some(list) if !list.is_empty() => {
            println!("relays configured (from config.toml):");
            for r in list {
                println!("  {r}");
            }
        }
        _ => println!("relays: none configured"),
    }
    println!();
    println!("for support, open an issue at:");
    println!("  https://github.com/richer-richard/huddle/issues");
    Ok(())
}
