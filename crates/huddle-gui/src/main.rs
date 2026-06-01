//! huddle-gui — native desktop client (egui/eframe) for huddle.
//!
//! Not `#[tokio::main]`: eframe owns winit, which must run on the main thread
//! (macOS). We build a multi-thread tokio runtime, keep it alive for the
//! process, construct `AppHandle` inside it, and bridge events to egui via
//! channels (see `bridge.rs`).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod bridge;
mod cli;
mod doctor;
mod fmt;
mod modals;
mod model;
mod notifier;
mod panes;
mod theme;
mod widgets;

use anyhow::{anyhow, Result};

fn main() -> Result<()> {
    let args = cli::Cli::parse_args();

    // Best-effort data-dir isolation for multi-instance testing. Must run
    // before any core path resolution and while still single-threaded.
    if let Some(dir) = args.data_dir.clone() {
        cli::apply_data_dir_override(&dir);
    }

    // `doctor` runs without a runtime or window.
    if args.is_doctor() {
        return doctor::run();
    }

    init_logging();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1120.0, 740.0])
            .with_min_inner_size([900.0, 600.0])
            .with_title("huddle"),
        ..Default::default()
    };

    eframe::run_native(
        "huddle",
        native_options,
        Box::new(move |cc| Ok(Box::new(app::HuddleApp::new(cc, rt, args)))),
    )
    .map_err(|e| anyhow!("eframe failed: {e}"))?;

    Ok(())
}

/// Log to a rolling file in the data dir (mirrors the TUI; separate filename so
/// a co-running TUI doesn't clash).
fn init_logging() {
    use tracing_subscriber::EnvFilter;
    let dir = huddle_core::config::data_dir();
    let _ = std::fs::create_dir_all(&dir);
    let appender = tracing_appender::rolling::never(&dir, "huddle-gui.log");
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("huddle_gui=debug,huddle_core=info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(appender)
        .with_ansi(false)
        .try_init();
}
