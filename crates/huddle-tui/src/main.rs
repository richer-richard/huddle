use anyhow::Result;
use clap::Parser;
use tracing_appender::rolling;
use tracing_subscriber::EnvFilter;

mod app;
mod input;
mod ui;

#[derive(Parser)]
#[command(name = "huddle-tui", version, about = "Huddle - decentralized encrypted chat (TUI)")]
struct Cli {
    #[arg(long, help = "Override data directory")]
    data_dir: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _cli = Cli::parse();

    let log_path = huddle_core::config::log_path();
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file_appender = rolling::never(
        log_path.parent().unwrap(),
        log_path.file_name().unwrap(),
    );
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("huddle=debug".parse()?))
        .with_writer(file_appender)
        .with_ansi(false)
        .init();

    let handle = huddle_core::app::AppHandle::start().await?;
    app::run_tui(handle).await
}
