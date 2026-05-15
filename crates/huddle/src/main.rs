use anyhow::{anyhow, Result};
use clap::Parser;
use tracing_appender::rolling;
use tracing_subscriber::EnvFilter;

use huddle_core::network::NetworkMode;
use huddle_core::storage::keychain;

mod app;
mod input;
mod ui;

#[derive(Parser)]
#[command(name = "huddle", version, about = "Huddle — decentralized encrypted chat (TUI)")]
struct Cli {
    #[arg(long, help = "Override data directory")]
    data_dir: Option<String>,

    /// Connection mode. If omitted, you'll be asked at startup.
    /// Values: `mdns` (LAN auto-discover) or `direct` (manual dial only).
    #[arg(long, value_parser = parse_mode)]
    mode: Option<NetworkMode>,

    /// TCP port to listen on (0 = random). Pick a stable one if you want
    /// people to be able to dial you reliably from outside the LAN.
    #[arg(long, default_value_t = 0u16)]
    port: u16,

    /// Optional human-readable display name shown alongside your short
    /// fingerprint in chat.
    #[arg(long)]
    name: Option<String>,

    /// Skip the master passphrase prompt and run with an unencrypted
    /// at-rest database (Phase 1 behavior). For testing only.
    #[arg(long)]
    no_master_passphrase: bool,
}

fn parse_mode(s: &str) -> std::result::Result<NetworkMode, String> {
    NetworkMode::from_str(s).ok_or_else(|| format!("unknown mode `{s}` (try mdns or direct)"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

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

    // Restore the terminal on panic before the message prints, so a crash
    // inside the TUI doesn't leave the shell in raw mode / alt screen.
    app::install_panic_hook();

    let mode = cli.mode.unwrap_or(NetworkMode::Mdns);

    // Skip the welcome card if a mode was given explicitly — power users
    // who script `--mode direct` don't want a prompt in the way.
    if cli.mode.is_none() && !app::show_welcome()? {
        return Ok(());
    }

    // Master passphrase: derives the SQLCipher DB key + Megolm persist
    // subkey. `--no-master-passphrase` falls back to an unencrypted DB
    // (Phase 1 behavior).
    //
    // First-launch detection happens BEFORE we create the salt — once
    // the salt exists on disk, the file's there even if no DB is.
    let (master_key, signup_name) = if cli.no_master_passphrase {
        (None, None)
    } else {
        let salt_path = keychain::keychain_salt_path();
        let salt_exists = salt_path.exists();
        // A database with no keychain salt was created by a previous
        // `--no-master-passphrase` run and is unencrypted. Taking the
        // normal (encrypted) path here would derive a fresh key, fail to
        // unlock that DB, and trap the user behind a cryptic SQLCipher
        // error. Refuse early with actionable guidance instead.
        if !salt_exists && huddle_core::config::db_path().exists() {
            anyhow::bail!(
                "found an existing database with no keychain salt — it was \
                 created with --no-master-passphrase and is unencrypted. \
                 Re-run with --no-master-passphrase, or move {} aside to \
                 start fresh.",
                huddle_core::config::db_path().display()
            );
        }
        let is_new = !salt_exists;
        let prompt = app::prompt_master_passphrase(is_new)?;
        if prompt.passphrase.is_empty() {
            return Ok(());
        }
        // Only persist the salt once the user has committed a
        // passphrase — otherwise pressing Esc on first launch leaves
        // a salt file behind and a future launch would think the DB
        // already existed.
        let salt = keychain::load_or_create_salt().map_err(|e| anyhow!(e))?;
        let key =
            keychain::derive_master_key(&prompt.passphrase, &salt).map_err(|e| anyhow!(e))?;
        (Some(key), prompt.username)
    };

    let handle = huddle_core::app::AppHandle::start_with_options(
        mode,
        cli.port,
        master_key.as_ref(),
    )
    .await
    .map_err(|e| anyhow!(e))?;

    // CLI --name wins over the prompt-supplied username.
    let name_to_set = cli.name.clone().or(signup_name);
    if let Some(name) = name_to_set {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            handle
                .set_display_name(Some(trimmed))
                .map_err(|e| anyhow!(e))?;
        }
    }
    app::run_tui(handle).await
}
