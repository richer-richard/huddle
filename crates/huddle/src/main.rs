use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use libp2p::Multiaddr;
use tracing_appender::rolling;
use tracing_subscriber::EnvFilter;

use huddle_core::network::NetworkMode;
use huddle_core::storage::keychain;

mod app;
mod clipboard;
mod input;
mod keybindings;
mod notifier;
mod ui;

#[derive(Parser)]
#[command(name = "huddle", version, about = "Huddle — decentralized encrypted chat (TUI)")]
struct Cli {
    #[arg(long, help = "Override data directory")]
    data_dir: Option<String>,

    /// Connection mode. huddle 0.8 defaults to `server` (onion-relay
    /// only — no libp2p). Pass `mdns` (LAN auto-discover) or `direct`
    /// (manual dial only) to ALSO start a libp2p swarm alongside the
    /// relay. `server` is the recommended default for internet use.
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

    /// Phase D: register with a libp2p Circuit Relay v2 server so peers
    /// behind NAT can dial us via `<this-addr>/p2p-circuit/p2p/<our-id>`.
    /// Repeat to register with multiple relays. The multiaddr MUST
    /// include `/p2p/<peer-id>` so the dial enforces pubkey match.
    /// No defaults — you opt in.
    #[arg(long = "relay", value_name = "MULTIADDR")]
    relays: Vec<String>,

    /// Phase D: opt out of relay registration even if `config.toml` has
    /// entries. LAN-only operation.
    #[arg(long)]
    no_relay: bool,

    /// huddle 0.8: override the centralized server (a Tor onion relay)
    /// WebSocket URL. Defaults to the baked-in onion. `.onion` hosts are
    /// dialed through the local Tor SOCKS5 proxy (127.0.0.1:9050).
    #[arg(long = "server", value_name = "WS_URL")]
    server: Option<String>,

    /// huddle 0.8: don't connect to the centralized server. Combined with
    /// the default (no `--mode`), this leaves NO transport — useful only
    /// for offline inspection. With `--mode mdns|direct` it falls back to
    /// libp2p-only (LAN / relay).
    #[arg(long)]
    no_server: bool,

    /// huddle 0.8: override the local Tor SOCKS5 proxy used to reach
    /// `.onion` server URLs (default 127.0.0.1:9050) — e.g. the Tor
    /// Browser bundle's 127.0.0.1:9150. Also settable in config.toml as
    /// `tor_socks = "..."`; this flag wins.
    #[arg(long = "tor-socks", value_name = "HOST:PORT")]
    tor_socks: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// huddle 0.6: print version, paths, and config for bug reports.
    /// Useful for "what does my install look like?" — runs without
    /// the TUI, doesn't touch the network, and never asks for the
    /// master passphrase.
    Doctor,
}

fn parse_mode(s: &str) -> std::result::Result<NetworkMode, String> {
    NetworkMode::from_str(s).ok_or_else(|| format!("unknown mode `{s}` (try mdns or direct)"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // huddle 0.6: `huddle doctor` runs without the TUI, log appender,
    // or network. Just a pretty diagnostic dump for bug reports.
    if let Some(Commands::Doctor) = &cli.command {
        return run_doctor();
    }

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

    let cli_mode_explicit = cli.mode.is_some();
    // huddle 0.9.1: the startup mode is resolved AFTER the master key is
    // available (below), so we can honor the persisted in-app mDNS toggle
    // without the user hand-editing config.toml. `--mode`, when given, still
    // wins; the welcome card is skipped for explicit-mode launches.

    // Skip the welcome card if a mode was given explicitly — power users
    // who script `--mode direct` don't want a prompt in the way.
    if !cli_mode_explicit && !app::show_welcome()? {
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

    // huddle 0.9.1: resolve the startup network mode. An explicit `--mode`
    // wins; otherwise honor the persisted in-app "run LAN mDNS alongside the
    // relay" toggle (Settings → Network). `Mdns` runs libp2p AND the onion
    // relay together; `Server` (the default when the toggle is off) is
    // relay-only.
    let mode = if let Some(m) = cli.mode {
        m
    } else if huddle_core::app::AppHandle::peek_mdns_enabled(master_key.as_ref())
        .unwrap_or(false)
    {
        NetworkMode::Mdns
    } else {
        NetworkMode::Server
    };

    // Phase D: assemble the relay multiaddr list. CLI flags override
    // config.toml. `--no-relay` wins over everything else.
    let relays: Vec<Multiaddr> = if cli.no_relay {
        Vec::new()
    } else {
        let mut from_cli: Vec<String> = cli.relays.clone();
        if from_cli.is_empty() {
            from_cli = huddle_core::config::load_relays()
                .unwrap_or_default();
        }
        let mut parsed = Vec::new();
        for s in &from_cli {
            match s.parse::<Multiaddr>() {
                Ok(m) => parsed.push(m),
                Err(e) => tracing::warn!(%e, addr = %s, "ignoring invalid --relay addr"),
            }
        }
        parsed
    };

    // huddle 0.9.1: libp2p is opt-in either via `--mode mdns|direct` OR the
    // persisted in-app mDNS toggle (resolved into `mode` above). When on,
    // the libp2p swarm runs alongside the onion relay; otherwise relay-only.

    // huddle 0.8: resolve the centralized-server URL. `--no-server` wins;
    // otherwise precedence is `--server` flag → config.toml `server_url` →
    // the baked-in default onion. The onion address is self-authenticating
    // (it IS the server's key), so baking it in pins the server identity;
    // the override exists so you can repoint without recompiling.
    let server_url: Option<String> = if cli.no_server {
        None
    } else {
        Some(
            cli.server
                .clone()
                .or_else(huddle_core::config::server_url)
                .unwrap_or_else(|| huddle_core::app::DEFAULT_SERVER_URL.to_string()),
        )
    };
    // SOCKS proxy override: `--tor-socks` flag → config.toml `tor_socks` →
    // (core default 127.0.0.1:9050). `None` lets core pick the default.
    let tor_socks: Option<String> = cli.tor_socks.clone().or_else(huddle_core::config::tor_socks);

    if server_url.is_none() && !mode.uses_libp2p() {
        tracing::warn!(
            "no transport configured (--no-server with default mode) — \
             huddle will run offline; pass --mode mdns|direct for LAN"
        );
    }

    let handle = huddle_core::app::AppHandle::start_with_options(
        mode,
        cli.port,
        master_key.as_ref(),
        relays,
        server_url,
        tor_socks,
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

/// huddle 0.6: print a diagnostic snapshot — version, build target,
/// data paths, file sizes, config contents. Output is plain text
/// (no TUI) so users can copy-paste into bug reports.
fn run_doctor() -> Result<()> {
    use huddle_core::config;
    use std::fs;

    println!("huddle {}", env!("CARGO_PKG_VERSION"));
    println!("tui version: 2.0 (sidebar + pane)");
    println!("repository: https://github.com/richer-richard/huddle");
    println!();
    println!("paths:");
    let data_dir = config::data_dir();
    let db_path = config::db_path();
    let log_path = config::log_path();
    let config_path = config::config_path();
    println!("  data dir:   {}", data_dir.display());
    println!("  database:   {}", db_path.display());
    println!("  log file:   {}", log_path.display());
    println!("  config:     {}", config_path.display());
    println!();

    let exists = |p: &std::path::Path| {
        if let Ok(meta) = fs::metadata(p) {
            let kb = meta.len() / 1024;
            format!("present ({} KB)", kb)
        } else {
            "absent".to_string()
        }
    };
    println!("data files:");
    for name in &[
        "huddle.db",
        "huddle.db-shm",
        "huddle.db-wal",
        "keychain.salt",
        "identity.key",
        "huddle.log",
    ] {
        let p = data_dir.join(name);
        println!("  {:<16} {}", format!("{}:", name), exists(&p));
    }
    println!();

    // Config: just print the relay list if any.
    match config::load_relays() {
        Some(list) if !list.is_empty() => {
            println!("relays configured (from config.toml):");
            for r in list {
                println!("  {}", r);
            }
        }
        _ => {
            println!("relays: none configured");
        }
    }
    println!();

    println!("for support, open an issue at:");
    println!("  https://github.com/richer-richard/huddle/issues");
    Ok(())
}
