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
mod install;
mod keybindings;
mod notifier;
mod ui;

#[derive(Parser)]
#[command(
    name = "huddle",
    version,
    about = "Huddle — decentralized encrypted chat (TUI)"
)]
struct Cli {
    #[arg(long, help = "Override data directory")]
    data_dir: Option<String>,

    /// Connection mode. By default huddle runs LAN discovery (libp2p
    /// mDNS) AND the relay together — no flag needed. Pass `mdns`,
    /// `direct` (libp2p without LAN broadcast), or `server` (relay only,
    /// no libp2p) to override. When absent, LAN follows the Settings →
    /// Network toggle (on by default).
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

    /// Don't connect to the relay. LAN (libp2p) still works by default,
    /// so this gives you LAN-only operation. Combined with an explicit
    /// `--mode server` it leaves no transport (offline inspection only).
    #[arg(long)]
    no_server: bool,

    /// huddle 0.8: override the local Tor SOCKS5 proxy used to reach
    /// `.onion` server URLs (default 127.0.0.1:9050) — e.g. the Tor
    /// Browser bundle's 127.0.0.1:9150. Also settable in config.toml as
    /// `tor_socks = "..."`; this flag wins.
    #[arg(long = "tor-socks", value_name = "HOST:PORT")]
    tor_socks: Option<String>,

    /// huddle 1.0: a clearnet relay URL onto the SAME backend as the onion —
    /// `ws://<ip>:<port>/ws` (plain, fast) or `wss://host/ws` (TLS). For VPN
    /// users or networks where Tor is blocked. Also `clearnet_url` in config.
    #[arg(long = "clearnet-server", value_name = "WS_URL")]
    clearnet_server: Option<String>,

    /// huddle 1.0: pin a single transport "door" by id (run
    /// `huddle transports` to list them): onion-tor, onion-bridge,
    /// onion-arti, clearnet-wss, clearnet-ws. Default tries them in order.
    #[arg(long = "transport", value_name = "ID")]
    transport: Option<String>,

    /// huddle 1.0: explicit fallback order, comma-separated transport ids
    /// (most-preferred first). Overrides the default most-private-first order.
    #[arg(long = "transport-order", value_name = "ID,ID,...")]
    transport_order: Option<String>,

    /// huddle 1.0: a Tor bridge line (obfs4/WebTunnel) for the bridge door,
    /// to reach Tor where it's blocked. Also `tor_bridge` in config.
    #[arg(long = "tor-bridge", value_name = "LINE")]
    tor_bridge: Option<String>,

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
    /// huddle 1.0: list the transport "doors" onto the relay (onion / bridge
    /// / Arti / clearnet), each with its privacy tradeoff and whether it's
    /// usable in this build + config. Runs without the TUI.
    Transports,
    /// huddle 1.1.3: build the desktop GUI from source and install it where the
    /// OS keeps apps (macOS `/Applications/Huddle.app`, Linux `.desktop` in the
    /// app menu, Windows Start Menu), then launch it. Run from a source clone
    /// (or set `HUDDLE_SRC`). The plain `huddle` command still opens the TUI.
    App,
}

fn parse_mode(s: &str) -> std::result::Result<NetworkMode, String> {
    NetworkMode::from_str(s).ok_or_else(|| format!("unknown mode `{s}` (try mdns or direct)"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // huddle 0.6: `huddle doctor` runs without the TUI, log appender,
    // or network. Just a pretty diagnostic dump for bug reports.
    // huddle 1.0: `huddle transports` lists the anti-censorship doors.
    match &cli.command {
        Some(Commands::Doctor) => return run_doctor(),
        Some(Commands::Transports) => return run_transports(&cli),
        // huddle 1.1.3: build + install + launch the desktop GUI. Runs without
        // the TUI / log appender / network, like `doctor` and `transports`.
        Some(Commands::App) => return install::run(),
        None => {}
    }

    let log_path = huddle_core::config::log_path();
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file_appender = rolling::never(log_path.parent().unwrap(), log_path.file_name().unwrap());
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("huddle=debug".parse()?))
        .with_writer(file_appender)
        .with_ansi(false)
        .init();

    // Restore the terminal on panic before the message prints, so a crash
    // inside the TUI doesn't leave the shell in raw mode / alt screen.
    app::install_panic_hook();

    let cli_mode_explicit = cli.mode.is_some();
    // huddle 0.9.2: the startup mode is resolved AFTER the master key is
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
        // huddle 2.0.0 (F6): on a fresh launch, offer to recover an existing
        // identity from a BIP39 seed phrase before the user picks a (local)
        // master passphrase. The phrase recovers the Ed25519 identity; the
        // passphrase still encrypts the local database.
        let imported_seed_phrase = if is_new {
            app::prompt_import_seed()?
        } else {
            None
        };
        let prompt = app::prompt_master_passphrase(is_new)?;
        if prompt.passphrase.is_empty() {
            return Ok(());
        }
        // Only persist the salt once the user has committed a
        // passphrase — otherwise pressing Esc on first launch leaves
        // a salt file behind and a future launch would think the DB
        // already existed.
        let salt = keychain::load_or_create_salt().map_err(|e| anyhow!(e))?;
        let key = keychain::derive_master_key(&prompt.passphrase, &salt).map_err(|e| anyhow!(e))?;
        // huddle 2.0.0 (F6): persist the recovered identity into the freshly
        // created (encrypted) database before the AppHandle would otherwise
        // generate a random one.
        if let Some(phrase) = &imported_seed_phrase {
            import_identity_into_db(&key, phrase)?;
        }
        (Some(key), prompt.username)
    };

    // huddle 0.9.2: resolve the startup network mode. An explicit `--mode`
    // wins; otherwise honor the persisted in-app "run LAN mDNS alongside the
    // relay" toggle (Settings → Network). `Mdns` runs libp2p AND the onion
    // relay together; `Server` (the default when the toggle is off) is
    // relay-only.
    let mode = if let Some(m) = cli.mode {
        m
    } else if huddle_core::app::AppHandle::peek_mdns_enabled(master_key.as_ref()).unwrap_or(false) {
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
            from_cli = huddle_core::config::load_relays().unwrap_or_default();
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

    // huddle 0.9.2: libp2p is opt-in either via `--mode mdns|direct` OR the
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
    let tor_socks: Option<String> = cli
        .tor_socks
        .clone()
        .or_else(huddle_core::config::tor_socks);

    if server_url.is_none() && !mode.uses_libp2p() {
        tracing::warn!(
            "no transport configured (--no-server with --mode server) — \
             huddle will run offline; drop --mode server (LAN is on by \
             default) or remove --no-server"
        );
    }

    // huddle 1.0: bundle the transport inputs. The onion url + tor_socks are
    // resolved above (CLI → config → default); clearnet / bridge / pin / order
    // pass the raw CLI values and the core folds in config.toml + saved
    // settings before building the ordered set of doors.
    let transports = huddle_core::app::TransportConfig {
        onion_url: server_url,
        clearnet_url: cli.clearnet_server.clone(),
        tor_socks,
        tor_bridge: cli.tor_bridge.clone(),
        pin: cli.transport.clone(),
        order: cli.transport_order.as_ref().map(|s| {
            s.split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect()
        }),
    };

    let handle = huddle_core::app::AppHandle::start_with_options(
        mode,
        cli.port,
        master_key.as_ref(),
        relays,
        transports,
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

/// huddle 2.0.0 (F6): persist a seed-recovered identity into the (just-created)
/// encrypted database so the AppHandle loads it instead of generating a fresh
/// random one. Opens the DB with the master key, validates + decodes the phrase,
/// and writes the identity only if none exists yet (defensive — a fresh launch
/// has none). The connection is dropped before `start_with_options` reopens the
/// same file.
fn import_identity_into_db(master_key: &[u8; 32], phrase: &str) -> Result<()> {
    use huddle_core::storage::{self, repo};

    let id = huddle_core::app::import_identity_from_phrase(phrase).map_err(|e| anyhow!(e))?;
    let db = storage::open_db(&huddle_core::config::db_path(), Some(master_key))
        .map_err(|e| anyhow!(e))?;
    if repo::load_identity(&db).map_err(|e| anyhow!(e))?.is_none() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        repo::save_identity(&db, &id.secret_bytes(), now).map_err(|e| anyhow!(e))?;
        tracing::info!(fingerprint = %id.fingerprint(), "recovered identity from seed phrase");
    }
    Ok(())
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

/// huddle 1.0: print the transport "doors" onto the relay — each one's
/// privacy / anti-censorship tradeoff and whether it's usable in this build +
/// config — in the order the app would try them. No TUI, no network.
fn run_transports(cli: &Cli) -> Result<()> {
    use huddle_core::network::transport::{builtin_profiles, default_fallback_order, TransportId};

    let onion = if cli.no_server {
        None
    } else {
        Some(
            cli.server
                .clone()
                .or_else(huddle_core::config::server_url)
                .unwrap_or_else(|| huddle_core::app::DEFAULT_SERVER_URL.to_string()),
        )
    };
    let clearnet = cli
        .clearnet_server
        .clone()
        .or_else(huddle_core::config::clearnet_url)
        // huddle 1.1: surface the operator's baked-in clearnet door, gated on
        // the onion default being present (mirrors AppHandle's resolution).
        .or_else(|| {
            onion
                .as_ref()
                .map(|_| huddle_core::app::DEFAULT_CLEARNET_URL.to_string())
        });
    let tor_socks = cli
        .tor_socks
        .clone()
        .or_else(huddle_core::config::tor_socks)
        .unwrap_or_else(|| huddle_core::app::DEFAULT_TOR_SOCKS.to_string());
    let bridge = cli
        .tor_bridge
        .clone()
        .or_else(huddle_core::config::tor_bridge);

    let profiles = builtin_profiles(
        onion.as_deref(),
        clearnet.as_deref(),
        &tor_socks,
        bridge.as_deref(),
    );

    let order: Vec<TransportId> =
        if let Some(pin) = cli.transport.as_deref().and_then(TransportId::from_str) {
            vec![pin]
        } else if let Some(o) = cli.transport_order.as_deref() {
            let v: Vec<TransportId> = o.split(',').filter_map(TransportId::from_str).collect();
            if v.is_empty() {
                default_fallback_order()
            } else {
                v
            }
        } else {
            default_fallback_order()
        };

    println!("huddle transports — doors onto the relay (most private first)\n");
    for id in &order {
        if let Some(p) = profiles.iter().find(|p| p.id == *id) {
            let status = if p.available() {
                format!("AVAILABLE   {}", p.url.as_deref().unwrap_or(""))
            } else {
                format!("unavailable ({})", p.reason.unwrap_or(""))
            };
            println!("  [{}] {}", p.id.as_str(), p.id.label());
            println!("      {status}");
            println!("      {}", p.id.description());
            println!();
        }
    }
    if cli.transport.is_some() {
        println!("(pinned to a single door via --transport)");
    } else {
        println!("Tried top-to-bottom until one connects — onion is most private, clearnet-ws the least.");
    }
    Ok(())
}
