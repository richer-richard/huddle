//! Command-line flags — a mirror of the TUI's `crates/huddle/src/main.rs`
//! so the GUI honors the same `--mode` / `--server` / relay options.

use clap::{Parser, Subcommand};
use huddle_core::network::NetworkMode;
use libp2p::Multiaddr;

#[derive(Parser)]
#[command(name = "huddle-gui", version, about = "Huddle — decentralized encrypted chat (native GUI)")]
pub struct Cli {
    /// Override the data directory (best-effort — see `apply_data_dir_override`).
    #[arg(long)]
    pub data_dir: Option<String>,

    /// Connection mode. Defaults to `server` (Tor onion relay only). Pass
    /// `mdns` (LAN auto-discover) or `direct` (manual dial) to ALSO start a
    /// libp2p swarm alongside the relay.
    #[arg(long, value_parser = parse_mode)]
    pub mode: Option<NetworkMode>,

    /// TCP port to listen on (0 = random). Only relevant with `--mode mdns|direct`.
    #[arg(long, default_value_t = 0u16)]
    pub port: u16,

    /// Display name shown alongside your short fingerprint in chat.
    #[arg(long)]
    pub name: Option<String>,

    /// Run with an unencrypted at-rest database (skips the unlock screen).
    #[arg(long)]
    pub no_master_passphrase: bool,

    /// Register with a libp2p Circuit Relay v2 server. Repeat for multiple.
    #[arg(long = "relay", value_name = "MULTIADDR")]
    pub relays: Vec<String>,

    /// Opt out of relay registration even if `config.toml` has entries.
    #[arg(long)]
    pub no_relay: bool,

    /// Override the centralized server (Tor onion relay) WebSocket URL.
    #[arg(long = "server", value_name = "WS_URL")]
    pub server: Option<String>,

    /// Don't connect to the centralized server.
    #[arg(long)]
    pub no_server: bool,

    /// Override the local Tor SOCKS5 proxy used to reach `.onion` URLs.
    #[arg(long = "tor-socks", value_name = "HOST:PORT")]
    pub tor_socks: Option<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Print version, paths, and config for bug reports (no window).
    Doctor,
}

fn parse_mode(s: &str) -> std::result::Result<NetworkMode, String> {
    NetworkMode::from_str(s).ok_or_else(|| format!("unknown mode `{s}` (try server, mdns or direct)"))
}

impl Cli {
    pub fn parse_args() -> Self {
        <Self as Parser>::parse()
    }

    pub fn is_doctor(&self) -> bool {
        matches!(self.command, Some(Commands::Doctor))
    }

    pub fn resolve_relays(&self) -> Vec<Multiaddr> {
        if self.no_relay {
            return Vec::new();
        }
        let mut from = self.relays.clone();
        if from.is_empty() {
            from = huddle_core::config::load_relays().unwrap_or_default();
        }
        from.iter()
            .filter_map(|s| match s.parse::<Multiaddr>() {
                Ok(m) => Some(m),
                Err(e) => {
                    tracing::warn!(%e, addr = %s, "ignoring invalid --relay addr");
                    None
                }
            })
            .collect()
    }

    pub fn resolve_server_url(&self) -> Option<String> {
        if self.no_server {
            None
        } else {
            Some(
                self.server
                    .clone()
                    .or_else(huddle_core::config::server_url)
                    .unwrap_or_else(|| huddle_core::app::DEFAULT_SERVER_URL.to_string()),
            )
        }
    }

    pub fn resolve_tor_socks(&self) -> Option<String> {
        self.tor_socks.clone().or_else(huddle_core::config::tor_socks)
    }
}

/// huddle-core derives all paths from the `dirs` crate, which has no single
/// override knob. As a best-effort testing aid, point the platform data /
/// config roots at `dir` so a second instance can run against an isolated
/// profile. Must be called BEFORE any core path resolution (logging, salt
/// check) and while the process is still single-threaded.
pub fn apply_data_dir_override(dir: &str) {
    // Linux (XDG) — the clean path.
    std::env::set_var("XDG_DATA_HOME", dir);
    std::env::set_var("XDG_CONFIG_HOME", dir);
    // macOS resolves data_dir() from $HOME/Library/Application Support, and
    // Windows from %APPDATA%; override those so isolation works cross-platform.
    #[cfg(target_os = "macos")]
    std::env::set_var("HOME", dir);
    #[cfg(target_os = "windows")]
    std::env::set_var("APPDATA", dir);
}
