//! The async bridge between `AppHandle` (tokio world) and egui (main-thread,
//! immediate-mode). This is the load-bearing part of the GUI.
//!
//! - `AppHandle` is built INSIDE the runtime (it calls `tokio::spawn`
//!   internally), and the result is handed back over a oneshot.
//! - One pump task owns the `broadcast::Receiver<AppEvent>` and forwards every
//!   event into a `crossbeam_channel` the UI drains each frame, waking egui via
//!   `Context::request_repaint()` (the documented cross-thread mechanism).
//! - UI-thread mutations fire-and-forget through `Cmd`; the few return-value
//!   commands deliver their result back through the same inbox.

use huddle_core::app::events::AppEvent;
use huddle_core::app::AppHandle;
use huddle_core::network::NetworkMode;
use libp2p::Multiaddr;
use std::future::Future;
use std::path::PathBuf;

/// Everything the UI drains from the worker side, in one channel.
pub enum Inbox {
    /// A core event arrived on the broadcast stream.
    Event(AppEvent),
    /// The broadcast receiver fell behind and dropped `n` events.
    Lagged(u64),
    /// A fire-and-forget command failed.
    CmdError(String),
    /// A return-value command succeeded.
    ReqOk(ReqTag, ReqOk),
    /// A return-value command failed.
    ReqErr(ReqTag, String),
}

/// Identifies which return-value command an `Inbox::ReqOk/ReqErr` belongs to,
/// so the reducer can route the result to the right place.
#[derive(Debug, Clone)]
#[allow(dead_code)] // variants wired up across later phases
pub enum ReqTag {
    StartRoom,
    StartDirect,
    JoinCode { room_id: String, room_name: String },
    SaveDownload { file_id: String },
    SasStart { room_id: String, partner: String },
    SendFile,
    GoDark,
}

/// The payload of a successful return-value command.
#[derive(Debug, Clone)]
#[allow(dead_code)] // variants wired up across later phases
pub enum ReqOk {
    RoomId(String),
    JoinCode(String),
    SavedPath(PathBuf),
    TxId(String),
    FileId(String),
    Unit,
}

/// How to authenticate the local database at startup.
pub enum AuthChoice {
    /// `--no-master-passphrase`: unencrypted DB, key = None.
    NoPassphrase,
    /// Derive the master key from this passphrase (Argon2id, off the UI thread).
    Passphrase(String),
}

/// Inputs needed to bring up an `AppHandle`.
pub struct BuildParams {
    /// An explicit `--mode` flag, if given. When `None`, the startup mode is
    /// resolved from the persisted in-app mDNS toggle (default relay-only).
    pub explicit_mode: Option<NetworkMode>,
    pub port: u16,
    pub relays: Vec<Multiaddr>,
    pub server_url: Option<String>,
    pub tor_socks: Option<String>,
    pub auth: AuthChoice,
    pub name: Option<String>,
}

/// Handed back to the UI once the handle is up and the pump is running.
pub struct ReadyParts {
    pub handle: AppHandle,
    pub inbox_rx: crossbeam_channel::Receiver<Inbox>,
    pub inbox_tx: crossbeam_channel::Sender<Inbox>,
}

/// Spawn the handle build on the runtime and return a oneshot the UI polls.
pub fn spawn_build(
    rt: &tokio::runtime::Handle,
    ctx: egui::Context,
    params: BuildParams,
) -> tokio::sync::oneshot::Receiver<Result<ReadyParts, String>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    rt.spawn(async move {
        let res = build_inner(ctx, params).await;
        let _ = tx.send(res);
    });
    rx
}

async fn build_inner(ctx: egui::Context, params: BuildParams) -> Result<ReadyParts, String> {
    use huddle_core::storage::keychain;

    let key: Option<[u8; 32]> = match params.auth {
        AuthChoice::NoPassphrase => None,
        AuthChoice::Passphrase(pass) => {
            // Mirror the TUI guard: a DB with no keychain salt was created by a
            // previous `--no-master-passphrase` run and is unencrypted.
            if !keychain::keychain_salt_path().exists() && huddle_core::config::db_path().exists() {
                return Err(format!(
                    "found an existing database with no keychain salt — it was created \
                     with --no-master-passphrase and is unencrypted. Re-run with \
                     --no-master-passphrase, or move {} aside to start fresh.",
                    huddle_core::config::db_path().display()
                ));
            }
            let salt = keychain::load_or_create_salt().map_err(|e| e.to_string())?;
            // Argon2id (64 MiB, 3 iters) — heavy, but we're on a runtime worker,
            // not the UI thread.
            Some(keychain::derive_master_key(&pass, &salt).map_err(|e| e.to_string())?)
        }
    };

    // Resolve the startup mode: an explicit `--mode` wins; otherwise honor the
    // persisted in-app "run LAN mDNS alongside the relay" toggle (default off →
    // relay-only `Server`). `Mdns` runs libp2p AND the onion relay together.
    let mode = match params.explicit_mode {
        Some(m) => m,
        None => {
            if AppHandle::peek_mdns_enabled(key.as_ref()).unwrap_or(false) {
                NetworkMode::Mdns
            } else {
                NetworkMode::Server
            }
        }
    };

    // huddle 1.0: the relay is reached through transport "doors". The GUI
    // keeps its onion + SOCKS config; clearnet / bridge / Arti doors fall back
    // to config.toml + defaults (a future GUI pass can surface them).
    let transports = huddle_core::app::TransportConfig {
        onion_url: params.server_url,
        tor_socks: params.tor_socks,
        ..Default::default()
    };
    let handle = AppHandle::start_with_options(
        mode,
        params.port,
        key.as_ref(),
        params.relays,
        transports,
    )
    .await
    .map_err(|e| e.to_string())?;

    if let Some(n) = params.name {
        let trimmed = n.trim();
        if !trimmed.is_empty() {
            let _ = handle.set_display_name(Some(trimmed));
        }
    }

    let (tx, rx) = crossbeam_channel::unbounded::<Inbox>();
    spawn_event_pump(handle.subscribe(), tx.clone(), ctx);

    Ok(ReadyParts {
        handle,
        inbox_rx: rx,
        inbox_tx: tx,
    })
}

/// Forward every broadcast `AppEvent` into the UI inbox and wake the UI.
fn spawn_event_pump(
    mut events: tokio::sync::broadcast::Receiver<AppEvent>,
    tx: crossbeam_channel::Sender<Inbox>,
    ctx: egui::Context,
) {
    use tokio::sync::broadcast::error::RecvError;
    tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(ev) => {
                    if tx.send(Inbox::Event(ev)).is_err() {
                        break; // UI gone
                    }
                    ctx.request_repaint();
                }
                Err(RecvError::Lagged(n)) => {
                    let _ = tx.send(Inbox::Lagged(n));
                    ctx.request_repaint();
                }
                Err(RecvError::Closed) => break,
            }
        }
    });
}

/// Dispatches async `AppHandle` mutations from the UI thread onto the runtime.
/// Cheap to clone; lives in the `Ready` state.
#[derive(Clone)]
pub struct Cmd {
    rt: tokio::runtime::Handle,
    pub handle: AppHandle,
    tx: crossbeam_channel::Sender<Inbox>,
    ctx: egui::Context,
}

impl Cmd {
    pub fn new(
        rt: tokio::runtime::Handle,
        handle: AppHandle,
        tx: crossbeam_channel::Sender<Inbox>,
        ctx: egui::Context,
    ) -> Self {
        Self { rt, handle, tx, ctx }
    }

    /// Fire-and-forget: run an async mutation; on error, surface a `CmdError`.
    /// Effects (new messages, joins, …) arrive separately as `AppEvent`s.
    #[allow(dead_code)] // first callers land in Phase 2
    pub fn fire<F, Fut, E>(&self, f: F)
    where
        F: FnOnce(AppHandle) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
        E: std::fmt::Display + Send + 'static,
    {
        let handle = self.handle.clone();
        let tx = self.tx.clone();
        let ctx = self.ctx.clone();
        self.rt.spawn(async move {
            if let Err(e) = f(handle).await {
                let _ = tx.send(Inbox::CmdError(e.to_string()));
                ctx.request_repaint();
            }
        });
    }

    /// Run an async command whose return value the UI needs; deliver it back
    /// tagged so the reducer can route it.
    #[allow(dead_code)] // first callers land in Phase 4+
    pub fn request<F, Fut>(&self, tag: ReqTag, f: F)
    where
        F: FnOnce(AppHandle) -> Fut + Send + 'static,
        Fut: Future<Output = Result<ReqOk, String>> + Send + 'static,
    {
        let handle = self.handle.clone();
        let tx = self.tx.clone();
        let ctx = self.ctx.clone();
        self.rt.spawn(async move {
            match f(handle).await {
                Ok(ok) => {
                    let _ = tx.send(Inbox::ReqOk(tag, ok));
                }
                Err(e) => {
                    let _ = tx.send(Inbox::ReqErr(tag, e));
                }
            }
            ctx.request_repaint();
        });
    }
}
