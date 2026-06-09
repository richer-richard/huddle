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
    /// huddle 2.0.0 (F5): change the master passphrase. A failure (wrong current
    /// passphrase) routes back to the modal's inline error; success arrives as
    /// AppEvent::PassphraseChanged.
    ChangePassphrase,
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
    /// huddle 1.0: clearnet relay door (`--clearnet-server`); `None` lets the
    /// core fold in config.toml + the persisted in-app setting.
    pub clearnet_url: Option<String>,
    /// huddle 1.0: bridge line (`--tor-bridge`).
    pub tor_bridge: Option<String>,
    /// huddle 1.0: pin one door (`--transport`).
    pub transport_pin: Option<String>,
    /// huddle 1.0: explicit door order (`--transport-order`).
    pub transport_order: Option<Vec<String>>,
    pub auth: AuthChoice,
    pub name: Option<String>,
    /// huddle 2.0.0 (F6): on a fresh install, restore the identity from this
    /// 24-word BIP39 seed phrase before the handle generates a random one.
    /// `None` keeps the default (generate a new identity). Ignored when a
    /// stored identity already exists.
    pub import_phrase: Option<String>,
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

    // huddle 1.0: the relay is reached through transport "doors". Pass the full
    // set through so the GUI has parity with the TUI; the core folds in
    // config.toml + the persisted in-app clearnet/order settings for any field
    // left `None` (e.g. a relay set from Settings → Network or an invite).
    let transports = huddle_core::app::TransportConfig {
        onion_url: params.server_url,
        clearnet_url: params.clearnet_url,
        tor_socks: params.tor_socks,
        tor_bridge: params.tor_bridge,
        pin: params.transport_pin,
        order: params.transport_order,
    };
    let handle = match params.import_phrase {
        // huddle 2.0.0 (F6): fresh-install identity restore. Seed the DB with the
        // imported identity BEFORE the handle loads it, then start on that same
        // DB. This mirrors `AppHandle::start_with_options`' own
        // `open_db → start_with_db_and_options` funnel, with one extra step (save
        // the imported secret). The `load_identity` guard makes it a no-op if an
        // identity already exists, so a stray import phrase can never overwrite
        // one.
        Some(phrase) => {
            use huddle_core::storage::repo;
            huddle_core::config::ensure_data_dir().map_err(|e| e.to_string())?;
            let persist = match key {
                Some(mk) => keychain::derive_subkey(&mk, b"megolm-persist"),
                None => [0u8; 32],
            };
            let db = huddle_core::storage::open_db(&huddle_core::config::db_path(), key.as_ref())
                .map_err(|e| e.to_string())?;
            if repo::load_identity(&db).map_err(|e| e.to_string())?.is_none() {
                let id = huddle_core::app::import_identity_from_phrase(&phrase)
                    .map_err(|e| e.to_string())?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                repo::save_identity(&db, &id.secret_bytes(), now).map_err(|e| e.to_string())?;
            }
            AppHandle::start_with_db_and_options(
                db,
                mode,
                params.port,
                persist,
                params.relays,
                transports,
            )
            .await
            .map_err(|e| e.to_string())?
        }
        None => AppHandle::start_with_options(
            mode,
            params.port,
            key.as_ref(),
            params.relays,
            transports,
        )
        .await
        .map_err(|e| e.to_string())?,
    };

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
