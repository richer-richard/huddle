pub mod app;
pub mod config;
pub mod crypto;
pub mod error;
pub mod files;
pub mod identity;
pub mod invite;
pub mod network;
pub mod storage;

/// Install the process-wide rustls [`CryptoProvider`] (ring), idempotently.
///
/// rustls 0.23 builds no TLS config until a provider is selected. It *can*
/// auto-pick one from crate features, but only when exactly one of rustls'
/// `ring`/`aws-lc-rs` features is enabled in the final binary's dependency
/// closure. huddle-core pulls rustls via tokio-tungstenite's `wss://` door
/// without a provider feature, so before this fix only the TUI worked (it
/// enables `ring` transitively through `ureq`); huddle-gui's `wss` worker
/// thread panicked at startup. We now depend on rustls' `ring` directly and
/// install it here, so every consumer is deterministic regardless of which
/// other crates happen to be in the closure.
///
/// Called at the top of the [`AppHandle`](crate::app::AppHandle) start path,
/// before any transport door builds a TLS config. Safe to call repeatedly —
/// a second call (or one racing a transitive dep's install) is a no-op.
///
/// [`CryptoProvider`]: https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html
pub fn install_default_crypto_provider() {
    // `install_default` returns Err if a provider was already installed — by
    // an earlier call here or by a transitive dependency. Either way the
    // process has a provider afterward, so the error is not actionable.
    let _ = rustls::crypto::ring::default_provider().install_default();
}
