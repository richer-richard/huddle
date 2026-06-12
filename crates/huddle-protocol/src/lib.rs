//! # huddle-protocol
//!
//! The Huddle wire protocol and the pure cryptographic constructions it rests
//! on, extracted into one runtime-free crate so both the client
//! (`huddle-core`) and the relay (`huddle-server`) speak from a single source
//! of truth — "the spec, as code."
//!
//! This crate depends ONLY on RustCrypto-family + serde crates: no `tokio`,
//! `libp2p`, `rusqlite`, or `vodozemac`. Anything needing a runtime — the
//! Megolm group ratchet with its SQLCipher persistence, the libp2p identity
//! wrapper, transports, storage — stays in `huddle-core`, which re-exports the
//! items here at their original module paths so existing call sites are
//! unchanged.
//!
//! Wire compatibility is a hard invariant: every type here serializes
//! byte-for-byte as it did before extraction (1.x / 2.x peers and relays are
//! unaffected). New optional fields use `#[serde(default, skip_serializing_if
//! = "...")]` so they stay off the wire when unset.

pub mod crypto;
pub mod error;
pub mod identity;
pub mod invite;
pub mod protocol;
pub mod relay;

pub use error::{ProtocolError, Result};
pub use identity::{
    compute_fingerprint, relay_auth_msg, safety_code, IdentityKeys, RELAY_AUTH_DOMAIN,
};
pub use protocol::{
    EncryptedFileMeta, RoomAnnouncement, RoomKind, RoomMessage, SignedRoomMessage, WireMessage,
};
