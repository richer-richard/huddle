//! huddle-core crypto: the runtime-free constructions live in `huddle-protocol`
//! and are re-exported here at their original `crate::crypto::…` paths; the
//! Megolm group ratchet (`RoomCrypto`), which needs vodozemac + SQLCipher
//! persistence, stays in this crate.

pub mod megolm;

pub use megolm::RoomCrypto;

// huddle 2.0.4 (WS1.1): the pure wire/crypto surface, re-exported so existing
// `crate::crypto::{verify_signed, sign_message, dm, sas, pqc, passphrase,
// mnemonic, SIGNED_ENVELOPE_WINDOW_MS, …}` call sites are unchanged. (The
// private `signed_bytes` / `now_unix_ms` helpers stay internal to the protocol
// crate.)
pub use huddle_protocol::crypto::{
    dm, mnemonic, passphrase, pqc, sas, sign_message, sign_message_at, verify_signed,
    verify_signed_at, SIGNED_ENVELOPE_WINDOW_MS,
};
