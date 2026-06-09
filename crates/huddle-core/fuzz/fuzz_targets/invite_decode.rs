#![no_main]
//! Fuzz the `huddle://invite#...` parser against arbitrary input.
//!
//! `invite::decode` parses, base64url-decodes, JSON-deserializes, and (for
//! v>=2) verifies an Ed25519 signature over attacker-controlled bytes. It must
//! never panic — every malformed, truncated, or hostile input has to surface as
//! a clean `Err`.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = huddle_core::invite::decode(s);
    }
});
