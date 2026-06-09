#![no_main]
//! Fuzz serde/JSON decoding of a wire `RoomMessage`.
//!
//! Every gossipsub payload is an untrusted, attacker-shaped `RoomMessage`.
//! Deserialization of arbitrary bytes must fail cleanly (`Err`) and never panic,
//! recurse without bound, or over-allocate into an abort.

use libfuzzer_sys::fuzz_target;

use huddle_core::network::protocol::RoomMessage;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<RoomMessage>(data);
});
