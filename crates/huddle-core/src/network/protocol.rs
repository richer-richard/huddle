//! huddle 2.0.4 (WS1.1): the wire protocol moved to `huddle-protocol`. This
//! module re-exports it at its original `crate::network::protocol::…` path so
//! every app / network / storage call site (`WireMessage`, `RoomMessage`,
//! `SignedRoomMessage`, `RoomAnnouncement`, `RoomKind`, `EncryptedFileMeta`,
//! `ROOMS_TOPIC`, `room_topic`, …) is unchanged.

pub use huddle_protocol::protocol::*;
