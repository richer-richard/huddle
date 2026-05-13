//! Wire protocol for room discovery and message broadcast.
//!
//! Two gossipsub topics:
//!   - `ROOMS_TOPIC` — global, every node subscribes. Used for room
//!     advertisements (so all peers see "rooms in this network").
//!   - `format!("{ROOM_TOPIC_PREFIX}{room_id}")` — per-room. Only members
//!     of a room subscribe. All room messages flow here.

use serde::{Deserialize, Serialize};

pub const ROOMS_TOPIC: &str = "huddle-rooms-v1";
pub const ROOM_TOPIC_PREFIX: &str = "huddle-room-";

pub fn room_topic(room_id: &str) -> String {
    format!("{ROOM_TOPIC_PREFIX}{room_id}")
}

/// Broadcast on the global ROOMS_TOPIC. Each peer republishes the rooms
/// they're currently in, periodically. Listeners maintain a cache with TTL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomAnnouncement {
    pub room_id: String,
    pub name: String,
    pub encrypted: bool,
    /// Argon2id salt — present iff `encrypted`. Joiners derive their
    /// passphrase key from (passphrase, salt) to unwrap session keys.
    pub passphrase_salt: Option<Vec<u8>>,
    pub member_count: u32,
    pub creator_fingerprint: String,
    /// Seconds since UNIX_EPOCH when this announcement was emitted.
    pub announced_at: i64,
}

/// All messages on a room's per-room topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoomMessage {
    /// Announce my presence in the room. For encrypted rooms, also share
    /// my Megolm session key (passphrase-wrapped).
    MemberAnnounce {
        sender_fingerprint: String,
        /// base64(nonce || chacha20poly1305_ciphertext) of the Megolm
        /// SessionKey, encrypted under the passphrase-derived key.
        /// None for unencrypted rooms.
        wrapped_session_key: Option<String>,
    },
    /// A request from a recently-joined member: "I need session keys".
    /// Existing members respond with MemberAnnounce.
    SessionKeyRequest {
        requester_fingerprint: String,
    },
    /// An encrypted message in an encrypted room.
    Encrypted {
        sender_fingerprint: String,
        session_id: String,
        /// base64-encoded MegolmMessage bytes
        ciphertext_b64: String,
    },
    /// A plaintext message in an unencrypted room.
    Plain {
        sender_fingerprint: String,
        body: String,
    },
    /// Explicit leave notification.
    MemberLeave {
        sender_fingerprint: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_announcement_round_trip() {
        let ann = RoomAnnouncement {
            room_id: "rid".into(),
            name: "general".into(),
            encrypted: true,
            passphrase_salt: Some(vec![1, 2, 3, 4]),
            member_count: 3,
            creator_fingerprint: "creator-fp".into(),
            announced_at: 100,
        };
        let json = serde_json::to_vec(&ann).unwrap();
        let back: RoomAnnouncement = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.name, "general");
        assert_eq!(back.passphrase_salt, Some(vec![1, 2, 3, 4]));
    }

    #[test]
    fn room_message_variants_round_trip() {
        let msgs = vec![
            RoomMessage::MemberAnnounce {
                sender_fingerprint: "fp".into(),
                wrapped_session_key: Some("base64data".into()),
            },
            RoomMessage::Plain {
                sender_fingerprint: "fp".into(),
                body: "hi".into(),
            },
            RoomMessage::Encrypted {
                sender_fingerprint: "fp".into(),
                session_id: "sid".into(),
                ciphertext_b64: "ct".into(),
            },
            RoomMessage::SessionKeyRequest {
                requester_fingerprint: "fp".into(),
            },
            RoomMessage::MemberLeave {
                sender_fingerprint: "fp".into(),
            },
        ];
        for m in msgs {
            let json = serde_json::to_vec(&m).unwrap();
            let back: RoomMessage = serde_json::from_slice(&json).unwrap();
            assert_eq!(format!("{m:?}"), format!("{back:?}"));
        }
    }

    #[test]
    fn room_topic_format() {
        assert_eq!(room_topic("abc123"), "huddle-room-abc123");
    }
}
