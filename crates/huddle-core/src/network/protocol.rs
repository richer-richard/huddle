//! Wire protocol for room discovery and message broadcast.
//!
//! Two gossipsub topics:
//!   - `ROOMS_TOPIC` — global, every node subscribes. Used for room
//!     advertisements (so all peers see "rooms in this network").
//!   - `format!("{ROOM_TOPIC_PREFIX}{room_id}")` — per-room. Only members
//!     of a room subscribe. All room messages flow here.

use serde::{Deserialize, Serialize};

use crate::files::encryption::EncryptedFileMeta;

pub const ROOMS_TOPIC: &str = "huddle-rooms-v1";
pub const ROOM_TOPIC_PREFIX: &str = "huddle-room-";

pub fn room_topic(room_id: &str) -> String {
    format!("{ROOM_TOPIC_PREFIX}{room_id}")
}

/// Application-level signed envelope around a `RoomMessage`. Used for
/// any message whose authenticity matters beyond gossipsub's transport-
/// level signing.
///
/// The following variants MUST be sent inside a `Signed` envelope, and
/// receivers MUST drop them when they arrive unsigned:
///   - `RotateRoomKey` (signer must equal the claimed `rotator_fingerprint`)
///   - `OwnerGrant`, `BanMember` (signer must be a current room owner)
///   - `SasInit`, `SasResponse`, `SasConfirm` (SAS handshake — signature
///     binds the ephemeral X25519 pubkey to the sender's identity)
///   - `CodeJoinRequest`, `CodeJoinResponse` (signer is the joiner /
///     owner)
///   - `JoinRefused` (signer is a room owner; tells the rejected joiner
///     it really came from the room)
///
/// Verification happens via `crate::crypto::verify_signed`: it re-derives
/// the fingerprint from `ed25519_pubkey_b64`, asserts equality with
/// `fingerprint`, then `Ed25519::verify` over `payload_b64` decoded.
///
/// Format choice: payload is base64'd serialized `RoomMessage` JSON
/// (not the JSON bytes directly) so the envelope itself is plain JSON
/// without escaping nightmares.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedRoomMessage {
    pub fingerprint: String,
    pub ed25519_pubkey_b64: String,
    pub payload_b64: String,
    pub signature_b64: String,
}

/// What actually gets serialized onto a per-room gossipsub topic. New
/// in v0.3.0 — previously, the raw `RoomMessage` JSON went on the wire.
/// All outgoing messages now flow through this envelope so the receiver
/// can tell signed from unsigned at the outer layer without trial-
/// parsing. Tagged so future variants don't silently misparse.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum WireMessage {
    /// Unsigned — equivalent to the old wire format. Used for messages
    /// whose authenticity isn't security-critical: `Plain`, `Typing`,
    /// `MemberAnnounce` (the wrapped key in encrypted rooms is itself
    /// AEAD-authenticated), `FileChunk`, etc.
    Plain(RoomMessage),
    /// App-level Ed25519-signed envelope.
    Signed(SignedRoomMessage),
}

/// Serialize an unsigned `RoomMessage` to its on-wire bytes inside the
/// new `WireMessage::Plain` envelope. The single helper keeps every send
/// site in `app/mod.rs` from open-coding the wrap.
pub fn encode_wire(msg: &RoomMessage) -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec(&WireMessage::Plain(msg.clone()))
}

/// Serialize a `SignedRoomMessage` envelope to its on-wire bytes.
pub fn encode_wire_signed(env: &SignedRoomMessage) -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec(&WireMessage::Signed(env.clone()))
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
    /// Phase B: fingerprints with role = 'owner' — the soft moderator
    /// set. Newcomers learn from this who's authorized to grant other
    /// owners and to issue bans (signed via `SignedRoomMessage`).
    /// `#[serde(default)]` for forward-compat with pre-0.3 senders.
    #[serde(default)]
    pub owner_fingerprints: Vec<String>,
    /// Phase E: when true, existing members refuse to wrap their
    /// session key for a joiner whose fingerprint isn't in the
    /// global `verified_peers` set. Joiner sees a `JoinRefused`
    /// reply from at least one owner so the UX isn't a silent hang.
    /// `#[serde(default)]` so pre-0.3 senders default to permissive.
    #[serde(default)]
    pub verified_only: bool,
    /// Phase D follow-up: dialable multiaddrs of the announcing node.
    /// Populated from AutoNAT-confirmed external addresses + relay
    /// circuit reservations (capped at 4 entries to keep the
    /// announcement small). Empty for pre-0.3-followup senders.
    ///
    /// Consumer: when a peer sees an announcement with non-empty
    /// `host_addrs` and isn't already connected to `creator_fingerprint`,
    /// it opportunistically dials the first entry. This lets cross-
    /// internet peers bootstrap via relay-circuit addresses without
    /// requiring an invite link.
    #[serde(default)]
    pub host_addrs: Vec<String>,
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
        /// Optional human-readable display name. Serde defaults to
        /// `None` for forward compat with older peers.
        #[serde(default)]
        display_name: Option<String>,
        /// Base64 of the sender's 32-byte Ed25519 public key. Lets every
        /// existing member learn the new member's pubkey on first contact,
        /// so they can verify future `SignedRoomMessage` envelopes from
        /// this fingerprint. `#[serde(default)]` for forward compat: a
        /// pre-0.3.0 peer that doesn't send this still works, but its
        /// signed messages can't be verified until it re-announces.
        #[serde(default)]
        sender_ed25519_pubkey: Option<String>,
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
    /// "I'm rotating the room key — derive a new passphrase key from
    /// `new_salt` + the new passphrase you'll be told out-of-band, then
    /// wait for my MemberAnnounce." Phase 3 v1: simplistic — only the
    /// rotator's outbound changes; receivers must opt in by entering
    /// the new passphrase to decrypt new wrapped session keys.
    RotateRoomKey {
        rotator_fingerprint: String,
        /// Argon2id salt for the new passphrase-derived key.
        new_salt: Vec<u8>,
    },
    /// Ephemeral "I'm typing" signal. TTL on the receive side is 3s.
    Typing {
        sender_fingerprint: String,
    },
    /// Announce a file the sender is about to push. The receiver creates
    /// an attachment row (status=offered) and waits for chunks. For
    /// encrypted rooms `encrypted_meta` carries the Megolm-wrapped file
    /// key + ChaCha20 nonce.
    FileOffer {
        sender_fingerprint: String,
        file_id: String,
        name: String,
        size_bytes: u64,
        mime: Option<String>,
        chunk_count: u32,
        encrypted_meta: Option<EncryptedFileMeta>,
    },
    /// One chunk of an in-flight file. Receivers reassemble by index
    /// and verify the final SHA-256 against `file_id`.
    FileChunk {
        sender_fingerprint: String,
        file_id: String,
        chunk_index: u32,
        total_chunks: u32,
        /// base64 of raw chunk bytes (plaintext bytes for unencrypted
        /// rooms, ChaCha20-Poly1305 ciphertext for encrypted).
        data_b64: String,
    },
    /// Phase B: an existing owner promotes `target_fingerprint` to
    /// owner. MUST be sent inside `WireMessage::Signed` — the signer
    /// must be on the room's current `owner_fingerprints` list for
    /// honest receivers to apply the change.
    OwnerGrant {
        room_id: String,
        target_fingerprint: String,
    },
    /// Phase B: an existing owner bans `target_fingerprint` from the
    /// room. MUST be sent inside `WireMessage::Signed`. Honest clients
    /// then ignore the banned fingerprint's MemberAnnounce + messages.
    /// The cryptographic enforcement is the immediate `RotateRoomKey`
    /// that the banning owner sends right after.
    BanMember {
        room_id: String,
        target_fingerprint: String,
    },
    /// Phase G: SAS verification step 1. The initiator picks a random
    /// `tx_id` and an ephemeral X25519 keypair, sends the pubkey.
    /// MUST be sent inside `WireMessage::Signed` so the receiver can
    /// bind this ephemeral key to the initiator's Ed25519 identity.
    SasInit {
        tx_id: String,
        ephemeral_x25519_pubkey_b64: String,
        target_fingerprint: String,
    },
    /// Phase G: SAS step 2 — responder's ephemeral X25519 pubkey.
    /// Both sides now have what they need to compute the shared
    /// secret and derive the SAS code locally. Signed.
    SasResponse {
        tx_id: String,
        ephemeral_x25519_pubkey_b64: String,
    },
    /// Phase G: SAS step 3 — once both sides have OOB-compared the
    /// derived code and pressed "Match", each broadcasts this. On
    /// receiving the partner's `matched=true`, the local side flips
    /// `verified=1` for the partner's fingerprint. Signed.
    SasConfirm {
        tx_id: String,
        matched: bool,
    },
    /// Phase E: an existing owner of a `verified_only` room is
    /// telling `target_fingerprint` (an unverified joiner) why their
    /// announce went unanswered. Replaces a silent hang on the
    /// joiner's side. Signed.
    JoinRefused {
        room_id: String,
        target_fingerprint: String,
        reason: String,
    },
    /// Phase F: a joiner is asking to enter a room using a short-lived
    /// owner-issued code (no passphrase). Includes the joiner's
    /// ephemeral X25519 pubkey for ECDH key delivery. Signed (so the
    /// owner knows who's asking).
    CodeJoinRequest {
        room_id: String,
        joiner_x25519_pubkey_b64: String,
        code: String,
    },
    /// Phase F: an issuing owner's response to a valid `CodeJoinRequest`.
    /// Carries the owner's ephemeral X25519 pubkey + the current Megolm
    /// session key wrapped under the ECDH-derived key. Joiner does
    /// X25519 the other direction, derives the same wrap key, unwraps
    /// the session key. Signed.
    CodeJoinResponse {
        room_id: String,
        target_fingerprint: String,
        owner_x25519_pubkey_b64: String,
        owner_session_id: String,
        wrapped_session_key_b64: String,
        nonce_b64: String,
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
            owner_fingerprints: vec!["creator-fp".into()],
            verified_only: false,
            host_addrs: vec![],
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
                display_name: Some("Daisy".into()),
                sender_ed25519_pubkey: Some("AAA=".into()),
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
            RoomMessage::FileOffer {
                sender_fingerprint: "fp".into(),
                file_id: "fid".into(),
                name: "f.bin".into(),
                size_bytes: 1024,
                mime: Some("application/octet-stream".into()),
                chunk_count: 2,
                encrypted_meta: None,
            },
            RoomMessage::FileChunk {
                sender_fingerprint: "fp".into(),
                file_id: "fid".into(),
                chunk_index: 0,
                total_chunks: 2,
                data_b64: "AAA=".into(),
            },
            RoomMessage::RotateRoomKey {
                rotator_fingerprint: "fp".into(),
                new_salt: vec![1u8; 16],
            },
            RoomMessage::Typing {
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
