//! Wire protocol for room discovery and message broadcast.
//!
//! Two gossipsub topics:
//!   - `ROOMS_TOPIC` — global, every node subscribes. Used for room
//!     advertisements (so all peers see "rooms in this network").
//!   - `format!("{ROOM_TOPIC_PREFIX}{room_id}")` — per-room. Only members
//!     of a room subscribe. All room messages flow here.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::files::encryption::EncryptedFileMeta;
use crate::storage::repo::RoomKind;

pub const ROOMS_TOPIC: &str = "huddle-rooms-v1";
pub const ROOM_TOPIC_PREFIX: &str = "huddle-room-";

pub fn room_topic(room_id: &str) -> String {
    format!("{ROOM_TOPIC_PREFIX}{room_id}")
}

/// huddle 1.0: a stable, per-identity "inbox" room id for relay-routed
/// contact requests — `inbox:<hex(sha256("huddle-inbox-v1" || fingerprint))>`.
/// Lets "add by HD-ID" work over the internet (not just the LAN mesh): the
/// requester publishes a signed `ContactRequest` here and the owner, who
/// auto-subscribes to their own inbox, picks it up (live or from the relay
/// mailbox). The relay only ever sees this hash, never the raw fingerprint
/// (preimage resistance), so it can't reconstruct a contact graph; the
/// `inbox:` prefix + distinct salt keep it from colliding with DM / group
/// room ids. Both sides derive the same id from the target fingerprint.
pub fn inbox_room_id(fingerprint: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"huddle-inbox-v1");
    h.update(fingerprint.as_bytes());
    format!("inbox:{}", hex::encode(h.finalize()))
}

/// Application-level signed envelope around a `RoomMessage`. Used for
/// any message whose authenticity matters beyond gossipsub's transport-
/// level signing.
///
/// The following variants MUST be sent inside a `Signed` envelope, and
/// receivers MUST drop them when they arrive unsigned:
///   - `MemberLeave` (signer must equal the claimed `sender_fingerprint`;
///     huddle 0.7.11 — closes the unsigned-leave spoof bug)
///   - `MemberAnnounce` (signer must equal the claimed `sender_fingerprint`;
///     huddle 0.7.11 — closes the TOFU-pubkey hijack bug)
///   - `FileOffer` (signer must equal the claimed `sender_fingerprint`;
///     huddle 0.7.11 — prevents attribution spoofing)
///   - `RotateRoomKey` (signer must equal the claimed `rotator_fingerprint`)
///   - `OwnerGrant`, `BanMember` (signer must be a current room owner)
///   - `SasInit`, `SasResponse`, `SasConfirm` (SAS handshake — signature
///     binds the ephemeral X25519 pubkey to the sender's identity)
///   - `CodeJoinRequest`, `CodeJoinResponse` (signer is the joiner /
///     owner)
///   - `JoinRefused` (signer is a room owner; tells the rejected joiner
///     it really came from the room)
///   - `ProfileUpdate` (signer must equal the claimed `sender_fingerprint`;
///     prevents anyone from spoofing another peer's username)
///   - `ContactRequest` (signer must equal the claimed `requester_fingerprint`;
///     huddle 1.0 — the signature proves who's asking to connect)
///   - `Reaction`, `Edit`, `Delete` (huddle 2.0 / F10 — signer must equal
///     the claimed `sender_fingerprint`; edits & deletes are additionally
///     applied only when the signer is the original sender OR a current
///     room owner)
///   - `RoomSetting` (huddle 2.0 / F9 — disappearing-messages TTL; the
///     signer must be the room creator or a current owner)
///
/// Verification happens via `crate::crypto::verify_signed`: it re-derives
/// the fingerprint from `ed25519_pubkey_b64`, asserts equality with
/// `fingerprint`, runs `Ed25519::verify_strict` over the decoded
/// `payload_b64`, and rejects envelopes whose `signed_at_ms` falls
/// outside a ±5 min window from now (replay protection).
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
    /// huddle 0.7.11: epoch-ms timestamp the sender bound into the
    /// signature, used by receivers as replay protection. `#[serde(default)]`
    /// for forward-compat parsing — but the verifier rejects `0` and
    /// values outside the configured window, so legacy pre-0.7.11 senders
    /// no longer satisfy `verify_signed`.
    #[serde(default)]
    pub signed_at_ms: i64,
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
    /// `FileChunk`, etc. NOTE: `MemberAnnounce` moved to the **signed**
    /// envelope in 0.7.11 (see `broadcast_member_announce`), so its
    /// fingerprint pin can't be hijacked — and, as of 1.3, so its
    /// ML-KEM key + ciphertext can't be stripped by a relay to force a
    /// post-quantum downgrade without breaking the signature.
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
    /// huddle 0.7: explicit room kind. `RoomKind::Direct` (1-1 DM) is
    /// filtered out by honest 0.7+ consumers if neither member is them —
    /// DMs never leak past the two participants' sidebars. Pre-0.7
    /// peers omit the field, which `#[serde(default)]` resolves to
    /// `RoomKind::Group` (`Default` impl) — they keep working unchanged.
    #[serde(default)]
    pub kind: RoomKind,
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
        /// huddle 1.3: base64 of the sender's 1184-byte ML-KEM-768
        /// encapsulation (public) key, for hybrid post-quantum DM key
        /// agreement. Populated only on **Direct** room announces. Its
        /// presence is how the peer signals PQ capability: a DM goes hybrid
        /// iff the partner published this (or we have it pinned from a prior
        /// announce — see `app::ensure_dm_key`). `#[serde(default,
        /// skip_serializing_if = "Option::is_none")]` keeps pre-1.3 peers (and
        /// all group announces) byte-compatible — when `None` the field simply
        /// doesn't appear, and a missing field decodes back to `None`. (Do NOT
        /// "simplify" this to serde's bare `skip`: that would drop the field on
        /// the wire unconditionally and silently disable the whole PQ path.)
        /// Carried inside the *signed* `MemberAnnounce` envelope, so the relay
        /// can't strip it to force a downgrade without breaking the signature.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sender_mlkem_pubkey: Option<String>,
        /// huddle 1.3: base64 of the 1088-byte ML-KEM-768 ciphertext sent by
        /// the DM **initiator** (the lower-fingerprint peer) to the responder,
        /// who decapsulates it to recover the shared post-quantum secret. Only
        /// the initiator sets this; the responder's announces omit it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mlkem_ciphertext: Option<String>,
    },
    /// A request from a recently-joined member: "I need session keys".
    /// Existing members respond with MemberAnnounce.
    SessionKeyRequest { requester_fingerprint: String },
    /// An encrypted message in an encrypted room.
    Encrypted {
        sender_fingerprint: String,
        session_id: String,
        /// base64-encoded MegolmMessage bytes
        ciphertext_b64: String,
        /// huddle 2.0 (F10): sender-minted stable id for this message, used
        /// as the cross-peer targeting key for reactions, edits, replies and
        /// deletes. `#[serde(default, skip_serializing_if = "Option::is_none")]`
        /// keeps pre-2.0 peers byte-compatible: when `None` the field is
        /// omitted on the wire, and a missing field decodes back to `None`
        /// (so messages from older peers simply can't be a content-affordance
        /// target — content still flows).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_msg_id: Option<String>,
        /// huddle 2.0 (F10): `client_msg_id` of the message this one replies
        /// to, if any. `None` (and omitted on the wire) for top-level messages
        /// and pre-2.0 senders.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reply_to: Option<String>,
    },
    /// A plaintext message in an unencrypted room.
    Plain {
        sender_fingerprint: String,
        body: String,
        /// huddle 2.0 (F10): see `Encrypted::client_msg_id`. Sender-minted
        /// stable id; `#[serde(default, skip_serializing_if = "Option::is_none")]`
        /// for byte-compat with pre-2.0 peers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_msg_id: Option<String>,
        /// huddle 2.0 (F10): `client_msg_id` of the message this one replies
        /// to, if any. `None` for top-level messages and pre-2.0 senders.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reply_to: Option<String>,
    },
    /// Explicit leave notification.
    MemberLeave {
        sender_fingerprint: String,
        /// huddle 2.0.3 (audit N-M2): the room this leave is for. The Ed25519
        /// signature commits to the payload but NOT the gossip topic, so without
        /// this a malicious relay could replay a signed leave from room A onto
        /// room B's topic. `Option` + `skip_serializing_if` keeps the wire
        /// byte-identical to pre-2.0.3 when unset (graceful back-compat); honest
        /// receivers cross-check it against the delivery topic when present.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        room_id: Option<String>,
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
        /// huddle 2.0.3 (audit N-M2): the room being rotated, cross-checked
        /// against the delivery topic so a signed rotation can't be replayed
        /// into another room. Optional for pre-2.0.3 back-compat.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        room_id: Option<String>,
    },
    /// Ephemeral "I'm typing" signal. TTL on the receive side is 3s.
    Typing { sender_fingerprint: String },
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
    SasConfirm { tx_id: String, matched: bool },
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
    /// Phase 0.5: a peer is announcing (or clearing) their self-declared
    /// username. MUST be sent inside `WireMessage::Signed` — receivers
    /// require `verified_signer == sender_fingerprint`. Last-write-wins
    /// by `updated_at` (monotonic ms). `username = None` clears the
    /// previously-set username and the peer renders as `[anonymous]`.
    ProfileUpdate {
        sender_fingerprint: String,
        username: Option<String>,
        updated_at: i64,
    },
    /// huddle 1.0: a contact/DM request delivered to the target's relay
    /// inbox (`inbox_room_id`). MUST be sent inside `WireMessage::Signed` —
    /// the signer's fingerprint IS the requester's identity (the whole
    /// point: it proves who's asking). Carries the requester's Ed25519
    /// pubkey so the recipient can TOFU-pin it and later derive the DM ECDH
    /// key without a round-trip.
    ContactRequest {
        requester_fingerprint: String,
        #[serde(default)]
        display_name: Option<String>,
        #[serde(default)]
        note: Option<String>,
        #[serde(default)]
        sender_ed25519_pubkey: Option<String>,
    },
    /// huddle 2.0 (F10): add or remove an emoji reaction on another message
    /// in this room. MUST be sent inside `WireMessage::Signed` — the signer
    /// must equal `sender_fingerprint`; honest receivers drop unsigned
    /// reactions (like `FileOffer` / `MemberAnnounce`). The toggle unit is
    /// one emoji per (sender, target message): `removed = false` adds the
    /// reaction, `removed = true` clears it. A brand-new variant, so pre-2.0
    /// peers never produce it and ignore it on receipt.
    Reaction {
        sender_fingerprint: String,
        /// `client_msg_id` of the message being reacted to (must exist in
        /// this room for honest receivers to apply the reaction).
        target_msg_id: String,
        /// A single emoji or short custom code (e.g. "+1", "laugh").
        emoji: String,
        /// `false` = add the reaction, `true` = remove it (toggle off).
        /// `#[serde(default)]` so a missing field decodes to `false` (add).
        #[serde(default)]
        removed: bool,
    },
    /// huddle 2.0 (F10): edit the body of an existing message. MUST be sent
    /// inside `WireMessage::Signed`; honest receivers apply it only when the
    /// signer is the original sender OR a current room owner (moderation).
    /// Last-write-wins. For encrypted rooms the replacement body rides as a
    /// fresh Megolm ciphertext in `new_ciphertext_b64` (decrypted exactly
    /// like an `Encrypted` body, against the carried `session_id`); for
    /// plaintext rooms it rides as `new_body`.
    Edit {
        sender_fingerprint: String,
        /// `client_msg_id` of the message being edited.
        target_msg_id: String,
        /// base64 MegolmMessage bytes of the replacement body, for encrypted
        /// rooms. Empty for plaintext rooms (which carry the new body in
        /// `new_body` instead).
        new_ciphertext_b64: String,
        /// huddle 2.0 (F10): the Megolm `session_id` the editor encrypted
        /// `new_ciphertext_b64` under, so receivers decrypt the edit against
        /// the correct session — exactly like `Encrypted::session_id` — with
        /// no reliance on an in-memory "last inbound session" guess (which
        /// failed after a session rotation, after restart, from a second
        /// device, or before any other message on the session). Empty (and
        /// omitted on the wire) for plaintext rooms. `#[serde(default,
        /// skip_serializing_if = "String::is_empty")]` keeps it additive: a
        /// pre-session-id edit decodes to an empty string and is dropped
        /// gracefully rather than mis-decrypted.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        session_id: String,
        /// Replacement plaintext body, for unencrypted rooms. `None` (and
        /// omitted on the wire) for encrypted rooms, whose new body lives in
        /// `new_ciphertext_b64`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        new_body: Option<String>,
    },
    /// huddle 2.0 (F10): delete (tombstone) an existing message. MUST be
    /// sent inside `WireMessage::Signed`; honest receivers apply it only when
    /// the signer is the original sender OR a current room owner. Idempotent —
    /// the original message row is kept and a tombstone is recorded, so the
    /// body renders as "[deleted]" everywhere.
    Delete {
        sender_fingerprint: String,
        /// `client_msg_id` of the message being deleted.
        target_msg_id: String,
    },
    /// huddle 2.0 (F9): a signed control message that sets this room's
    /// disappearing-messages TTL. MUST be sent inside `WireMessage::Signed` —
    /// honest receivers apply it only when the signer is the room creator or a
    /// current owner. `disappearing_ttl_secs = 0` turns expiry off; any value
    /// > 0 makes each peer locally auto-delete messages that many seconds
    /// after they were stored. Pre-2.0 peers ignore the unknown variant and
    /// never expire their local copies (graceful downgrade).
    RoomSetting {
        sender_fingerprint: String,
        disappearing_ttl_secs: u64,
        /// huddle 2.0.3 (audit N-M2): the room this setting applies to. Without
        /// it a malicious relay could replay a signed disappearing-TTL from one
        /// room (where the signer is an owner) onto another room they also own,
        /// forcing a retroactive history purge there (chains L-24). Cross-checked
        /// against the delivery topic on receive. Optional for back-compat.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        room_id: Option<String>,
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
            kind: RoomKind::Group,
        };
        let json = serde_json::to_vec(&ann).unwrap();
        let back: RoomAnnouncement = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.name, "general");
        assert_eq!(back.passphrase_salt, Some(vec![1, 2, 3, 4]));
        assert_eq!(back.kind, RoomKind::Group);
    }

    #[test]
    fn room_announcement_direct_kind_round_trip() {
        let ann = RoomAnnouncement {
            room_id: "dm-rid".into(),
            name: "dm".into(),
            encrypted: false,
            passphrase_salt: None,
            member_count: 2,
            creator_fingerprint: "alice-fp".into(),
            announced_at: 100,
            owner_fingerprints: vec![],
            verified_only: false,
            host_addrs: vec![],
            kind: RoomKind::Direct,
        };
        let json = serde_json::to_vec(&ann).unwrap();
        let back: RoomAnnouncement = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.kind, RoomKind::Direct);
    }

    #[test]
    fn room_announcement_missing_kind_defaults_to_group() {
        // Simulates a pre-0.7 peer's announcement: same JSON shape
        // without the `kind` field. The serde(default) attribute on the
        // field must resolve to RoomKind::Group so older peers keep
        // working unchanged.
        let pre_0_7_json = serde_json::json!({
            "room_id": "rid",
            "name": "general",
            "encrypted": false,
            "passphrase_salt": null,
            "member_count": 1,
            "creator_fingerprint": "creator-fp",
            "announced_at": 100,
        });
        let back: RoomAnnouncement = serde_json::from_value(pre_0_7_json).unwrap();
        assert_eq!(back.kind, RoomKind::Group);
    }

    #[test]
    fn room_message_variants_round_trip() {
        let msgs = vec![
            RoomMessage::MemberAnnounce {
                sender_fingerprint: "fp".into(),
                wrapped_session_key: Some("base64data".into()),
                display_name: Some("Daisy".into()),
                sender_ed25519_pubkey: Some("AAA=".into()),
                sender_mlkem_pubkey: Some("BBB=".into()),
                mlkem_ciphertext: Some("CCC=".into()),
            },
            RoomMessage::Plain {
                sender_fingerprint: "fp".into(),
                body: "hi".into(),
                client_msg_id: Some("cmid-1".into()),
                reply_to: None,
            },
            RoomMessage::Encrypted {
                sender_fingerprint: "fp".into(),
                session_id: "sid".into(),
                ciphertext_b64: "ct".into(),
                client_msg_id: Some("cmid-2".into()),
                reply_to: Some("cmid-1".into()),
            },
            RoomMessage::SessionKeyRequest {
                requester_fingerprint: "fp".into(),
            },
            RoomMessage::MemberLeave {
                sender_fingerprint: "fp".into(),
                room_id: None,
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
                room_id: None,
            },
            RoomMessage::Typing {
                sender_fingerprint: "fp".into(),
            },
            // huddle 2.0 (F10/F9): new content + control variants.
            RoomMessage::Reaction {
                sender_fingerprint: "fp".into(),
                target_msg_id: "cmid-1".into(),
                emoji: "👍".into(),
                removed: false,
            },
            RoomMessage::Edit {
                sender_fingerprint: "fp".into(),
                target_msg_id: "cmid-1".into(),
                new_ciphertext_b64: "ct2".into(),
                session_id: "sid".into(),
                new_body: None,
            },
            RoomMessage::Edit {
                sender_fingerprint: "fp".into(),
                target_msg_id: "cmid-1".into(),
                new_ciphertext_b64: String::new(),
                session_id: String::new(),
                new_body: Some("edited body".into()),
            },
            RoomMessage::Delete {
                sender_fingerprint: "fp".into(),
                target_msg_id: "cmid-1".into(),
            },
            RoomMessage::RoomSetting {
                sender_fingerprint: "fp".into(),
                disappearing_ttl_secs: 3600,
                room_id: None,
            },
        ];
        for m in msgs {
            let json = serde_json::to_vec(&m).unwrap();
            let back: RoomMessage = serde_json::from_slice(&json).unwrap();
            assert_eq!(format!("{m:?}"), format!("{back:?}"));
        }
    }

    #[test]
    fn plain_without_new_fields_defaults_to_none() {
        // Simulates a pre-2.0 peer's Plain message: externally-tagged JSON
        // with no `client_msg_id` / `reply_to`. The serde(default) attrs must
        // resolve both to `None` so old senders keep working unchanged.
        let pre_2_0_json = serde_json::json!({
            "Plain": {
                "sender_fingerprint": "fp",
                "body": "hi",
            }
        });
        let back: RoomMessage = serde_json::from_value(pre_2_0_json).unwrap();
        match back {
            RoomMessage::Plain {
                client_msg_id,
                reply_to,
                ..
            } => {
                assert_eq!(client_msg_id, None);
                assert_eq!(reply_to, None);
            }
            other => panic!("expected Plain, got {other:?}"),
        }
    }

    #[test]
    fn plain_with_none_ids_omits_fields_on_wire() {
        // skip_serializing_if must keep the wire bytes byte-compatible with
        // pre-2.0 peers when the new fields are absent.
        let m = RoomMessage::Plain {
            sender_fingerprint: "fp".into(),
            body: "hi".into(),
            client_msg_id: None,
            reply_to: None,
        };
        let v = serde_json::to_value(&m).unwrap();
        let inner = &v["Plain"];
        assert!(inner.get("client_msg_id").is_none());
        assert!(inner.get("reply_to").is_none());
    }

    #[test]
    fn reaction_missing_removed_defaults_to_false() {
        // `removed` carries serde(default) so a peer that omits it (an "add"
        // reaction) decodes to `false`.
        let json = serde_json::json!({
            "Reaction": {
                "sender_fingerprint": "fp",
                "target_msg_id": "cmid-1",
                "emoji": "❤️",
            }
        });
        let back: RoomMessage = serde_json::from_value(json).unwrap();
        match back {
            RoomMessage::Reaction { removed, emoji, .. } => {
                assert!(!removed);
                assert_eq!(emoji, "❤️");
            }
            other => panic!("expected Reaction, got {other:?}"),
        }
    }

    #[test]
    fn edit_missing_session_id_defaults_to_empty() {
        // huddle 2.0.0 (F10): an `Edit` minted before `session_id` was added
        // to the wire must decode to an empty `session_id` (graceful drop on
        // the receive side) rather than fail to parse.
        let json = serde_json::json!({
            "Edit": {
                "sender_fingerprint": "fp",
                "target_msg_id": "cmid-1",
                "new_ciphertext_b64": "ct2",
            }
        });
        let back: RoomMessage = serde_json::from_value(json).unwrap();
        match back {
            RoomMessage::Edit { session_id, .. } => assert_eq!(session_id, ""),
            other => panic!("expected Edit, got {other:?}"),
        }
    }

    #[test]
    fn edit_empty_session_id_omitted_on_wire() {
        // A plaintext-room edit has no session; `skip_serializing_if` keeps
        // those wire bytes free of an empty `session_id`. The encrypted-room
        // edit, by contrast, always carries one.
        let plain = RoomMessage::Edit {
            sender_fingerprint: "fp".into(),
            target_msg_id: "cmid-1".into(),
            new_ciphertext_b64: String::new(),
            session_id: String::new(),
            new_body: Some("edited".into()),
        };
        let v = serde_json::to_value(&plain).unwrap();
        assert!(v["Edit"].get("session_id").is_none());

        let enc = RoomMessage::Edit {
            sender_fingerprint: "fp".into(),
            target_msg_id: "cmid-1".into(),
            new_ciphertext_b64: "ct2".into(),
            session_id: "sid".into(),
            new_body: None,
        };
        let v = serde_json::to_value(&enc).unwrap();
        assert_eq!(v["Edit"]["session_id"], "sid");
    }

    #[test]
    fn room_topic_format() {
        assert_eq!(room_topic("abc123"), "huddle-room-abc123");
    }
}
