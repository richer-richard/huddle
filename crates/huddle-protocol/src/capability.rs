//! Peer capability bits (huddle 2.2 / M-C4).
//!
//! A peer advertises which **new wire forms** it understands so a sender can
//! retire a legacy/cleartext form *only* once the other end is known-capable —
//! the additive way to make an otherwise non-additive wire change. Caps ride in
//! the signed `MemberAnnounce` (per-member, in-room) and in `RoomAnnouncement`
//! (the announcer's caps, learned at discovery time). Because the carrying
//! `MemberAnnounce` is signed end-to-end, a relay can't forge or strip caps
//! without breaking the signature.
//!
//! Encoded as a `u32` bitset. Unknown/absent → `0` (a legacy peer), so a missing
//! field decodes to "supports nothing new" and every gate below stays false.
//! New bits are append-only; never renumber an existing bit.

/// Code-join v2 (audit PA-1): the peer sends an Argon2 *proof of knowledge* of
/// the join code bound to its ephemeral X25519 key + room id, instead of the
/// cleartext bearer code. A v2 joiner omits the cleartext code entirely, so a
/// malicious relay can no longer read it and rebind it to a forged ephemeral.
pub const CODE_JOIN_V2: u32 = 1 << 0;

/// Private file metadata (audit FILES-2): the peer accepts a keyed-MAC content
/// commitment (`EncryptedFileMeta.content_mac_b64`) in place of the plaintext
/// `content_hash = SHA256(plaintext)`, so the relay no longer sees a
/// plaintext-confirmation oracle for attachments.
pub const FILE_META_PRIVATE: u32 = 1 << 1;

/// Everything THIS build implements — advertised in our announces.
pub const OURS: u32 = CODE_JOIN_V2 | FILE_META_PRIVATE;

/// True iff `caps` advertises `bit`.
#[inline]
pub fn supports(caps: u32, bit: u32) -> bool {
    caps & bit == bit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_are_distinct_and_in_ours() {
        assert_ne!(CODE_JOIN_V2, FILE_META_PRIVATE);
        assert!(supports(OURS, CODE_JOIN_V2));
        assert!(supports(OURS, FILE_META_PRIVATE));
    }

    #[test]
    fn legacy_zero_supports_nothing() {
        assert!(!supports(0, CODE_JOIN_V2));
        assert!(!supports(0, FILE_META_PRIVATE));
    }

    #[test]
    fn supports_requires_all_bits_of_the_query() {
        // `supports` is an all-bits-present test, not "any overlap".
        assert!(supports(CODE_JOIN_V2 | FILE_META_PRIVATE, CODE_JOIN_V2));
        assert!(!supports(CODE_JOIN_V2, CODE_JOIN_V2 | FILE_META_PRIVATE));
    }
}
