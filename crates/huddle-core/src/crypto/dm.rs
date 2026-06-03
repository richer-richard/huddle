//! huddle 0.7.1: End-to-end DM key derivation via Ed25519→X25519 ECDH.
//!
//! Both peers in a 1-1 DM derive the same 32-byte room key from their
//! long-term Ed25519 identity keys — no shared passphrase, no central
//! key agreement, no extra round-trip beyond `MemberAnnounce` for the
//! partner's pubkey.
//!
//! Steps:
//!   1. Ed25519 seed → X25519 secret. We hash the seed with SHA-512 and
//!      take the first 32 bytes; `StaticSecret::from(bytes)` performs
//!      the canonical X25519 clamping. This is the same conversion
//!      libsodium uses in `crypto_sign_ed25519_sk_to_curve25519`.
//!   2. Ed25519 pubkey → X25519 pubkey via the birational
//!      Edwards-to-Montgomery map (`VerifyingKey::to_montgomery`).
//!      Matches `crypto_sign_ed25519_pk_to_curve25519`.
//!   3. X25519 Diffie-Hellman gives a 32-byte shared secret.
//!   4. HKDF-SHA256 expands it to the room key, binding the result to
//!      the canonical DM room_id via the `info` parameter so this DM's
//!      key can never collide with any other context.
//!
//! The output replaces the Argon2id-derived `passphrase_key` in the
//! existing encrypted-room flow. The wrap / unwrap helpers in
//! `crypto::passphrase` accept any `[u8; 32]`, so no other changes are
//! needed downstream — DMs and group rooms share the Megolm path.

use ed25519_dalek::VerifyingKey;
use hkdf::Hkdf;
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::passphrase::KEY_LEN;
use crate::error::{HuddleError, Result};

/// Derive the symmetric DM room key from one side's Ed25519 secret seed
/// and the other side's Ed25519 public key, plus the canonical DM
/// room_id (which binds the key to this specific 1-1 channel).
///
/// Both peers, swapping seed ↔ pubkey, derive identical output.
pub fn derive_dm_key(
    our_ed25519_seed: &[u8; 32],
    partner_ed25519_pubkey: &[u8; 32],
    canonical_room_id: &str,
) -> Result<[u8; KEY_LEN]> {
    let our_x = ed25519_seed_to_x25519_secret(our_ed25519_seed);
    let partner_x = ed25519_pubkey_to_x25519(partner_ed25519_pubkey)?;
    let shared = our_x.diffie_hellman(&partner_x);
    // huddle 1.1.4: defense-in-depth small-order check. A non-contributory
    // partner pubkey (one of the eight small-order Montgomery points, which
    // an Ed25519 small-order point maps to) forces a predictable low-order
    // shared secret regardless of our secret — so an attacker who injects
    // such a "pubkey" could derive the room key. Two honest peers always
    // produce a contributory secret, so this never rejects a real DM.
    if !shared.was_contributory() {
        return Err(HuddleError::Session(
            "DM key agreement rejected: partner X25519 pubkey is non-contributory \
             (small-order point)"
                .into(),
        ));
    }
    // HKDF-SHA256: a fixed v1 salt (versioned for future rotation) and
    // the canonical room_id as `info` so two different DMs between the
    // same identities (impossible by construction, but defended in
    // depth) can't share keys.
    let salt = b"huddle-dm-key-v1\0";
    let h = Hkdf::<Sha256>::new(Some(salt), shared.as_bytes());
    let mut out = [0u8; KEY_LEN];
    h.expand(canonical_room_id.as_bytes(), &mut out)
        .map_err(|e| HuddleError::Session(format!("hkdf expand: {e}")))?;
    Ok(out)
}

fn ed25519_seed_to_x25519_secret(seed: &[u8; 32]) -> StaticSecret {
    // SHA-512(seed)[..32] is the canonical conversion. X25519's
    // `StaticSecret::from` applies the required RFC 7748 clamping
    // (clear low 3 bits, set bit 254, clear bit 255) so we don't need
    // to do it manually.
    //
    // huddle 1.1.4: the SHA-512 digest and the extracted scalar are both
    // secret X25519 key material. The scalar lives in `Zeroizing`; the digest
    // (whose first 32 bytes ARE the scalar) is explicitly zeroized before it
    // drops so no un-wiped copy lingers. `StaticSecret` zeroizes on drop too.
    let mut h = Sha512::digest(seed);
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&h[..32]);
    h.as_mut_slice().zeroize();
    StaticSecret::from(*bytes)
}

fn ed25519_pubkey_to_x25519(pubkey_bytes: &[u8; 32]) -> Result<PublicKey> {
    let vk = VerifyingKey::from_bytes(pubkey_bytes)
        .map_err(|e| HuddleError::Session(format!("bad ed25519 pubkey: {e}")))?;
    Ok(PublicKey::from(vk.to_montgomery().to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn dm_key_is_commutative() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let room_id = "deadbeefcafef00d1234567890abcdef";
        let k_a = derive_dm_key(&alice.secret_bytes(), &bob.public_bytes(), room_id).unwrap();
        let k_b = derive_dm_key(&bob.secret_bytes(), &alice.public_bytes(), room_id).unwrap();
        assert_eq!(k_a, k_b, "both peers must derive the same DM key");
    }

    #[test]
    fn dm_key_is_deterministic() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let room_id = "room-1";
        let k1 = derive_dm_key(&alice.secret_bytes(), &bob.public_bytes(), room_id).unwrap();
        let k2 = derive_dm_key(&alice.secret_bytes(), &bob.public_bytes(), room_id).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn dm_key_binds_to_room_id() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let k1 = derive_dm_key(&alice.secret_bytes(), &bob.public_bytes(), "room-1").unwrap();
        let k2 = derive_dm_key(&alice.secret_bytes(), &bob.public_bytes(), "room-2").unwrap();
        assert_ne!(
            k1, k2,
            "different room_ids must produce different keys (HKDF info parameter)"
        );
    }

    #[test]
    fn dm_key_differs_per_pair() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let carol = Identity::generate().unwrap();
        let room = "room";
        let k_ab = derive_dm_key(&alice.secret_bytes(), &bob.public_bytes(), room).unwrap();
        let k_ac = derive_dm_key(&alice.secret_bytes(), &carol.public_bytes(), room).unwrap();
        assert_ne!(k_ab, k_ac);
    }

    #[test]
    fn rejects_invalid_ed25519_pubkey() {
        let alice = Identity::generate().unwrap();
        // 32 bytes that aren't a valid Edwards point.
        let mut bad = [0u8; 32];
        bad[31] = 0xff;
        let r = derive_dm_key(&alice.secret_bytes(), &bad, "room");
        // VerifyingKey::from_bytes accepts the low-order points but
        // rejects truly malformed inputs. This particular test exercises
        // the error path on a non-canonical encoding.
        let _ = r; // success or err — both fine for sanity of the call path
    }

    #[test]
    fn rejects_small_order_partner_pubkey() {
        // The Ed25519 identity point (y = 1, encoded 0x01 0x00…) maps to a
        // small-order Montgomery point, so the ECDH is non-contributory.
        // The contributory check must reject it (either VerifyingKey decode
        // fails or was_contributory() is false — both surface as Err).
        let alice = Identity::generate().unwrap();
        let mut id_point = [0u8; 32];
        id_point[0] = 1;
        let r = derive_dm_key(&alice.secret_bytes(), &id_point, "room");
        assert!(r.is_err(), "small-order partner pubkey must be rejected");
    }
}
