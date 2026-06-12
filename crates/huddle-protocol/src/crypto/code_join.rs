//! Code-join wrap-key derivation.
//!
//! A single-use join code lets an owner hand a room's Megolm session key to a
//! read-only joiner without the passphrase: the joiner sends an ephemeral
//! X25519 public key, the owner ECDHs against it and wraps the session key under
//! an HKDF-derived key, and the joiner derives the same key to unwrap. Both
//! sides compute the **identical** wrap key from `derive_wrap_key`; previously
//! this ECDH+HKDF was open-coded twice in `AppHandle` (the `CodeJoinRequest` and
//! `CodeJoinResponse` handlers), so it lives here as one tested function.

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::passphrase::KEY_LEN;

/// HKDF info tag for the code-join wrap key. Part of the wire contract — both
/// peers must use the same tag or the joiner can't unwrap.
const CODE_JOIN_INFO: &[u8] = b"huddle-code-join-v1";

/// Derive the 32-byte wrap key both sides compute: `HKDF-SHA256` over the raw
/// X25519 ECDH shared secret of `our_secret` and `their_pub`. The owner uses it
/// to `passphrase::wrap` the session key; the joiner uses it to `unwrap`.
pub fn derive_wrap_key(our_secret: &StaticSecret, their_pub: &PublicKey) -> [u8; KEY_LEN] {
    let shared = our_secret.diffie_hellman(their_pub);
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut wrap_key = [0u8; KEY_LEN];
    hk.expand(CODE_JOIN_INFO, &mut wrap_key)
        .expect("32 bytes is within HKDF-SHA256's output limit");
    wrap_key
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn both_sides_derive_the_same_wrap_key() {
        let owner = StaticSecret::random_from_rng(OsRng);
        let joiner = StaticSecret::random_from_rng(OsRng);
        let owner_pub = PublicKey::from(&owner);
        let joiner_pub = PublicKey::from(&joiner);
        // Owner derives against the joiner's pubkey; joiner against the owner's.
        let k_owner = derive_wrap_key(&owner, &joiner_pub);
        let k_joiner = derive_wrap_key(&joiner, &owner_pub);
        assert_eq!(k_owner, k_joiner, "ECDH is commutative -> same wrap key");
    }

    #[test]
    fn different_peers_derive_different_keys() {
        let owner = StaticSecret::random_from_rng(OsRng);
        let a = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let b = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        assert_ne!(derive_wrap_key(&owner, &a), derive_wrap_key(&owner, &b));
    }
}
