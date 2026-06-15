//! Code-join wrap-key derivation.
//!
//! A single-use join code lets an owner hand a room's Megolm session key to a
//! read-only joiner without the passphrase: the joiner sends an ephemeral
//! X25519 public key, the owner ECDHs against it and wraps the session key under
//! an HKDF-derived key, and the joiner derives the same key to unwrap. Both
//! sides compute the **identical** wrap key from `derive_wrap_key`; previously
//! this ECDH+HKDF was open-coded twice in `AppHandle` (the `CodeJoinRequest` and
//! `CodeJoinResponse` handlers), so it lives here as one tested function.

use argon2::{Algorithm, Argon2, Version};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::passphrase::{argon2id_params, KEY_LEN};
use crate::error::{ProtocolError, Result};

/// HKDF info tag for the code-join wrap key. Part of the wire contract — both
/// peers must use the same tag or the joiner can't unwrap.
const CODE_JOIN_INFO: &[u8] = b"huddle-code-join-v1";

/// Derive the 32-byte wrap key both sides compute: `HKDF-SHA256` over the raw
/// X25519 ECDH shared secret of `our_secret` and `their_pub`. The owner uses it
/// to `passphrase::wrap` the session key; the joiner uses it to `unwrap`.
pub fn derive_wrap_key(our_secret: &StaticSecret, their_pub: &PublicKey) -> Result<[u8; KEY_LEN]> {
    let shared = our_secret.diffie_hellman(their_pub);
    // huddle 2.1.2 (audit CR-1): reject a non-contributory (small-order) peer
    // pubkey, the same defense-in-depth check the DM (`dm.rs`) and SAS
    // (`sas.rs`) ECDH paths already perform. Two honest peers always produce a
    // contributory secret, so this never rejects a real code-join.
    if !shared.was_contributory() {
        return Err(ProtocolError::Session(
            "code-join key agreement rejected: peer X25519 pubkey is non-contributory \
             (small-order point)"
                .into(),
        ));
    }
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut wrap_key = [0u8; KEY_LEN];
    hk.expand(CODE_JOIN_INFO, &mut wrap_key)
        .expect("32 bytes is within HKDF-SHA256's output limit");
    Ok(wrap_key)
}

/// Domain tag for the code-join proof-of-knowledge salt. Part of the wire
/// contract (huddle 2.2 / audit PA-1): both sides derive the salt the same way.
const CODE_PROOF_INFO: &[u8] = b"huddle-code-join-proof-v2";

/// huddle 2.2 (audit PA-1): the marker a v2 owner prepends to every join code it
/// issues. This is the **out-of-band capability anchor** that defeats a relay
/// downgrade: the owner hands the joiner the code over a channel the relay does
/// not control (Signal, in person, a QR), so the relay cannot strip this marker
/// the way it can strip a `capabilities` field from a network announcement. A
/// joiner that sees the marker sends the proof form **unconditionally** — it
/// never consults the relay-mediated capability for the code-join decision — so
/// the relay can no longer force the cleartext fallback. The marker begins with
/// a lowercase letter, which the join-code alphabet (`ABCDEFGHJKMNPQRSTUVWXYZ23456789`,
/// uppercase-only) never produces, so a legacy code can never be mistaken for a
/// v2 one. The proof is computed over the FULL code string, marker included.
pub const CODE_JOIN_V2_PREFIX: &str = "v2-";

/// huddle 2.2 (audit PA-1): derive a memory-hard *proof of knowledge* of the
/// join `code`, bound to the room and the joiner's ephemeral X25519 public key.
///
/// This replaces putting the cleartext bearer code on the (relay-readable) room
/// topic. A malicious relay that captures a proof cannot rebind it to its own
/// forged ephemeral key — that would require recomputing `Argon2id(code, …new
/// pubkey…)`, i.e. knowing the code — and cannot brute-force the ~40-bit code
/// out of the proof: the salt is unique per (room, ephemeral) so there is no
/// precomputation, and a single 64 MiB Argon2id guess over a 10-minute,
/// single-use code window is infeasible at any plausible attacker bandwidth.
///
/// Both the joiner (to build the request) and the owner (to verify it) call
/// this with the SAME `joiner_x25519_pub` — the 32 raw bytes of the ephemeral
/// key the joiner put in the request.
pub fn derive_code_proof(
    code: &str,
    room_id: &str,
    joiner_x25519_pub: &[u8; 32],
) -> Result<[u8; 32]> {
    // Salt = SHA256(domain || room_id || joiner_pubkey)[..16]. Binding the
    // ephemeral pubkey is what stops the relay's key-substitution; binding
    // room_id stops cross-room proof replay. Argon2id requires salt >= 8 bytes.
    let mut h = Sha256::new();
    h.update(CODE_PROOF_INFO);
    h.update(room_id.as_bytes());
    h.update(joiner_x25519_pub);
    let digest = h.finalize();
    let salt = &digest[..16];

    let params = argon2id_params(32)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(code.as_bytes(), salt, &mut out)
        .map_err(|e| ProtocolError::Session(format!("code-proof argon2: {e}")))?;
    Ok(out)
}

/// huddle 2.2 (audit PA-1): constant-time check that `proof` is the proof for
/// `expected_code` under this (`room_id`, `joiner_x25519_pub`). The owner calls
/// this for each unexpired issued code; the comparison is constant-time so a
/// timing side-channel can't leak how many proof bytes matched.
pub fn verify_code_proof(
    expected_code: &str,
    room_id: &str,
    joiner_x25519_pub: &[u8; 32],
    proof: &[u8; 32],
) -> Result<bool> {
    let recomputed = derive_code_proof(expected_code, room_id, joiner_x25519_pub)?;
    Ok(ct_eq_32(&recomputed, proof))
}

/// Constant-time equality for two 32-byte arrays — no early exit, so the time
/// taken doesn't depend on where the first differing byte is. (Local helper to
/// avoid pulling `subtle` as a direct dependency of this runtime-free crate.)
#[inline]
fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
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
        let k_owner = derive_wrap_key(&owner, &joiner_pub).unwrap();
        let k_joiner = derive_wrap_key(&joiner, &owner_pub).unwrap();
        assert_eq!(k_owner, k_joiner, "ECDH is commutative -> same wrap key");
    }

    #[test]
    fn different_peers_derive_different_keys() {
        let owner = StaticSecret::random_from_rng(OsRng);
        let a = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let b = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        assert_ne!(
            derive_wrap_key(&owner, &a).unwrap(),
            derive_wrap_key(&owner, &b).unwrap()
        );
    }

    #[test]
    fn code_proof_round_trips_for_the_right_code_and_pubkey() {
        let joiner = StaticSecret::random_from_rng(OsRng);
        let joiner_pub = PublicKey::from(&joiner);
        let proof = derive_code_proof("ABCD-2345", "room-x", joiner_pub.as_bytes()).unwrap();
        assert!(
            verify_code_proof("ABCD-2345", "room-x", joiner_pub.as_bytes(), &proof).unwrap(),
            "the issuing owner re-derives the same proof from the code it handed out"
        );
    }

    #[test]
    fn code_proof_rejects_wrong_code() {
        let joiner_pub = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let proof = derive_code_proof("ABCD-2345", "room-x", joiner_pub.as_bytes()).unwrap();
        assert!(!verify_code_proof("WXYZ-9876", "room-x", joiner_pub.as_bytes(), &proof).unwrap());
    }

    #[test]
    fn code_proof_is_bound_to_the_joiner_ephemeral_key() {
        // The PA-1 attack: a relay tries to rebind a captured proof to its OWN
        // ephemeral pubkey. The proof must not verify under a different pubkey.
        let real_pub = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let relay_pub = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let proof = derive_code_proof("ABCD-2345", "room-x", real_pub.as_bytes()).unwrap();
        assert!(
            !verify_code_proof("ABCD-2345", "room-x", relay_pub.as_bytes(), &proof).unwrap(),
            "a proof for the real joiner's key must fail under the relay's substituted key"
        );
    }

    #[test]
    fn v2_prefix_cannot_collide_with_a_legacy_code() {
        // The OOB downgrade-defense relies on a legacy code never being mistaken
        // for a v2 one. Legacy codes come from the uppercase-only alphabet
        // `ABCDEFGHJKMNPQRSTUVWXYZ23456789` with '-' only at index 4; the marker
        // leads with a lowercase letter that alphabet never emits.
        const LEGACY_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
        let first = CODE_JOIN_V2_PREFIX.as_bytes()[0];
        assert!((first as char).is_ascii_lowercase());
        assert!(!LEGACY_ALPHABET.contains(&first));
        assert!(!"ABCD-2345".starts_with(CODE_JOIN_V2_PREFIX));
        assert!("v2-ABCD-2345".starts_with(CODE_JOIN_V2_PREFIX));
    }

    #[test]
    fn code_proof_is_bound_to_the_room() {
        let joiner_pub = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let proof = derive_code_proof("ABCD-2345", "room-a", joiner_pub.as_bytes()).unwrap();
        assert!(
            !verify_code_proof("ABCD-2345", "room-b", joiner_pub.as_bytes(), &proof).unwrap(),
            "no cross-room proof replay"
        );
    }

    #[test]
    fn rejects_small_order_peer_pubkey() {
        // huddle 2.1.2 (audit CR-1): a small-order Montgomery point yields a
        // non-contributory shared secret and must be rejected.
        let owner = StaticSecret::random_from_rng(OsRng);
        // All-zero is the canonical small-order (identity) X25519 point.
        let small_order = PublicKey::from([0u8; 32]);
        assert!(derive_wrap_key(&owner, &small_order).is_err());
    }
}
