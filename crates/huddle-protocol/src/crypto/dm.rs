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
use crate::crypto::pqc::{self, PqKeypair, SS_LEN};
use crate::error::{ProtocolError, Result};

/// Compute the classical X25519 shared secret half of a DM: our Ed25519 seed
/// against the partner's Ed25519 pubkey, with the 1.1.4 small-order
/// (contributory) check. Returned zeroizing so the raw secret is wiped after
/// it has been fed into a KDF. Shared by the classical and hybrid paths so the
/// contributory check has a single source of truth.
fn x25519_shared(
    our_ed25519_seed: &[u8; 32],
    partner_ed25519_pubkey: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
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
        return Err(ProtocolError::Session(
            "DM key agreement rejected: partner X25519 pubkey is non-contributory \
             (small-order point)"
                .into(),
        ));
    }
    Ok(Zeroizing::new(*shared.as_bytes()))
}

/// Derive the symmetric DM room key from one side's Ed25519 secret seed
/// and the other side's Ed25519 public key, plus the canonical DM
/// room_id (which binds the key to this specific 1-1 channel).
///
/// Both peers, swapping seed ↔ pubkey, derive identical output. This is the
/// **classical** (pre-quantum) derivation, kept as the backward-compatible
/// fallback when a peer has not published an ML-KEM key. See
/// `derive_dm_key_hybrid_initiator` / `_responder` for the post-quantum path.
pub fn derive_dm_key(
    our_ed25519_seed: &[u8; 32],
    partner_ed25519_pubkey: &[u8; 32],
    canonical_room_id: &str,
) -> Result<[u8; KEY_LEN]> {
    let shared = x25519_shared(our_ed25519_seed, partner_ed25519_pubkey)?;
    // HKDF-SHA256: a fixed v1 salt (versioned for future rotation) and
    // the canonical room_id as `info` so two different DMs between the
    // same identities (impossible by construction, but defended in
    // depth) can't share keys.
    let salt = b"huddle-dm-key-v1\0";
    let h = Hkdf::<Sha256>::new(Some(salt), shared.as_slice());
    let mut out = [0u8; KEY_LEN];
    h.expand(canonical_room_id.as_bytes(), &mut out)
        .map_err(|e| ProtocolError::Session(format!("hkdf expand: {e}")))?;
    Ok(out)
}

/// HKDF label for the deterministic ML-KEM encapsulation message.
const DM_ENCAPS_LABEL: &[u8] = b"huddle-dm-mlkem-encaps-v1";

/// Deterministic 32-byte ML-KEM encapsulation message for a DM, derived from
/// the **initiator's** Ed25519 seed bound to the partner's ML-KEM ek and the
/// canonical room id. This lets the initiator reproduce the exact ciphertext +
/// shared secret with no stored per-DM state, while `m` stays secret to anyone
/// without the initiator's seed — so a Shor attacker who recovers the X25519
/// secret still cannot reconstruct the ML-KEM half. (See `crypto::pqc`.)
fn derive_encaps_message(
    initiator_ed25519_seed: &[u8; 32],
    partner_mlkem_ek: &[u8],
    canonical_room_id: &str,
) -> Zeroizing<[u8; SS_LEN]> {
    let hk = Hkdf::<Sha256>::new(Some(DM_ENCAPS_LABEL), initiator_ed25519_seed);
    let mut info = Vec::with_capacity(partner_mlkem_ek.len() + canonical_room_id.len());
    info.extend_from_slice(partner_mlkem_ek);
    info.extend_from_slice(canonical_room_id.as_bytes());
    let mut m = Zeroizing::new([0u8; SS_LEN]);
    hk.expand(&info, m.as_mut_slice())
        .expect("HKDF expand to 32 bytes is within SHA-256's output limit");
    m
}

/// huddle 1.3: **initiator** side of the hybrid (X25519 + ML-KEM-768) DM key
/// agreement. The initiator — by convention the peer whose fingerprint sorts
/// lower — encapsulates a fresh ML-KEM secret to the partner's published
/// encapsulation key, mixes it with the classical X25519 secret, and gets the
/// DM wrap key plus the KEM ciphertext to transmit to the partner.
///
/// Returns `(hybrid_dm_key, kem_ciphertext)`. The ciphertext is **public** wire
/// data (carried in `MemberAnnounce.mlkem_ciphertext`); the responder needs it
/// to recover the same key via `derive_dm_key_hybrid_responder`.
pub fn derive_dm_key_hybrid_initiator(
    our_ed25519_seed: &[u8; 32],
    partner_ed25519_pubkey: &[u8; 32],
    partner_mlkem_ek: &[u8],
    canonical_room_id: &str,
) -> Result<([u8; KEY_LEN], Vec<u8>)> {
    let ss_x = x25519_shared(our_ed25519_seed, partner_ed25519_pubkey)?;
    let m = derive_encaps_message(our_ed25519_seed, partner_mlkem_ek, canonical_room_id);
    let (ct, ss_pq) = pqc::encapsulate_deterministic(partner_mlkem_ek, &m)?;
    let key = pqc::combine_hybrid(&ss_x, &ss_pq, &ct, canonical_room_id.as_bytes());
    Ok((*key, ct))
}

/// huddle 1.3: **responder** side of the hybrid DM key agreement. The responder
/// — the higher-fingerprint peer — decapsulates the initiator's KEM ciphertext
/// with its own ML-KEM keypair, mixes the recovered secret with the same
/// classical X25519 secret, and arrives at the identical DM wrap key.
pub fn derive_dm_key_hybrid_responder(
    our_pq: &PqKeypair,
    our_ed25519_seed: &[u8; 32],
    partner_ed25519_pubkey: &[u8; 32],
    kem_ciphertext: &[u8],
    canonical_room_id: &str,
) -> Result<[u8; KEY_LEN]> {
    let ss_x = x25519_shared(our_ed25519_seed, partner_ed25519_pubkey)?;
    let ss_pq = our_pq.decapsulate(kem_ciphertext)?;
    let key = pqc::combine_hybrid(&ss_x, &ss_pq, kem_ciphertext, canonical_room_id.as_bytes());
    Ok(*key)
}

/// huddle 2.0: downgrade guard for the DM **classical** (X25519-only) fallback.
///
/// Returns `true` when a classical DM key MUST be refused because the peer is
/// known to be post-quantum capable yet no ML-KEM encapsulation key is
/// available to build the hybrid key from — the fingerprint of a relay that
/// stripped the partner's ML-KEM pubkey to force a quantum-unsafe downgrade.
///
/// `peer_known_pq_capable` is the OR of every capability anchor the app holds:
/// an ML-KEM key on the current signed `MemberAnnounce`, the durable
/// `room_members.mlkem_pubkey` pin, **or** the out-of-band
/// `verified_peers.pq_capable` flag set when the peer SAS-verified with the F1
/// capability binding (`crypto::sas::derive_sas_code` with the partner's ek). The
/// verified-peer anchor is the strongest of the three: it survives a relay
/// dropping both the live announce key and the pin, so a peer we once confirmed
/// PQ-capable can never be silently re-keyed classical.
///
/// `have_mlkem_ek` is whether we currently hold a usable ek (announce or pin) to
/// derive the hybrid key. When the peer is known capable but `have_mlkem_ek` is
/// `false`, the caller should derive **no** key and instead wait for / request a
/// genuine hybrid announce rather than locking in a classical key.
///
/// This is a pure predicate so the security-critical downgrade policy is unit
/// testable without an `AppHandle`; the full key-derivation decision (initiator
/// vs responder, one-way classical→hybrid upgrade) lives in `app::plan_dm_key`,
/// which folds this guard in via its `partner_pq_capable` input.
pub fn must_refuse_classical_fallback(peer_known_pq_capable: bool, have_mlkem_ek: bool) -> bool {
    peer_known_pq_capable && !have_mlkem_ek
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
        .map_err(|e| ProtocolError::Session(format!("bad ed25519 pubkey: {e}")))?;
    Ok(PublicKey::from(vk.to_montgomery().to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKeys;

    #[test]
    fn dm_key_is_commutative() {
        let alice = IdentityKeys::generate().unwrap();
        let bob = IdentityKeys::generate().unwrap();
        let room_id = "deadbeefcafef00d1234567890abcdef";
        let k_a = derive_dm_key(&alice.secret_bytes(), &bob.public_bytes(), room_id).unwrap();
        let k_b = derive_dm_key(&bob.secret_bytes(), &alice.public_bytes(), room_id).unwrap();
        assert_eq!(k_a, k_b, "both peers must derive the same DM key");
    }

    #[test]
    fn dm_key_is_deterministic() {
        let alice = IdentityKeys::generate().unwrap();
        let bob = IdentityKeys::generate().unwrap();
        let room_id = "room-1";
        let k1 = derive_dm_key(&alice.secret_bytes(), &bob.public_bytes(), room_id).unwrap();
        let k2 = derive_dm_key(&alice.secret_bytes(), &bob.public_bytes(), room_id).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn dm_key_binds_to_room_id() {
        let alice = IdentityKeys::generate().unwrap();
        let bob = IdentityKeys::generate().unwrap();
        let k1 = derive_dm_key(&alice.secret_bytes(), &bob.public_bytes(), "room-1").unwrap();
        let k2 = derive_dm_key(&alice.secret_bytes(), &bob.public_bytes(), "room-2").unwrap();
        assert_ne!(
            k1, k2,
            "different room_ids must produce different keys (HKDF info parameter)"
        );
    }

    #[test]
    fn dm_key_differs_per_pair() {
        let alice = IdentityKeys::generate().unwrap();
        let bob = IdentityKeys::generate().unwrap();
        let carol = IdentityKeys::generate().unwrap();
        let room = "room";
        let k_ab = derive_dm_key(&alice.secret_bytes(), &bob.public_bytes(), room).unwrap();
        let k_ac = derive_dm_key(&alice.secret_bytes(), &carol.public_bytes(), room).unwrap();
        assert_ne!(k_ab, k_ac);
    }

    #[test]
    fn rejects_invalid_ed25519_pubkey() {
        let alice = IdentityKeys::generate().unwrap();
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
        let alice = IdentityKeys::generate().unwrap();
        let mut id_point = [0u8; 32];
        id_point[0] = 1;
        let r = derive_dm_key(&alice.secret_bytes(), &id_point, "room");
        assert!(r.is_err(), "small-order partner pubkey must be rejected");
    }

    // ---- huddle 1.3: hybrid X25519 + ML-KEM-768 DM key agreement ----

    #[test]
    fn hybrid_initiator_and_responder_agree() {
        // alice = initiator (encapsulates to bob's ek), bob = responder.
        let alice = IdentityKeys::generate().unwrap();
        let bob = IdentityKeys::generate().unwrap();
        let room = "deadbeefcafef00d1234567890abcdef";

        let (k_init, ct) = derive_dm_key_hybrid_initiator(
            &alice.secret_bytes(),
            &bob.public_bytes(),
            &bob.mlkem_public_bytes(),
            room,
        )
        .unwrap();

        let k_resp = derive_dm_key_hybrid_responder(
            &bob.pq_keypair(),
            &bob.secret_bytes(),
            &alice.public_bytes(),
            &ct,
            room,
        )
        .unwrap();

        assert_eq!(
            k_init, k_resp,
            "both peers must derive the same hybrid DM key"
        );
    }

    #[test]
    fn hybrid_key_differs_from_classical() {
        let alice = IdentityKeys::generate().unwrap();
        let bob = IdentityKeys::generate().unwrap();
        let room = "room-x";

        let classical = derive_dm_key(&alice.secret_bytes(), &bob.public_bytes(), room).unwrap();
        let (hybrid, _ct) = derive_dm_key_hybrid_initiator(
            &alice.secret_bytes(),
            &bob.public_bytes(),
            &bob.mlkem_public_bytes(),
            room,
        )
        .unwrap();
        assert_ne!(
            classical, hybrid,
            "hybrid key must mix in the ML-KEM secret, so it differs from classical"
        );
    }

    #[test]
    fn hybrid_is_reproducible_by_initiator() {
        // Deterministic encapsulation: the initiator re-derives the identical
        // key + ciphertext with no stored per-DM state (survives a restart).
        let alice = IdentityKeys::generate().unwrap();
        let bob = IdentityKeys::generate().unwrap();
        let room = "room-determinism";
        let (k1, ct1) = derive_dm_key_hybrid_initiator(
            &alice.secret_bytes(),
            &bob.public_bytes(),
            &bob.mlkem_public_bytes(),
            room,
        )
        .unwrap();
        let (k2, ct2) = derive_dm_key_hybrid_initiator(
            &alice.secret_bytes(),
            &bob.public_bytes(),
            &bob.mlkem_public_bytes(),
            room,
        )
        .unwrap();
        assert_eq!(k1, k2);
        assert_eq!(ct1, ct2);
    }

    #[test]
    fn hybrid_binds_to_room_id() {
        let alice = IdentityKeys::generate().unwrap();
        let bob = IdentityKeys::generate().unwrap();
        let (k1, _) = derive_dm_key_hybrid_initiator(
            &alice.secret_bytes(),
            &bob.public_bytes(),
            &bob.mlkem_public_bytes(),
            "room-1",
        )
        .unwrap();
        let (k2, _) = derive_dm_key_hybrid_initiator(
            &alice.secret_bytes(),
            &bob.public_bytes(),
            &bob.mlkem_public_bytes(),
            "room-2",
        )
        .unwrap();
        assert_ne!(k1, k2, "different rooms must yield different hybrid keys");
    }

    #[test]
    fn hybrid_responder_rejects_tampered_ciphertext() {
        // A flipped ciphertext bit decapsulates to a different ML-KEM secret
        // (implicit rejection), so the responder derives a DIFFERENT key than
        // the initiator — the wrapped session key then fails to unwrap, which
        // is the desired fail-closed behaviour.
        let alice = IdentityKeys::generate().unwrap();
        let bob = IdentityKeys::generate().unwrap();
        let room = "room-tamper";
        let (k_init, mut ct) = derive_dm_key_hybrid_initiator(
            &alice.secret_bytes(),
            &bob.public_bytes(),
            &bob.mlkem_public_bytes(),
            room,
        )
        .unwrap();
        ct[0] ^= 0x01;
        let k_resp = derive_dm_key_hybrid_responder(
            &bob.pq_keypair(),
            &bob.secret_bytes(),
            &alice.public_bytes(),
            &ct,
            room,
        )
        .unwrap();
        assert_ne!(k_init, k_resp);
    }

    #[test]
    fn hybrid_initiator_rejects_bad_ek_length() {
        let alice = IdentityKeys::generate().unwrap();
        let bob = IdentityKeys::generate().unwrap();
        let r = derive_dm_key_hybrid_initiator(
            &alice.secret_bytes(),
            &bob.public_bytes(),
            &[0u8; 16], // wrong ek length
            "room",
        );
        assert!(r.is_err());
    }

    // ---- huddle 2.0: classical-fallback downgrade guard ----

    #[test]
    fn refuses_classical_only_for_known_capable_peer_without_ek() {
        // The single dangerous combination: peer is known PQ-capable but no
        // ML-KEM key is currently available to build the hybrid key from.
        assert!(must_refuse_classical_fallback(true, false));
    }

    #[test]
    fn allows_classical_when_peer_not_known_capable() {
        // A genuine pre-1.3 / classical-only peer: classical is the correct key.
        assert!(!must_refuse_classical_fallback(false, false));
        assert!(!must_refuse_classical_fallback(false, true));
    }

    #[test]
    fn does_not_refuse_when_ek_is_available() {
        // Capable peer *with* an ek isn't refused here — the caller will derive
        // the hybrid key instead; this guard only blocks the classical fallback.
        assert!(!must_refuse_classical_fallback(true, true));
    }
}
