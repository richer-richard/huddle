//! huddle 1.3: post-quantum hybrid key-agreement primitives (ML-KEM-768).
//!
//! This module is the quantum-resistant half of huddle's **hybrid** DM key
//! agreement. It wraps the FIPS 203 ML-KEM-768 KEM (RustCrypto `ml-kem`,
//! pure Rust) and a transcript-binding HKDF **combiner** that mixes a
//! classical X25519 shared secret with the ML-KEM shared secret. The result
//! is at least as strong as the *stronger* of the two:
//!
//!   * a future quantum computer that breaks X25519 (via Shor) still cannot
//!     recover the key without also breaking ML-KEM, and
//!   * a (hypothetical) cryptanalytic break of ML-KEM still leaves the
//!     classical X25519 secret protecting the key.
//!
//! That is exactly the "harvest-now, decrypt-later" defence: an adversary who
//! records DM ciphertext today and builds a quantum computer tomorrow gains
//! nothing, because the X25519 secret they can eventually recover is only one
//! of the two HKDF inputs.
//!
//! ## Design choices specific to huddle's *non-interactive, static* DM model
//!
//! huddle's classical DM key (`crypto::dm::derive_dm_key`) is non-interactive
//! and reproducible: both peers derive the same `[u8; 32]` from long-term keys
//! with no stored per-DM state. ML-KEM is a KEM (directional: one side
//! encapsulates, the other decapsulates), so a hybrid path cannot be perfectly
//! symmetric — a ciphertext must travel from the initiator to the responder.
//! We keep everything else stateless by being *deterministic*:
//!
//!   * The ML-KEM keypair is **derived from the peer's long-term Ed25519
//!     identity seed** (`PqKeypair::from_identity_seed`, HKDF domain-
//!     separated), so it needs no extra storage and is stable across restarts.
//!     The public encapsulation key is still *published* to peers — they
//!     cannot compute it from the Ed25519 *public* key alone.
//!   * Encapsulation is **deterministic** (`encapsulate_deterministic`),
//!     seeded by a message `m` that the caller derives from the *initiator's*
//!     Ed25519 secret (see `crypto::dm`). This lets the initiator reproduce
//!     the exact ciphertext + shared secret with no per-DM secret state, while
//!     staying PQ-secure: `m` is unknown to anyone without the initiator's
//!     seed, so a Shor attacker who recovers the X25519 secret *still* cannot
//!     reconstruct the ML-KEM shared secret (that needs either `m`, which is
//!     seed-derived, or the responder's decapsulation key).
//!
//! See `crypto::dm::derive_dm_key_hybrid_initiator` / `_responder` for the
//! protocol wiring.

use hkdf::Hkdf;
use ml_kem::array::Array;
use ml_kem::{Decapsulate, DecapsulationKey, EncapsulationKey, KeyExport, MlKem768};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{HuddleError, Result};

/// Serialized length of an ML-KEM-768 encapsulation (public) key.
pub const MLKEM_EK_LEN: usize = 1184;
/// Serialized length of an ML-KEM-768 ciphertext.
pub const MLKEM_CT_LEN: usize = 1088;
/// Shared-secret length (ML-KEM, X25519, and our combined output all 32B).
pub const SS_LEN: usize = 32;

/// HKDF label for expanding an identity's Ed25519 seed into ML-KEM seed bytes.
const MLKEM_SEED_LABEL: &[u8] = b"huddle-mlkem-768-seed-v1";
/// HKDF salt for the hybrid combiner.
const HYBRID_COMBINE_SALT: &[u8] = b"huddle-hybrid-kem-v1";

/// A deterministically-derived ML-KEM-768 keypair bound to a huddle identity.
///
/// The decapsulation (secret) key never leaves the owner; the encapsulation
/// (public) key is published so peers can encapsulate a DM key to it. The
/// inner `DecapsulationKey` zeroizes its secret material on drop (ml-kem's
/// `zeroize` feature).
pub struct PqKeypair {
    dk: DecapsulationKey<MlKem768>,
}

impl PqKeypair {
    /// Derive the identity's ML-KEM-768 keypair from its 32-byte Ed25519
    /// secret seed. Deterministic and domain-separated, so the same identity
    /// always yields the same keypair with **zero** extra storage.
    ///
    /// The ML-KEM seed is `HKDF-SHA256(seed; salt = MLKEM_SEED_LABEL)` expanded
    /// to 64 bytes (ML-KEM's `d || z`), making the post-quantum key material
    /// cryptographically independent of both the Ed25519 signing key and the
    /// X25519 DM scalar (which use different derivations / labels).
    pub fn from_identity_seed(ed25519_seed: &[u8; 32]) -> Self {
        let mut seed64 = Zeroizing::new([0u8; 64]);
        let hk = Hkdf::<Sha256>::new(Some(MLKEM_SEED_LABEL), ed25519_seed);
        hk.expand(b"", seed64.as_mut_slice())
            .expect("HKDF expand to 64 bytes is within SHA-256's output limit");
        // Build ML-KEM's 64-byte Seed array, then derive the keypair. The
        // transient `seed` array is a short-lived stack copy; the long-lived
        // secret lives in `dk`, which zeroizes on drop.
        let seed: ml_kem::Seed =
            Array::try_from(seed64.as_slice()).expect("ML-KEM seed is exactly 64 bytes");
        let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
        Self { dk }
    }

    /// The serialized encapsulation (public) key, to publish to peers.
    pub fn encapsulation_key_bytes(&self) -> [u8; MLKEM_EK_LEN] {
        let encoded = self.dk.encapsulation_key().to_bytes();
        let mut out = [0u8; MLKEM_EK_LEN];
        out.copy_from_slice(&encoded);
        out
    }

    /// Decapsulate a ciphertext a peer produced by encapsulating to our
    /// encapsulation key, recovering the shared ML-KEM secret.
    ///
    /// ML-KEM decapsulation is infallible by construction (FIPS 203 implicit
    /// rejection: a malformed/forged ciphertext yields a pseudo-random secret
    /// rather than an error), so the only error path here is a wrong-length
    /// ciphertext.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; SS_LEN]>> {
        if ciphertext.len() != MLKEM_CT_LEN {
            return Err(HuddleError::Session(format!(
                "ML-KEM ciphertext is {} bytes, expected {MLKEM_CT_LEN}",
                ciphertext.len()
            )));
        }
        let ct = Array::try_from(ciphertext)
            .map_err(|_| HuddleError::Session("ML-KEM ciphertext decode failed".into()))?;
        let ss = self.dk.decapsulate(&ct);
        let mut out = Zeroizing::new([0u8; SS_LEN]);
        out.copy_from_slice(&ss);
        Ok(out)
    }
}

/// Encapsulate to a peer's ML-KEM-768 encapsulation key using a caller-supplied
/// **deterministic** 32-byte message `m`. Returns `(ciphertext, shared_secret)`.
///
/// `m` MUST be uniformly-distributed and secret. In huddle it is an HKDF output
/// keyed by the initiator's long-term Ed25519 seed (`crypto::dm`). The
/// determinism is intentional — it lets the initiator reproduce the exact DM
/// key with no per-DM secret state — and safe, because `m`'s secrecy rests on
/// the initiator's stored seed, not on the (quantum-breakable) X25519 secret.
pub fn encapsulate_deterministic(
    partner_ek_bytes: &[u8],
    m: &[u8; SS_LEN],
) -> Result<(Vec<u8>, Zeroizing<[u8; SS_LEN]>)> {
    if partner_ek_bytes.len() != MLKEM_EK_LEN {
        return Err(HuddleError::Session(format!(
            "ML-KEM encapsulation key is {} bytes, expected {MLKEM_EK_LEN}",
            partner_ek_bytes.len()
        )));
    }
    let ek_arr = Array::try_from(partner_ek_bytes)
        .map_err(|_| HuddleError::Session("ML-KEM encapsulation key decode failed".into()))?;
    let ek = EncapsulationKey::<MlKem768>::new(&ek_arr)
        .map_err(|_| HuddleError::Session("invalid ML-KEM encapsulation key".into()))?;
    let m_arr: ml_kem::B32 =
        Array::try_from(&m[..]).expect("encapsulation message is exactly 32 bytes");
    let (ct, ss) = ek.encapsulate_deterministic(&m_arr);
    let mut ss_out = Zeroizing::new([0u8; SS_LEN]);
    ss_out.copy_from_slice(&ss);
    Ok((ct.to_vec(), ss_out))
}

/// Combine a classical X25519 shared secret and an ML-KEM shared secret into a
/// single 32-byte hybrid key, binding the KEM ciphertext and a context label
/// into the transcript.
///
/// Construction:
/// ```text
/// HKDF-SHA256(
///     salt = "huddle-hybrid-kem-v1",
///     IKM  = ss_x25519 || ss_mlkem,
///     info = ct || context )
/// ```
///
/// This is a standard concatenation KEM-combiner: feeding both secrets as IKM
/// means the output is a secure key as long as *either* secret is secure (HKDF
/// behaves as a PRF keyed by the full IKM). Binding the ciphertext `ct` into
/// `info` ties the key to this exact exchange, so an attacker cannot pair our
/// shared secret with a different ciphertext. The result is never weaker than
/// the classical-only key: even if ML-KEM contributed nothing, `ss_x25519` is
/// still mixed in under the same HKDF.
pub fn combine_hybrid(
    ss_x25519: &[u8; SS_LEN],
    ss_mlkem: &[u8; SS_LEN],
    kem_ciphertext: &[u8],
    context: &[u8],
) -> Zeroizing<[u8; SS_LEN]> {
    let mut ikm = Zeroizing::new([0u8; 2 * SS_LEN]);
    ikm[..SS_LEN].copy_from_slice(ss_x25519);
    ikm[SS_LEN..].copy_from_slice(ss_mlkem);

    let mut info = Vec::with_capacity(kem_ciphertext.len() + context.len());
    info.extend_from_slice(kem_ciphertext);
    info.extend_from_slice(context);

    let hk = Hkdf::<Sha256>::new(Some(HYBRID_COMBINE_SALT), ikm.as_slice());
    let mut out = Zeroizing::new([0u8; SS_LEN]);
    hk.expand(&info, out.as_mut_slice())
        .expect("HKDF expand to 32 bytes is within SHA-256's output limit");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn keypair_is_deterministic_from_seed() {
        let a = PqKeypair::from_identity_seed(&seed(7));
        let b = PqKeypair::from_identity_seed(&seed(7));
        assert_eq!(
            a.encapsulation_key_bytes(),
            b.encapsulation_key_bytes(),
            "same identity seed must yield the same ML-KEM public key"
        );
    }

    #[test]
    fn different_seeds_yield_different_keys() {
        let a = PqKeypair::from_identity_seed(&seed(1));
        let b = PqKeypair::from_identity_seed(&seed(2));
        assert_ne!(a.encapsulation_key_bytes(), b.encapsulation_key_bytes());
    }

    #[test]
    fn ek_has_expected_size() {
        let kp = PqKeypair::from_identity_seed(&seed(9));
        assert_eq!(kp.encapsulation_key_bytes().len(), MLKEM_EK_LEN);
    }

    #[test]
    fn encapsulate_decapsulate_round_trip() {
        let responder = PqKeypair::from_identity_seed(&seed(42));
        let ek = responder.encapsulation_key_bytes();
        let m = [3u8; SS_LEN];

        let (ct, ss_send) = encapsulate_deterministic(&ek, &m).unwrap();
        assert_eq!(ct.len(), MLKEM_CT_LEN);

        let ss_recv = responder.decapsulate(&ct).unwrap();
        assert_eq!(
            *ss_send, *ss_recv,
            "encapsulator and decapsulator must agree"
        );
    }

    #[test]
    fn deterministic_encapsulation_reproduces() {
        let responder = PqKeypair::from_identity_seed(&seed(11));
        let ek = responder.encapsulation_key_bytes();
        let m = [5u8; SS_LEN];
        let (ct1, ss1) = encapsulate_deterministic(&ek, &m).unwrap();
        let (ct2, ss2) = encapsulate_deterministic(&ek, &m).unwrap();
        assert_eq!(ct1, ct2, "same m + ek must reproduce the same ciphertext");
        assert_eq!(*ss1, *ss2, "same m + ek must reproduce the same secret");
    }

    #[test]
    fn different_m_yields_different_ciphertext_and_secret() {
        let responder = PqKeypair::from_identity_seed(&seed(11));
        let ek = responder.encapsulation_key_bytes();
        let (ct_a, ss_a) = encapsulate_deterministic(&ek, &[1u8; SS_LEN]).unwrap();
        let (ct_b, ss_b) = encapsulate_deterministic(&ek, &[2u8; SS_LEN]).unwrap();
        assert_ne!(ct_a, ct_b);
        assert_ne!(*ss_a, *ss_b);
    }

    #[test]
    fn tampered_ciphertext_does_not_recover_secret() {
        // ML-KEM implicit rejection: a flipped ciphertext bit decapsulates to
        // a *different* (pseudo-random) secret rather than erroring. The point
        // is that the attacker cannot force agreement on the real secret.
        let responder = PqKeypair::from_identity_seed(&seed(99));
        let ek = responder.encapsulation_key_bytes();
        let (mut ct, ss_send) = encapsulate_deterministic(&ek, &[8u8; SS_LEN]).unwrap();
        ct[0] ^= 0x01;
        let ss_recv = responder.decapsulate(&ct).unwrap();
        assert_ne!(
            *ss_send, *ss_recv,
            "a tampered ciphertext must not recover the encapsulated secret"
        );
    }

    #[test]
    fn wrong_ek_length_is_rejected() {
        let err = encapsulate_deterministic(&[0u8; 10], &[0u8; SS_LEN]);
        assert!(err.is_err());
    }

    #[test]
    fn wrong_ct_length_is_rejected() {
        let kp = PqKeypair::from_identity_seed(&seed(1));
        assert!(kp.decapsulate(&[0u8; 10]).is_err());
    }

    #[test]
    fn combiner_is_deterministic_and_input_sensitive() {
        let ss_x = [1u8; SS_LEN];
        let ss_pq = [2u8; SS_LEN];
        let ct = vec![3u8; MLKEM_CT_LEN];
        let ctx = b"room-1";

        let k = *combine_hybrid(&ss_x, &ss_pq, &ct, ctx);
        let k_again = *combine_hybrid(&ss_x, &ss_pq, &ct, ctx);
        assert_eq!(k, k_again, "combiner must be deterministic");

        // Sensitive to each input.
        assert_ne!(k, *combine_hybrid(&[9u8; SS_LEN], &ss_pq, &ct, ctx));
        assert_ne!(k, *combine_hybrid(&ss_x, &[9u8; SS_LEN], &ct, ctx));
        let mut ct2 = ct.clone();
        ct2[0] ^= 0xFF;
        assert_ne!(k, *combine_hybrid(&ss_x, &ss_pq, &ct2, ctx));
        assert_ne!(k, *combine_hybrid(&ss_x, &ss_pq, &ct, b"room-2"));
    }

    #[test]
    fn combiner_differs_from_either_raw_secret() {
        let ss_x = [4u8; SS_LEN];
        let ss_pq = [5u8; SS_LEN];
        let ct = vec![6u8; MLKEM_CT_LEN];
        let k = *combine_hybrid(&ss_x, &ss_pq, &ct, b"ctx");
        assert_ne!(k, ss_x, "hybrid key must not equal the raw X25519 secret");
        assert_ne!(k, ss_pq, "hybrid key must not equal the raw ML-KEM secret");
    }

    #[test]
    fn full_two_party_hybrid_agreement() {
        // End-to-end: initiator encapsulates to responder's identity-derived
        // ek; both run the combiner over the SAME (ss_x, ss_pq, ct) and agree.
        let responder = PqKeypair::from_identity_seed(&seed(21));
        let ek = responder.encapsulation_key_bytes();
        let ss_x = [7u8; SS_LEN]; // stand-in for the X25519 half (tested in dm.rs)
        let m = [13u8; SS_LEN];

        let (ct, ss_pq_send) = encapsulate_deterministic(&ek, &m).unwrap();
        let key_initiator = *combine_hybrid(&ss_x, &ss_pq_send, &ct, b"dm-room");

        let ss_pq_recv = responder.decapsulate(&ct).unwrap();
        let key_responder = *combine_hybrid(&ss_x, &ss_pq_recv, &ct, b"dm-room");

        assert_eq!(key_initiator, key_responder);
    }
}
