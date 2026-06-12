//! huddle 2.0.6 (WS2-a): ML-DSA-65 (FIPS 204) signatures for **hybrid
//! post-quantum authentication**.
//!
//! Identity/authority envelopes are signed classically with Ed25519 *and*
//! (when the composite path is used) with ML-DSA-65, so a forgery requires
//! breaking BOTH — a quantum adversary that breaks Ed25519 still can't forge.
//! The ML-DSA keypair is **deterministically derived from the same 32-byte
//! Ed25519 identity seed** (via an HKDF with a distinct domain label), so every
//! identity gains a PQ signing key for free with no new on-disk material —
//! exactly the model `pqc` (ML-KEM) uses for confidentiality.
//!
//! ML-DSA signatures are large (3309 bytes) and public keys are 1952 bytes, so
//! the composite is applied to **low-frequency identity/authority messages**
//! (announces, invites, owner/ban grants), never to every chat line.

use hkdf::Hkdf;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa65, Signature, Signer, SigningKey,
    VerifyingKey, B32,
};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Serialized length of an ML-DSA-65 verifying (public) key.
pub const MLDSA_PK_LEN: usize = 1952;
/// Serialized length of an ML-DSA-65 signature.
pub const MLDSA_SIG_LEN: usize = 3309;

/// HKDF label expanding an identity's Ed25519 seed into the 32-byte ML-DSA seed.
/// Distinct from the ML-KEM and DM labels so the PQ-auth key is cryptographically
/// independent of every other key derived from the same root seed.
const MLDSA_SEED_LABEL: &[u8] = b"huddle-mldsa-65-seed-v1";

/// A deterministically-derived ML-DSA-65 keypair bound to a huddle identity.
pub struct MlDsaKeypair {
    sk: SigningKey<MlDsa65>,
}

impl MlDsaKeypair {
    /// Derive the identity's ML-DSA-65 keypair from its 32-byte Ed25519 secret
    /// seed. Deterministic + domain-separated; reproduces the same keypair on
    /// every call with zero extra storage.
    pub fn from_identity_seed(ed25519_seed: &[u8; 32]) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        let hk = Hkdf::<Sha256>::new(Some(MLDSA_SEED_LABEL), ed25519_seed);
        hk.expand(b"", seed.as_mut_slice())
            .expect("HKDF expand to 32 bytes is within SHA-256's output limit");
        let seed_arr: B32 = (*seed).into();
        let sk = SigningKey::<MlDsa65>::from_seed(&seed_arr);
        Self { sk }
    }

    /// The serialized ML-DSA-65 verifying (public) key, to publish + pin.
    pub fn public_bytes(&self) -> [u8; MLDSA_PK_LEN] {
        let enc: EncodedVerifyingKey<MlDsa65> = self.sk.verifying_key().encode();
        let mut out = [0u8; MLDSA_PK_LEN];
        out.copy_from_slice(enc.as_slice());
        out
    }

    /// Sign `msg` (FIPS 204, empty context — the message bytes already carry
    /// huddle's domain-separation tag).
    pub fn sign(&self, msg: &[u8]) -> [u8; MLDSA_SIG_LEN] {
        let sig: Signature<MlDsa65> = self.sk.sign(msg);
        let enc: EncodedSignature<MlDsa65> = sig.encode();
        let mut out = [0u8; MLDSA_SIG_LEN];
        out.copy_from_slice(enc.as_slice());
        out
    }
}

/// Verify an ML-DSA-65 signature over `msg` against a serialized verifying key.
/// Returns `false` on any malformed input or signature mismatch.
pub fn verify(pubkey_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> bool {
    let pk_enc = match EncodedVerifyingKey::<MlDsa65>::try_from(pubkey_bytes) {
        Ok(a) => a,
        Err(_) => return false,
    };
    let vk = VerifyingKey::<MlDsa65>::decode(&pk_enc);
    let sig_enc = match EncodedSignature::<MlDsa65>::try_from(sig_bytes) {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig = match Signature::<MlDsa65>::decode(&sig_enc) {
        Some(s) => s,
        None => return false,
    };
    vk.verify_with_context(msg, &[], &sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_keypair_and_sizes() {
        let a = MlDsaKeypair::from_identity_seed(&[7u8; 32]);
        let b = MlDsaKeypair::from_identity_seed(&[7u8; 32]);
        assert_eq!(a.public_bytes(), b.public_bytes());
        assert_eq!(a.public_bytes().len(), MLDSA_PK_LEN);
        let c = MlDsaKeypair::from_identity_seed(&[8u8; 32]);
        assert_ne!(a.public_bytes(), c.public_bytes());
    }

    #[test]
    fn sign_verify_round_trip() {
        let kp = MlDsaKeypair::from_identity_seed(&[1u8; 32]);
        let pk = kp.public_bytes();
        let sig = kp.sign(b"authority message");
        assert_eq!(sig.len(), MLDSA_SIG_LEN);
        assert!(verify(&pk, b"authority message", &sig));
        // Wrong message, tampered signature, and wrong key all fail.
        assert!(!verify(&pk, b"different message", &sig));
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(!verify(&pk, b"authority message", &bad));
        let other = MlDsaKeypair::from_identity_seed(&[2u8; 32]).public_bytes();
        assert!(!verify(&other, b"authority message", &sig));
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        let kp = MlDsaKeypair::from_identity_seed(&[3u8; 32]);
        let sig = kp.sign(b"m");
        assert!(!verify(b"too short", b"m", &sig));
        assert!(!verify(&kp.public_bytes(), b"m", b"short sig"));
    }
}
