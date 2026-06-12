use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::pqc::{self, PqKeypair};
use crate::error::Result;

/// The runtime-free half of a huddle identity: the Ed25519 signing key, its
/// derived 24-char fingerprint, and (on demand) the ML-KEM-768 keypair derived
/// from the same seed.
///
/// `huddle-core::identity::Identity` wraps this and adds the libp2p
/// `PeerId`/`Keypair` (which need the libp2p dependency), delegating every pure
/// method here via `Deref` — so `id.fingerprint()`, `id.sign(..)`, `id.seed()`
/// etc. resolve to these implementations and existing call sites are unchanged.
pub struct IdentityKeys {
    signing_key: SigningKey,
    fingerprint: String,
}

impl IdentityKeys {
    pub fn generate() -> Result<Self> {
        let mut rng = rand::thread_rng();
        Ok(Self::from_signing_key(SigningKey::generate(&mut rng)))
    }

    pub fn from_secret_bytes(bytes: [u8; 32]) -> Result<Self> {
        Ok(Self::from_signing_key(SigningKey::from_bytes(&bytes)))
    }

    fn from_signing_key(signing_key: SigningKey) -> Self {
        let public = signing_key.verifying_key().to_bytes();
        let fingerprint = compute_fingerprint(&public);
        Self {
            signing_key,
            fingerprint,
        }
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Ed25519-sign `msg` with our identity key. Used by protocol envelopes
    /// (`SignedRoomMessage`) and signed invites so receivers can prove the
    /// sender's identity at the application layer.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing_key.sign(msg).to_bytes()
    }

    /// huddle 1.3: this identity's ML-KEM-768 keypair, **deterministically
    /// derived** from the Ed25519 secret seed (see [`crate::crypto::pqc`]).
    /// Computed on demand — there is no extra key material on disk; the 32-byte
    /// Ed25519 seed is the sole root secret, so every pre-1.3 identity gains a
    /// post-quantum keypair for free with no migration.
    pub fn pq_keypair(&self) -> PqKeypair {
        let seed = Zeroizing::new(self.signing_key.to_bytes());
        PqKeypair::from_identity_seed(&seed)
    }

    /// huddle 1.3: our serialized ML-KEM-768 encapsulation (public) key,
    /// published to peers in the signed `MemberAnnounce` on Direct rooms.
    /// Stable across restarts.
    pub fn mlkem_public_bytes(&self) -> [u8; pqc::MLKEM_EK_LEN] {
        self.pq_keypair().encapsulation_key_bytes()
    }

    /// huddle 2.0.6 (WS2-a): our serialized ML-DSA-65 verifying (public) key,
    /// published in signed announces so peers can **pin** it for hybrid
    /// post-quantum authentication. Deterministically derived from the Ed25519
    /// seed (see [`crate::crypto::mldsa`]); stable across restarts, no storage.
    pub fn mldsa_public_bytes(&self) -> [u8; crate::crypto::mldsa::MLDSA_PK_LEN] {
        let seed = Zeroizing::new(self.signing_key.to_bytes());
        crate::crypto::mldsa::MlDsaKeypair::from_identity_seed(&seed).public_bytes()
    }

    /// huddle 2.0.6 (WS2-a): ML-DSA-65-sign `msg` with our identity's
    /// deterministically-derived post-quantum authentication key. Used for the
    /// composite signature on identity/authority envelopes.
    pub fn mldsa_sign(&self, msg: &[u8]) -> [u8; crate::crypto::mldsa::MLDSA_SIG_LEN] {
        let seed = Zeroizing::new(self.signing_key.to_bytes());
        crate::crypto::mldsa::MlDsaKeypair::from_identity_seed(&seed).sign(msg)
    }

    /// huddle 2.0: export this identity's 32-byte Ed25519 seed — the **sole
    /// root secret** from which the PeerId, the ML-KEM-768 keypair, and every
    /// DM key deterministically derive. Returned in a `Zeroizing` wrapper so
    /// the copy is scrubbed when the caller drops it. Rendered as a 24-word
    /// BIP39 phrase by [`crate::crypto::mnemonic::seed_to_phrase`] for backup /
    /// recovery; treat it as the crown jewel.
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing_key.to_bytes())
    }

    /// huddle 2.0: rebuild from a 32-byte Ed25519 seed recovered from a BIP39
    /// phrase ([`crate::crypto::mnemonic::phrase_to_seed`]). The seed is the
    /// only input, so the restored keys are byte-for-byte the original.
    pub fn from_seed(seed: Zeroizing<[u8; 32]>) -> Result<Self> {
        Ok(Self::from_signing_key(SigningKey::from_bytes(&seed)))
    }
}

/// Derive the human-facing 24-char fingerprint from an Ed25519 public key.
/// Format: `xxxx-xxxx-xxxx-xxxx-xxxx-xxxx` (6 groups of 4 hex chars, 24 hex
/// chars total = 12 bytes = 96 bits of SHA-256 over the pubkey). Public so
/// `crypto::verify_signed` can re-derive it from a signed envelope's pubkey
/// and check that it matches the asserted fingerprint.
pub fn compute_fingerprint(public_key: &[u8; 32]) -> String {
    let hash = Sha256::digest(public_key);
    let hex_str = hex::encode(&hash[..12]);
    hex_str
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<&str>>()
        .join("-")
}

/// huddle 1.1.4: domain-separation prefix for the relay client-auth
/// challenge-response. The client signs `RELAY_AUTH_DOMAIN || nonce` with its
/// Ed25519 identity key; the relay verifies that signature against the
/// presented pubkey and checks the pubkey hashes to the claimed fingerprint.
/// The distinct domain tag keeps this signature from ever being mistaken for a
/// `SignedRoomMessage` envelope (which commits a different tag).
pub const RELAY_AUTH_DOMAIN: &[u8] = b"huddle-relay-auth-v1";

/// Build the exact bytes a client signs to prove control of its identity key to
/// the relay: the domain tag followed by the server's challenge nonce. The
/// relay (`huddle-server`) now calls this same function, so the two stay
/// byte-for-byte in sync by construction.
pub fn relay_auth_msg(nonce: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(RELAY_AUTH_DOMAIN.len() + nonce.len());
    m.extend_from_slice(RELAY_AUTH_DOMAIN);
    m.extend_from_slice(nonce);
    m
}

/// huddle 0.7.8: 12-hex Safety Code derived from the same SHA-256 of the
/// Ed25519 pubkey that backs `compute_fingerprint`. Format
/// `SAFE-XXXX-XXXX-XXXX` (uppercase, dash-separated). Display-only — a shorter,
/// less ambiguous handle to compare against a friend at the start of a session.
pub fn safety_code(public_key: &[u8; 32]) -> String {
    let hash = Sha256::digest(public_key);
    let hex_str = hex::encode(&hash[..6]).to_ascii_uppercase();
    let groups: Vec<&str> = hex_str
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    format!("SAFE-{}", groups.join("-"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_deterministic_and_well_formed() {
        let id = IdentityKeys::from_secret_bytes([42u8; 32]).unwrap();
        let id2 = IdentityKeys::from_secret_bytes([42u8; 32]).unwrap();
        assert_eq!(id.fingerprint(), id2.fingerprint());
        let parts: Vec<&str> = id.fingerprint().split('-').collect();
        assert_eq!(parts.len(), 6);
        for p in &parts {
            assert_eq!(p.len(), 4);
            assert!(p.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn mlkem_pubkey_is_stable_and_per_identity() {
        let bytes = IdentityKeys::generate().unwrap().secret_bytes();
        let a = IdentityKeys::from_secret_bytes(bytes).unwrap();
        let b = IdentityKeys::from_secret_bytes(bytes).unwrap();
        assert_eq!(a.mlkem_public_bytes(), b.mlkem_public_bytes());
        assert_eq!(a.mlkem_public_bytes().len(), pqc::MLKEM_EK_LEN);
        let other = IdentityKeys::generate().unwrap();
        assert_ne!(a.mlkem_public_bytes(), other.mlkem_public_bytes());
    }

    #[test]
    fn seed_round_trips_keys() {
        let id = IdentityKeys::generate().unwrap();
        assert_eq!(*id.seed(), id.secret_bytes());
        let restored = IdentityKeys::from_seed(id.seed()).unwrap();
        assert_eq!(id.fingerprint(), restored.fingerprint());
        assert_eq!(id.mlkem_public_bytes(), restored.mlkem_public_bytes());
    }

    #[test]
    fn safety_code_is_stable_and_well_formed() {
        let a = safety_code(&[7u8; 32]);
        assert_eq!(a, safety_code(&[7u8; 32]));
        assert!(a.starts_with("SAFE-"));
        let groups: Vec<&str> = a.trim_start_matches("SAFE-").split('-').collect();
        assert_eq!(groups.len(), 3);
        for g in &groups {
            assert_eq!(g.len(), 4);
        }
    }

    #[test]
    fn relay_auth_msg_is_domain_prefixed() {
        let m = relay_auth_msg(&[9u8; 32]);
        assert!(m.starts_with(RELAY_AUTH_DOMAIN));
        assert_eq!(m.len(), RELAY_AUTH_DOMAIN.len() + 32);
    }
}
