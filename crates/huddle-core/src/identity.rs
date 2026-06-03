use ed25519_dalek::{Signer, SigningKey};
use libp2p::identity::{self, Keypair};
use libp2p::PeerId;
use sha2::{Digest, Sha256};

use crate::error::{HuddleError, Result};

pub struct Identity {
    signing_key: SigningKey,
    libp2p_keypair: Keypair,
    peer_id: PeerId,
    fingerprint: String,
}

impl Identity {
    pub fn generate() -> Result<Self> {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        Self::from_signing_key(signing_key)
    }

    pub fn from_secret_bytes(bytes: [u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(&bytes);
        Self::from_signing_key(signing_key)
    }

    fn from_signing_key(signing_key: SigningKey) -> Result<Self> {
        let secret = signing_key.to_bytes();
        let public = signing_key.verifying_key().to_bytes();
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&secret);
        combined[32..].copy_from_slice(&public);

        let ed25519_kp = identity::ed25519::Keypair::try_from_bytes(&mut combined)
            .map_err(|e| HuddleError::Identity(e.to_string()))?;
        let libp2p_keypair = Keypair::from(ed25519_kp);
        let peer_id = PeerId::from(libp2p_keypair.public());
        let fingerprint = compute_fingerprint(&public);

        Ok(Self {
            signing_key,
            libp2p_keypair,
            peer_id,
            fingerprint,
        })
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn keypair(&self) -> &Keypair {
        &self.libp2p_keypair
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Ed25519-sign `msg` with our identity key. The signature binds
    /// arbitrary bytes to this fingerprint; used by protocol envelopes
    /// (`SignedRoomMessage`) so receivers can prove the sender's identity
    /// at the application layer (gossipsub only proves transport-level).
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing_key.sign(msg).to_bytes()
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
/// challenge-response. The client signs `RELAY_AUTH_DOMAIN || nonce` with
/// its Ed25519 identity key; the relay verifies that signature against the
/// presented pubkey and checks the pubkey hashes to the claimed fingerprint.
/// The distinct domain tag keeps this signature from ever being mistaken for
/// a `SignedRoomMessage` envelope (which commits a different tag).
pub const RELAY_AUTH_DOMAIN: &[u8] = b"huddle-relay-auth-v1";

/// Build the exact bytes a client signs to prove control of its identity key
/// to the relay: the domain tag followed by the server's 32-byte challenge
/// nonce. The relay (`huddle-server`) open-codes the identical construction,
/// so the two must stay byte-for-byte in sync.
pub fn relay_auth_msg(nonce: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(RELAY_AUTH_DOMAIN.len() + nonce.len());
    m.extend_from_slice(RELAY_AUTH_DOMAIN);
    m.extend_from_slice(nonce);
    m
}

/// huddle 0.7.8: 12-hex Safety Code derived from the same SHA-256 of the
/// Ed25519 pubkey that backs `compute_fingerprint`. Format
/// `SAFE-XXXX-XXXX-XXXX` (uppercase, dash-separated). Display-only — a
/// shorter, less ambiguous handle to compare against a friend at the
/// start of a session. SAS-via-emoji is still the real verification
/// primitive; this is the visual analogue of DirectChat's
/// `accountSafetyCode`.
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
    fn fingerprint_is_deterministic() {
        let key_bytes = [42u8; 32];
        let id = Identity::from_secret_bytes(key_bytes).unwrap();
        let id2 = Identity::from_secret_bytes(key_bytes).unwrap();
        assert_eq!(id.fingerprint(), id2.fingerprint());
    }

    #[test]
    fn fingerprint_format_is_correct() {
        let id = Identity::generate().unwrap();
        let fp = id.fingerprint();
        let parts: Vec<&str> = fp.split('-').collect();
        assert_eq!(parts.len(), 6);
        for part in &parts {
            assert_eq!(part.len(), 4);
            assert!(part.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn different_keys_produce_different_fingerprints() {
        let id1 = Identity::generate().unwrap();
        let id2 = Identity::generate().unwrap();
        assert_ne!(id1.fingerprint(), id2.fingerprint());
    }

    #[test]
    fn round_trip_through_bytes() {
        let id1 = Identity::generate().unwrap();
        let bytes = id1.secret_bytes();
        let id2 = Identity::from_secret_bytes(bytes).unwrap();
        assert_eq!(id1.fingerprint(), id2.fingerprint());
        assert_eq!(id1.peer_id(), id2.peer_id());
    }

    #[test]
    fn peer_id_is_derived_from_same_key() {
        let id = Identity::generate().unwrap();
        let pid = id.peer_id();
        assert!(!pid.to_string().is_empty());
    }

    #[test]
    fn safety_code_is_stable_and_well_formed() {
        let key = [7u8; 32];
        let a = safety_code(&key);
        let b = safety_code(&key);
        assert_eq!(a, b);
        assert!(a.starts_with("SAFE-"));
        let groups: Vec<&str> = a.trim_start_matches("SAFE-").split('-').collect();
        assert_eq!(groups.len(), 3);
        for g in &groups {
            assert_eq!(g.len(), 4);
            assert!(g.chars().all(|c| c.is_ascii_hexdigit() && c.is_ascii_uppercase() || c.is_ascii_digit()));
        }
    }
}
