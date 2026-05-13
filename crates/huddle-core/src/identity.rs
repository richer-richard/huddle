use ed25519_dalek::SigningKey;
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
}

fn compute_fingerprint(public_key: &[u8; 32]) -> String {
    let hash = Sha256::digest(public_key);
    let hex_str = hex::encode(&hash[..12]);
    hex_str
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<&str>>()
        .join("-")
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
}
