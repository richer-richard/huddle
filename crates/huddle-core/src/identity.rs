//! huddle-core's `Identity` — the libp2p-aware wrapper over the runtime-free
//! [`huddle_protocol::IdentityKeys`]. It holds the same Ed25519 key plus the
//! libp2p `Keypair`/`PeerId` derived from the same seed, and `Deref`s to
//! `IdentityKeys` so every pure method (`fingerprint`, `sign`, `seed`,
//! `pq_keypair`, `mlkem_public_bytes`, …) resolves there and existing call
//! sites are unchanged.

use libp2p::identity::{self, Keypair};
use libp2p::PeerId;
use zeroize::Zeroizing;

use huddle_protocol::IdentityKeys;

use crate::error::{HuddleError, Result};

// huddle 2.0.4 (WS1.1): re-export the pure identity helpers at their original
// `crate::identity::…` paths so `compute_fingerprint`, `safety_code`,
// `relay_auth_msg`, and `RELAY_AUTH_DOMAIN` callers don't move.
pub use huddle_protocol::identity::{
    compute_fingerprint, relay_auth_msg, safety_code, RELAY_AUTH_DOMAIN,
};

/// A huddle identity: the runtime-free [`IdentityKeys`] (Ed25519 signing key +
/// fingerprint + derived ML-KEM keypair) plus the libp2p `Keypair`/`PeerId`
/// derived from the same 32-byte seed. Derefs to `IdentityKeys`.
pub struct Identity {
    keys: IdentityKeys,
    libp2p_keypair: Keypair,
    peer_id: PeerId,
}

impl std::ops::Deref for Identity {
    type Target = IdentityKeys;

    fn deref(&self) -> &Self::Target {
        &self.keys
    }
}

impl Identity {
    pub fn generate() -> Result<Self> {
        Self::from_keys(IdentityKeys::generate()?)
    }

    pub fn from_secret_bytes(bytes: [u8; 32]) -> Result<Self> {
        Self::from_keys(IdentityKeys::from_secret_bytes(bytes)?)
    }

    /// huddle 2.0: rebuild from a 32-byte Ed25519 seed recovered from a BIP39
    /// phrase. The seed is the only input, so the restored identity is
    /// byte-for-byte the original — same fingerprint, PeerId, and ML-KEM key.
    pub fn from_seed(seed: Zeroizing<[u8; 32]>) -> Result<Self> {
        Self::from_keys(IdentityKeys::from_seed(seed)?)
    }

    /// Derive the libp2p `Keypair`/`PeerId` from the same Ed25519 seed the
    /// `IdentityKeys` already hold. F6: the extracted secret and the
    /// `[secret || public]` scratch buffer are `Zeroizing` so they're scrubbed
    /// when this returns rather than left on the stack.
    fn from_keys(keys: IdentityKeys) -> Result<Self> {
        let secret = Zeroizing::new(keys.secret_bytes());
        let public = keys.public_bytes();
        let mut combined = Zeroizing::new([0u8; 64]);
        combined[..32].copy_from_slice(&*secret);
        combined[32..].copy_from_slice(&public);

        let ed25519_kp = identity::ed25519::Keypair::try_from_bytes(&mut *combined)
            .map_err(|e| HuddleError::Identity(e.to_string()))?;
        let libp2p_keypair = Keypair::from(ed25519_kp);
        let peer_id = PeerId::from(libp2p_keypair.public());

        Ok(Self {
            keys,
            libp2p_keypair,
            peer_id,
        })
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn keypair(&self) -> &Keypair {
        &self.libp2p_keypair
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pqc;

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
    fn mlkem_pubkey_is_stable_across_reload() {
        // huddle 1.3: the ML-KEM keypair is derived from the Ed25519 seed, so
        // reloading the same identity must reproduce the same public key — no
        // persistence, no migration, stable across restarts.
        let bytes = Identity::generate().unwrap().secret_bytes();
        let a = Identity::from_secret_bytes(bytes).unwrap();
        let b = Identity::from_secret_bytes(bytes).unwrap();
        assert_eq!(a.mlkem_public_bytes(), b.mlkem_public_bytes());
        assert_eq!(a.mlkem_public_bytes().len(), pqc::MLKEM_EK_LEN);
    }

    #[test]
    fn mlkem_pubkey_differs_per_identity() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        assert_ne!(a.mlkem_public_bytes(), b.mlkem_public_bytes());
    }

    #[test]
    fn mlkem_keypair_round_trips_against_self() {
        // Encapsulate to our own published ek, then decapsulate — sanity that
        // the deterministically-derived keypair is internally consistent.
        let id = Identity::generate().unwrap();
        let ek = id.mlkem_public_bytes();
        let (ct, ss_send) = pqc::encapsulate_deterministic(&ek, &[1u8; pqc::SS_LEN]).unwrap();
        let ss_recv = id.pq_keypair().decapsulate(&ct).unwrap();
        assert_eq!(*ss_send, *ss_recv);
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
            assert!(g
                .chars()
                .all(|c| c.is_ascii_hexdigit() && c.is_ascii_uppercase() || c.is_ascii_digit()));
        }
    }

    #[test]
    fn seed_matches_secret_bytes() {
        // huddle 2.0: `seed` is the same 32 bytes as `secret_bytes`, just
        // wrapped in Zeroizing so the export copy is scrubbed on drop.
        let id = Identity::generate().unwrap();
        assert_eq!(*id.seed(), id.secret_bytes());
    }

    #[test]
    fn from_seed_round_trips_identity() {
        // huddle 2.0: export the seed and rebuild — the restored identity must
        // be byte-for-byte identical (fingerprint, PeerId, ML-KEM pubkey).
        let id = Identity::generate().unwrap();
        let restored = Identity::from_seed(id.seed()).unwrap();
        assert_eq!(id.fingerprint(), restored.fingerprint());
        assert_eq!(id.peer_id(), restored.peer_id());
        assert_eq!(id.mlkem_public_bytes(), restored.mlkem_public_bytes());
    }

    #[test]
    fn bip39_phrase_fully_restores_identity() {
        // huddle 2.0: the end-to-end recovery path — export the seed as a
        // 24-word phrase, decode it back, and reconstruct the identity, exactly
        // as the "write it down, import on a fresh install" flow does.
        let id = Identity::generate().unwrap();
        let phrase = crate::crypto::mnemonic::seed_to_phrase(&id.seed());
        let seed = crate::crypto::mnemonic::phrase_to_seed(&phrase).unwrap();
        let restored = Identity::from_seed(seed).unwrap();
        assert_eq!(id.fingerprint(), restored.fingerprint());
        assert_eq!(id.peer_id(), restored.peer_id());
        assert_eq!(id.mlkem_public_bytes(), restored.mlkem_public_bytes());
    }
}
