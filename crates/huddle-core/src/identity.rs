use ed25519_dalek::{Signer, SigningKey};
use libp2p::identity::{self, Keypair};
use libp2p::PeerId;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::pqc::{self, PqKeypair};
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
        // F6: both the extracted secret and the [secret || public] scratch buffer
        // hold the crown-jewel seed. Wrap them in `Zeroizing` so they're scrubbed
        // when this function returns rather than left on the stack. (`public` is
        // not secret — it's the verifying key — so it stays a bare array.)
        let secret = Zeroizing::new(signing_key.to_bytes());
        let public = signing_key.verifying_key().to_bytes();
        let mut combined = Zeroizing::new([0u8; 64]);
        combined[..32].copy_from_slice(&*secret);
        combined[32..].copy_from_slice(&public);

        let ed25519_kp = identity::ed25519::Keypair::try_from_bytes(&mut *combined)
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

    /// huddle 1.3: this identity's ML-KEM-768 keypair, **deterministically
    /// derived** from the Ed25519 secret seed (see `crypto::pqc`). Computed on
    /// demand — there is no extra key material on disk; the existing 32-byte
    /// Ed25519 seed is the sole root secret, so every pre-1.3 identity gains a
    /// post-quantum keypair for free with no migration.
    pub fn pq_keypair(&self) -> PqKeypair {
        let seed = Zeroizing::new(self.signing_key.to_bytes());
        PqKeypair::from_identity_seed(&seed)
    }

    /// huddle 1.3: our serialized ML-KEM-768 encapsulation (public) key,
    /// published to peers in the signed `MemberAnnounce` on Direct rooms so they
    /// can encapsulate a hybrid DM key to us (and persist it as our PQ-capability
    /// pin). Stable across restarts. (Not carried in `ContactRequest`, which has
    /// no ML-KEM field — capability is always learned from a `MemberAnnounce`.)
    pub fn mlkem_public_bytes(&self) -> [u8; pqc::MLKEM_EK_LEN] {
        self.pq_keypair().encapsulation_key_bytes()
    }

    /// huddle 2.0: export this identity's 32-byte Ed25519 seed — the **sole
    /// root secret** from which the PeerId, the ML-KEM-768 keypair, and every
    /// DM key deterministically derive. Returned in a `Zeroizing` wrapper so
    /// the copy is scrubbed from memory when the caller drops it. Rendered as a
    /// 24-word BIP39 phrase by `crate::crypto::mnemonic::seed_to_phrase` for
    /// backup / recovery; treat it as the crown jewel (anyone holding it owns
    /// this identity). Distinct from `secret_bytes`, which hands back the raw
    /// (un-scrubbed) bytes the storage layer persists.
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing_key.to_bytes())
    }

    /// huddle 2.0: rebuild an identity from a 32-byte Ed25519 seed recovered
    /// from a BIP39 phrase (`crate::crypto::mnemonic::phrase_to_seed`). The
    /// seed is the only input, so the restored identity is byte-for-byte the
    /// original — same fingerprint, PeerId, and ML-KEM keypair — letting a
    /// fresh install fully recover from the written-down phrase with no DB
    /// migration. Takes the seed by `Zeroizing` value so the caller's copy is
    /// scrubbed on drop once we've turned it into key state.
    pub fn from_seed(seed: Zeroizing<[u8; 32]>) -> Result<Self> {
        // Build the signing key straight from the `Zeroizing` buffer by reference
        // (`&seed` deref-coerces to `&[u8; 32]`) so the seed is never copied into
        // a bare array on the stack en route — `from_signing_key` then scrubs the
        // key material it derives (F6).
        let signing_key = SigningKey::from_bytes(&seed);
        Self::from_signing_key(signing_key)
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
        // `phrase_to_seed` now hands back a `Zeroizing<[u8; 32]>`, which feeds
        // straight into `from_seed` with no intermediate bare-array copy.
        let seed = crate::crypto::mnemonic::phrase_to_seed(&phrase).unwrap();
        let restored = Identity::from_seed(seed).unwrap();
        assert_eq!(id.fingerprint(), restored.fingerprint());
        assert_eq!(id.peer_id(), restored.peer_id());
        assert_eq!(id.mlkem_public_bytes(), restored.mlkem_public_bytes());
    }
}
