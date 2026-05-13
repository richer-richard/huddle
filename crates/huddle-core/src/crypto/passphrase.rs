//! Passphrase-derived key wrapping for Megolm session keys.
//!
//! Argon2id derives a 32-byte key from a user passphrase + per-room salt.
//! ChaCha20-Poly1305 then wraps the Megolm session key for transmission.
//! Anyone in possession of the passphrase + salt can unwrap and join the room.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;

use crate::error::{HuddleError, Result};

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

/// Generate a random salt for a new encrypted room.
pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derive a 32-byte symmetric key from a passphrase and salt using Argon2id.
pub fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let params = Params::new(19_456, 2, 1, Some(KEY_LEN))
        .map_err(|e| HuddleError::Session(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| HuddleError::Session(format!("argon2 derive: {e}")))?;
    Ok(out)
}

/// Wrap arbitrary plaintext (typically a Megolm SessionKey) under the passphrase key.
/// Returns nonce || ciphertext, base64-encoded for transmission.
pub fn wrap(plaintext: &[u8], passphrase_key: &[u8; KEY_LEN]) -> Result<String> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(passphrase_key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| HuddleError::Session(format!("wrap failed: {e}")))?;
    let mut combined = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&ciphertext);
    Ok(base64::engine::general_purpose::STANDARD.encode(&combined))
}

/// Unwrap base64-encoded (nonce || ciphertext) under the passphrase key.
pub fn unwrap(encoded: &str, passphrase_key: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| HuddleError::Session(format!("bad base64: {e}")))?;
    if bytes.len() < NONCE_LEN + 16 {
        return Err(HuddleError::Session("wrapped key too short".into()));
    }
    let (nonce_bytes, ciphertext) = bytes.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(passphrase_key));
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| HuddleError::Session(format!("unwrap failed (wrong passphrase?): {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic() {
        let salt = [42u8; SALT_LEN];
        let k1 = derive_key("hunter2", &salt).unwrap();
        let k2 = derive_key("hunter2", &salt).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn different_passphrases_different_keys() {
        let salt = [42u8; SALT_LEN];
        let k1 = derive_key("hunter2", &salt).unwrap();
        let k2 = derive_key("hunter3", &salt).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn different_salts_different_keys() {
        let k1 = derive_key("same", &[1u8; SALT_LEN]).unwrap();
        let k2 = derive_key("same", &[2u8; SALT_LEN]).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn wrap_unwrap_round_trip() {
        let salt = random_salt();
        let key = derive_key("hunter2", &salt).unwrap();
        let secret = b"this is a megolm session key";
        let wrapped = wrap(secret, &key).unwrap();
        let recovered = unwrap(&wrapped, &key).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn wrong_passphrase_fails_unwrap() {
        let salt = random_salt();
        let right_key = derive_key("hunter2", &salt).unwrap();
        let wrong_key = derive_key("hunter3", &salt).unwrap();
        let wrapped = wrap(b"secret", &right_key).unwrap();
        assert!(unwrap(&wrapped, &wrong_key).is_err());
    }

    #[test]
    fn wrapped_output_is_nondeterministic() {
        let salt = random_salt();
        let key = derive_key("hunter2", &salt).unwrap();
        let w1 = wrap(b"hello", &key).unwrap();
        let w2 = wrap(b"hello", &key).unwrap();
        assert_ne!(w1, w2, "nonce should differ each time");
    }
}
