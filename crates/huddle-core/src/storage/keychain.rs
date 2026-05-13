//! Master-key derivation for at-rest encryption.
//!
//! On launch the user enters a master passphrase. We combine it with a
//! per-installation salt (kept in the data dir, unencrypted — its only
//! job is to make rainbow-table attacks unreasonable) and feed both into
//! Argon2id to derive a 32-byte master key. That key is used for:
//!
//!  1. `PRAGMA key` on the SQLCipher connection
//!  2. HKDF input for the Megolm session-persistence key
//!     (replaces the hardcoded all-zero key from Phase 1)

use std::fs;
use std::path::PathBuf;

use argon2::Argon2;
use rand::RngCore;

use crate::config;
use crate::error::{HuddleError, Result};

pub const MASTER_KEY_LEN: usize = 32;
pub const KEYCHAIN_SALT_LEN: usize = 16;

/// Returns the path holding the keychain salt. The salt is not secret;
/// only the passphrase is.
pub fn keychain_salt_path() -> PathBuf {
    config::data_dir().join("keychain.salt")
}

/// Load the keychain salt, generating + persisting it on first launch.
pub fn load_or_create_salt() -> Result<[u8; KEYCHAIN_SALT_LEN]> {
    let path = keychain_salt_path();
    if let Ok(bytes) = fs::read(&path) {
        if bytes.len() == KEYCHAIN_SALT_LEN {
            let mut out = [0u8; KEYCHAIN_SALT_LEN];
            out.copy_from_slice(&bytes);
            return Ok(out);
        }
    }
    config::ensure_data_dir()?;
    let mut salt = [0u8; KEYCHAIN_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    fs::write(&path, salt).map_err(|e| HuddleError::Other(format!("write salt: {e}")))?;
    Ok(salt)
}

/// Derive a 32-byte master key from passphrase + salt via Argon2id.
pub fn derive_master_key(
    passphrase: &str,
    salt: &[u8; KEYCHAIN_SALT_LEN],
) -> Result<[u8; MASTER_KEY_LEN]> {
    let argon = Argon2::default();
    let mut out = [0u8; MASTER_KEY_LEN];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| HuddleError::Other(format!("argon2 derive: {e}")))?;
    Ok(out)
}

/// Returns a 32-byte subkey for `purpose` (e.g. "megolm-persist") derived
/// from the master key via SHA-256. Good enough for our use since the
/// master key is already cryptographically random.
pub fn derive_subkey(master_key: &[u8; MASTER_KEY_LEN], purpose: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(master_key);
    hasher.update(b"|");
    hasher.update(purpose);
    let h = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic() {
        let salt = [42u8; KEYCHAIN_SALT_LEN];
        let k1 = derive_master_key("hunter2", &salt).unwrap();
        let k2 = derive_master_key("hunter2", &salt).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_differs_with_passphrase() {
        let salt = [42u8; KEYCHAIN_SALT_LEN];
        let k1 = derive_master_key("hunter2", &salt).unwrap();
        let k2 = derive_master_key("hunter3", &salt).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn subkeys_are_purpose_separated() {
        let mk = [9u8; MASTER_KEY_LEN];
        let a = derive_subkey(&mk, b"megolm-persist");
        let b = derive_subkey(&mk, b"db-encryption");
        assert_ne!(a, b);
    }
}
