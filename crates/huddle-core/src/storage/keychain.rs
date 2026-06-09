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
use std::io::Write;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

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
///
/// huddle 1.3.4: this used to **silently regenerate** the salt whenever the
/// file existed but did not read back as exactly `KEYCHAIN_SALT_LEN` bytes
/// (and even on a non-`NotFound` read error such as a permission/IO fault).
/// Because the salt is deterministic input to Argon2id, overwriting it
/// derives a *different* master key and the existing SQLCipher DB becomes
/// permanently undecryptable — surfacing only as a misleading "wrong master
/// passphrase" later. We now regenerate **only** when the file genuinely does
/// not exist, and otherwise refuse to clobber it, returning an actionable
/// error so the user can restore a backup rather than lose the database.
pub fn load_or_create_salt() -> Result<[u8; KEYCHAIN_SALT_LEN]> {
    let path = keychain_salt_path();
    match fs::read(&path) {
        Ok(bytes) => match classify_existing_salt(&bytes) {
            SaltState::Good(salt) => Ok(salt),
            // A zero-byte file is the signature of an interrupted first-launch
            // write (created, never filled). No key was ever derived from it,
            // so regenerating is safe and recovers the install.
            SaltState::EmptyRegenerable => generate_and_persist_salt(&path),
            SaltState::Corrupt(len) => Err(HuddleError::Other(format!(
                "keychain salt file at {} is corrupt: {len} bytes, expected {}. \
                 Refusing to overwrite it, because regenerating the salt would \
                 make the existing encrypted database permanently undecryptable. \
                 Restore your backup of this file, or (only if you accept losing \
                 the existing database) delete it and restart to begin fresh.",
                path.display(),
                KEYCHAIN_SALT_LEN
            ))),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            generate_and_persist_salt(&path)
        }
        Err(e) => Err(HuddleError::Other(format!(
            "failed to read keychain salt at {} ({e}). Refusing to regenerate, \
             since overwriting a present-but-unreadable salt would brick the \
             existing encrypted database. Fix the file's permissions/IO and retry.",
            path.display()
        ))),
    }
}

/// The three meaningful states of an *existing* salt file, split out as a
/// pure function so the corrupt-vs-empty-vs-good decision is unit-testable.
#[derive(Debug, PartialEq, Eq)]
enum SaltState {
    /// Correct length — use it verbatim.
    Good([u8; KEYCHAIN_SALT_LEN]),
    /// Zero-length (interrupted first write) — safe to regenerate.
    EmptyRegenerable,
    /// Present but wrong length — must NOT be overwritten (carries the length).
    Corrupt(usize),
}

fn classify_existing_salt(bytes: &[u8]) -> SaltState {
    if bytes.len() == KEYCHAIN_SALT_LEN {
        let mut out = [0u8; KEYCHAIN_SALT_LEN];
        out.copy_from_slice(bytes);
        SaltState::Good(out)
    } else if bytes.is_empty() {
        SaltState::EmptyRegenerable
    } else {
        SaltState::Corrupt(bytes.len())
    }
}

/// Generate a fresh random salt and persist it. Only called when there is no
/// usable existing salt to protect (first launch / empty file).
fn generate_and_persist_salt(path: &Path) -> Result<[u8; KEYCHAIN_SALT_LEN]> {
    let salt = generate_new_salt()?;
    persist_salt(path, &salt)?;
    Ok(salt)
}

/// Mint a fresh random 16-byte salt **without** writing it anywhere.
///
/// Factored out of `generate_and_persist_salt` so minting and persisting are
/// separable and independently unit-testable. Returns `Result` only to compose
/// with the persisting callers; the RNG draw itself cannot fail.
///
/// huddle 2.0.0 (F5): the master-passphrase change flow deliberately does NOT
/// call this. It re-derives the new master key from the new passphrase against
/// the *existing* salt — Argon2id with the same salt but a different passphrase
/// already yields a different key, so a new salt buys nothing. Rotating the salt
/// there would instead open an unrecoverable window: if the salt write failed
/// *after* `PRAGMA rekey` committed, the on-disk salt would still derive the OLD
/// key while the DB is now encrypted under the NEW one, bricking the database.
/// This helper is therefore only used for first-launch salt creation.
pub fn generate_new_salt() -> Result<[u8; KEYCHAIN_SALT_LEN]> {
    let mut salt = [0u8; KEYCHAIN_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    Ok(salt)
}

/// Write `salt` to `path` atomically: stage it in a sibling temp file, fsync,
/// then rename into place. The rename is the single commit point, so an
/// interrupted write can never leave a truncated salt — precisely the
/// "present but wrong length" corruption that `load_or_create_salt` now
/// refuses to clobber (huddle 1.3.4). Creates the parent directory if needed.
pub fn persist_salt(path: &Path, salt: &[u8; KEYCHAIN_SALT_LEN]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| HuddleError::Other(format!("create salt dir: {e}")))?;
    }
    // Stage beside the destination so the rename stays on one filesystem
    // (a cross-device rename is not atomic).
    let tmp = path.with_extension("salt.tmp");
    {
        let mut f = fs::File::create(&tmp)
            .map_err(|e| HuddleError::Other(format!("stage salt: {e}")))?;
        f.write_all(salt)
            .map_err(|e| HuddleError::Other(format!("write salt: {e}")))?;
        f.sync_all()
            .map_err(|e| HuddleError::Other(format!("sync salt: {e}")))?;
    }
    fs::rename(&tmp, path).map_err(|e| HuddleError::Other(format!("commit salt: {e}")))?;
    Ok(())
}

// huddle 2.0.0 (F5): a `rotate_salt` helper used to live here, called by the
// master-passphrase change flow to overwrite `keychain.salt` after a re-key. It
// was removed: rotating the salt on a passphrase change is unnecessary (Argon2id
// over the same salt with a different passphrase already derives a different
// key) and actively dangerous — a salt write that failed after `PRAGMA rekey`
// committed would brick the database. The change flow now keeps the salt fixed,
// so there is no salt write to fail. See `app::change_master_passphrase`.

/// Derive a 32-byte master key from passphrase + salt via Argon2id.
/// Parameters follow the strong RFC 9106 / OWASP profile (64 MiB memory,
/// 3 iterations, 4 lanes) and must stay in sync with the room-passphrase
/// KDF in `crypto::passphrase::derive_key`.
pub fn derive_master_key(
    passphrase: &str,
    salt: &[u8; KEYCHAIN_SALT_LEN],
) -> Result<[u8; MASTER_KEY_LEN]> {
    let params = Params::new(65_536, 3, 4, Some(MASTER_KEY_LEN))
        .map_err(|e| HuddleError::Other(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; MASTER_KEY_LEN];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| HuddleError::Other(format!("argon2 derive: {e}")))?;
    Ok(out)
}

/// Return a 32-byte subkey for `purpose` (e.g. "megolm-persist") derived
/// from the master key via HKDF-SHA256. The master key is the input key
/// material and `purpose` is the HKDF `info` parameter — proper domain
/// separation, no ad-hoc separator ambiguity.
pub fn derive_subkey(master_key: &[u8; MASTER_KEY_LEN], purpose: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut out = [0u8; 32];
    hk.expand(purpose, &mut out)
        .expect("32 bytes is well within HKDF-SHA256's output limit");
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

    // huddle 2.0.0 (F5): a freshly minted salt is exactly the right length
    // and never collides with the previous one (rainbow-table reset).
    #[test]
    fn generate_new_salt_is_random() {
        let a = generate_new_salt().unwrap();
        let b = generate_new_salt().unwrap();
        assert_eq!(a.len(), KEYCHAIN_SALT_LEN);
        // Collision probability is ~2^-128 — a failure here means a broken RNG.
        assert_ne!(a, b);
    }

    // huddle 2.0.0 (F5): persist must round-trip verbatim, leave no temp file
    // behind, and overwrite cleanly so a later read never sees a partial salt.
    #[test]
    fn persist_salt_round_trips_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keychain.salt");

        let salt = generate_new_salt().unwrap();
        persist_salt(&path, &salt).unwrap();
        let back = fs::read(&path).unwrap();
        assert_eq!(back.len(), KEYCHAIN_SALT_LEN);
        assert_eq!(back, salt);
        // The staging file is consumed by the rename, never left dangling.
        assert!(!path.with_extension("salt.tmp").exists());

        // Rotating to a different salt overwrites in place, no leftovers.
        let salt2 = generate_new_salt().unwrap();
        persist_salt(&path, &salt2).unwrap();
        assert_eq!(fs::read(&path).unwrap(), salt2);
        assert!(!path.with_extension("salt.tmp").exists());
    }

    // huddle 1.3.4: corruption must be detected, never silently overwritten.
    #[test]
    fn classify_salt_good_empty_corrupt() {
        let good = [7u8; KEYCHAIN_SALT_LEN];
        assert_eq!(classify_existing_salt(&good), SaltState::Good(good));
        assert_eq!(classify_existing_salt(&[]), SaltState::EmptyRegenerable);
        // Truncated (8 bytes) and expanded (24 bytes) both count as corrupt.
        assert_eq!(classify_existing_salt(&[1u8; 8]), SaltState::Corrupt(8));
        assert_eq!(classify_existing_salt(&[1u8; 24]), SaltState::Corrupt(24));
        // One byte short of correct is still corrupt, not "good".
        assert_eq!(
            classify_existing_salt(&[1u8; KEYCHAIN_SALT_LEN - 1]),
            SaltState::Corrupt(KEYCHAIN_SALT_LEN - 1)
        );
    }
}
