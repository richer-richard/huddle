//! huddle 2.0: BIP39 seed-phrase encoding of the 32-byte Ed25519 identity
//! seed (F6).
//!
//! This is a deterministic 1:1 encoding, **not** a key-derivation step. The
//! 256-bit Ed25519 seed maps to a checksummed 24-word English mnemonic and
//! back, so the phrase *is* the crown-jewel root secret: written on paper it
//! restores the whole identity — PeerId, the deterministically-derived
//! ML-KEM-768 keypair, and every DM key — on a fresh install, without ever
//! touching the database (the DB only ever stores the raw 32 bytes). There is
//! no passphrase / PBKDF2 stretching and no RNG here: we use only bip39's
//! entropy <-> word mapping. See `crate::identity::Identity::{seed, from_seed}`
//! for the identity-level export/import that sits on top of this.

use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

use crate::error::{HuddleError, Result};

/// Encode a 32-byte Ed25519 identity seed as a 24-word BIP39 English
/// mnemonic. 256 bits of entropy → 24 words, where the last word folds in an
/// 8-bit SHA-256 checksum, so a single mistyped or transposed word is caught
/// on import. Deterministic: the same seed always yields the same phrase.
pub fn seed_to_phrase(seed: &[u8; 32]) -> String {
    // `from_entropy` only errors for entropy lengths BIP39 doesn't define
    // (must be a multiple of 32 bits in [128, 256]). 256 bits is valid, so
    // this is infallible for our fixed 32-byte seed — the `expect` documents
    // that invariant rather than guarding a reachable failure.
    Mnemonic::from_entropy(seed)
        .expect("a 32-byte seed is a valid 256-bit BIP39 entropy length")
        .to_string()
}

/// Decode a 24-word BIP39 mnemonic back to the 32-byte Ed25519 seed,
/// validating the checksum. Input is trimmed and lower-cased first (BIP39
/// English words are ASCII-lowercase, and `split_whitespace` inside the
/// parser collapses any run of spaces/tabs/newlines), so a phrase pasted
/// with odd casing or stray whitespace still imports cleanly.
///
/// Errors if any word is off the wordlist, the word count is wrong, or the
/// checksum doesn't match — i.e. a corrupted or mistyped phrase. The returned
/// seed is the sole input to `Identity::from_seed`, so a successful decode
/// reproduces the original identity byte-for-byte.
pub fn phrase_to_seed(phrase: &str) -> Result<[u8; 32]> {
    let normalized = phrase.trim().to_lowercase();
    let mnemonic = Mnemonic::parse_in(Language::English, normalized)
        .map_err(|e| HuddleError::Identity(format!("invalid seed phrase: {e}")))?;

    // `to_entropy_array` writes the entropy into a fixed 33-byte buffer and
    // reports its real length; for a checksum-valid 24-word phrase that length
    // is exactly 32. Anything else (e.g. a 12-word phrase) is a syntactically
    // valid mnemonic that simply isn't a 256-bit Ed25519 seed. Keep the buffer
    // in `Zeroizing` so the secret entropy is scrubbed when we return.
    let (raw, len) = mnemonic.to_entropy_array();
    let raw = Zeroizing::new(raw);
    if len != 32 {
        return Err(HuddleError::Identity(format!(
            "seed phrase decodes to {len} bytes; expected a 24-word (32-byte) phrase"
        )));
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&raw[..32]);
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical BIP39 256-bit all-zero entropy test vector (Trezor/BIP39
    /// spec): 23 × `abandon` + the checksum word `art`.
    fn zero_seed_phrase() -> String {
        let mut words = vec!["abandon"; 23];
        words.push("art");
        words.join(" ")
    }

    #[test]
    fn zero_seed_matches_bip39_vector() {
        // Encode the spec's all-zero seed and confirm we land on the exact
        // published 24-word phrase (covers the English wordlist + checksum).
        let phrase = seed_to_phrase(&[0u8; 32]);
        assert_eq!(phrase, zero_seed_phrase());
        assert_eq!(phrase.split_whitespace().count(), 24);
        // …and decode it back to the all-zero seed.
        assert_eq!(phrase_to_seed(&zero_seed_phrase()).unwrap(), [0u8; 32]);
    }

    #[test]
    fn round_trips_random_seeds() {
        for _ in 0..32 {
            let seed: [u8; 32] = rand::random();
            let phrase = seed_to_phrase(&seed);
            assert_eq!(phrase.split_whitespace().count(), 24);
            assert_eq!(phrase_to_seed(&phrase).unwrap(), seed);
        }
    }

    #[test]
    fn is_case_insensitive_and_trims_whitespace() {
        let seed = [7u8; 32];
        let phrase = seed_to_phrase(&seed);
        // Upper-case the whole phrase and bury it in tabs / newlines / double
        // spaces — it must still decode to the same seed.
        let messy = format!("  \t {} \n  ", phrase.to_uppercase().replace(' ', "  "));
        assert_eq!(phrase_to_seed(&messy).unwrap(), seed);
    }

    #[test]
    fn rejects_bad_checksum() {
        // 24 × `abandon` is a syntactically valid word list but encodes the
        // wrong checksum for all-zero entropy (the correct word is `art`), so
        // the checksum guard must reject it.
        let bad_checksum = vec!["abandon"; 24].join(" ");
        assert!(phrase_to_seed(&bad_checksum).is_err());
    }

    #[test]
    fn rejects_off_wordlist_word() {
        let mut words = vec!["abandon"; 23];
        words.push("notabip39word");
        assert!(phrase_to_seed(&words.join(" ")).is_err());
    }

    #[test]
    fn rejects_wrong_word_count() {
        // 23 words is not a defined BIP39 length.
        let short = vec!["abandon"; 23].join(" ");
        assert!(phrase_to_seed(&short).is_err());
    }
}
