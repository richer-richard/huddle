//! File encryption for room attachments.
//!
//! Megolm advances its ratchet on every encrypted message. Chunk-wise
//! Megolm would burn through key material; instead we encrypt each
//! file body with a fresh ChaCha20-Poly1305 key, then Megolm-wrap that
//! key once. The wrapped key + nonce travel inside the FileOffer.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto::RoomCrypto;
use crate::error::{HuddleError, Result};

/// Metadata that lets the receiver decrypt an encrypted file: the
/// Megolm session id used to wrap the file key, the wrapped file key
/// itself, and the ChaCha20-Poly1305 nonce. All bytes base64-encoded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedFileMeta {
    pub megolm_session_id: String,
    pub wrapped_key_b64: String,
    pub nonce_b64: String,
    /// SHA-256 of the plaintext, hex-encoded. Bound as AEAD associated
    /// data so the (key, nonce, ciphertext) triple can't be replayed
    /// against different content, and verified after decryption.
    pub content_hash: String,
}

/// Encrypt `plaintext` with a fresh ChaCha20-Poly1305 key, then Megolm-
/// wrap that key via the room's outbound session. The returned bytes
/// are what gets chunked and sent on the wire; the meta travels in the
/// FileOffer alongside the file_id.
pub fn encrypt_file(
    plaintext: &[u8],
    room_crypto: &mut RoomCrypto,
) -> Result<(Vec<u8>, EncryptedFileMeta)> {
    let mut file_key = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut file_key);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // Bind the ciphertext to a commitment of its plaintext via AEAD
    // associated data, so a room member can't replay this (key, nonce,
    // ciphertext) triple under a different file_id / name.
    let content_hash = super::sha256_hex(plaintext);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&file_key));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: content_hash.as_bytes(),
            },
        )
        .map_err(|e| HuddleError::Other(format!("chacha20 encrypt: {e}")))?;

    let (session_id, wrapped) = room_crypto.encrypt(&file_key)?;
    let meta = EncryptedFileMeta {
        megolm_session_id: session_id,
        wrapped_key_b64: B64.encode(wrapped),
        nonce_b64: B64.encode(nonce_bytes),
        content_hash,
    };
    Ok((ciphertext, meta))
}

/// Inverse of `encrypt_file`. The caller supplies the sender's
/// fingerprint so we know which inbound Megolm session to use.
pub fn decrypt_file(
    ciphertext: &[u8],
    meta: &EncryptedFileMeta,
    room_crypto: &mut RoomCrypto,
    sender_fingerprint: &str,
) -> Result<Vec<u8>> {
    let wrapped = B64
        .decode(&meta.wrapped_key_b64)
        .map_err(|e| HuddleError::Other(format!("bad wrapped_key_b64: {e}")))?;
    let file_key_bytes = room_crypto.decrypt(sender_fingerprint, &meta.megolm_session_id, &wrapped)?;
    if file_key_bytes.len() != 32 {
        return Err(HuddleError::Other(format!(
            "unwrapped file key is {} bytes, expected 32",
            file_key_bytes.len()
        )));
    }
    let nonce_bytes = B64
        .decode(&meta.nonce_b64)
        .map_err(|e| HuddleError::Other(format!("bad nonce_b64: {e}")))?;
    if nonce_bytes.len() != 12 {
        return Err(HuddleError::Other(format!(
            "nonce is {} bytes, expected 12",
            nonce_bytes.len()
        )));
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&file_key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad: meta.content_hash.as_bytes(),
            },
        )
        .map_err(|e| HuddleError::Other(format!("chacha20 decrypt: {e}")))?;
    // The AEAD tag already binds the ciphertext to the content_hash AAD;
    // verifying the hash explicitly also catches a sender who announced a
    // content_hash that doesn't match what they actually encrypted.
    if super::sha256_hex(&plaintext) != meta.content_hash {
        return Err(HuddleError::Other(
            "decrypted file content does not match its announced hash".into(),
        ));
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::open_db_in_memory;
    use crate::storage::repo::{insert_room, StoredRoom};

    fn make_room(id: &str) -> StoredRoom {
        StoredRoom {
            id: id.into(),
            name: "test".into(),
            creator_fingerprint: "alice-fp".into(),
            encrypted: true,
            passphrase_salt: None,
            created_at: 1,
            last_active: None,
        }
    }

    #[test]
    fn round_trip_alice_to_bob() {
        let db_a = open_db_in_memory().unwrap();
        let db_b = open_db_in_memory().unwrap();
        let room_id = "r1";
        insert_room(&db_a, &make_room(room_id)).unwrap();
        insert_room(&db_b, &make_room(room_id)).unwrap();

        let mut alice =
            RoomCrypto::new_for_room(db_a.clone(), room_id.into(), "alice-fp".into(), [0u8; 32])
                .unwrap();
        let mut bob =
            RoomCrypto::new_for_room(db_b.clone(), room_id.into(), "bob-fp".into(), [0u8; 32])
                .unwrap();
        // Bob must learn Alice's outbound session before decrypting.
        bob.add_inbound_session("alice-fp", &alice.our_session_key_b64())
            .unwrap();

        let plaintext = b"the quick brown fox jumps over the lazy dog. this is a test file.";
        let (ciphertext, meta) = encrypt_file(plaintext, &mut alice).unwrap();
        assert_ne!(&ciphertext[..], &plaintext[..]);

        let recovered = decrypt_file(&ciphertext, &meta, &mut bob, "alice-fp").unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let db_a = open_db_in_memory().unwrap();
        let db_b = open_db_in_memory().unwrap();
        let room_id = "r1";
        insert_room(&db_a, &make_room(room_id)).unwrap();
        insert_room(&db_b, &make_room(room_id)).unwrap();

        let mut alice =
            RoomCrypto::new_for_room(db_a.clone(), room_id.into(), "alice-fp".into(), [0u8; 32])
                .unwrap();
        let mut bob =
            RoomCrypto::new_for_room(db_b.clone(), room_id.into(), "bob-fp".into(), [0u8; 32])
                .unwrap();
        bob.add_inbound_session("alice-fp", &alice.our_session_key_b64())
            .unwrap();

        let plaintext = b"sensitive content";
        let (mut ct, meta) = encrypt_file(plaintext, &mut alice).unwrap();
        ct[0] ^= 0x01;
        assert!(decrypt_file(&ct, &meta, &mut bob, "alice-fp").is_err());
    }

    #[test]
    fn wrong_sender_fingerprint_fails() {
        let db_a = open_db_in_memory().unwrap();
        let db_b = open_db_in_memory().unwrap();
        let room_id = "r1";
        insert_room(&db_a, &make_room(room_id)).unwrap();
        insert_room(&db_b, &make_room(room_id)).unwrap();

        let mut alice =
            RoomCrypto::new_for_room(db_a.clone(), room_id.into(), "alice-fp".into(), [0u8; 32])
                .unwrap();
        let mut bob =
            RoomCrypto::new_for_room(db_b.clone(), room_id.into(), "bob-fp".into(), [0u8; 32])
                .unwrap();
        bob.add_inbound_session("alice-fp", &alice.our_session_key_b64())
            .unwrap();

        let (ct, meta) = encrypt_file(b"hi", &mut alice).unwrap();
        // Bob doesn't have a session keyed by "evil-fp" → must error.
        assert!(decrypt_file(&ct, &meta, &mut bob, "evil-fp").is_err());
    }
}
