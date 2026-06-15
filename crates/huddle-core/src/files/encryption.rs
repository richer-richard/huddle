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
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

use crate::crypto::RoomCrypto;
use crate::error::{HuddleError, Result};

/// huddle 2.2 (audit FILES-2): a KEYED content commitment — `HMAC-SHA256(
/// HKDF(file_key, "huddle-file-mac-v2"), plaintext)`. Used as AEAD associated
/// data in place of the relay-visible `SHA256(plaintext)`, so the file offer no
/// longer leaks a plaintext-confirmation oracle to the relay. Only room members
/// (who unwrap the per-file key from the Megolm-wrapped `wrapped_key_b64`) can
/// compute it. Implemented via `hkdf::extract` (HKDF-Extract == HMAC) to avoid
/// pulling a separate `hmac` crate; the plaintext is fed as IKM, not copied.
fn file_content_mac(file_key: &[u8; 32], plaintext: &[u8]) -> [u8; 32] {
    let mut mac_key = [0u8; 32];
    Hkdf::<Sha256>::new(None, file_key)
        .expand(b"huddle-file-mac-v2", &mut mac_key)
        .expect("32 bytes is within HKDF-SHA256's output limit");
    let (prk, _) = Hkdf::<Sha256>::extract(Some(&mac_key), plaintext);
    let mut out = [0u8; 32];
    out.copy_from_slice(prk.as_slice());
    out
}

// huddle 2.0.4 (WS1.1): `EncryptedFileMeta` is a wire type (it rides in
// `FileOffer`), so it moved to `huddle-protocol`; re-exported here so
// `files::encryption::EncryptedFileMeta` call sites are unchanged. The
// `encrypt_file` / `decrypt_file` helpers below stay (they drive `RoomCrypto`).
pub use huddle_protocol::EncryptedFileMeta;

/// Encrypt `plaintext` with a fresh ChaCha20-Poly1305 key, then Megolm-
/// wrap that key via the room's outbound session. The returned bytes
/// are what gets chunked and sent on the wire; the meta travels in the
/// FileOffer alongside the file_id.
pub fn encrypt_file(
    plaintext: &[u8],
    room_crypto: &mut RoomCrypto,
    private_meta: bool,
) -> Result<(Vec<u8>, EncryptedFileMeta)> {
    let mut file_key = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut file_key);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // Bind the ciphertext to a commitment of its plaintext via AEAD associated
    // data, so a room member can't replay this (key, nonce, ciphertext) triple
    // under a different file_id / name. huddle 2.2 (audit FILES-2): when every
    // recipient is capable (`private_meta`), the commitment is a KEYED MAC under
    // the file key, so the relay-visible offer no longer carries
    // `SHA256(plaintext)`; otherwise keep the legacy hash for old receivers.
    let (content_hash, content_mac_b64, aad): (String, Option<String>, Vec<u8>) = if private_meta {
        let mac = file_content_mac(&file_key, plaintext);
        (String::new(), Some(B64.encode(mac)), mac.to_vec())
    } else {
        let h = super::sha256_hex(plaintext);
        let aad = h.as_bytes().to_vec();
        (h, None, aad)
    };

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&file_key));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| HuddleError::Other(format!("chacha20 encrypt: {e}")))?;

    let (session_id, wrapped) = room_crypto.encrypt(&file_key)?;
    let meta = EncryptedFileMeta {
        megolm_session_id: session_id,
        wrapped_key_b64: B64.encode(wrapped),
        nonce_b64: B64.encode(nonce_bytes),
        content_hash,
        content_mac_b64,
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
    // huddle 2.0.0 (F2): decrypt now also yields the Megolm message_index; the
    // file-key unwrap doesn't dedup (the attachment lifecycle is keyed by
    // file_id), so we only need the unwrapped key bytes here.
    let (file_key_bytes, _message_index) =
        room_crypto.decrypt(sender_fingerprint, &meta.megolm_session_id, &wrapped)?;
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
    // huddle 2.2 (audit FILES-2): prefer the keyed-MAC commitment when the
    // sender used the private form; otherwise fall back to the legacy hash.
    let expected_mac: Option<[u8; 32]> = match &meta.content_mac_b64 {
        Some(mac_b64) => Some(
            B64.decode(mac_b64)
                .ok()
                .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
                .ok_or_else(|| HuddleError::Other("bad content_mac_b64".into()))?,
        ),
        None => None,
    };
    let aad: Vec<u8> = match &expected_mac {
        Some(mac) => mac.to_vec(),
        None => meta.content_hash.as_bytes().to_vec(),
    };
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&file_key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|e| HuddleError::Other(format!("chacha20 decrypt: {e}")))?;
    // The AEAD tag already binds the ciphertext to the AAD commitment; verifying
    // it explicitly after decryption also catches a sender who announced a
    // commitment that doesn't match what they actually encrypted.
    match expected_mac {
        Some(mac) => {
            let mut fk = [0u8; 32];
            fk.copy_from_slice(&file_key_bytes);
            if file_content_mac(&fk, &plaintext) != mac {
                return Err(HuddleError::Other(
                    "decrypted file content does not match its announced MAC".into(),
                ));
            }
        }
        None => {
            if super::sha256_hex(&plaintext) != meta.content_hash {
                return Err(HuddleError::Other(
                    "decrypted file content does not match its announced hash".into(),
                ));
            }
        }
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::open_db_in_memory;
    use crate::storage::repo::{insert_room, RoomKind, StoredRoom};

    fn make_room(id: &str) -> StoredRoom {
        StoredRoom {
            id: id.into(),
            name: "test".into(),
            creator_fingerprint: "alice-fp".into(),
            encrypted: true,
            passphrase_salt: None,
            created_at: 1,
            last_active: None,
            kind: RoomKind::Group,
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
        let (ciphertext, meta) = encrypt_file(plaintext, &mut alice, false).unwrap();
        assert_ne!(&ciphertext[..], &plaintext[..]);
        // Legacy form: the plaintext hash is present (and visible to the relay).
        assert!(meta.content_mac_b64.is_none());
        assert_eq!(meta.content_hash, super::super::sha256_hex(plaintext));

        let recovered = decrypt_file(&ciphertext, &meta, &mut bob, "alice-fp").unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn round_trip_private_meta_carries_no_plaintext_hash() {
        // huddle 2.2 (audit FILES-2): the v2 private form round-trips, and the
        // offer the relay sees carries a keyed MAC instead of SHA256(plaintext).
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

        let plaintext = b"a known candidate document the relay must not be able to confirm";
        let (ciphertext, meta) = encrypt_file(plaintext, &mut alice, true).unwrap();
        // No plaintext-hash oracle: content_hash is empty, the keyed MAC is set,
        // and the MAC is NOT the plaintext SHA-256.
        assert!(meta.content_hash.is_empty());
        let mac_b64 = meta.content_mac_b64.clone().expect("v2 carries the MAC");
        assert_ne!(
            B64.decode(&mac_b64).unwrap(),
            hex::decode(super::super::sha256_hex(plaintext)).unwrap(),
            "the commitment must not equal SHA256(plaintext)"
        );

        let recovered = decrypt_file(&ciphertext, &meta, &mut bob, "alice-fp").unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn private_meta_tamper_is_rejected() {
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
        let (mut ct, meta) = encrypt_file(b"secret attachment", &mut alice, true).unwrap();
        ct[0] ^= 0x01;
        assert!(decrypt_file(&ct, &meta, &mut bob, "alice-fp").is_err());
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
        let (mut ct, meta) = encrypt_file(plaintext, &mut alice, false).unwrap();
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

        let (ct, meta) = encrypt_file(b"hi", &mut alice, false).unwrap();
        // Bob doesn't have a session keyed by "evil-fp" → must error.
        assert!(decrypt_file(&ct, &meta, &mut bob, "evil-fp").is_err());
    }
}
