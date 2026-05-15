pub mod megolm;
pub mod passphrase;

pub use megolm::RoomCrypto;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::error::{HuddleError, Result};
use crate::identity::compute_fingerprint;
use crate::network::protocol::{RoomMessage, SignedRoomMessage};

/// Verify a `SignedRoomMessage` envelope:
/// 1. The asserted `fingerprint` must equal the fingerprint derived from
///    `ed25519_pubkey_b64` — closes the "claim someone else's fingerprint
///    but sign with your own key" attack.
/// 2. The Ed25519 signature must verify over the decoded `payload_b64`.
/// 3. The payload must deserialize as a `RoomMessage`.
///
/// Returns the inner message and the (verified) sender fingerprint on
/// success. Caller should still check that the fingerprint is one they
/// expect for this context (e.g. an owner for `BanMember`).
pub fn verify_signed(env: &SignedRoomMessage) -> Result<(RoomMessage, String)> {
    let pubkey_bytes = B64
        .decode(&env.ed25519_pubkey_b64)
        .map_err(|e| HuddleError::Session(format!("bad pubkey_b64: {e}")))?;
    if pubkey_bytes.len() != 32 {
        return Err(HuddleError::Session(format!(
            "pubkey is {} bytes, expected 32",
            pubkey_bytes.len()
        )));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pubkey_bytes);

    let derived_fp = compute_fingerprint(&pk_arr);
    if derived_fp != env.fingerprint {
        return Err(HuddleError::Session(format!(
            "fingerprint mismatch: envelope claims {}, key derives {}",
            env.fingerprint, derived_fp
        )));
    }

    let payload = B64
        .decode(&env.payload_b64)
        .map_err(|e| HuddleError::Session(format!("bad payload_b64: {e}")))?;
    let sig_bytes = B64
        .decode(&env.signature_b64)
        .map_err(|e| HuddleError::Session(format!("bad signature_b64: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(HuddleError::Session(format!(
            "signature is {} bytes, expected 64",
            sig_bytes.len()
        )));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    let verifying_key = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| HuddleError::Session(format!("bad verifying key: {e}")))?;
    verifying_key
        .verify(&payload, &signature)
        .map_err(|e| HuddleError::Session(format!("signature verify failed: {e}")))?;

    let msg: RoomMessage = serde_json::from_slice(&payload)
        .map_err(|e| HuddleError::Session(format!("bad payload json: {e}")))?;
    Ok((msg, derived_fp))
}

/// Wrap a `RoomMessage` into a `SignedRoomMessage` using the given
/// identity's signing key. Mirror of `verify_signed`; symmetric helper
/// so phase B/F/G/etc. don't each open-code the base64 dance.
pub fn sign_message(
    identity: &crate::identity::Identity,
    msg: &RoomMessage,
) -> Result<SignedRoomMessage> {
    let payload = serde_json::to_vec(msg)
        .map_err(|e| HuddleError::Session(format!("encode payload: {e}")))?;
    let sig = identity.sign(&payload);
    Ok(SignedRoomMessage {
        fingerprint: identity.fingerprint().to_string(),
        ed25519_pubkey_b64: B64.encode(identity.public_bytes()),
        payload_b64: B64.encode(&payload),
        signature_b64: B64.encode(sig),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn sample_msg() -> RoomMessage {
        RoomMessage::MemberLeave {
            sender_fingerprint: "test-fp".into(),
        }
    }

    #[test]
    fn sign_verify_round_trip() {
        let id = Identity::generate().unwrap();
        let env = sign_message(&id, &sample_msg()).unwrap();
        let (msg, fp) = verify_signed(&env).unwrap();
        assert_eq!(fp, id.fingerprint());
        assert!(matches!(msg, RoomMessage::MemberLeave { .. }));
    }

    #[test]
    fn tampered_payload_fails() {
        let id = Identity::generate().unwrap();
        let mut env = sign_message(&id, &sample_msg()).unwrap();
        // Re-encode a different message; signature was over the original.
        let other = serde_json::to_vec(&RoomMessage::Typing {
            sender_fingerprint: "evil-fp".into(),
        })
        .unwrap();
        env.payload_b64 = B64.encode(&other);
        assert!(verify_signed(&env).is_err());
    }

    #[test]
    fn fingerprint_pubkey_mismatch_fails() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let mut env = sign_message(&alice, &sample_msg()).unwrap();
        // Substitute bob's fingerprint — derived fp from alice's pubkey
        // won't match, so this must reject before the signature check.
        env.fingerprint = bob.fingerprint().to_string();
        assert!(verify_signed(&env).is_err());
    }

    #[test]
    fn swapped_pubkey_fails_signature() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let mut env = sign_message(&alice, &sample_msg()).unwrap();
        // Substitute bob's pubkey + fingerprint together: derived check
        // passes, but the signature was made with alice's key and won't
        // verify under bob's pubkey.
        env.ed25519_pubkey_b64 = B64.encode(bob.public_bytes());
        env.fingerprint = bob.fingerprint().to_string();
        assert!(verify_signed(&env).is_err());
    }
}
