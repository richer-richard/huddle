pub mod dm;
pub mod megolm;
pub mod mnemonic;
pub mod passphrase;
pub mod pqc;
pub mod sas;

pub use megolm::RoomCrypto;

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};

use crate::error::{HuddleError, Result};
use crate::identity::compute_fingerprint;
use crate::network::protocol::{RoomMessage, SignedRoomMessage};

/// huddle 0.7.11: max accepted skew between `signed_at_ms` on a signed
/// envelope and the receiver's wall clock. Anything outside the window
/// is rejected as a replay (or as a clock that's drifted too far).
pub const SIGNED_ENVELOPE_WINDOW_MS: i64 = 5 * 60 * 1000;

/// Verify a `SignedRoomMessage` envelope:
/// 1. The asserted `fingerprint` must equal the fingerprint derived from
///    `ed25519_pubkey_b64` — closes the "claim someone else's fingerprint
///    but sign with your own key" attack.
/// 2. The Ed25519 signature must `verify_strict` over the decoded
///    `payload_b64` (strict rejects low-order / mixed-order pubkeys).
/// 3. The payload must deserialize as a `RoomMessage`.
/// 4. huddle 0.7.11: `signed_at_ms` must be non-zero and within
///    `SIGNED_ENVELOPE_WINDOW_MS` of the receiver's wall clock — closes
///    indefinite replay of captured signed messages.
///
/// Returns the inner message and the (verified) sender fingerprint on
/// success. Caller should still check that the fingerprint is one they
/// expect for this context (e.g. an owner for `BanMember`).
pub fn verify_signed(env: &SignedRoomMessage) -> Result<(RoomMessage, String)> {
    let now_ms = now_unix_ms();
    verify_signed_at(env, now_ms, SIGNED_ENVELOPE_WINDOW_MS)
}

/// Same as `verify_signed` but with an explicit clock and window —
/// kept public for tests that want to exercise the replay-window logic
/// deterministically without a SystemTime detour.
pub fn verify_signed_at(
    env: &SignedRoomMessage,
    now_ms: i64,
    window_ms: i64,
) -> Result<(RoomMessage, String)> {
    if env.signed_at_ms == 0 {
        return Err(HuddleError::Session(
            "signed envelope is missing signed_at_ms — pre-0.7.11 sender or forgery".into(),
        ));
    }
    // huddle 1.2: the replay-window check moved to AFTER cryptographic
    // verification (below) so we know the message TYPE and can exempt store-
    // and-forward control messages from the wall-clock window.

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
    // huddle 0.7.11: verify_strict rejects mixed-order / low-order
    // pubkeys and is the recommended call per ed25519_dalek's docs.
    // The signature is also bound to the `signed_at_ms` timestamp via
    // the payload bytes (the payload deserializes to a RoomMessage,
    // but the signature was over the raw payload + timestamp, so any
    // tampering of either field invalidates verification).
    verifying_key
        .verify_strict(&signed_bytes(&payload, env.signed_at_ms), &signature)
        .map_err(|e| HuddleError::Session(format!("signature verify failed: {e}")))?;

    let msg: RoomMessage = serde_json::from_slice(&payload)
        .map_err(|e| HuddleError::Session(format!("bad payload json: {e}")))?;

    // huddle 1.2: apply the wall-clock replay window SELECTIVELY. Store-and-
    // forward, idempotent control messages — ContactRequest, MemberAnnounce,
    // SessionKeyRequest — are EXEMPT: they ride the relay's offline mailbox,
    // which can hold them for hours or days until the recipient reconnects, so
    // a ±5-minute window would silently drop legitimate first-contact requests
    // and first key-exchange announces (precisely the "I added them but no
    // chat ever appears" failure). Their replay protection is idempotency
    // (re-applying them is a no-op) plus the signature, which still proves the
    // sender's identity and is verified above regardless of type. Every other
    // signed type keeps the strict window.
    if window_applies(&msg) && (now_ms - env.signed_at_ms).abs() > window_ms {
        return Err(HuddleError::Session(format!(
            "signed envelope timestamp {} is outside the ±{}ms window vs now {}",
            env.signed_at_ms, window_ms, now_ms
        )));
    }
    Ok((msg, derived_fp))
}

/// huddle 1.2: whether the wall-clock replay window applies to a signed
/// message of this type. Store-and-forward, idempotent control messages are
/// exempt because they legitimately arrive long after they were signed, via
/// the relay's offline mailbox. All other signed types keep the strict window.
fn window_applies(msg: &RoomMessage) -> bool {
    !matches!(
        msg,
        RoomMessage::ContactRequest { .. }
            | RoomMessage::MemberAnnounce { .. }
            | RoomMessage::SessionKeyRequest { .. }
    )
}

/// Wrap a `RoomMessage` into a `SignedRoomMessage` using the given
/// identity's signing key. Mirror of `verify_signed`; symmetric helper
/// so phase B/F/G/etc. don't each open-code the base64 dance.
///
/// huddle 0.7.11: also populates `signed_at_ms` with the current epoch
/// in milliseconds, and signs over (payload || signed_at_ms) so the
/// receiver's replay-window check is signature-bound.
pub fn sign_message(
    identity: &crate::identity::Identity,
    msg: &RoomMessage,
) -> Result<SignedRoomMessage> {
    sign_message_at(identity, msg, now_unix_ms())
}

/// Same as `sign_message` but with an explicit timestamp — used by the
/// replay-window unit tests so the clock isn't a hidden dependency.
pub fn sign_message_at(
    identity: &crate::identity::Identity,
    msg: &RoomMessage,
    signed_at_ms: i64,
) -> Result<SignedRoomMessage> {
    let payload = serde_json::to_vec(msg)
        .map_err(|e| HuddleError::Session(format!("encode payload: {e}")))?;
    let sig = identity.sign(&signed_bytes(&payload, signed_at_ms));
    Ok(SignedRoomMessage {
        fingerprint: identity.fingerprint().to_string(),
        ed25519_pubkey_b64: B64.encode(identity.public_bytes()),
        payload_b64: B64.encode(&payload),
        signature_b64: B64.encode(sig),
        signed_at_ms,
    })
}

/// Canonical bytes the signature commits to: the raw RoomMessage JSON
/// followed by a domain-separator and the big-endian timestamp. Putting
/// the timestamp inside the signed bytes means a replayer can't change
/// it without invalidating the signature.
fn signed_bytes(payload: &[u8], signed_at_ms: i64) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 24);
    out.extend_from_slice(payload);
    out.extend_from_slice(b"|huddle-signed-v1|");
    out.extend_from_slice(&signed_at_ms.to_be_bytes());
    out
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn sample_msg() -> RoomMessage {
        RoomMessage::MemberLeave {
            sender_fingerprint: "test-fp".into(),
            room_id: None,
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
        let other = serde_json::to_vec(&RoomMessage::Typing {
            sender_fingerprint: "evil-fp".into(),
        })
        .unwrap();
        env.payload_b64 = B64.encode(&other);
        assert!(verify_signed(&env).is_err());
    }

    #[test]
    fn tampered_timestamp_fails_signature() {
        // huddle 0.7.11: the signed bytes commit to signed_at_ms, so a
        // replayer who rewrites the timestamp to bring it back inside
        // the window invalidates the signature.
        let id = Identity::generate().unwrap();
        let now_ms = 1_700_000_000_000_i64;
        let mut env = sign_message_at(&id, &sample_msg(), now_ms).unwrap();
        env.signed_at_ms = now_ms + 1;
        let err = verify_signed_at(&env, now_ms, SIGNED_ENVELOPE_WINDOW_MS).unwrap_err();
        let s = format!("{err}");
        assert!(s.contains("signature verify failed"), "got: {s}");
    }

    #[test]
    fn fingerprint_pubkey_mismatch_fails() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let mut env = sign_message(&alice, &sample_msg()).unwrap();
        env.fingerprint = bob.fingerprint().to_string();
        assert!(verify_signed(&env).is_err());
    }

    #[test]
    fn swapped_pubkey_fails_signature() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let mut env = sign_message(&alice, &sample_msg()).unwrap();
        env.ed25519_pubkey_b64 = B64.encode(bob.public_bytes());
        env.fingerprint = bob.fingerprint().to_string();
        assert!(verify_signed(&env).is_err());
    }

    #[test]
    fn missing_timestamp_rejected() {
        // huddle 0.7.11: signed_at_ms == 0 is the serde default, which
        // we use as the "legacy pre-replay-protection" sentinel and
        // reject outright.
        let id = Identity::generate().unwrap();
        let mut env = sign_message(&id, &sample_msg()).unwrap();
        env.signed_at_ms = 0;
        assert!(verify_signed(&env).is_err());
    }

    #[test]
    fn outside_window_rejected() {
        let id = Identity::generate().unwrap();
        let signed_at = 1_700_000_000_000_i64;
        let env = sign_message_at(&id, &sample_msg(), signed_at).unwrap();
        // 6 minutes later — outside the default 5 min window.
        let now = signed_at + 6 * 60 * 1000;
        assert!(verify_signed_at(&env, now, SIGNED_ENVELOPE_WINDOW_MS).is_err());
        // Inside the window: ok.
        let now = signed_at + 4 * 60 * 1000;
        assert!(verify_signed_at(&env, now, SIGNED_ENVELOPE_WINDOW_MS).is_ok());
    }

    #[test]
    fn store_and_forward_types_exempt_from_window() {
        // huddle 1.2: ContactRequest and MemberAnnounce ride the relay's
        // offline mailbox and may legitimately arrive days later. They MUST
        // verify even far outside the wall-clock window (signature still
        // proves identity); otherwise offline first-contact + first key
        // exchange silently fail and "no chat ever appears".
        let id = Identity::generate().unwrap();
        let signed_at = 1_700_000_000_000_i64;
        let now = signed_at + 30 * 24 * 60 * 60 * 1000; // 30 days later

        let contact = RoomMessage::ContactRequest {
            requester_fingerprint: id.fingerprint().to_string(),
            display_name: Some("late arrival".into()),
            note: None,
            sender_ed25519_pubkey: Some(B64.encode(id.public_bytes())),
        };
        let env = sign_message_at(&id, &contact, signed_at).unwrap();
        assert!(
            verify_signed_at(&env, now, SIGNED_ENVELOPE_WINDOW_MS).is_ok(),
            "a mailboxed ContactRequest must verify regardless of age"
        );

        let announce = RoomMessage::MemberAnnounce {
            sender_fingerprint: id.fingerprint().to_string(),
            wrapped_session_key: Some("d2VsbA==".into()),
            display_name: None,
            sender_ed25519_pubkey: Some(B64.encode(id.public_bytes())),
            sender_mlkem_pubkey: None,
            mlkem_ciphertext: None,
        };
        let env = sign_message_at(&id, &announce, signed_at).unwrap();
        assert!(
            verify_signed_at(&env, now, SIGNED_ENVELOPE_WINDOW_MS).is_ok(),
            "a mailboxed MemberAnnounce (carries the session key) must verify regardless of age"
        );

        // A non-exempt type (MemberLeave) still honors the window.
        let env = sign_message_at(&id, &sample_msg(), signed_at).unwrap();
        assert!(
            verify_signed_at(&env, now, SIGNED_ENVELOPE_WINDOW_MS).is_err(),
            "non-store-and-forward types must still be window-checked"
        );

        // Tampering still fails for exempt types — signature is verified
        // regardless of the window exemption.
        let mut bad = sign_message_at(&id, &contact, signed_at).unwrap();
        bad.signature_b64 = B64.encode([0u8; 64]);
        assert!(
            verify_signed_at(&bad, now, SIGNED_ENVELOPE_WINDOW_MS).is_err(),
            "an exempt type with a bad signature must still be rejected"
        );
    }
}
