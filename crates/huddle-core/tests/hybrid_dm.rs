//! huddle 1.3: end-to-end test of the hybrid (X25519 + ML-KEM-768) DM key
//! agreement at the protocol level.
//!
//! This drives the exact sequence the app performs — build a `MemberAnnounce`
//! carrying each peer's ML-KEM encapsulation key, serialize/deserialize it over
//! the wire (serde round-trip), have the initiator (lower fingerprint)
//! encapsulate and publish the ciphertext, the responder decapsulate, and both
//! sides wrap/unwrap a Megolm session key under the agreed hybrid key — without
//! standing up the full networking stack. It also covers the backward-compatible
//! fallback to the classical key when the partner is a pre-1.3 peer that
//! publishes no ML-KEM key.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use huddle_core::app::canonical_dm_room_id;
use huddle_core::crypto::{dm, passphrase};
use huddle_core::identity::Identity;
use huddle_core::network::protocol::RoomMessage;

/// Order two fresh identities into (initiator, responder) by the same
/// fingerprint comparison the app uses (`our_fp < partner_fp` ⇒ initiator).
fn ordered_pair() -> (Identity, Identity) {
    let a = Identity::generate().unwrap();
    let b = Identity::generate().unwrap();
    if a.fingerprint() < b.fingerprint() {
        (a, b)
    } else {
        (b, a)
    }
}

/// Serialize a RoomMessage to JSON and back, mimicking the wire hop. Asserts the
/// new optional ML-KEM fields survive the round-trip.
fn wire_round_trip(msg: &RoomMessage) -> RoomMessage {
    let json = serde_json::to_vec(msg).unwrap();
    serde_json::from_slice(&json).unwrap()
}

#[test]
fn hybrid_dm_full_handshake_end_to_end() {
    let (initiator, responder) = ordered_pair();
    let room_id = canonical_dm_room_id(initiator.fingerprint(), responder.fingerprint());

    // --- Responder announces first, advertising its ML-KEM key. ---
    let responder_announce = RoomMessage::MemberAnnounce {
        sender_fingerprint: responder.fingerprint().to_string(),
        wrapped_session_key: None,
        display_name: None,
        sender_ed25519_pubkey: Some(B64.encode(responder.public_bytes())),
        sender_mlkem_pubkey: Some(B64.encode(responder.mlkem_public_bytes())),
        mlkem_ciphertext: None,
        capabilities: None,
    };
    let responder_announce = wire_round_trip(&responder_announce);

    // --- Initiator handles it: derives the hybrid key + KEM ciphertext. ---
    let (init_key, ciphertext) = match responder_announce {
        RoomMessage::MemberAnnounce {
            sender_ed25519_pubkey: Some(ed),
            sender_mlkem_pubkey: Some(ek),
            ..
        } => {
            let ed = decode32(&ed);
            let ek = B64.decode(&ek).unwrap();
            dm::derive_dm_key_hybrid_initiator(&initiator.secret_bytes(), &ed, &ek, &room_id)
                .unwrap()
        }
        _ => panic!("expected responder announce with ML-KEM key"),
    };

    // Initiator wraps its Megolm session key under the hybrid key and ships it
    // alongside the ciphertext.
    let init_session_key = "alice-megolm-session-key-b64";
    let wrapped = passphrase::wrap(init_session_key.as_bytes(), &init_key).unwrap();
    let initiator_announce = RoomMessage::MemberAnnounce {
        sender_fingerprint: initiator.fingerprint().to_string(),
        wrapped_session_key: Some(wrapped),
        display_name: None,
        sender_ed25519_pubkey: Some(B64.encode(initiator.public_bytes())),
        sender_mlkem_pubkey: Some(B64.encode(initiator.mlkem_public_bytes())),
        mlkem_ciphertext: Some(B64.encode(&ciphertext)),
        capabilities: None,
    };
    let initiator_announce = wire_round_trip(&initiator_announce);

    // --- Responder handles it: decapsulates, derives the SAME hybrid key,
    //     and unwraps the initiator's session key. ---
    let (resp_key, recovered) = match initiator_announce {
        RoomMessage::MemberAnnounce {
            sender_ed25519_pubkey: Some(ed),
            mlkem_ciphertext: Some(ct_b64),
            wrapped_session_key: Some(w),
            ..
        } => {
            let ed = decode32(&ed);
            let ct = B64.decode(&ct_b64).unwrap();
            let key = dm::derive_dm_key_hybrid_responder(
                &responder.pq_keypair(),
                &responder.secret_bytes(),
                &ed,
                &ct,
                &room_id,
            )
            .unwrap();
            let recovered = passphrase::unwrap(&w, &key).unwrap();
            (key, recovered)
        }
        _ => panic!("expected initiator announce with ciphertext + wrapped key"),
    };

    assert_eq!(
        init_key, resp_key,
        "both peers must agree on the hybrid DM key"
    );
    assert_eq!(
        recovered,
        init_session_key.as_bytes(),
        "responder must unwrap the initiator's Megolm session key"
    );

    // And the reverse direction: responder wraps under the same key, initiator
    // unwraps (it already holds the hybrid key from its own derivation).
    let resp_session_key = "bob-megolm-session-key-b64";
    let wrapped_back = passphrase::wrap(resp_session_key.as_bytes(), &resp_key).unwrap();
    let back = passphrase::unwrap(&wrapped_back, &init_key).unwrap();
    assert_eq!(back, resp_session_key.as_bytes());
}

#[test]
fn classical_fallback_when_partner_has_no_mlkem_key() {
    // A pre-1.3 partner publishes no ML-KEM key. Both sides must derive the
    // identical *classical* key and interoperate.
    let (a, b) = ordered_pair();
    let room_id = canonical_dm_room_id(a.fingerprint(), b.fingerprint());

    // `a` is on 1.3 but sees no ML-KEM key from `b` (the field is absent) ⇒
    // classical path; `b` (old) derives classical the old way too.
    let a_key = dm::derive_dm_key(&a.secret_bytes(), &b.public_bytes(), &room_id).unwrap();
    let b_key = dm::derive_dm_key(&b.secret_bytes(), &a.public_bytes(), &room_id).unwrap();
    assert_eq!(a_key, b_key);

    // Round-trip a wrapped session key to prove interop.
    let wrapped = passphrase::wrap(b"session", &a_key).unwrap();
    assert_eq!(passphrase::unwrap(&wrapped, &b_key).unwrap(), b"session");
}

#[test]
fn pre_1_3_member_announce_deserializes_without_mlkem_fields() {
    // Forward/backward compat: a JSON MemberAnnounce produced by a pre-1.3 peer
    // (no ML-KEM fields at all) must still deserialize, with the new fields
    // defaulting to None.
    let json = serde_json::json!({
        "MemberAnnounce": {
            "sender_fingerprint": "abcd-ef01-2345-6789-abcd-ef01",
            "wrapped_session_key": null,
            "display_name": "Legacy",
            "sender_ed25519_pubkey": "AAAA"
        }
    });
    let msg: RoomMessage = serde_json::from_value(json).unwrap();
    match msg {
        RoomMessage::MemberAnnounce {
            sender_mlkem_pubkey,
            mlkem_ciphertext,
            display_name,
            ..
        } => {
            assert!(sender_mlkem_pubkey.is_none());
            assert!(mlkem_ciphertext.is_none());
            assert_eq!(display_name.as_deref(), Some("Legacy"));
        }
        _ => panic!("expected MemberAnnounce"),
    }
}

#[test]
fn hybrid_wrong_responder_cannot_derive_key() {
    // An eavesdropper/impostor with a DIFFERENT ML-KEM keypair cannot recover
    // the hybrid key from the public ciphertext — decapsulation yields a
    // different secret, so the derived key (and thus session-key unwrap) fails.
    let (initiator, responder) = ordered_pair();
    let room_id = canonical_dm_room_id(initiator.fingerprint(), responder.fingerprint());

    let (init_key, ct) = dm::derive_dm_key_hybrid_initiator(
        &initiator.secret_bytes(),
        &responder.public_bytes(),
        &responder.mlkem_public_bytes(),
        &room_id,
    )
    .unwrap();

    // An impostor decapsulating with the wrong keypair derives a different key.
    let impostor = Identity::generate().unwrap();
    let impostor_key = dm::derive_dm_key_hybrid_responder(
        &impostor.pq_keypair(),
        &impostor.secret_bytes(),
        &initiator.public_bytes(),
        &ct,
        &room_id,
    )
    .unwrap();
    assert_ne!(init_key, impostor_key);
}

fn decode32(b64: &str) -> [u8; 32] {
    let v = B64.decode(b64).unwrap();
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}
