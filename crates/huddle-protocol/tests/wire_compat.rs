//! huddle 2.0.4 (WS1.1): wire-compatibility guard for the extracted protocol
//! crate. These assertions pin the load-bearing serde behaviour — the variant
//! tags and the `skip_serializing_if` attributes that keep new optional fields
//! OFF the wire when unset — so a future change (e.g. the WS2 PQ/MLS additions)
//! can't silently alter the bytes a 1.x / 2.x peer or relay expects.
//!
//! The extraction itself moved these types verbatim; this test makes the
//! resulting wire format an explicit, frozen contract rather than an accident.

use huddle_protocol::protocol::{
    EncryptedFileMeta, RoomKind, RoomMessage, SignedRoomMessage, WireMessage,
};
use huddle_protocol::relay::{ClientMsg, ServerMsg};
use serde_json::{json, Value};

fn to_value<T: serde::Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap()
}

#[test]
fn room_kind_is_snake_case_externally() {
    // `RoomAnnouncement.kind` and the `rooms.kind` column both depend on this.
    assert_eq!(
        serde_json::to_string(&RoomKind::Direct).unwrap(),
        "\"direct\""
    );
    assert_eq!(
        serde_json::to_string(&RoomKind::Group).unwrap(),
        "\"group\""
    );
    assert_eq!(
        serde_json::from_str::<RoomKind>("\"direct\"").unwrap(),
        RoomKind::Direct
    );
}

#[test]
fn wire_message_uses_type_content_tagging() {
    let env = WireMessage::Plain(RoomMessage::Typing {
        sender_fingerprint: "fp".into(),
    });
    let v = to_value(&env);
    assert_eq!(v["type"], json!("plain"));
    // RoomMessage is externally tagged (PascalCase variant keys).
    assert_eq!(v["data"]["Typing"]["sender_fingerprint"], json!("fp"));
}

#[test]
fn optional_room_id_is_omitted_when_none_but_present_when_some() {
    // huddle 2.0.3 (audit N-M2) added an OPTIONAL `room_id`; the skip attribute
    // keeps the wire byte-identical to 1.x/2.0.x peers that never send it.
    let none = to_value(&WireMessage::Plain(RoomMessage::MemberLeave {
        sender_fingerprint: "fp".into(),
        room_id: None,
    }));
    let leave = &none["data"]["MemberLeave"];
    assert_eq!(leave["sender_fingerprint"], json!("fp"));
    assert!(
        leave.get("room_id").is_none(),
        "room_id MUST be absent when None, or old peers see different bytes"
    );

    let some = to_value(&WireMessage::Plain(RoomMessage::MemberLeave {
        sender_fingerprint: "fp".into(),
        room_id: Some("r1".into()),
    }));
    assert_eq!(some["data"]["MemberLeave"]["room_id"], json!("r1"));
}

#[test]
fn signed_envelope_shape_is_stable() {
    let env = SignedRoomMessage {
        fingerprint: "fp".into(),
        ed25519_pubkey_b64: "pk".into(),
        payload_b64: "pl".into(),
        signature_b64: "sig".into(),
        signed_at_ms: 1234,
        mldsa_pubkey_b64: None,
        mldsa_signature_b64: None,
    };
    let v = to_value(&env);
    for k in [
        "fingerprint",
        "ed25519_pubkey_b64",
        "payload_b64",
        "signature_b64",
        "signed_at_ms",
    ] {
        assert!(v.get(k).is_some(), "SignedRoomMessage must keep field {k}");
    }
    assert_eq!(v["signed_at_ms"], json!(1234));
}

#[test]
fn relay_server_message_omits_mailbox_id_when_none() {
    // The relay's authoritative serialization: live/legacy deliveries carry no
    // `mailbox_id`, so a pre-2.0 client sees exactly the bytes it expects.
    let live = to_value(&ServerMsg::Message {
        room: "r".into(),
        id: "i".into(),
        payload_b64: "p".into(),
        mailbox_id: None,
        seq: None,
    });
    assert_eq!(live["type"], json!("message"));
    assert!(live.get("mailbox_id").is_none());
    // huddle 2.0.8 (WS2 #5): the per-room `seq` is also additive — absent on the
    // wire when None, so older clients/relays see byte-identical messages.
    assert!(live.get("seq").is_none());

    let queued = to_value(&ServerMsg::Message {
        room: "r".into(),
        id: "i".into(),
        payload_b64: "p".into(),
        mailbox_id: Some(7),
        seq: Some(42),
    });
    assert_eq!(queued["mailbox_id"], json!(7));
    assert_eq!(queued["seq"], json!(42));
}

#[test]
fn relay_ready_and_hello_shapes_match_the_unified_definition() {
    // Ready carries the echoed fingerprint (clients ignore it); Hello carries
    // all five fields the client always sends.
    let ready = to_value(&ServerMsg::Ready {
        fingerprint: "fp".into(),
    });
    assert_eq!(ready["type"], json!("ready"));
    assert_eq!(ready["fingerprint"], json!("fp"));

    let hello = to_value(&ClientMsg::Hello {
        fingerprint: "fp".into(),
        pubkey_b64: "pk".into(),
        signature_b64: "sig".into(),
        rooms: vec!["r1".into()],
        acks: true,
    });
    assert_eq!(hello["type"], json!("hello"));
    for k in [
        "fingerprint",
        "pubkey_b64",
        "signature_b64",
        "rooms",
        "acks",
    ] {
        assert!(hello.get(k).is_some(), "Hello must keep field {k}");
    }
}

#[test]
fn relay_messages_round_trip() {
    // Deserialize what the relay serializes (and vice-versa) so both directions
    // of the shared definition stay consistent.
    let msgs = [
        ClientMsg::Subscribe { room: "r".into() },
        ClientMsg::Publish {
            room: "r".into(),
            id: "i".into(),
            payload_b64: "p".into(),
        },
        ClientMsg::Ack { mailbox_id: 9 },
        ClientMsg::Ping,
    ];
    for m in &msgs {
        let s = serde_json::to_string(m).unwrap();
        let back: ClientMsg = serde_json::from_str(&s).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), s);
    }
}

#[test]
fn encrypted_file_meta_round_trips() {
    let meta = EncryptedFileMeta {
        megolm_session_id: "sid".into(),
        wrapped_key_b64: "wk".into(),
        nonce_b64: "n".into(),
        content_hash: "h".into(),
    };
    let s = serde_json::to_string(&meta).unwrap();
    let back: EncryptedFileMeta = serde_json::from_str(&s).unwrap();
    assert_eq!(meta, back);
}
