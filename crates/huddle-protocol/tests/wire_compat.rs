//! huddle 2.0.4 (WS1.1): wire-compatibility guard for the extracted protocol
//! crate. These assertions pin the load-bearing serde behaviour — the variant
//! tags and the `skip_serializing_if` attributes that keep new optional fields
//! OFF the wire when unset — so a future change (e.g. the WS2 PQ/MLS additions)
//! can't silently alter the bytes a 1.x / 2.x peer or relay expects.
//!
//! The extraction itself moved these types verbatim; this test makes the
//! resulting wire format an explicit, frozen contract rather than an accident.

use huddle_protocol::protocol::{
    EncryptedFileMeta, RoomAnnouncement, RoomKind, RoomMessage, SignedRoomMessage, WireMessage,
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
        content_mac_b64: None,
    };
    let s = serde_json::to_string(&meta).unwrap();
    let back: EncryptedFileMeta = serde_json::from_str(&s).unwrap();
    assert_eq!(meta, back);
}

#[test]
fn mc4_new_fields_are_additive_both_directions() {
    // huddle 2.2 (M-C4 / PA-1 / FILES-2): prove the new optional fields are
    // additive in BOTH directions.
    //
    // (a) Forward compat — a NEW peer reading an OLD message: a pre-2.2
    //     CodeJoinRequest (no `code_proof`) / EncryptedFileMeta (no
    //     `content_mac_b64`) / MemberAnnounce (no `capabilities`) decodes, with
    //     the new field defaulting to None.
    let legacy_req: RoomMessage = serde_json::from_value(json!({
        "CodeJoinRequest": {"room_id": "r", "joiner_x25519_pubkey_b64": "ek", "code": "c"}
    }))
    .unwrap();
    match legacy_req {
        RoomMessage::CodeJoinRequest {
            code_proof, code, ..
        } => {
            assert!(code_proof.is_none());
            assert_eq!(code, "c");
        }
        _ => panic!("expected CodeJoinRequest"),
    }
    let legacy_meta: EncryptedFileMeta = serde_json::from_value(json!({
        "megolm_session_id": "s", "wrapped_key_b64": "w", "nonce_b64": "n", "content_hash": "h"
    }))
    .unwrap();
    assert!(legacy_meta.content_mac_b64.is_none());

    // (b) Backward compat — an OLD peer reading a NEW message: serde ignores
    //     unknown fields (no `deny_unknown_fields` anywhere), so a v2 message
    //     with the extra field decodes cleanly on a peer that doesn't know it.
    let v2_with_unknown: RoomMessage = serde_json::from_value(json!({
        "CodeJoinRequest": {
            "room_id": "r", "joiner_x25519_pubkey_b64": "ek", "code": "",
            "code_proof": "pf", "a_field_from_an_even_newer_peer": 1234
        }
    }))
    .unwrap();
    match v2_with_unknown {
        RoomMessage::CodeJoinRequest { code_proof, .. } => {
            assert_eq!(code_proof.as_deref(), Some("pf"));
        }
        _ => panic!("expected CodeJoinRequest"),
    }
}

#[test]
fn mls_wire_variants_round_trip() {
    // huddle 2.1 (WS2-b): the MLS group-messaging variants are externally tagged
    // (PascalCase) like every other RoomMessage; they round-trip and are additive
    // (a pre-2.1 peer simply fails to decode the unknown variant and drops it).
    let msgs = [
        RoomMessage::MlsKeyPackage {
            sender_fingerprint: "fp".into(),
            key_package_b64: "kp".into(),
        },
        RoomMessage::MlsWelcome {
            target_fingerprint: "fp".into(),
            welcome_b64: "w".into(),
        },
        RoomMessage::MlsCommit {
            sender_fingerprint: "fp".into(),
            commit_b64: "c".into(),
        },
        RoomMessage::MlsApplication {
            sender_fingerprint: "fp".into(),
            ciphertext_b64: "ct".into(),
        },
    ];
    for m in msgs {
        let env = WireMessage::Plain(m);
        let s = serde_json::to_string(&env).unwrap();
        let back: WireMessage = serde_json::from_str(&s).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), s);
    }
    let v = to_value(&WireMessage::Plain(RoomMessage::MlsCommit {
        sender_fingerprint: "fp".into(),
        commit_b64: "c".into(),
    }));
    assert_eq!(v["data"]["MlsCommit"]["commit_b64"], json!("c"));
}

/// huddle 2.1.3: byte-frozen golden corpus. Pins the EXACT serialized bytes of a
/// representative instance of every wire type/variant, so the additive-only wire
/// policy is an enforced CI gate rather than a convention. The earlier tests
/// check shape (keys present/absent); this one freezes the literal bytes, so a
/// field RENAME / RETYPE / REORDER, or dropping a `skip_serializing_if`, fails
/// here even on a variant no shape test covers.
///
/// If this fails: an ADDITIVE change (a new optional field that is skipped when
/// None, or a brand-new enum variant) is fine — just refresh `EXPECTED` from the
/// printed `actual`. A change to an EXISTING line BREAKS 1.x<->2.x compatibility
/// and must be reverted (or gated behind wire-version negotiation).
#[test]
fn wire_golden_bytes_are_frozen() {
    let mut lines: Vec<String> = Vec::new();
    macro_rules! pin {
        ($label:expr, $val:expr) => {
            lines.push(format!(
                "{} = {}",
                $label,
                serde_json::to_string(&$val).unwrap()
            ));
        };
    }

    // ---- RoomMessage (externally tagged); optionals left None to pin skip vs null ----
    pin!(
        "MemberAnnounce",
        RoomMessage::MemberAnnounce {
            sender_fingerprint: "fp".into(),
            wrapped_session_key: None,
            display_name: None,
            sender_ed25519_pubkey: None,
            sender_mlkem_pubkey: None,
            mlkem_ciphertext: None,
            capabilities: None
        }
    );
    pin!(
        "MemberAnnounce.full",
        RoomMessage::MemberAnnounce {
            sender_fingerprint: "fp".into(),
            wrapped_session_key: Some("wsk".into()),
            display_name: Some("dn".into()),
            sender_ed25519_pubkey: Some("ek".into()),
            sender_mlkem_pubkey: Some("mk".into()),
            mlkem_ciphertext: Some("ct".into()),
            capabilities: None
        }
    );
    // huddle 2.2 (M-C4): the new capability field serializes when Some — pinned
    // on its own line so the existing two stay byte-frozen (additivity proof).
    pin!(
        "MemberAnnounce.caps",
        RoomMessage::MemberAnnounce {
            sender_fingerprint: "fp".into(),
            wrapped_session_key: None,
            display_name: None,
            sender_ed25519_pubkey: None,
            sender_mlkem_pubkey: None,
            mlkem_ciphertext: None,
            capabilities: Some(3)
        }
    );
    pin!(
        "SessionKeyRequest",
        RoomMessage::SessionKeyRequest {
            requester_fingerprint: "fp".into()
        }
    );
    pin!(
        "Encrypted",
        RoomMessage::Encrypted {
            sender_fingerprint: "fp".into(),
            session_id: "sid".into(),
            ciphertext_b64: "ct".into(),
            client_msg_id: None,
            reply_to: None
        }
    );
    pin!(
        "Plain",
        RoomMessage::Plain {
            sender_fingerprint: "fp".into(),
            body: "hi".into(),
            client_msg_id: None,
            reply_to: None
        }
    );
    pin!(
        "MemberLeave",
        RoomMessage::MemberLeave {
            sender_fingerprint: "fp".into(),
            room_id: None
        }
    );
    pin!(
        "RotateRoomKey",
        RoomMessage::RotateRoomKey {
            rotator_fingerprint: "fp".into(),
            new_salt: vec![1, 2, 3],
            room_id: None
        }
    );
    pin!(
        "Typing",
        RoomMessage::Typing {
            sender_fingerprint: "fp".into()
        }
    );
    pin!(
        "FileOffer",
        RoomMessage::FileOffer {
            sender_fingerprint: "fp".into(),
            file_id: "fid".into(),
            name: "f".into(),
            size_bytes: 10,
            mime: None,
            chunk_count: 1,
            encrypted_meta: None
        }
    );
    pin!(
        "FileChunk",
        RoomMessage::FileChunk {
            sender_fingerprint: "fp".into(),
            file_id: "fid".into(),
            chunk_index: 0,
            total_chunks: 1,
            data_b64: "d".into()
        }
    );
    pin!(
        "OwnerGrant",
        RoomMessage::OwnerGrant {
            room_id: "r".into(),
            target_fingerprint: "fp".into()
        }
    );
    pin!(
        "BanMember",
        RoomMessage::BanMember {
            room_id: "r".into(),
            target_fingerprint: "fp".into()
        }
    );
    pin!(
        "SasInit",
        RoomMessage::SasInit {
            tx_id: "tx".into(),
            ephemeral_x25519_pubkey_b64: "ek".into(),
            target_fingerprint: "fp".into()
        }
    );
    pin!(
        "SasResponse",
        RoomMessage::SasResponse {
            tx_id: "tx".into(),
            ephemeral_x25519_pubkey_b64: "ek".into()
        }
    );
    pin!(
        "SasConfirm",
        RoomMessage::SasConfirm {
            tx_id: "tx".into(),
            matched: true
        }
    );
    pin!(
        "JoinRefused",
        RoomMessage::JoinRefused {
            room_id: "r".into(),
            target_fingerprint: "fp".into(),
            reason: "no".into()
        }
    );
    pin!(
        "CodeJoinRequest",
        RoomMessage::CodeJoinRequest {
            room_id: "r".into(),
            joiner_x25519_pubkey_b64: "ek".into(),
            code: "c".into(),
            code_proof: None
        }
    );
    // huddle 2.2 (audit PA-1): the v2 form carries an empty code + the proof.
    pin!(
        "CodeJoinRequest.proof",
        RoomMessage::CodeJoinRequest {
            room_id: "r".into(),
            joiner_x25519_pubkey_b64: "ek".into(),
            code: "".into(),
            code_proof: Some("pf".into())
        }
    );
    pin!(
        "CodeJoinResponse",
        RoomMessage::CodeJoinResponse {
            room_id: "r".into(),
            target_fingerprint: "fp".into(),
            owner_x25519_pubkey_b64: "ek".into(),
            owner_session_id: "sid".into(),
            wrapped_session_key_b64: "wsk".into(),
            nonce_b64: "n".into()
        }
    );
    pin!(
        "ProfileUpdate",
        RoomMessage::ProfileUpdate {
            sender_fingerprint: "fp".into(),
            username: None,
            updated_at: 5
        }
    );
    pin!(
        "ContactRequest",
        RoomMessage::ContactRequest {
            requester_fingerprint: "fp".into(),
            display_name: None,
            note: None,
            sender_ed25519_pubkey: None
        }
    );
    pin!(
        "Reaction",
        RoomMessage::Reaction {
            sender_fingerprint: "fp".into(),
            target_msg_id: "m".into(),
            emoji: "x".into(),
            removed: false
        }
    );
    pin!(
        "Edit",
        RoomMessage::Edit {
            sender_fingerprint: "fp".into(),
            target_msg_id: "m".into(),
            new_ciphertext_b64: "ct".into(),
            session_id: "sid".into(),
            new_body: None
        }
    );
    pin!(
        "Delete",
        RoomMessage::Delete {
            sender_fingerprint: "fp".into(),
            target_msg_id: "m".into()
        }
    );
    pin!(
        "RoomSetting",
        RoomMessage::RoomSetting {
            sender_fingerprint: "fp".into(),
            disappearing_ttl_secs: 60,
            room_id: None
        }
    );
    pin!(
        "MlsKeyPackage",
        RoomMessage::MlsKeyPackage {
            sender_fingerprint: "fp".into(),
            key_package_b64: "kp".into()
        }
    );
    pin!(
        "MlsWelcome",
        RoomMessage::MlsWelcome {
            target_fingerprint: "fp".into(),
            welcome_b64: "w".into()
        }
    );
    pin!(
        "MlsCommit",
        RoomMessage::MlsCommit {
            sender_fingerprint: "fp".into(),
            commit_b64: "c".into()
        }
    );
    pin!(
        "MlsApplication",
        RoomMessage::MlsApplication {
            sender_fingerprint: "fp".into(),
            ciphertext_b64: "ct".into()
        }
    );

    // ---- envelopes ----
    pin!(
        "WireMessage::Plain",
        WireMessage::Plain(RoomMessage::Typing {
            sender_fingerprint: "fp".into()
        })
    );
    pin!(
        "SignedRoomMessage",
        SignedRoomMessage {
            fingerprint: "fp".into(),
            ed25519_pubkey_b64: "pk".into(),
            payload_b64: "pl".into(),
            signature_b64: "sig".into(),
            signed_at_ms: 1234,
            mldsa_pubkey_b64: None,
            mldsa_signature_b64: None
        }
    );
    pin!(
        "SignedRoomMessage.pq",
        SignedRoomMessage {
            fingerprint: "fp".into(),
            ed25519_pubkey_b64: "pk".into(),
            payload_b64: "pl".into(),
            signature_b64: "sig".into(),
            signed_at_ms: 1234,
            mldsa_pubkey_b64: Some("mk".into()),
            mldsa_signature_b64: Some("ms".into())
        }
    );
    pin!(
        "EncryptedFileMeta",
        EncryptedFileMeta {
            megolm_session_id: "sid".into(),
            wrapped_key_b64: "wk".into(),
            nonce_b64: "n".into(),
            content_hash: "h".into(),
            content_mac_b64: None
        }
    );
    // huddle 2.2 (audit FILES-2): v2 form carries the keyed MAC + empty hash.
    pin!(
        "EncryptedFileMeta.mac",
        EncryptedFileMeta {
            megolm_session_id: "sid".into(),
            wrapped_key_b64: "wk".into(),
            nonce_b64: "n".into(),
            content_hash: "".into(),
            content_mac_b64: Some("mac".into())
        }
    );
    pin!(
        "RoomAnnouncement",
        RoomAnnouncement {
            room_id: "r".into(),
            name: "n".into(),
            encrypted: true,
            passphrase_salt: Some(vec![1, 2]),
            member_count: 2,
            creator_fingerprint: "fp".into(),
            announced_at: 7,
            owner_fingerprints: vec!["fp".into()],
            verified_only: false,
            host_addrs: vec![],
            kind: RoomKind::Group,
            capabilities: None
        }
    );
    // huddle 2.2 (M-C4): announcer caps surface at discovery time when Some.
    pin!(
        "RoomAnnouncement.caps",
        RoomAnnouncement {
            room_id: "r".into(),
            name: "n".into(),
            encrypted: true,
            passphrase_salt: Some(vec![1, 2]),
            member_count: 2,
            creator_fingerprint: "fp".into(),
            announced_at: 7,
            owner_fingerprints: vec!["fp".into()],
            verified_only: false,
            host_addrs: vec![],
            kind: RoomKind::Group,
            capabilities: Some(3)
        }
    );

    // ---- relay ClientMsg (internally tagged: {"type":..}) ----
    pin!(
        "ClientMsg::Hello",
        ClientMsg::Hello {
            fingerprint: "fp".into(),
            pubkey_b64: "pk".into(),
            signature_b64: "sig".into(),
            rooms: vec!["r".into()],
            acks: true
        }
    );
    pin!(
        "ClientMsg::Subscribe",
        ClientMsg::Subscribe { room: "r".into() }
    );
    pin!(
        "ClientMsg::Unsubscribe",
        ClientMsg::Unsubscribe { room: "r".into() }
    );
    pin!(
        "ClientMsg::Publish",
        ClientMsg::Publish {
            room: "r".into(),
            id: "i".into(),
            payload_b64: "p".into()
        }
    );
    pin!(
        "ClientMsg::SendDirect",
        ClientMsg::SendDirect {
            to: "t".into(),
            room: "r".into(),
            id: "i".into(),
            payload_b64: "p".into()
        }
    );
    pin!(
        "ClientMsg::CreateConnectToken",
        ClientMsg::CreateConnectToken
    );
    pin!(
        "ClientMsg::RedeemConnectToken",
        ClientMsg::RedeemConnectToken {
            token: "tok".into()
        }
    );
    pin!("ClientMsg::Fetch", ClientMsg::Fetch);
    pin!("ClientMsg::Ack", ClientMsg::Ack { mailbox_id: 9 });
    pin!("ClientMsg::Ping", ClientMsg::Ping);

    // ---- relay ServerMsg ----
    pin!(
        "ServerMsg::Challenge",
        ServerMsg::Challenge {
            nonce_b64: "n".into()
        }
    );
    pin!(
        "ServerMsg::Ready",
        ServerMsg::Ready {
            fingerprint: "fp".into()
        }
    );
    pin!(
        "ServerMsg::Message",
        ServerMsg::Message {
            room: "r".into(),
            id: "i".into(),
            payload_b64: "p".into(),
            mailbox_id: None,
            seq: None
        }
    );
    pin!(
        "ServerMsg::Message.full",
        ServerMsg::Message {
            room: "r".into(),
            id: "i".into(),
            payload_b64: "p".into(),
            mailbox_id: Some(7),
            seq: Some(42)
        }
    );
    pin!(
        "ServerMsg::Sent",
        ServerMsg::Sent {
            id: "i".into(),
            delivered: 1,
            queued: 0
        }
    );
    pin!(
        "ServerMsg::ConnectToken",
        ServerMsg::ConnectToken {
            token: "tok".into(),
            ttl_secs: 300
        }
    );
    pin!(
        "ServerMsg::ConnectTokenResolved",
        ServerMsg::ConnectTokenResolved {
            token: "tok".into(),
            fingerprint: None,
            pubkey_b64: None
        }
    );
    pin!("ServerMsg::Pong", ServerMsg::Pong);
    pin!(
        "ServerMsg::Error",
        ServerMsg::Error {
            message: "e".into()
        }
    );

    let actual = lines.join("\n");
    assert_eq!(
        actual, EXPECTED,
        "\n\n=== WIRE BYTES CHANGED ===\nIf ADDITIVE (new skipped-when-None field, or a new variant), refresh EXPECTED \
         from the actual below. If an EXISTING line changed, it BREAKS 1.x<->2.x compat — revert it.\n\nactual:\n{actual}\n"
    );
}

const EXPECTED: &str = r#"MemberAnnounce = {"MemberAnnounce":{"sender_fingerprint":"fp","wrapped_session_key":null,"display_name":null,"sender_ed25519_pubkey":null}}
MemberAnnounce.full = {"MemberAnnounce":{"sender_fingerprint":"fp","wrapped_session_key":"wsk","display_name":"dn","sender_ed25519_pubkey":"ek","sender_mlkem_pubkey":"mk","mlkem_ciphertext":"ct"}}
MemberAnnounce.caps = {"MemberAnnounce":{"sender_fingerprint":"fp","wrapped_session_key":null,"display_name":null,"sender_ed25519_pubkey":null,"capabilities":3}}
SessionKeyRequest = {"SessionKeyRequest":{"requester_fingerprint":"fp"}}
Encrypted = {"Encrypted":{"sender_fingerprint":"fp","session_id":"sid","ciphertext_b64":"ct"}}
Plain = {"Plain":{"sender_fingerprint":"fp","body":"hi"}}
MemberLeave = {"MemberLeave":{"sender_fingerprint":"fp"}}
RotateRoomKey = {"RotateRoomKey":{"rotator_fingerprint":"fp","new_salt":[1,2,3]}}
Typing = {"Typing":{"sender_fingerprint":"fp"}}
FileOffer = {"FileOffer":{"sender_fingerprint":"fp","file_id":"fid","name":"f","size_bytes":10,"mime":null,"chunk_count":1,"encrypted_meta":null}}
FileChunk = {"FileChunk":{"sender_fingerprint":"fp","file_id":"fid","chunk_index":0,"total_chunks":1,"data_b64":"d"}}
OwnerGrant = {"OwnerGrant":{"room_id":"r","target_fingerprint":"fp"}}
BanMember = {"BanMember":{"room_id":"r","target_fingerprint":"fp"}}
SasInit = {"SasInit":{"tx_id":"tx","ephemeral_x25519_pubkey_b64":"ek","target_fingerprint":"fp"}}
SasResponse = {"SasResponse":{"tx_id":"tx","ephemeral_x25519_pubkey_b64":"ek"}}
SasConfirm = {"SasConfirm":{"tx_id":"tx","matched":true}}
JoinRefused = {"JoinRefused":{"room_id":"r","target_fingerprint":"fp","reason":"no"}}
CodeJoinRequest = {"CodeJoinRequest":{"room_id":"r","joiner_x25519_pubkey_b64":"ek","code":"c"}}
CodeJoinRequest.proof = {"CodeJoinRequest":{"room_id":"r","joiner_x25519_pubkey_b64":"ek","code":"","code_proof":"pf"}}
CodeJoinResponse = {"CodeJoinResponse":{"room_id":"r","target_fingerprint":"fp","owner_x25519_pubkey_b64":"ek","owner_session_id":"sid","wrapped_session_key_b64":"wsk","nonce_b64":"n"}}
ProfileUpdate = {"ProfileUpdate":{"sender_fingerprint":"fp","username":null,"updated_at":5}}
ContactRequest = {"ContactRequest":{"requester_fingerprint":"fp","display_name":null,"note":null,"sender_ed25519_pubkey":null}}
Reaction = {"Reaction":{"sender_fingerprint":"fp","target_msg_id":"m","emoji":"x","removed":false}}
Edit = {"Edit":{"sender_fingerprint":"fp","target_msg_id":"m","new_ciphertext_b64":"ct","session_id":"sid"}}
Delete = {"Delete":{"sender_fingerprint":"fp","target_msg_id":"m"}}
RoomSetting = {"RoomSetting":{"sender_fingerprint":"fp","disappearing_ttl_secs":60}}
MlsKeyPackage = {"MlsKeyPackage":{"sender_fingerprint":"fp","key_package_b64":"kp"}}
MlsWelcome = {"MlsWelcome":{"target_fingerprint":"fp","welcome_b64":"w"}}
MlsCommit = {"MlsCommit":{"sender_fingerprint":"fp","commit_b64":"c"}}
MlsApplication = {"MlsApplication":{"sender_fingerprint":"fp","ciphertext_b64":"ct"}}
WireMessage::Plain = {"type":"plain","data":{"Typing":{"sender_fingerprint":"fp"}}}
SignedRoomMessage = {"fingerprint":"fp","ed25519_pubkey_b64":"pk","payload_b64":"pl","signature_b64":"sig","signed_at_ms":1234}
SignedRoomMessage.pq = {"fingerprint":"fp","ed25519_pubkey_b64":"pk","payload_b64":"pl","signature_b64":"sig","signed_at_ms":1234,"mldsa_pubkey_b64":"mk","mldsa_signature_b64":"ms"}
EncryptedFileMeta = {"megolm_session_id":"sid","wrapped_key_b64":"wk","nonce_b64":"n","content_hash":"h"}
EncryptedFileMeta.mac = {"megolm_session_id":"sid","wrapped_key_b64":"wk","nonce_b64":"n","content_hash":"","content_mac_b64":"mac"}
RoomAnnouncement = {"room_id":"r","name":"n","encrypted":true,"passphrase_salt":[1,2],"member_count":2,"creator_fingerprint":"fp","announced_at":7,"owner_fingerprints":["fp"],"verified_only":false,"host_addrs":[],"kind":"group"}
RoomAnnouncement.caps = {"room_id":"r","name":"n","encrypted":true,"passphrase_salt":[1,2],"member_count":2,"creator_fingerprint":"fp","announced_at":7,"owner_fingerprints":["fp"],"verified_only":false,"host_addrs":[],"kind":"group","capabilities":3}
ClientMsg::Hello = {"type":"hello","fingerprint":"fp","pubkey_b64":"pk","signature_b64":"sig","rooms":["r"],"acks":true}
ClientMsg::Subscribe = {"type":"subscribe","room":"r"}
ClientMsg::Unsubscribe = {"type":"unsubscribe","room":"r"}
ClientMsg::Publish = {"type":"publish","room":"r","id":"i","payload_b64":"p"}
ClientMsg::SendDirect = {"type":"send_direct","to":"t","room":"r","id":"i","payload_b64":"p"}
ClientMsg::CreateConnectToken = {"type":"create_connect_token"}
ClientMsg::RedeemConnectToken = {"type":"redeem_connect_token","token":"tok"}
ClientMsg::Fetch = {"type":"fetch"}
ClientMsg::Ack = {"type":"ack","mailbox_id":9}
ClientMsg::Ping = {"type":"ping"}
ServerMsg::Challenge = {"type":"challenge","nonce_b64":"n"}
ServerMsg::Ready = {"type":"ready","fingerprint":"fp"}
ServerMsg::Message = {"type":"message","room":"r","id":"i","payload_b64":"p"}
ServerMsg::Message.full = {"type":"message","room":"r","id":"i","payload_b64":"p","mailbox_id":7,"seq":42}
ServerMsg::Sent = {"type":"sent","id":"i","delivered":1,"queued":0}
ServerMsg::ConnectToken = {"type":"connect_token","token":"tok","ttl_secs":300}
ServerMsg::ConnectTokenResolved = {"type":"connect_token_resolved","token":"tok","fingerprint":null,"pubkey_b64":null}
ServerMsg::Pong = {"type":"pong"}
ServerMsg::Error = {"type":"error","message":"e"}"#;
