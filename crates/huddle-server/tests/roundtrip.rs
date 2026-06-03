//! End-to-end test: spawns the real `huddle-server` binary and drives it
//! with WebSocket clients to verify online fan-out and offline mailbox.

use std::process::{Child, Command};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use huddle_core::identity::{relay_auth_msg, Identity};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

fn spawn_server(port: u16, db: &str) -> Child {
    Command::new(env!("CARGO_BIN_EXE_huddle-server"))
        .env("HUDDLE_SERVER_BIND", format!("127.0.0.1:{port}"))
        .env("HUDDLE_SERVER_DB", db)
        .env("RUST_LOG", "warn")
        .spawn()
        .expect("spawn huddle-server")
}

async fn wait_listening(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("server never started listening");
}

async fn connect(port: u16) -> Ws {
    let (ws, _) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/ws"))
        .await
        .expect("ws connect");
    ws
}

async fn send(ws: &mut Ws, v: Value) {
    ws.send(Message::Text(v.to_string().into())).await.unwrap();
}

async fn recv(ws: &mut Ws) -> Value {
    loop {
        match ws.next().await.expect("stream open").expect("frame") {
            Message::Text(t) => return serde_json::from_str(t.as_str()).unwrap(),
            Message::Close(_) => panic!("closed"),
            _ => continue,
        }
    }
}

/// huddle 1.1.4: complete the relay's challenge-response handshake — read the
/// opening `challenge`, sign the nonce with `id`, send an authenticated
/// `hello`, and expect `ready`.
async fn handshake(ws: &mut Ws, id: &Identity, rooms: &[&str]) {
    let ch = recv(ws).await;
    assert_eq!(ch["type"], "challenge", "server must greet with a challenge");
    let nonce = B64.decode(ch["nonce_b64"].as_str().unwrap()).unwrap();
    let sig = id.sign(&relay_auth_msg(&nonce));
    send(
        ws,
        json!({
            "type": "hello",
            "fingerprint": id.fingerprint(),
            "pubkey_b64": B64.encode(id.public_bytes()),
            "signature_b64": B64.encode(sig),
            "rooms": rooms,
        }),
    )
    .await;
    assert_eq!(recv(ws).await["type"], "ready");
}

#[tokio::test]
async fn online_fanout_and_offline_mailbox() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("t.db");
    let port = 18787;
    let mut child = spawn_server(port, db.to_str().unwrap());
    wait_listening(port).await;

    // Health probe on the same port.
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 256];
        let n = s.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("200 OK"), "health response: {resp}");
        assert!(resp.contains("huddle-server"));
    }

    // A and B both members of ROOM1, both online. huddle 1.1.4: real
    // identities so the relay's auth handshake verifies (B is reused on
    // reconnect below so it keeps the same fingerprint and drains its mailbox).
    let a_id = Identity::generate().unwrap();
    let b_id = Identity::generate().unwrap();

    let mut a = connect(port).await;
    handshake(&mut a, &a_id, &["ROOM1"]).await;

    let mut b = connect(port).await;
    handshake(&mut b, &b_id, &["ROOM1"]).await;

    // A publishes → online B receives it.
    send(
        &mut a,
        json!({"type":"publish","room":"ROOM1","id":"m1","payload_b64":"aGVsbG8="}),
    )
    .await;
    let m = recv(&mut b).await;
    assert_eq!(m["type"], "message");
    assert_eq!(m["id"], "m1");
    assert_eq!(m["payload_b64"], "aGVsbG8=");

    // B goes offline; A publishes again; B reconnects and drains the mailbox.
    drop(b);
    tokio::time::sleep(Duration::from_millis(150)).await;
    send(
        &mut a,
        json!({"type":"publish","room":"ROOM1","id":"m2","payload_b64":"d29ybGQ="}),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut b2 = connect(port).await;
    handshake(&mut b2, &b_id, &["ROOM1"]).await;
    let queued = recv(&mut b2).await;
    assert_eq!(queued["type"], "message");
    assert_eq!(queued["id"], "m2");
    assert_eq!(queued["payload_b64"], "d29ybGQ=");

    child.kill().ok();
}

/// huddle 1.1.4: a client whose signature doesn't verify against the challenge
/// is rejected — it never reaches `ready`, getting an `error` and/or a close.
#[tokio::test]
async fn rejects_bad_auth_signature() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("bad.db");
    let port = 18791;
    let mut child = spawn_server(port, db.to_str().unwrap());
    wait_listening(port).await;

    let id = Identity::generate().unwrap();
    let mut a = connect(port).await;
    let ch = recv(&mut a).await;
    assert_eq!(ch["type"], "challenge");
    // Sign the WRONG bytes (not the domain-tagged challenge) so verify_strict
    // fails even though the pubkey/fingerprint are genuine.
    let bogus = id.sign(b"not the challenge");
    send(
        &mut a,
        json!({
            "type": "hello",
            "fingerprint": id.fingerprint(),
            "pubkey_b64": B64.encode(id.public_bytes()),
            "signature_b64": B64.encode(bogus),
            "rooms": ["ROOM1"],
        }),
    )
    .await;
    // The server rejects by tearing the connection down, so the next frame is
    // one of: an explicit `error` text, a WS close, an abrupt reset (the
    // server drops the socket without a closing handshake), or end-of-stream.
    // All are valid rejections — the only failure is reaching `ready`.
    match a.next().await {
        Some(Ok(Message::Text(t))) => {
            let v: Value = serde_json::from_str(t.as_str()).unwrap();
            assert_eq!(v["type"], "error", "bad signature must be rejected: {v}");
        }
        Some(Ok(Message::Close(_))) | Some(Err(_)) | None => { /* rejected */ }
        other => panic!("unexpected frame after bad auth: {other:?}"),
    }

    child.kill().ok();
}

/// huddle 1.1.4 regression: an authenticated client cannot send a SECOND Hello
/// claiming a different fingerprint to steal that identity's queued mailbox.
/// (The fix pins the server-derived fingerprint to the connection and ignores
/// the client-claimed `fingerprint` field after the proof.)
#[tokio::test]
async fn second_hello_cannot_steal_another_identitys_mailbox() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("steal.db");
    let port = 18793;
    let mut child = spawn_server(port, db.to_str().unwrap());
    wait_listening(port).await;

    let a_id = Identity::generate().unwrap();
    let b_id = Identity::generate().unwrap(); // victim
    let c_id = Identity::generate().unwrap(); // attacker

    // B joins ROOM, then goes offline.
    let mut b = connect(port).await;
    handshake(&mut b, &b_id, &["ROOM"]).await;
    drop(b);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // A publishes to ROOM → queued for offline B.
    let mut a = connect(port).await;
    handshake(&mut a, &a_id, &["ROOM"]).await;
    send(
        &mut a,
        json!({"type":"publish","room":"ROOM","id":"secret","payload_b64":"c2VjcmV0"}),
    )
    .await;
    let receipt = recv(&mut a).await;
    assert_eq!(receipt["type"], "sent");
    assert_eq!(receipt["queued"], 1, "message should be queued for offline B");

    // Attacker C authenticates as itself, then sends a SECOND Hello CLAIMING
    // B's fingerprint (with C's own pubkey + a bogus signature). The relay must
    // ignore the claimed fingerprint and NOT drain B's mailbox to C.
    let mut c = connect(port).await;
    handshake(&mut c, &c_id, &["ROOM"]).await; // consumes C's own Ready (+ empty flush)
    send(
        &mut c,
        json!({
            "type": "hello",
            "fingerprint": b_id.fingerprint(),                 // impersonation attempt
            "pubkey_b64": B64.encode(c_id.public_bytes()),
            "signature_b64": B64.encode(c_id.sign(b"bogus")),
            "rooms": ["ROOM"],
        }),
    )
    .await;
    let mut saw_secret = false;
    let mut saw_ready = false;
    let pump = async {
        while let Some(Ok(Message::Text(t))) = c.next().await {
            let v: Value = serde_json::from_str(t.as_str()).unwrap();
            match v["type"].as_str() {
                Some("message") if v["id"] == "secret" => saw_secret = true,
                Some("ready") => {
                    saw_ready = true;
                    assert_eq!(
                        v["fingerprint"],
                        c_id.fingerprint(),
                        "re-Hello must Ready as C's OWN fingerprint, not the claimed one"
                    );
                }
                _ => {}
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_millis(400), pump).await;
    assert!(saw_ready, "C should get a Ready for its own fingerprint");
    assert!(
        !saw_secret,
        "attacker must NOT receive the victim's queued message"
    );

    // B reconnects and still receives its message (it was never stolen).
    let mut b2 = connect(port).await;
    handshake(&mut b2, &b_id, &["ROOM"]).await;
    let queued = recv(&mut b2).await;
    assert_eq!(queued["type"], "message");
    assert_eq!(queued["id"], "secret");

    child.kill().ok();
}
