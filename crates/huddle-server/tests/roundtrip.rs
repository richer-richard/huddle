//! End-to-end test: spawns the real `huddle-server` binary and drives it
//! with WebSocket clients to verify online fan-out and offline mailbox.

use std::process::{Child, Command};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
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

    // A and B both members of ROOM1, both online.
    let mut a = connect(port).await;
    send(&mut a, json!({"type":"hello","fingerprint":"AAAA","rooms":["ROOM1"]})).await;
    assert_eq!(recv(&mut a).await["type"], "ready");

    let mut b = connect(port).await;
    send(&mut b, json!({"type":"hello","fingerprint":"BBBB","rooms":["ROOM1"]})).await;
    assert_eq!(recv(&mut b).await["type"], "ready");

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
    send(&mut b2, json!({"type":"hello","fingerprint":"BBBB","rooms":["ROOM1"]})).await;
    assert_eq!(recv(&mut b2).await["type"], "ready");
    let queued = recv(&mut b2).await;
    assert_eq!(queued["type"], "message");
    assert_eq!(queued["id"], "m2");
    assert_eq!(queued["payload_b64"], "d29ybGQ=");

    child.kill().ok();
}
