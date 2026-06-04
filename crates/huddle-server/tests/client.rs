//! End-to-end test of the real client connector
//! (`huddle_core::network::server::ServerClient`) against the spawned
//! `huddle-server` binary, over a direct (non-Tor) WebSocket.

use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use huddle_core::identity::Identity;
use huddle_core::network::server::{ServerClient, ServerEvent};
use huddle_core::network::transport::DialMode;
use tokio::net::TcpStream;

/// Owns the spawned server process and kills it on drop — so even a failed
/// assertion (which unwinds) can't leave a zombie holding the test port.
struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn spawn_server(port: u16, db: &str) -> Server {
    let child = Command::new(env!("CARGO_BIN_EXE_huddle-server"))
        .env("HUDDLE_SERVER_BIND", format!("127.0.0.1:{port}"))
        .env("HUDDLE_SERVER_DB", db)
        .env("RUST_LOG", "warn")
        .spawn()
        .expect("spawn huddle-server");
    Server(child)
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

type Rx = tokio::sync::mpsc::UnboundedReceiver<ServerEvent>;

/// Pull the next `Message` event, skipping handshake/receipt events.
async fn next_message(rx: &mut Rx) -> (String, Vec<u8>) {
    let fut = async {
        loop {
            match rx.recv().await.expect("event stream open") {
                ServerEvent::Message { id, payload, .. } => return (id, payload),
                ServerEvent::Ready | ServerEvent::Sent { .. } => continue,
                ServerEvent::Disconnected => panic!("disconnected"),
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .expect("timed out waiting for message")
}

/// Pull the next `Sent` delivery receipt, skipping other events.
async fn next_sent(rx: &mut Rx) -> (String, usize, usize) {
    let fut = async {
        loop {
            match rx.recv().await.expect("event stream open") {
                ServerEvent::Sent { id, delivered, queued } => return (id, delivered, queued),
                ServerEvent::Ready | ServerEvent::Message { .. } => continue,
                ServerEvent::Disconnected => panic!("disconnected"),
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .expect("timed out waiting for sent receipt")
}

#[tokio::test]
async fn client_connector_fanout_and_mailbox() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("c.db");
    let port = 18799;
    let _server = spawn_server(port, db.to_str().unwrap());
    wait_listening(port).await;
    let url = format!("ws://127.0.0.1:{port}/ws");

    // A and B both members of ROOMX, both online (direct ws, no Tor). huddle
    // 1.1.3: connect takes the identity and authenticates internally. B's
    // identity is reused on reconnect below so its fingerprint (and mailbox)
    // are stable.
    let a_id = Arc::new(Identity::generate().unwrap());
    let b_id = Arc::new(Identity::generate().unwrap());
    let (a, mut a_rx) = ServerClient::connect(&url, &DialMode::Direct, a_id.clone(), vec!["ROOMX".into()])
        .await
        .unwrap();
    let (b, mut b_rx) = ServerClient::connect(&url, &DialMode::Direct, b_id.clone(), vec!["ROOMX".into()])
        .await
        .unwrap();

    // Give both hellos time to register membership server-side.
    tokio::time::sleep(Duration::from_millis(200)).await;

    a.publish("ROOMX", "msg-1", b"\x00\x01\x02hello").unwrap();
    // B (online) receives the exact bytes back through base64.
    let (id, payload) = next_message(&mut b_rx).await;
    assert_eq!(id, "msg-1");
    assert_eq!(payload, b"\x00\x01\x02hello");
    // A gets a delivery receipt: 1 delivered live, 0 queued.
    let (sid, delivered, queued) = next_sent(&mut a_rx).await;
    assert_eq!(sid, "msg-1");
    assert_eq!((delivered, queued), (1, 0));

    // Offline mailbox: drop B (closes its socket → server marks it offline),
    // publish, then reconnect B and expect the queued message.
    drop(b);
    drop(b_rx);
    tokio::time::sleep(Duration::from_millis(300)).await;
    a.publish("ROOMX", "msg-2", b"queued-while-offline").unwrap();
    // The receipt now reports it queued (B offline), not delivered.
    let (sid2, delivered2, queued2) = next_sent(&mut a_rx).await;
    assert_eq!(sid2, "msg-2");
    assert_eq!((delivered2, queued2), (0, 1));

    let (_b2, mut b2_rx) = ServerClient::connect(&url, &DialMode::Direct, b_id.clone(), vec!["ROOMX".into()])
        .await
        .unwrap();
    let (id2, payload2) = next_message(&mut b2_rx).await;
    assert_eq!(id2, "msg-2");
    assert_eq!(payload2, b"queued-while-offline");
}

/// huddle 1.2: fingerprint-addressed direct delivery. The whole point is that
/// it works with **no shared room membership at all** — neither side ever
/// subscribes the room. This is what makes 1:1 DMs and friend requests robust:
/// the sender knows the recipient's fingerprint, so the relay delivers straight
/// to it (live), or queues it in that fingerprint's mailbox when offline. This
/// is the behavior that was missing pre-1.2 (relay only fanned out by room
/// membership, so a DM needed the fragile both-sides-subscribed convergence).
#[tokio::test]
async fn send_direct_delivers_by_fingerprint_without_membership() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("d.db");
    let port = 18801;
    let _server = spawn_server(port, db.to_str().unwrap());
    wait_listening(port).await;
    let url = format!("ws://127.0.0.1:{port}/ws");

    let a_id = Arc::new(Identity::generate().unwrap());
    let b_id = Arc::new(Identity::generate().unwrap());
    let b_fp = b_id.fingerprint().to_string();

    // Both connect with NO rooms — zero membership anywhere.
    let (a, mut a_rx) = ServerClient::connect(&url, &DialMode::Direct, a_id.clone(), vec![])
        .await
        .unwrap();
    let (_b, mut b_rx) = ServerClient::connect(&url, &DialMode::Direct, b_id.clone(), vec![])
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // A → B by fingerprint. `room` is just an opaque filing tag (a DM room id).
    a.send_direct(&b_fp, "dm-tag-1", "d1", b"\x00direct-hi").unwrap();
    let (id, payload) = next_message(&mut b_rx).await;
    assert_eq!(id, "d1");
    assert_eq!(payload, b"\x00direct-hi");
    // A's receipt: delivered live, not queued — despite no room membership.
    let (sid, delivered, queued) = next_sent(&mut a_rx).await;
    assert_eq!(sid, "d1");
    assert_eq!((delivered, queued), (1, 0));

    // Offline path: drop B, send direct, reconnect B → the per-fingerprint
    // mailbox flushes it on Hello with no Subscribe/Fetch needed.
    drop(_b);
    drop(b_rx);
    tokio::time::sleep(Duration::from_millis(300)).await;
    a.send_direct(&b_fp, "dm-tag-1", "d2", b"direct-while-offline").unwrap();
    let (sid2, delivered2, queued2) = next_sent(&mut a_rx).await;
    assert_eq!(sid2, "d2");
    assert_eq!((delivered2, queued2), (0, 1));

    let (_b2, mut b2_rx) = ServerClient::connect(&url, &DialMode::Direct, b_id.clone(), vec![])
        .await
        .unwrap();
    let (id2, payload2) = next_message(&mut b2_rx).await;
    assert_eq!(id2, "d2");
    assert_eq!(payload2, b"direct-while-offline");
}
