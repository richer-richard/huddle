//! The real proof: two `huddle_core::AppHandle`s in **Server mode** (the
//! 0.8 default — NO libp2p swarm at all) exchange a room message purely
//! through the spawned `huddle-server`. This exercises the full wiring:
//! `send_room_message` → `NetworkHandle` server-mirror → server fan-out →
//! the client connector → injection into the `RoomMessageReceived` handler
//! → `AppEvent::MessageReceived`.

use std::process::{Child, Command};
use std::time::Duration;

use huddle_core::app::{AppEvent, AppHandle};
use huddle_core::network::NetworkMode;
use huddle_core::storage::{self, repo};
use huddle_core::storage::repo::{RoomKind, StoredRoom};

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
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("server never started listening");
}

async fn wait_server_connected(h: &AppHandle) {
    for _ in 0..100 {
        if h.server_connected() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("AppHandle never connected to the server");
}

async fn next_message(rx: &mut tokio::sync::broadcast::Receiver<AppEvent>) -> String {
    let fut = async {
        loop {
            match rx.recv().await {
                Ok(AppEvent::MessageReceived { body, .. }) => return body,
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(_) => panic!("event channel closed"),
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(10), fut)
        .await
        .expect("timed out waiting for MessageReceived")
}

/// Validates the real Tor path: dial the live baked-in `.onion` through
/// Tor's SOCKS5 proxy via the exact code `huddle` runs on launch. Ignored
/// by default (needs Tor running + the live onion); run with
/// `cargo test -p huddle-server --test app_over_server -- --ignored`.
#[tokio::test]
#[ignore]
async fn connects_to_live_onion_over_tor() {
    let db = storage::open_db_in_memory().unwrap();
    let handle = AppHandle::start_with_db_and_options(
        db,
        NetworkMode::Server,
        0,
        [0u8; 32],
        Vec::new(),
        Some(huddle_core::app::DEFAULT_SERVER_URL.to_string()),
        None,
    )
    .await
    .unwrap();

    // Tor circuit + onion connect can take a while; poll up to 90s.
    let connected = tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            if handle.server_connected() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .unwrap_or(false);

    handle.shutdown().await;
    assert!(connected, "did not connect to the live onion over Tor");
}

#[tokio::test]
async fn two_apps_exchange_messages_over_the_server() {
    let dir = tempfile::tempdir().unwrap();
    let port = 18811;
    let _server = spawn_server(port, dir.path().join("srv.db").to_str().unwrap());
    wait_listening(port).await;
    let url = format!("ws://127.0.0.1:{port}/ws"); // direct ws, no Tor

    // Node A.
    let db_a = storage::open_db_in_memory().unwrap();
    let handle_a = AppHandle::start_with_db_and_options(
        db_a,
        NetworkMode::Server,
        0,
        [0u8; 32],
        Vec::new(),
        Some(url.clone()),
        None,
    )
    .await
    .unwrap();
    let mut events_a = handle_a.subscribe();

    // A creates an unencrypted group room.
    let room_id = handle_a
        .start_room("server-test", false, None, RoomKind::Group)
        .await
        .unwrap();

    // Node B: seed its DB with the same room row so `join_room` resolves it
    // without any discovery layer (Server mode runs NO libp2p at all). In
    // the real app this row arrives via the invite's room metadata
    // (`seed_invite_room`); here we insert it directly.
    let db_b = storage::open_db_in_memory().unwrap();
    let info = StoredRoom {
        id: room_id.clone(),
        name: "server-test".into(),
        creator_fingerprint: handle_a.fingerprint().to_string(),
        encrypted: false,
        passphrase_salt: None,
        created_at: 0,
        last_active: Some(0),
        kind: RoomKind::Group,
    };
    repo::insert_room(&db_b, &info).unwrap();

    let handle_b = AppHandle::start_with_db_and_options(
        db_b,
        NetworkMode::Server,
        0,
        [0u8; 32],
        Vec::new(),
        Some(url.clone()),
        None,
    )
    .await
    .unwrap();
    let mut events_b = handle_b.subscribe();

    // Both must be connected to the server before they can route through it.
    wait_server_connected(&handle_a).await;
    wait_server_connected(&handle_b).await;

    // B joins the room → subscribes on the server (registers membership).
    handle_b.join_room(&room_id, None).await.unwrap();
    // Let the subscribe register server-side before A publishes.
    tokio::time::sleep(Duration::from_millis(400)).await;

    // A → B purely over the server (no libp2p path exists between them).
    handle_a
        .send_room_message(&room_id, "hello over the onion relay")
        .await
        .unwrap();
    assert_eq!(next_message(&mut events_b).await, "hello over the onion relay");

    // B → A reply, same path in reverse.
    handle_b.send_room_message(&room_id, "got it").await.unwrap();
    assert_eq!(next_message(&mut events_a).await, "got it");

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}
