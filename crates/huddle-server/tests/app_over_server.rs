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

async fn next_contact_request(rx: &mut tokio::sync::broadcast::Receiver<AppEvent>) -> String {
    let fut = async {
        loop {
            match rx.recv().await {
                Ok(AppEvent::ContactRequestReceived { fingerprint, .. }) => return fingerprint,
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(_) => panic!("event channel closed"),
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(10), fut)
        .await
        .expect("timed out waiting for ContactRequestReceived")
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
        huddle_core::app::TransportConfig::onion_only(huddle_core::app::DEFAULT_SERVER_URL.to_string()),
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
        huddle_core::app::TransportConfig::onion_only(url.clone()),
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
        huddle_core::app::TransportConfig::onion_only(url.clone()),
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

/// huddle 1.0: the relay contact-inbox path — "add by HD-ID over the
/// internet". A sends a signed ContactRequest to B's inbox (no prior shared
/// room, no LAN); B sees it as a pending request, accepts, and an encrypted
/// DM converges over the relay in both directions. Exercises the inbox
/// auto-subscribe, the signed ContactRequest round-trip, and the
/// mutual/echo-back convergence that makes both sides subscribe the DM room.
#[tokio::test]
async fn contact_request_over_server_opens_dm() {
    let dir = tempfile::tempdir().unwrap();
    let port = 18812;
    let _server = spawn_server(port, dir.path().join("srv.db").to_str().unwrap());
    wait_listening(port).await;
    let url = format!("ws://127.0.0.1:{port}/ws");

    let db_a = storage::open_db_in_memory().unwrap();
    let handle_a = AppHandle::start_with_db_and_options(
        db_a,
        NetworkMode::Server,
        0,
        [0u8; 32],
        Vec::new(),
        huddle_core::app::TransportConfig::onion_only(url.clone()),
    )
    .await
    .unwrap();
    let db_b = storage::open_db_in_memory().unwrap();
    let handle_b = AppHandle::start_with_db_and_options(
        db_b,
        NetworkMode::Server,
        0,
        [0u8; 32],
        Vec::new(),
        huddle_core::app::TransportConfig::onion_only(url.clone()),
    )
    .await
    .unwrap();
    let mut events_a = handle_a.subscribe();
    let mut events_b = handle_b.subscribe();
    wait_server_connected(&handle_a).await;
    wait_server_connected(&handle_b).await;

    let a_fp = handle_a.fingerprint().to_string();
    let b_fp = handle_b.fingerprint().to_string();

    // A adds B by HD-ID — a signed request lands in B's relay inbox.
    handle_a
        .send_contact_request(&b_fp, Some("hi from A"))
        .await
        .unwrap();
    assert_eq!(next_contact_request(&mut events_b).await, a_fp);

    // B accepts → opens the DM + echoes back so A converges too.
    handle_b.accept_contact_request(&a_fp).await.unwrap();

    // Let the echo + DM MemberAnnounce key exchange converge over the relay.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let dm_room = huddle_core::app::canonical_dm_room_id(&a_fp, &b_fp);
    handle_a
        .send_room_message(&dm_room, "yo over the inbox")
        .await
        .unwrap();
    assert_eq!(next_message(&mut events_b).await, "yo over the inbox");
    handle_b.send_room_message(&dm_room, "hey back").await.unwrap();
    assert_eq!(next_message(&mut events_a).await, "hey back");

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

async fn next_connect_code(rx: &mut tokio::sync::broadcast::Receiver<AppEvent>) -> String {
    let fut = async {
        loop {
            match rx.recv().await {
                Ok(AppEvent::ConnectCodeCreated { code, .. }) => return code,
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(_) => panic!("event channel closed"),
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(10), fut)
        .await
        .expect("timed out waiting for ConnectCodeCreated")
}

/// huddle 1.2.1: the connect-code shortcut for DMs. A mints a short code; B
/// types it (instead of A's full HD-ID); the relay resolves it and B sends A a
/// contact request — so A sees an inbound request from B, exactly as if B had
/// typed the HD-ID. Proves the whole create→share→redeem→contact-request path
/// across two real AppHandles over the relay.
#[tokio::test]
async fn connect_code_adds_contact_over_server() {
    let dir = tempfile::tempdir().unwrap();
    let port = 18815;
    let _server = spawn_server(port, dir.path().join("srv.db").to_str().unwrap());
    wait_listening(port).await;
    let url = format!("ws://127.0.0.1:{port}/ws");

    let db_a = storage::open_db_in_memory().unwrap();
    let handle_a = AppHandle::start_with_db_and_options(
        db_a,
        NetworkMode::Server,
        0,
        [0u8; 32],
        Vec::new(),
        huddle_core::app::TransportConfig::onion_only(url.clone()),
    )
    .await
    .unwrap();
    let db_b = storage::open_db_in_memory().unwrap();
    let handle_b = AppHandle::start_with_db_and_options(
        db_b,
        NetworkMode::Server,
        0,
        [0u8; 32],
        Vec::new(),
        huddle_core::app::TransportConfig::onion_only(url.clone()),
    )
    .await
    .unwrap();
    let mut events_a = handle_a.subscribe();
    wait_server_connected(&handle_a).await;
    wait_server_connected(&handle_b).await;
    let b_fp = handle_b.fingerprint().to_string();

    // A mints a connect code and shares it (out of band).
    handle_a.create_connect_code().unwrap();
    let code = next_connect_code(&mut events_a).await;
    assert_eq!(code.len(), 8);
    // A well-formed code is recognized by the shared detector.
    assert!(huddle_core::app::normalize_connect_code(&code).is_some());

    // B types the code → resolves to A → B sends A a contact request.
    handle_b.redeem_connect_code(&code).unwrap();
    assert_eq!(next_contact_request(&mut events_a).await, b_fp);

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

/// huddle 1.2: the real-world first-contact case — you add someone by HD-ID
/// while they are OFFLINE. The signed ContactRequest is delivered straight to
/// their fingerprint's relay mailbox (1.2 direct delivery), held there, and
/// handed over when they next connect — even though that can be far outside the
/// signed-envelope replay window (1.2 exempts store-and-forward types). They
/// accept, and an encrypted DM converges in both directions over the relay.
/// Pre-1.2 this silently failed: the request needed a live inbox subscription
/// AND the mailboxed envelope was rejected as "outside the ±5min window".
#[tokio::test]
async fn offline_first_contact_then_dm_over_server() {
    let dir = tempfile::tempdir().unwrap();
    let port = 18814;
    let _server = spawn_server(port, dir.path().join("srv.db").to_str().unwrap());
    wait_listening(port).await;
    let url = format!("ws://127.0.0.1:{port}/ws");
    let b_db_path = dir.path().join("b.db");

    // Pre-seed B's identity on disk so A can address B by HD-ID while B has
    // NEVER connected (genuinely offline first contact). The request must
    // survive in B's per-fingerprint mailbox until B's very first Hello.
    let b_identity = huddle_core::identity::Identity::generate().unwrap();
    let b_fp = b_identity.fingerprint().to_string();
    {
        let db_seed = storage::open_db(&b_db_path, None).unwrap();
        repo::save_identity(&db_seed, &b_identity.secret_bytes(), 0).unwrap();
    }

    // A online.
    let db_a = storage::open_db_in_memory().unwrap();
    let handle_a = AppHandle::start_with_db_and_options(
        db_a,
        NetworkMode::Server,
        0,
        [0u8; 32],
        Vec::new(),
        huddle_core::app::TransportConfig::onion_only(url.clone()),
    )
    .await
    .unwrap();
    let mut events_a = handle_a.subscribe();
    let a_fp = handle_a.fingerprint().to_string();
    wait_server_connected(&handle_a).await;

    // A adds B by HD-ID while B is offline → request lands in B's mailbox.
    handle_a
        .send_contact_request(&b_fp, Some("hi while you were away"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;

    // B connects for the FIRST time: the mailboxed request flushes on Hello
    // and surfaces as a pending contact request — even though it is a signed
    // store-and-forward envelope (1.2 exempts these from the replay window).
    let db_b = storage::open_db(&b_db_path, None).unwrap();
    let handle_b = AppHandle::start_with_db_and_options(
        db_b,
        NetworkMode::Server,
        0,
        [0u8; 32],
        Vec::new(),
        huddle_core::app::TransportConfig::onion_only(url.clone()),
    )
    .await
    .unwrap();
    assert_eq!(handle_b.fingerprint(), b_fp, "pre-seeded identity loaded");
    let mut events_b = handle_b.subscribe();
    wait_server_connected(&handle_b).await;

    assert_eq!(next_contact_request(&mut events_b).await, a_fp);

    // B accepts → DM converges over the relay.
    handle_b.accept_contact_request(&a_fp).await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;

    let dm = huddle_core::app::canonical_dm_room_id(&a_fp, &b_fp);
    handle_a.send_room_message(&dm, "first words").await.unwrap();
    assert_eq!(next_message(&mut events_b).await, "first words");
    handle_b.send_room_message(&dm, "got them").await.unwrap();
    assert_eq!(next_message(&mut events_a).await, "got them");

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

/// huddle 1.0: DMs stay live across a restart. A establishes a DM with B,
/// exchanges a message, then A's process "restarts" (handle dropped, the same
/// on-disk DB reopened). The restarted A must auto-activate the DM (Phase 0.2)
/// and keep receiving B's messages over the relay — pre-1.0 the DM was parked
/// as "restorable" and silently dropped relay-delivered messages until it was
/// manually reopened.
#[tokio::test]
async fn dm_stays_live_across_restart_over_server() {
    let dir = tempfile::tempdir().unwrap();
    let port = 18813;
    let _server = spawn_server(port, dir.path().join("srv.db").to_str().unwrap());
    wait_listening(port).await;
    let url = format!("ws://127.0.0.1:{port}/ws");
    let a_db_path = dir.path().join("a.db");

    // B stays up the whole time (in-memory DB is fine).
    let db_b = storage::open_db_in_memory().unwrap();
    let handle_b = AppHandle::start_with_db_and_options(
        db_b,
        NetworkMode::Server,
        0,
        [0u8; 32],
        Vec::new(),
        huddle_core::app::TransportConfig::onion_only(url.clone()),
    )
    .await
    .unwrap();
    let mut events_b = handle_b.subscribe();
    let b_fp = handle_b.fingerprint().to_string();

    // First run of A — establish the DM and exchange a message.
    let a_fp;
    {
        let db_a = storage::open_db(&a_db_path, None).unwrap();
        let handle_a = AppHandle::start_with_db_and_options(
            db_a,
            NetworkMode::Server,
            0,
            [0u8; 32],
            Vec::new(),
            huddle_core::app::TransportConfig::onion_only(url.clone()),
        )
        .await
        .unwrap();
        a_fp = handle_a.fingerprint().to_string();
        wait_server_connected(&handle_a).await;
        wait_server_connected(&handle_b).await;
        // Both open the DM so the Megolm sessions converge over the relay.
        handle_a.start_direct(&b_fp).await.unwrap();
        handle_b.start_direct(&a_fp).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let dm = huddle_core::app::canonical_dm_room_id(&a_fp, &b_fp);
        handle_a.send_room_message(&dm, "before restart").await.unwrap();
        assert_eq!(next_message(&mut events_b).await, "before restart");
        handle_a.shutdown().await;
        // handle_a dropped at end of scope → simulates the process exiting.
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Restart A: reopen the SAME on-disk DB. Phase 0.2 should re-activate the
    // DM automatically (no manual reopen).
    let db_a2 = storage::open_db(&a_db_path, None).unwrap();
    let handle_a2 = AppHandle::start_with_db_and_options(
        db_a2,
        NetworkMode::Server,
        0,
        [0u8; 32],
        Vec::new(),
        huddle_core::app::TransportConfig::onion_only(url.clone()),
    )
    .await
    .unwrap();
    assert_eq!(handle_a2.fingerprint(), a_fp, "same identity across restart");
    let mut events_a2 = handle_a2.subscribe();
    wait_server_connected(&handle_a2).await;

    let dm = huddle_core::app::canonical_dm_room_id(&a_fp, &b_fp);
    assert!(
        handle_a2.active_room_ids().contains(&dm),
        "DM must be auto-activated on restart, not parked as restorable"
    );

    // B sends a fresh message; the restarted A receives + decrypts it with no
    // manual reopen — the load-bearing Phase 0.2 behavior.
    tokio::time::sleep(Duration::from_millis(800)).await;
    handle_b.send_room_message(&dm, "after restart").await.unwrap();
    assert_eq!(next_message(&mut events_a2).await, "after restart");

    handle_a2.shutdown().await;
    handle_b.shutdown().await;
}

async fn next_file_ready(rx: &mut tokio::sync::broadcast::Receiver<AppEvent>) -> String {
    let fut = async {
        loop {
            match rx.recv().await {
                Ok(AppEvent::FileReady { file_id }) => return file_id,
                Ok(AppEvent::FileFailed { reason, .. }) => panic!("file failed: {reason}"),
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(_) => panic!("event channel closed"),
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(30), fut)
        .await
        .expect("timed out waiting for FileReady")
}

/// Seed `room` into a fresh in-memory DB and start an AppHandle on it (Server
/// mode, pointed at `url`). Used to stand up extra group members.
async fn member_with_seeded_room(url: &str, room: &StoredRoom) -> AppHandle {
    let db = storage::open_db_in_memory().unwrap();
    repo::insert_room(&db, room).unwrap();
    AppHandle::start_with_db_and_options(
        db,
        NetworkMode::Server,
        0,
        [0u8; 32],
        Vec::new(),
        huddle_core::app::TransportConfig::onion_only(url.to_string()),
    )
    .await
    .unwrap()
}

/// huddle 1.2: a 3-member GROUP room over the relay — every member's message
/// must fan out to BOTH others (not just one). Exercises the membership
/// fan-out path with more than two parties.
#[tokio::test]
async fn group_fanout_reaches_all_members_over_server() {
    let dir = tempfile::tempdir().unwrap();
    let port = 18816;
    let _server = spawn_server(port, dir.path().join("srv.db").to_str().unwrap());
    wait_listening(port).await;
    let url = format!("ws://127.0.0.1:{port}/ws");

    let db_a = storage::open_db_in_memory().unwrap();
    let handle_a = AppHandle::start_with_db_and_options(
        db_a,
        NetworkMode::Server,
        0,
        [0u8; 32],
        Vec::new(),
        huddle_core::app::TransportConfig::onion_only(url.clone()),
    )
    .await
    .unwrap();
    let mut ev_a = handle_a.subscribe();
    let room_id = handle_a
        .start_room("trio", false, None, RoomKind::Group)
        .await
        .unwrap();
    let info = StoredRoom {
        id: room_id.clone(),
        name: "trio".into(),
        creator_fingerprint: handle_a.fingerprint().to_string(),
        encrypted: false,
        passphrase_salt: None,
        created_at: 0,
        last_active: Some(0),
        kind: RoomKind::Group,
    };
    let handle_b = member_with_seeded_room(&url, &info).await;
    let handle_c = member_with_seeded_room(&url, &info).await;
    let mut ev_b = handle_b.subscribe();
    let mut ev_c = handle_c.subscribe();

    wait_server_connected(&handle_a).await;
    wait_server_connected(&handle_b).await;
    wait_server_connected(&handle_c).await;
    handle_b.join_room(&room_id, None).await.unwrap();
    handle_c.join_room(&room_id, None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(600)).await;

    // A → both B and C.
    handle_a.send_room_message(&room_id, "hello trio").await.unwrap();
    assert_eq!(next_message(&mut ev_b).await, "hello trio");
    assert_eq!(next_message(&mut ev_c).await, "hello trio");

    // C → both A and B (fan-out works from any member, not just the creator).
    handle_c.send_room_message(&room_id, "from C").await.unwrap();
    assert_eq!(next_message(&mut ev_a).await, "from C");
    assert_eq!(next_message(&mut ev_b).await, "from C");

    handle_a.shutdown().await;
    handle_b.shutdown().await;
    handle_c.shutdown().await;
}

/// huddle 1.2.5: an ATTACHMENT larger than the old 1 MiB cap round-trips over
/// the relay — proving the server carries multi-chunk FileOffer+FileChunk
/// traffic and the receiver reassembles + SHA-256-verifies it (FileReady only
/// fires on a verified complete file). 2 MiB at 128 KiB/chunk = 16 chunks.
#[tokio::test]
async fn large_attachment_round_trips_over_server() {
    let dir = tempfile::tempdir().unwrap();
    let port = 18817;
    let _server = spawn_server(port, dir.path().join("srv.db").to_str().unwrap());
    wait_listening(port).await;
    let url = format!("ws://127.0.0.1:{port}/ws");

    let db_a = storage::open_db_in_memory().unwrap();
    let handle_a = AppHandle::start_with_db_and_options(
        db_a,
        NetworkMode::Server,
        0,
        [0u8; 32],
        Vec::new(),
        huddle_core::app::TransportConfig::onion_only(url.clone()),
    )
    .await
    .unwrap();
    let room_id = handle_a
        .start_room("files", false, None, RoomKind::Group)
        .await
        .unwrap();
    let info = StoredRoom {
        id: room_id.clone(),
        name: "files".into(),
        creator_fingerprint: handle_a.fingerprint().to_string(),
        encrypted: false,
        passphrase_salt: None,
        created_at: 0,
        last_active: Some(0),
        kind: RoomKind::Group,
    };
    let handle_b = member_with_seeded_room(&url, &info).await;
    let mut ev_b = handle_b.subscribe();

    wait_server_connected(&handle_a).await;
    wait_server_connected(&handle_b).await;
    handle_b.join_room(&room_id, None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // A 2 MiB file (> the old 1 MiB cap) with non-trivial content.
    let payload: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let path = dir.path().join("payload.bin");
    std::fs::write(&path, &payload).unwrap();

    let file_id = handle_a.send_file(&room_id, &path).await.unwrap();
    // FileReady on B means all chunks arrived over the relay AND the SHA-256
    // matched the file_id — a full integrity-checked round-trip.
    assert_eq!(next_file_ready(&mut ev_b).await, file_id);

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

/// huddle 1.2: smoke-test the **actually-deployed** relay (the systemd
/// `huddle-server` on 127.0.0.1:8787) end to end — a group message and a small
/// attachment between two real AppHandles. Ignored by default (needs the live
/// relay; adds a couple of ephemeral memberships to its DB). Run with:
/// `cargo test -p huddle-server --test app_over_server -- --ignored live_relay`
#[tokio::test]
#[ignore]
async fn live_relay_group_and_attachment() {
    let url = "ws://127.0.0.1:8787/ws".to_string();
    let dir = tempfile::tempdir().unwrap();

    let db_a = storage::open_db_in_memory().unwrap();
    let handle_a = AppHandle::start_with_db_and_options(
        db_a,
        NetworkMode::Server,
        0,
        [0u8; 32],
        Vec::new(),
        huddle_core::app::TransportConfig::onion_only(url.clone()),
    )
    .await
    .unwrap();
    let room_id = handle_a
        .start_room("live-smoke", false, None, RoomKind::Group)
        .await
        .unwrap();
    let info = StoredRoom {
        id: room_id.clone(),
        name: "live-smoke".into(),
        creator_fingerprint: handle_a.fingerprint().to_string(),
        encrypted: false,
        passphrase_salt: None,
        created_at: 0,
        last_active: Some(0),
        kind: RoomKind::Group,
    };
    let handle_b = member_with_seeded_room(&url, &info).await;
    let mut ev_b = handle_b.subscribe();
    wait_server_connected(&handle_a).await;
    wait_server_connected(&handle_b).await;
    handle_b.join_room(&room_id, None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(800)).await;

    handle_a.send_room_message(&room_id, "live group msg").await.unwrap();
    assert_eq!(next_message(&mut ev_b).await, "live group msg");

    let payload: Vec<u8> = (0..300 * 1024).map(|i| (i % 251) as u8).collect();
    let path = dir.path().join("live.bin");
    std::fs::write(&path, &payload).unwrap();
    let file_id = handle_a.send_file(&room_id, &path).await.unwrap();
    assert_eq!(next_file_ready(&mut ev_b).await, file_id);

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}
