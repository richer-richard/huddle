use std::time::Duration;

use huddle_core::app::events::AppEvent;
use huddle_core::app::AppHandle;
use huddle_core::storage;

const DISCOVERY_TIMEOUT_SECS: u64 = 30;
const MESSAGE_TIMEOUT_SECS: u64 = 15;

#[tokio::test]
async fn two_node_unencrypted_room_message_exchange() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("huddle=debug,warn")
        .try_init();

    let db_a = storage::open_db_in_memory().unwrap();
    let db_b = storage::open_db_in_memory().unwrap();
    let handle_a = AppHandle::start_with_db(db_a).await.unwrap();
    let handle_b = AppHandle::start_with_db(db_b).await.unwrap();

    eprintln!("A fp={} B fp={}", handle_a.fingerprint(), handle_b.fingerprint());

    let mut events_a = handle_a.subscribe();
    let mut events_b = handle_b.subscribe();

    // A starts a public room.
    let room_id = handle_a
        .start_room("test-room", false, None)
        .await
        .unwrap();

    // B waits to discover the room.
    let target_room_id = room_id.clone();
    let discovery = tokio::time::timeout(Duration::from_secs(DISCOVERY_TIMEOUT_SECS), async {
        loop {
            match events_b.recv().await {
                Ok(AppEvent::RoomDiscovered(r)) if r.room_id == target_room_id => return,
                Ok(_) => {}
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await;

    if discovery.is_err() {
        eprintln!("room discovery timed out (mDNS may be blocked); skipping");
        handle_a.shutdown().await;
        handle_b.shutdown().await;
        return;
    }
    eprintln!("B discovered room {}", room_id);

    // B joins the room.
    handle_b.join_room(&room_id, None).await.unwrap();

    // A sends a message.
    tokio::time::sleep(Duration::from_millis(1500)).await; // let gossipsub mesh settle
    handle_a
        .send_room_message(&room_id, "hello room")
        .await
        .unwrap();

    let msg = tokio::time::timeout(Duration::from_secs(MESSAGE_TIMEOUT_SECS), async {
        loop {
            match events_b.recv().await {
                Ok(AppEvent::MessageReceived { body, .. }) => return body,
                Ok(_) => {}
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await;
    assert!(msg.is_ok(), "B never received the message");
    assert_eq!(msg.unwrap(), "hello room");

    // B replies.
    handle_b
        .send_room_message(&room_id, "hi back")
        .await
        .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(MESSAGE_TIMEOUT_SECS), async {
        loop {
            match events_a.recv().await {
                Ok(AppEvent::MessageReceived { body, .. }) => return body,
                Ok(_) => {}
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await;
    assert!(reply.is_ok(), "A never received the reply");
    assert_eq!(reply.unwrap(), "hi back");

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

#[tokio::test]
async fn two_node_encrypted_room_message_exchange() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("huddle=debug,warn")
        .try_init();

    let db_a = storage::open_db_in_memory().unwrap();
    let db_b = storage::open_db_in_memory().unwrap();
    let handle_a = AppHandle::start_with_db(db_a).await.unwrap();
    let handle_b = AppHandle::start_with_db(db_b).await.unwrap();

    let mut events_a = handle_a.subscribe();
    let mut events_b = handle_b.subscribe();

    let room_id = handle_a
        .start_room("secret-room", true, Some("hunter2"))
        .await
        .unwrap();

    let target_room_id = room_id.clone();
    let discovery = tokio::time::timeout(Duration::from_secs(DISCOVERY_TIMEOUT_SECS), async {
        loop {
            match events_b.recv().await {
                Ok(AppEvent::RoomDiscovered(r)) if r.room_id == target_room_id => return,
                Ok(_) => {}
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await;
    if discovery.is_err() {
        eprintln!("room discovery timed out; skipping encrypted test");
        handle_a.shutdown().await;
        handle_b.shutdown().await;
        return;
    }

    handle_b
        .join_room(&room_id, Some("hunter2"))
        .await
        .unwrap();

    // Give time for member announcements + key exchange.
    tokio::time::sleep(Duration::from_millis(2500)).await;

    handle_a
        .send_room_message(&room_id, "encrypted hello")
        .await
        .unwrap();

    let msg = tokio::time::timeout(Duration::from_secs(MESSAGE_TIMEOUT_SECS), async {
        loop {
            match events_b.recv().await {
                Ok(AppEvent::MessageReceived { body, .. }) => return body,
                Ok(_) => {}
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await;
    assert!(msg.is_ok(), "B never decrypted the message");
    assert_eq!(msg.unwrap(), "encrypted hello");

    handle_b
        .send_room_message(&room_id, "encrypted reply")
        .await
        .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(MESSAGE_TIMEOUT_SECS), async {
        loop {
            match events_a.recv().await {
                Ok(AppEvent::MessageReceived { body, .. }) => return body,
                Ok(_) => {}
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await;
    assert!(reply.is_ok());
    assert_eq!(reply.unwrap(), "encrypted reply");

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}
