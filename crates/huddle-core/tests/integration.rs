use std::time::Duration;

use huddle_core::app::events::AppEvent;
use huddle_core::app::AppHandle;
use huddle_core::storage;

#[tokio::test]
async fn two_node_handshake_and_message_exchange() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("huddle=debug")
        .try_init();

    let db_a = storage::open_db_in_memory().unwrap();
    let db_b = storage::open_db_in_memory().unwrap();

    let handle_a = AppHandle::start_with_db(db_a).await.unwrap();
    let handle_b = AppHandle::start_with_db(db_b).await.unwrap();

    let mut events_a = handle_a.subscribe();
    let mut events_b = handle_b.subscribe();

    let fp_a = handle_a.fingerprint().to_string();
    let fp_b = handle_b.fingerprint().to_string();
    let peer_id_b = handle_b.peer_id();

    eprintln!("Node A: fingerprint={fp_a}, peer_id={}", handle_a.peer_id());
    eprintln!("Node B: fingerprint={fp_b}, peer_id={peer_id_b}");

    // Wait for mDNS discovery (up to 30 seconds)
    let discovery_timeout = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match events_a.recv().await {
                Ok(AppEvent::PeerDiscovered { peer_id, .. }) if peer_id == peer_id_b => {
                    eprintln!("A discovered B via mDNS");
                    return;
                }
                Ok(_) => {}
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    })
    .await;

    if discovery_timeout.is_err() {
        eprintln!("mDNS discovery timed out - this can happen in CI or restricted networks");
        eprintln!("Skipping the rest of the integration test");
        handle_a.shutdown().await;
        handle_b.shutdown().await;
        return;
    }

    // A initiates session with B
    handle_a.initiate_session(peer_id_b).await.unwrap();

    // Wait for session establishment on A
    let session_timeout = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events_a.recv().await {
                Ok(AppEvent::SessionEstablished { peer_id, .. }) if peer_id == peer_id_b => {
                    eprintln!("Session A->B established");
                    return;
                }
                Ok(_) => {}
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    })
    .await;
    assert!(session_timeout.is_ok(), "session establishment timed out");

    // A sends message to B
    handle_a
        .send_message(peer_id_b, "hello from A")
        .await
        .unwrap();

    // Wait for B to receive the message
    let msg_timeout = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events_b.recv().await {
                Ok(AppEvent::MessageReceived { body, .. }) => {
                    eprintln!("B received: {body}");
                    assert_eq!(body, "hello from A");
                    return;
                }
                Ok(_) => {}
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    })
    .await;
    assert!(msg_timeout.is_ok(), "message delivery timed out");

    // B replies
    let peer_id_a = handle_a.peer_id();
    handle_b
        .send_message(peer_id_a, "hello from B")
        .await
        .unwrap();

    // Wait for A to receive the reply
    let reply_timeout = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events_a.recv().await {
                Ok(AppEvent::MessageReceived { body, .. }) => {
                    eprintln!("A received: {body}");
                    assert_eq!(body, "hello from B");
                    return;
                }
                Ok(_) => {}
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    })
    .await;
    assert!(reply_timeout.is_ok(), "reply delivery timed out");

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}
