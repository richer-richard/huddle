//! End-to-end integration tests.
//!
//! Each test spawns 2-3 in-memory huddle instances and exercises a
//! full protocol flow.
//!
//! - The two original 2-node round-trip tests (unencrypted + encrypted)
//!   use mDNS for discovery. mDNS is unreliable in some sandboxed CI
//!   environments — those tests skip-with-warning on discovery
//!   timeout instead of failing.
//! - The Phase A tests use direct-dial (`NetworkMode::Direct`) so
//!   they're deterministic and run quickly without mDNS.
//! - The Phase B 3-node + Phase F code-join tests use mDNS like the
//!   original tests and apply the same skip-on-timeout guard.
//!
//! Run all six sequentially with `cargo test --workspace --test
//! integration -- --test-threads=1`; parallel runs may fight over
//! mDNS broadcast space on a single host.

use std::time::Duration;

use huddle_core::app::events::AppEvent;
use huddle_core::app::AppHandle;
use huddle_core::network::NetworkMode;
use huddle_core::storage;
use huddle_core::storage::repo::RoomKind;
use tokio::sync::broadcast;

const DISCOVERY_TIMEOUT_SECS: u64 = 30;
const MESSAGE_TIMEOUT_SECS: u64 = 15;
const DIRECT_DIAL_TIMEOUT_SECS: u64 = 15;

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

    eprintln!(
        "A fp={} B fp={}",
        handle_a.fingerprint(),
        handle_b.fingerprint()
    );

    let mut events_a = handle_a.subscribe();
    let mut events_b = handle_b.subscribe();

    let room_id = handle_a
        .start_room("test-room", false, None, RoomKind::Group)
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
        eprintln!("room discovery timed out (mDNS may be blocked); skipping");
        handle_a.shutdown().await;
        handle_b.shutdown().await;
        return;
    }
    eprintln!("B discovered room {}", room_id);

    handle_b.join_room(&room_id, None).await.unwrap();

    tokio::time::sleep(Duration::from_millis(1500)).await;
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
        .start_room("secret-room", true, Some("hunter2"), RoomKind::Group)
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

    handle_b.join_room(&room_id, Some("hunter2")).await.unwrap();

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

// =========================================================================
// Helpers added in the 0.3.x follow-up.
// =========================================================================

/// Start an AppHandle in `NetworkMode::Direct` so it doesn't broadcast
/// via mDNS. Returns the handle, a subscribed receiver, and a fresh
/// listening multiaddr (the first `/ip4/127.0.0.1/tcp/...` ListeningOn
/// event we observe). The returned address is `/ip4/127.0.0.1/tcp/N/p2p/<peer_id>`,
/// suitable to pass to `dial()` on the other side so libp2p enforces
/// the peer-id check.
async fn spawn_direct_node() -> (AppHandle, broadcast::Receiver<AppEvent>, String) {
    let db = storage::open_db_in_memory().unwrap();
    let handle = AppHandle::start_with_db_and_options(
        db,
        NetworkMode::Direct,
        0,
        [0u8; 32],
        Vec::new(),
        // integration tests run without any relay door (libp2p only)
        huddle_core::app::TransportConfig::default(),
    )
    .await
    .unwrap();
    let peer_id = handle.peer_id();
    let mut rx = handle.subscribe();
    let listen = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match rx.recv().await {
                Ok(AppEvent::ListeningOn { address }) if address.starts_with("/ip4/127.0.0.1/") => {
                    return address;
                }
                Ok(_) => {}
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("listen address materialised within 5 s");
    let full = format!("{}/p2p/{}", listen, peer_id);
    (handle, rx, full)
}

/// Poll a broadcast receiver until `predicate` returns `true` for an
/// event or the timeout expires. Returns the matching event on success.
async fn await_event<F>(
    rx: &mut broadcast::Receiver<AppEvent>,
    timeout: Duration,
    mut predicate: F,
) -> Option<AppEvent>
where
    F: FnMut(&AppEvent) -> bool,
{
    tokio::time::timeout(timeout, async {
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    if predicate(&ev) {
                        return Some(ev);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
    .await
    .unwrap_or(None)
}

// =========================================================================
// Phase A — inbound-dial accept / reject
// =========================================================================

#[tokio::test]
async fn phase_a_inbound_dial_accept_forms_mesh() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("huddle=debug,warn")
        .try_init();

    // A initiates the dial, B is the listener that gets the inbound-prompt.
    let (handle_a, _events_a, _addr_a) = spawn_direct_node().await;
    let (handle_b, mut events_b, addr_b) = spawn_direct_node().await;

    // A dials B.
    handle_a.dial(&addr_b).await.unwrap();

    // B should receive an `InboundDial` event with A's fingerprint.
    let inbound = await_event(
        &mut events_b,
        Duration::from_secs(DIRECT_DIAL_TIMEOUT_SECS),
        |ev| matches!(ev, AppEvent::InboundDial { fingerprint, .. } if fingerprint == handle_a.fingerprint()),
    )
    .await
    .expect("B should see InboundDial from A");
    let (peer_id, addr) = match inbound {
        AppEvent::InboundDial {
            peer_id, address, ..
        } => (peer_id, address),
        _ => unreachable!(),
    };
    assert_eq!(peer_id, handle_a.peer_id());

    // B accepts. After accept, A and B's gossipsub mesh should form
    // such that a room A creates is discoverable to B.
    handle_b.accept_inbound(peer_id, &addr).await;

    tokio::time::sleep(Duration::from_millis(1000)).await;
    let room_id = handle_a
        .start_room("phase-a-accept", false, None, RoomKind::Group)
        .await
        .unwrap();
    let target = room_id.clone();
    let discovered = await_event(
        &mut events_b,
        Duration::from_secs(MESSAGE_TIMEOUT_SECS),
        |ev| matches!(ev, AppEvent::RoomDiscovered(r) if r.room_id == target),
    )
    .await;
    assert!(
        discovered.is_some(),
        "B never discovered A's room after accept"
    );

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

#[tokio::test]
async fn phase_a_inbound_dial_reject_persists_block() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("huddle=debug,warn")
        .try_init();

    let (handle_a, _events_a, _addr_a) = spawn_direct_node().await;
    let (handle_b, mut events_b, addr_b) = spawn_direct_node().await;

    handle_a.dial(&addr_b).await.unwrap();

    let a_fp = handle_a.fingerprint().to_string();
    let inbound = await_event(
        &mut events_b,
        Duration::from_secs(DIRECT_DIAL_TIMEOUT_SECS),
        |ev| matches!(ev, AppEvent::InboundDial { fingerprint, .. } if fingerprint == &a_fp),
    )
    .await
    .expect("B should see InboundDial from A");
    let peer_id = match inbound {
        AppEvent::InboundDial { peer_id, .. } => peer_id,
        _ => unreachable!(),
    };

    // B rejects → blocks A's fingerprint persistently.
    handle_b.reject_inbound(peer_id, &a_fp).await.unwrap();

    // Persistent block landed.
    assert!(
        handle_b.list_blocked_peers().contains(&a_fp),
        "B's blocklist should contain A's fingerprint after reject"
    );

    // Allow the disconnect to propagate.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // A re-dials B. The auto-reject path inside B's InboundDial
    // handler short-circuits before the modal would fire, so no new
    // InboundDial event reaches B's subscribers.
    handle_a.dial(&addr_b).await.unwrap();
    let second = await_event(
        &mut events_b,
        Duration::from_secs(3),
        |ev| matches!(ev, AppEvent::InboundDial { fingerprint, .. } if fingerprint == &a_fp),
    )
    .await;
    assert!(
        second.is_none(),
        "B should NOT raise a second InboundDial — A is blocked"
    );

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

// =========================================================================
// Phase B — kick-and-rotate, three-party
// =========================================================================

#[tokio::test]
async fn phase_b_kick_rotates_key_and_excludes_banned() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("huddle=debug,warn")
        .try_init();

    let db_a = storage::open_db_in_memory().unwrap();
    let db_b = storage::open_db_in_memory().unwrap();
    let db_c = storage::open_db_in_memory().unwrap();
    let handle_a = AppHandle::start_with_db(db_a).await.unwrap();
    let handle_b = AppHandle::start_with_db(db_b).await.unwrap();
    let handle_c = AppHandle::start_with_db(db_c).await.unwrap();
    eprintln!(
        "A fp={} B fp={} C fp={}",
        handle_a.fingerprint(),
        handle_b.fingerprint(),
        handle_c.fingerprint()
    );

    let mut events_b = handle_b.subscribe();
    let mut events_c = handle_c.subscribe();

    // A starts an encrypted room; B and C join.
    let room_id = handle_a
        .start_room("phase-b", true, Some("first-pass"), RoomKind::Group)
        .await
        .unwrap();
    let target = room_id.clone();

    let saw_b = await_event(
        &mut events_b,
        Duration::from_secs(DISCOVERY_TIMEOUT_SECS),
        |ev| matches!(ev, AppEvent::RoomDiscovered(r) if r.room_id == target),
    )
    .await;
    let saw_c = await_event(
        &mut events_c,
        Duration::from_secs(DISCOVERY_TIMEOUT_SECS),
        |ev| matches!(ev, AppEvent::RoomDiscovered(r) if r.room_id == target),
    )
    .await;
    if saw_b.is_none() || saw_c.is_none() {
        eprintln!("3-node mDNS discovery timed out; skipping Phase B test");
        handle_a.shutdown().await;
        handle_b.shutdown().await;
        handle_c.shutdown().await;
        return;
    }
    handle_b
        .join_room(&room_id, Some("first-pass"))
        .await
        .unwrap();
    handle_c
        .join_room(&room_id, Some("first-pass"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(2500)).await;

    // Sanity round-trip before the kick.
    handle_a
        .send_room_message(&room_id, "pre-kick from A")
        .await
        .unwrap();
    let pre_b = await_event(
        &mut events_b,
        Duration::from_secs(MESSAGE_TIMEOUT_SECS),
        |ev| matches!(ev, AppEvent::MessageReceived { body, .. } if body == "pre-kick from A"),
    )
    .await;
    let pre_c = await_event(
        &mut events_c,
        Duration::from_secs(MESSAGE_TIMEOUT_SECS),
        |ev| matches!(ev, AppEvent::MessageReceived { body, .. } if body == "pre-kick from A"),
    )
    .await;
    assert!(pre_b.is_some() && pre_c.is_some(), "pre-kick fanout failed");

    // A kicks B. Returns the freshly-generated passphrase that A used
    // for the rotation (B doesn't have it). Phase 1 of this follow-up
    // ensures the RotateRoomKey is signed; receivers verify the signer
    // matches the claimed `rotator_fingerprint`.
    let new_pass = handle_a
        .kick_member(&room_id, handle_b.fingerprint())
        .await
        .unwrap();
    assert!(
        !new_pass.is_empty(),
        "encrypted room kick must return a new passphrase"
    );

    // C accepts the rotation with the new passphrase (the TUI would
    // prompt; we drive it directly).
    let rotation_for_c = await_event(
        &mut events_c,
        Duration::from_secs(MESSAGE_TIMEOUT_SECS),
        |ev| matches!(ev, AppEvent::RotationRequested { room_id: r, .. } if r == &room_id),
    )
    .await
    .expect("C should see RotationRequested");
    let new_salt = match rotation_for_c {
        AppEvent::RotationRequested { new_salt, .. } => new_salt,
        _ => unreachable!(),
    };
    handle_c
        .accept_rotation(&room_id, &new_salt, &new_pass)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(2500)).await;

    // A sends a post-kick message. C should receive + decrypt it. B
    // receives the gossipsub bytes but its `RoomCrypto` has no inbound
    // session matching the new outbound, so the decrypt fails silently
    // and no `MessageReceived` event reaches B's subscribers.
    handle_a
        .send_room_message(&room_id, "post-kick — only C should see this")
        .await
        .unwrap();
    let to_c = await_event(
        &mut events_c,
        Duration::from_secs(MESSAGE_TIMEOUT_SECS),
        |ev| matches!(ev, AppEvent::MessageReceived { body, .. } if body == "post-kick — only C should see this"),
    )
    .await;
    assert!(
        to_c.is_some(),
        "C should still decrypt A's post-kick message"
    );

    let to_b = await_event(
        &mut events_b,
        Duration::from_secs(3),
        |ev| matches!(ev, AppEvent::MessageReceived { body, .. } if body == "post-kick — only C should see this"),
    )
    .await;
    assert!(to_b.is_none(), "B should NOT decrypt the post-kick message");

    handle_a.shutdown().await;
    handle_b.shutdown().await;
    handle_c.shutdown().await;
}

// =========================================================================
// Phase F — code-join round-trip
// =========================================================================

#[tokio::test]
async fn phase_f_code_join_round_trip() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("huddle=debug,warn")
        .try_init();

    let db_a = storage::open_db_in_memory().unwrap();
    let db_b = storage::open_db_in_memory().unwrap();
    let handle_a = AppHandle::start_with_db(db_a).await.unwrap();
    let handle_b = AppHandle::start_with_db(db_b).await.unwrap();

    let mut events_b = handle_b.subscribe();

    // A starts an encrypted room; B sees it via mDNS but DOES NOT have
    // the passphrase. We'll get B in by issuing a join code instead.
    let room_id = handle_a
        .start_room("phase-f", true, Some("alice-only"), RoomKind::Group)
        .await
        .unwrap();
    let target = room_id.clone();
    let discovered = await_event(
        &mut events_b,
        Duration::from_secs(DISCOVERY_TIMEOUT_SECS),
        |ev| matches!(ev, AppEvent::RoomDiscovered(r) if r.room_id == target),
    )
    .await;
    if discovered.is_none() {
        eprintln!("Phase F: mDNS discovery timed out; skipping");
        handle_a.shutdown().await;
        handle_b.shutdown().await;
        return;
    }

    // A issues a code. Caller is the owner; passes our_fp check.
    let code = handle_a.generate_join_code(&room_id).unwrap();
    assert_eq!(code.len(), 9, "code is 4-dash-4 = 9 chars: {}", code);

    // B joins using the code. Round-trip should establish an inbound
    // Megolm session on B keyed by A's fingerprint.
    handle_b.join_room_with_code(&room_id, &code).await.unwrap();

    // Give the ECDH + wrap/unwrap round-trip time to land.
    tokio::time::sleep(Duration::from_millis(3000)).await;

    // A sends a message; B should decrypt it (the code-join gave B
    // A's outbound session as inbound).
    handle_a
        .send_room_message(&room_id, "alice -> code-joined bob")
        .await
        .unwrap();
    let to_b = await_event(
        &mut events_b,
        Duration::from_secs(MESSAGE_TIMEOUT_SECS),
        |ev| matches!(ev, AppEvent::MessageReceived { body, .. } if body == "alice -> code-joined bob"),
    )
    .await;
    assert!(
        to_b.is_some(),
        "B should decrypt A's message after code-join"
    );

    // B is marked read-only (no passphrase, no ability to wrap session
    // keys for future joiners). Surface check.
    assert!(
        handle_b.is_room_read_only(&room_id),
        "code-joined room should be read-only on B's side"
    );

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

// huddle 1.0: the GUI/CLI "Set relay" path persists a clearnet relay URL and
// biases the door order toward it. No networking — pure settings round-trip.
#[tokio::test]
async fn clearnet_relay_setting_round_trips() {
    let db = storage::open_db_in_memory().unwrap();
    let handle = AppHandle::start_with_db(db).await.unwrap();

    // Unset by default.
    assert_eq!(handle.clearnet_relay(), None);

    // Setting a URL persists it and reads back.
    handle
        .set_clearnet_relay(Some("wss://abc.trycloudflare.com/ws"))
        .unwrap();
    assert_eq!(
        handle.clearnet_relay().as_deref(),
        Some("wss://abc.trycloudflare.com/ws")
    );

    // Clearing resets to None.
    handle.set_clearnet_relay(None).unwrap();
    assert_eq!(handle.clearnet_relay(), None);

    // A blank/whitespace URL is treated as a clear, not a stored "".
    handle.set_clearnet_relay(Some("   ")).unwrap();
    assert_eq!(handle.clearnet_relay(), None);

    handle.shutdown().await;
}

/// huddle 2.0.0 (F10): `send_reaction` only fires for a message we actually
/// hold. A reaction to an unknown `client_msg_id` is rejected (no orphan row,
/// no broadcast); a reaction to a real message is stored. Single Direct-mode
/// node — no mDNS, so this is deterministic and won't fight other tests.
#[tokio::test]
async fn send_reaction_rejects_unknown_target() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("huddle=debug,warn")
        .try_init();

    let (handle, _events, _addr) = spawn_direct_node().await;

    let room_id = handle
        .start_room("react-room", false, None, RoomKind::Group)
        .await
        .unwrap();

    // Reacting to a target that isn't in the room is an error and stores
    // nothing locally.
    let bogus = handle
        .send_reaction(
            &room_id,
            "00000000-0000-4000-8000-000000000000",
            "👍",
            false,
        )
        .await;
    assert!(
        bogus.is_err(),
        "reaction to unknown target must be rejected"
    );
    assert!(
        handle.room_reactions(&room_id).is_empty(),
        "rejected reaction must not leave an orphan row"
    );

    // Send a real message, grab its client_msg_id, and react to it.
    handle
        .send_room_message(&room_id, "react to me")
        .await
        .unwrap();
    let target = handle
        .room_messages(&room_id, 10)
        .unwrap()
        .into_iter()
        .find_map(|m| m.client_msg_id)
        .expect("our own message carries a client_msg_id");
    handle
        .send_reaction(&room_id, &target, "👍", false)
        .await
        .expect("reaction to a real message succeeds");

    let stored = handle.room_reactions(&room_id);
    assert_eq!(stored.len(), 1, "exactly one reaction stored");
    assert_eq!(stored[0].target_client_msg_id, target);
    assert_eq!(stored[0].emoji, "👍");

    handle.shutdown().await;
}
