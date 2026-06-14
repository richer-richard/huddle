//! `AppHandle` background tasks + connection plumbing — the spawned reconnector /
//! event-processor / relay-connection / announcement-ticker / room-pruner loops,
//! plus the identity-load, room-salt, and announce helpers they use. Split out of
//! the `app/mod.rs` god file (huddle 2.1.x maintainability refactor) as an
//! additional inherent `impl AppHandle` block.

use super::*;

impl AppHandle {
    pub(crate) fn spawn_known_peer_reconnector(&self) {
        let handle = self.clone();
        tokio::spawn(async move {
            // Brief delay so our own listeners come up first.
            tokio::time::sleep(Duration::from_millis(500)).await;
            let known = repo::list_known_peers(&handle.db).unwrap_or_default();
            // Reconnect each peer from its own task on a staggered, jittered
            // delay so a long known-peer list doesn't fire a synchronized
            // burst of dials (and serialized DB writes) all at once.
            for (i, peer) in known.into_iter().enumerate() {
                let handle = handle.clone();
                tokio::spawn(async move {
                    // Deterministic per-address jitter de-correlates peers
                    // without pulling an RNG into scope.
                    let jitter = (peer.address.len() as u64 * 37) % 200;
                    tokio::time::sleep(Duration::from_millis(150 * i as u64 + jitter)).await;
                    // huddle 0.7.7: route through `dial_internal`, NOT
                    // `dial`. Startup reconnects shouldn't pop a DM
                    // every time a known peer comes online — only
                    // explicit user actions trigger the auto-DM.
                    let multiaddr = match peer.address.parse::<Multiaddr>() {
                        Ok(m) => m,
                        Err(_) => return,
                    };
                    if let Err(e) = handle.dial_internal(peer.address.clone(), multiaddr).await {
                        debug!(%e, addr = %peer.address, "auto-reconnect failed");
                    }
                });
            }
        });
    }

    // -------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------

    pub(crate) fn load_or_create_identity(db: &Db) -> Result<Identity> {
        if let Some(stored) = repo::load_identity(db)? {
            // huddle 2.1.3 (zeroization sweep): hold the seed copy in Zeroizing so
            // this stack/heap copy of the crown-jewel secret is wiped on drop.
            let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
            bytes.copy_from_slice(&stored.ed25519_secret);
            Identity::from_secret_bytes(*bytes)
        } else {
            let id = Identity::generate()?;
            repo::save_identity(db, &id.secret_bytes(), now_unix())?;
            Ok(id)
        }
    }

    pub(crate) fn get_room_salt(&self, room_id: &str) -> Option<Vec<u8>> {
        self.active_rooms
            .lock()
            .get(room_id)
            .and_then(|r| r.info.passphrase_salt.clone())
            .or_else(|| {
                // Try the cached announcement salt
                ROOM_SALT_CACHE.lock().get(room_id).cloned()
            })
    }

    pub(crate) async fn announce_room_now(&self, info: &StoredRoom, member_count: u32) {
        let owner_fingerprints = repo::list_room_owners(&self.db, &info.id).unwrap_or_default();
        let verified_only = repo::get_room_verified_only(&self.db, &info.id).unwrap_or(false);
        let host_addrs = self.dialable_addrs();
        let ann = RoomAnnouncement {
            room_id: info.id.clone(),
            name: info.name.clone(),
            encrypted: info.encrypted,
            passphrase_salt: info.passphrase_salt.clone(),
            member_count,
            creator_fingerprint: info.creator_fingerprint.clone(),
            announced_at: now_unix(),
            owner_fingerprints,
            verified_only,
            host_addrs,
            kind: info.kind,
        };
        self.network.announce_room(ann).await;
    }

    pub(crate) async fn broadcast_member_announce(&self, room_id: &str) -> Result<()> {
        let our_fp = self.identity.fingerprint().to_string();
        let (wrapped, is_direct, dm_ct) = {
            let mut rooms = self.active_rooms.lock();
            let room = rooms
                .get_mut(room_id)
                .ok_or_else(|| HuddleError::Other("not in room".into()))?;
            let is_direct = room.info.kind == RoomKind::Direct;
            // huddle 1.3: the KEM ciphertext we (as DM initiator) encapsulated,
            // re-published every announce so the responder can decapsulate the
            // same hybrid wrap key. `None` for groups, classical DMs, responders.
            let dm_ct = room.dm_kem_ciphertext.clone();
            let wrapped = if room.info.encrypted {
                let crypto = room.crypto.as_mut().unwrap();
                let session_key = crypto.our_session_key_b64();
                match room.passphrase_key.as_ref() {
                    Some(passphrase_key) => {
                        Some(passphrase::wrap(session_key.as_bytes(), passphrase_key)?)
                    }
                    None if is_direct => {
                        // huddle 0.7.1: DM-specific path — partner's
                        // pubkey hasn't been observed yet, so we can't
                        // derive the wrap key. Send announce without
                        // a wrapped key — it carries our Ed25519 +
                        // ML-KEM pubkeys, which let the partner derive
                        // the key on their side. They'll respond with
                        // their own wrapped key in a follow-up
                        // announce; once we receive it we re-broadcast
                        // ours with the wrap filled in.
                        None
                    }
                    None => {
                        return Err(HuddleError::Session("missing passphrase key".into()));
                    }
                }
            } else {
                None
            };
            (wrapped, is_direct, dm_ct)
        };
        let display_name = repo::get_display_name(&self.db).unwrap_or(None);
        // huddle 1.3: advertise our ML-KEM-768 encapsulation key on Direct-room
        // announces (only — group rooms stay byte-identical) so the partner can
        // run the hybrid post-quantum DM key agreement. Its presence is also how
        // the partner detects our PQ capability. The ciphertext is set only when
        // we are the initiator (lower fingerprint) and have encapsulated.
        let (sender_mlkem_pubkey, mlkem_ciphertext) = if is_direct {
            (Some(B64.encode(self.identity.mlkem_public_bytes())), dm_ct)
        } else {
            (None, None)
        };
        let msg = RoomMessage::MemberAnnounce {
            sender_fingerprint: our_fp,
            wrapped_session_key: wrapped,
            display_name,
            sender_ed25519_pubkey: Some(B64.encode(self.identity.public_bytes())),
            sender_mlkem_pubkey,
            mlkem_ciphertext,
        };
        // huddle 0.7.11: MemberAnnounce is now signed end-to-end. On the send
        // path the inner `sender_ed25519_pubkey` equals the envelope's pubkey by
        // construction (both are our identity key), and the receiver pins
        // whatever pubkey the announce carries. The pin is made safe not by
        // ignoring the inner field but by the receiver's `signer ==
        // sender_fingerprint` gate, which lets a peer write only its own row.
        let env = crate::crypto::sign_message(&self.identity, &msg)?;
        let bytes = crate::network::protocol::encode_wire_signed(&env)?;
        self.network
            .publish_room_message(room_id.to_string(), bytes)
            .await;
        Ok(())
    }

    pub(crate) fn spawn_event_processor(
        &self,
        mut net_rx: tokio::sync::mpsc::Receiver<NetworkEvent>,
    ) {
        let handle = self.clone();
        tokio::spawn(async move {
            while let Some(event) = net_rx.recv().await {
                handle.process_network_event(event).await;
            }
            info!("event processor stopped");
        });
    }

    /// huddle 0.8/1.0: maintain a connection to the relay backend for the
    /// life of the process. Reconnects with capped exponential backoff. Each
    /// attempt tries the transport "doors" in `order` (onion first, clearnet
    /// last, or a single pinned door) until one connects — so a censored user
    /// whose Tor is blocked transparently falls through to a clearnet door.
    /// While connected, the [`NetworkHandle`] mirrors outgoing room traffic
    /// to it (see `attach_server`), and incoming server messages are funneled
    /// into the *same* `RoomMessageReceived` handler as gossipsub — so a
    /// message arriving via the relay is decoded, verified, and decrypted by
    /// exactly the same code path. The live door is recorded in
    /// `active_transport` for the UI/CLI.
    /// huddle 1.2: every room id whose membership must be asserted on the
    /// relay — active rooms, rooms parked as `restorable` (encrypted groups /
    /// keyless DMs awaiting a passphrase or the partner's pubkey), and the aux
    /// subscriptions (our own contact inbox). Used both to build the Hello
    /// room set and to re-subscribe after each (re)connect, so the relay knows
    /// we belong to a room even before we can decrypt it — otherwise its
    /// fan-out skips us and group messages silently never arrive.
    fn relay_membership_ids(&self) -> Vec<String> {
        let mut set: HashSet<String> = self.active_rooms.lock().keys().cloned().collect();
        set.extend(self.restorable_rooms.lock().keys().cloned());
        set.extend(self.aux_subscriptions.lock().iter().cloned());
        set.into_iter().collect()
    }

    pub(crate) fn spawn_server_connection(&self) {
        let handle = self.clone();
        // huddle 2.1.1: the reconnect signal — poked by set_transport_order /
        // set_clearnet_relay so a live priority change drops the socket and
        // re-dials with the new door order.
        let reconnect = handle.relay_reconnect.clone();
        tokio::spawn(async move {
            let mut backoff = 1u64;
            loop {
                // huddle 2.0.0: once shutdown() trips the flag, stop reconnecting
                // and let this task end (it holds the only live relay socket and
                // an AppHandle clone — leaving it running leaks both and, across
                // an in-process restart, races the new instance on the shared DB).
                if handle
                    .shutting_down
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    handle.network.detach_server();
                    return;
                }
                // huddle 1.0: the Hello room set is every active chat room
                // PLUS our aux subscriptions (the contact inbox), so the relay
                // re-registers inbox membership on every reconnect and flushes
                // any queued contact requests.
                let rooms: Vec<String> = handle.relay_membership_ids();

                // huddle 2.1.1: re-read the door order each cycle so a live
                // priority change (set_transport_order / set_clearnet_relay)
                // takes effect on the very next reconnect, not just at launch.
                let order = handle.transport_order.lock().clone();

                // Try each door in order until one connects. Unavailable
                // doors (no URL / wrong build) are skipped.
                let mut connected: Option<(
                    ServerClient,
                    tokio::sync::mpsc::Receiver<ServerEvent>,
                    TransportId,
                )> = None;
                for id in &order {
                    let (url, dial) = match handle.transport_profiles.iter().find(|p| p.id == *id) {
                        Some(p) if p.available() => {
                            (p.url.clone().unwrap(), p.dial.clone().unwrap())
                        }
                        _ => continue,
                    };
                    // huddle 2.1.3: bound each door's connect with a per-door
                    // timeout so a hung door — especially the Arti path, which lazily
                    // bootstraps an embedded Tor client and can stall for minutes on a
                    // Tor-hostile network — is treated as a failed door and the loop
                    // falls through to the next one (e.g. the clearnet fallback) rather
                    // than starving it. Without this, a no-Tor user on the default
                    // most-private-first order could appear permanently offline.
                    let budget = std::time::Duration::from_secs(id.connect_timeout_secs());
                    let connect =
                        ServerClient::connect(&url, &dial, handle.identity.clone(), rooms.clone());
                    match tokio::time::timeout(budget, connect).await {
                        Ok(Ok((client, rx))) => {
                            info!(%url, transport = id.as_str(), "connected to relay");
                            connected = Some((client, rx, *id));
                            break;
                        }
                        Ok(Err(e)) => {
                            debug!(error = %e, transport = id.as_str(), %url, "relay door failed; trying next");
                        }
                        Err(_) => {
                            debug!(transport = id.as_str(), %url, secs = budget.as_secs(), "relay door connect timed out; trying next");
                        }
                    }
                }

                if let Some((client, mut rx, id)) = connected {
                    backoff = 1;
                    handle.network.attach_server(client);
                    *handle.active_transport.lock() = Some(id);
                    // huddle 1.2: re-assert membership for every active room
                    // over the freshly attached connection. Hello carried the
                    // room snapshot taken before we connected, so a room
                    // created/joined during the connect-handshake window would
                    // otherwise stay unknown to the relay until the next
                    // reconnect — silently breaking group fan-out for it. The
                    // relay's add_membership is idempotent, so re-subscribing is
                    // free. (DM rooms route by fingerprint and don't depend on
                    // this, but re-subscribing them is harmless.)
                    for rid in handle.relay_membership_ids() {
                        handle.network.subscribe_room(rid).await;
                    }
                    loop {
                        // huddle 2.1.1: read the next relay event, but also wake
                        // on a reconnect request so a priority change drops this
                        // socket and re-dials with the new door order.
                        let ev = tokio::select! {
                            ev = rx.recv() => match ev {
                                Some(ev) => ev,
                                None => break,
                            },
                            _ = reconnect.notified() => {
                                info!("transport priority changed; reconnecting to the relay");
                                break;
                            }
                        };
                        match ev {
                            ServerEvent::Message {
                                room,
                                payload,
                                mailbox_id,
                                ..
                            } => {
                                // huddle 2.0.0 (F7) + 2.0.2 (audit M-2): at-least-
                                // once relay delivery. `process_relay_message`
                                // dispatches the message and returns whether it was
                                // durably handled. We ACK the mailbox row (so the
                                // relay may delete its copy) ONLY when it was — an
                                // `Encrypted` body whose Megolm session key hasn't
                                // arrived returns false and is left in the mailbox
                                // for redelivery rather than ACKed-then-lost.
                                // `mailbox_id` is `Some` only for an offline-mailbox
                                // delivery from a 2.0+ relay; live fan-out and
                                // pre-2.0 relays leave it `None`. The relay's 24h
                                // sweep is the backstop.
                                let ack_ok = handle.process_relay_message(room, payload).await;
                                if ack_ok {
                                    if let Some(id) = mailbox_id {
                                        let _ = handle.network.send_mailbox_ack(id);
                                    }
                                }
                            }
                            ServerEvent::Ready | ServerEvent::Sent { .. } => {}
                            ServerEvent::ConnectToken { token, ttl_secs } => {
                                // huddle 1.2.1: relay minted our connect code.
                                let expires_at = now_unix() + ttl_secs as i64;
                                let _ = handle.app_event_tx.send(AppEvent::ConnectCodeCreated {
                                    code: token,
                                    expires_at,
                                });
                            }
                            ServerEvent::ConnectTokenResolved {
                                fingerprint,
                                pubkey_b64,
                            } => {
                                handle
                                    .on_connect_code_resolved(fingerprint, pubkey_b64)
                                    .await;
                            }
                            ServerEvent::Disconnected => break,
                        }
                    }
                    handle.network.detach_server();
                    *handle.active_transport.lock() = None;
                    warn!("relay connection closed; reconnecting");
                } else {
                    warn!("all relay doors failed; will retry");
                }
                // huddle 2.0.0: exit promptly on shutdown rather than sleeping
                // the backoff and looping back to reconnect.
                if handle
                    .shutting_down
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    handle.network.detach_server();
                    return;
                }
                // huddle 2.1.1: a reconnect request during backoff also wakes us
                // (and resets the backoff) so a new priority applies promptly
                // even while every door is failing.
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(backoff)) => {}
                    _ = reconnect.notified() => { backoff = 1; }
                }
                backoff = (backoff * 2).min(30);
            }
        });
    }

    pub(crate) fn spawn_announcement_ticker(&self) {
        let handle = self.clone();
        tokio::spawn(async move {
            let our_fp = handle.identity.fingerprint().to_string();
            let mut interval = tokio::time::interval(Duration::from_secs(ANNOUNCE_INTERVAL_SECS));
            interval.tick().await; // skip the immediate tick
            loop {
                interval.tick().await;
                // huddle 2.0.2 (audit M-3): stop the heartbeat once shutdown
                // has begun, so we don't keep reading/writing the DB or
                // publishing announces during/after the rekey + close window.
                if handle
                    .shutting_down
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    return;
                }
                // huddle 1.3.1: alongside the room re-announce, find Direct rooms
                // whose hybrid handshake hasn't converged (no wrap key yet, or
                // keyed classical while the partner is PQ-capable = upgrade
                // pending) and, while they still have retry budget, emit a
                // bounded `SessionKeyRequest` nudge. This heals a stalled
                // handshake (e.g. the initiator's single ciphertext-bearing
                // announce was lost) without a periodic full MemberAnnounce; the
                // hard cap keeps an unreachable partner's mailbox from filling.
                // huddle 2.0.0 (F4): read the scheduled-rotation policy once per
                // tick (outside the active_rooms lock — it touches the DB). The
                // heartbeat is what fires the *time*-based trigger for rooms that
                // aren't actively sending; the send path covers the count trigger.
                let rotation_policy = handle.megolm_rotation_policy();
                let (snapshot, dm_nudges, rotated): (
                    Vec<(StoredRoom, u32)>,
                    Vec<String>,
                    Vec<String>,
                ) = {
                    let mut active = handle.active_rooms.lock();
                    let snap: Vec<(StoredRoom, u32)> = active
                        .values()
                        .map(|r| (r.info.clone(), r.members.len() as u32))
                        .collect();
                    let mut nudges = Vec::new();
                    let mut rotated = Vec::new();
                    for room in active.values_mut() {
                        // F4: scheduled forward-only Megolm rotation for any keyed
                        // encrypted room (groups + DMs). Rotate in-place (sync)
                        // and re-announce the fresh key after the lock. Only keyed
                        // rooms rotate — an unkeyed DM has nothing to share yet.
                        if room.info.encrypted
                            && room.passphrase_key.is_some()
                            && rotation_policy.is_enabled()
                        {
                            if let Some(c) = room.crypto.as_mut() {
                                if c.should_rotate(&rotation_policy) {
                                    match c.rotate_outbound() {
                                        Ok(()) => {
                                            // F4: persist the reset (0/now) epoch so
                                            // the schedule doesn't re-arm from
                                            // scratch after a restart.
                                            handle.persist_rotation_state(c);
                                            rotated.push(room.info.id.clone());
                                        }
                                        Err(e) => warn!(
                                            %e, room_id = %room.info.id,
                                            "F4: scheduled Megolm rotation failed in heartbeat"
                                        ),
                                    }
                                }
                            }
                        }
                        if room.info.kind != RoomKind::Direct || !room.info.encrypted {
                            continue;
                        }
                        let keyed = room.passphrase_key.is_some();
                        let partner = room.members.iter().find(|m| m.as_str() != our_fp).cloned();
                        let pq_capable = match &partner {
                            Some(p) => repo::lookup_peer_mlkem_pubkey(&handle.db, p)
                                .ok()
                                .flatten()
                                .is_some(),
                            None => false,
                        };
                        // Converged = hybrid keyed, or classical keyed with a
                        // genuinely non-PQ partner. Anything else needs a nudge.
                        let needs_nudge = !keyed || (!room.dm_is_hybrid && pq_capable);
                        if needs_nudge {
                            if room.dm_key_retry < DM_KEY_RETRY_MAX {
                                room.dm_key_retry = room.dm_key_retry.saturating_add(1);
                                nudges.push(room.info.id.clone());
                            }
                        } else {
                            room.dm_key_retry = 0;
                        }
                    }
                    (snap, nudges, rotated)
                };
                for (info, member_count) in snapshot {
                    handle.announce_room_now(&info, member_count).await;
                }
                // F4: re-share each rotated room's fresh session key.
                for rid in rotated {
                    if let Err(e) = handle.broadcast_member_announce(&rid).await {
                        warn!(%e, room_id = %rid, "F4: post-rotation MemberAnnounce failed");
                    } else {
                        info!(room_id = %rid, "F4: rotated outbound Megolm epoch (heartbeat) and re-announced");
                    }
                }
                for rid in dm_nudges {
                    let req = RoomMessage::SessionKeyRequest {
                        requester_fingerprint: our_fp.clone(),
                    };
                    if let Ok(bytes) = encode_wire(&req) {
                        handle.network.publish_room_message(rid, bytes).await;
                    }
                }
            }
        });
    }

    pub(crate) fn spawn_discovered_room_pruner(&self) {
        let handle = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            interval.tick().await;
            loop {
                interval.tick().await;
                // huddle 2.0.2 (audit M-3): honor shutdown in the pruner too.
                if handle
                    .shutting_down
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    return;
                }
                let now = now_unix();
                let mut to_drop = Vec::new();
                {
                    let mut map = handle.discovered_rooms.lock();
                    map.retain(|id, r| {
                        if now - r.last_seen > DISCOVERED_TTL_SECS {
                            to_drop.push(id.clone());
                            false
                        } else {
                            true
                        }
                    });
                }
                // huddle 1.3.1: reap abandoned SAS flows so an inbound-SasInit
                // flood (or just unfinished handshakes) can't grow sas_flows
                // without bound. Finalized flows are already removed promptly.
                // huddle 1.3.3: `created_at` is refreshed on progress, so this is
                // an idle-since-last-activity TTL — a slow but live handshake survives.
                handle.sas.reap(now);
                // huddle 2.0.0 (F9): disappearing-messages sweep. Physically
                // delete every message past its room's TTL, against our own
                // clock (best-effort + local). F2 interaction: a deleted
                // message's `content_replay_seen` row survives, so a replayed
                // copy of an expired message is still dropped as a replay and can
                // never be resurrected into the chat. Emit a coarse refresh nudge
                // when anything was removed so the open room re-fetches history.
                match repo::delete_expired_messages(&handle.db, now) {
                    Ok(removed) if removed > 0 => {
                        debug!(removed, "F9: pruned expired messages");
                        let _ = handle
                            .app_event_tx
                            .send(AppEvent::MessagesExpired { count: removed });
                    }
                    Ok(_) => {}
                    Err(e) => warn!(%e, "F9: expired-message sweep failed"),
                }
                for id in to_drop {
                    let _ = handle.app_event_tx.send(AppEvent::RoomLost { room_id: id });
                }
            }
        });
    }
}
