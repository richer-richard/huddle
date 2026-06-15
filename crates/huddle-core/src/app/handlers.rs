//! `AppHandle` inbound-event handling — the network/relay event loop body and
//! the per-`RoomMessage` dispatch. Split out of the `app/mod.rs` god file
//! (huddle 2.1.x maintainability refactor) as an additional inherent
//! `impl AppHandle` block. `handle_room_message` is the central authority/decrypt
//! dispatch over every `RoomMessage` variant; it is moved here verbatim (a later
//! step decomposes it per-variant). The struct, its fields, the spawn_* tasks,
//! and the shared private helpers stay in `app/mod.rs`.

use super::*;

impl AppHandle {
    pub(crate) async fn process_network_event(&self, event: NetworkEvent) {
        match event {
            NetworkEvent::PeerDiscovered { peer_id } => {
                let _ = self.app_event_tx.send(AppEvent::PeerDiscovered { peer_id });
            }
            NetworkEvent::PeerExpired { peer_id } => {
                // Drop any tracked dial-connection entry for this peer so
                // the lobby's online/offline dots stay accurate. mDNS
                // expiry only gives us a PeerId (no fingerprint), so we
                // can't touch room membership here — that relies on the
                // explicit MemberLeave path and the discovered-room TTL.
                self.connected_dial_addrs
                    .lock()
                    .retain(|_addr, pid| *pid != peer_id);
                let _ = self.app_event_tx.send(AppEvent::PeerExpired { peer_id });
            }
            NetworkEvent::PeerDisconnected { peer_id } => {
                // huddle 0.7.11: relay / internet peers don't trigger
                // mDNS PeerExpired, so without this their entries in
                // connected_dial_addrs stayed forever and the lobby
                // showed them as "● online" indefinitely after they
                // dropped. Same cleanup shape as PeerExpired.
                self.connected_dial_addrs
                    .lock()
                    .retain(|_addr, pid| *pid != peer_id);
                let _ = self.app_event_tx.send(AppEvent::PeerExpired { peer_id });
            }
            // huddle 0.7.12: `RelayReservationLost` was removed —
            // libp2p 0.56's relay client doesn't surface a failure
            // variant we can listen on. Reservation loss currently
            // manifests as the next AutoNAT probe flipping to
            // "private" once the circuit drops; a future health-
            // check timer can re-introduce the dedicated signal.
            NetworkEvent::ListeningOn { address } => {
                let _ = self.app_event_tx.send(AppEvent::ListeningOn {
                    address: address.to_string(),
                });
            }
            NetworkEvent::RoomAnnouncementReceived(ann) => {
                // Cache the salt for join_room
                if let Some(salt) = &ann.passphrase_salt {
                    remember_room_salt(&ann.room_id, salt.clone());
                }
                // Phase D follow-up: opportunistically dial the
                // announcer's first host_addr if we're not already
                // connected. Skips self-announcements + rate-limits
                // by creator fingerprint so we don't dial-storm.
                let our_fp_for_dial = self.identity.fingerprint().to_string();
                if ann.creator_fingerprint != our_fp_for_dial && !ann.host_addrs.is_empty() {
                    let now = now_unix();
                    let should_dial = {
                        let mut attempts = self.host_addr_dial_attempts.lock();
                        // huddle 1.3.1: creator_fingerprint is unauthenticated, so
                        // drop entries past the backoff window (they no longer
                        // suppress a dial) and hard-cap inserts to bound a flood of
                        // distinct fingerprints from growing the map without limit.
                        attempts.retain(|_fp, last| now - *last < HOST_ADDR_DIAL_BACKOFF_SECS);
                        match attempts.get(&ann.creator_fingerprint).copied() {
                            Some(last) if now - last < HOST_ADDR_DIAL_BACKOFF_SECS => false,
                            _ => {
                                if attempts.len() < HOST_ADDR_DIAL_ATTEMPTS_CAP {
                                    attempts.insert(ann.creator_fingerprint.clone(), now);
                                    true
                                } else {
                                    // huddle 1.3.3: at cap we cannot record this
                                    // attempt, so dialing here would bypass the
                                    // per-fingerprint backoff entirely — every later
                                    // announce for an unrecordable fingerprint would
                                    // re-dial its (unauthenticated) host_addrs. An
                                    // attacker can keep the map saturated with bogus
                                    // creator_fingerprints, so refuse the dial rather
                                    // than amplify it into an outbound-connection
                                    // storm against an attacker-chosen address.
                                    // Legit saturation (4096 distinct live announcers
                                    // within the 300s backoff window) is implausible.
                                    false
                                }
                            }
                        }
                    };
                    if should_dial {
                        if let Some(first) = ann.host_addrs.first() {
                            info!(
                                announcer = %ann.creator_fingerprint,
                                addr = %first,
                                "opportunistic dial via room announcement host_addrs"
                            );
                            // huddle 0.7.7: NOT user-initiated — go
                            // through `dial_internal` so a passive
                            // announcement-driven dial doesn't pop a
                            // DM in the user's face.
                            if let Ok(multiaddr) = first.parse::<Multiaddr>() {
                                let canonical = multiaddr.to_string();
                                let _ = self.dial_internal(canonical, multiaddr).await;
                            }
                        }
                    }
                }
                // huddle 2.2 (M-C4): best-effort discovery-time capability hint.
                // RoomAnnouncement is unsigned, so `record_peer_capabilities`
                // only OR-s bits in (a relay can add, never clear) and the
                // authoritative caps still come from the signed MemberAnnounce;
                // keyed by creator_fingerprint since the creator overwhelmingly
                // announces their own room. A wrong guess only costs a code-join
                // retry, never a key leak.
                self.record_peer_capabilities(&ann.creator_fingerprint, ann.capabilities);
                let discovered = DiscoveredRoom {
                    room_id: ann.room_id.clone(),
                    name: ann.name.clone(),
                    encrypted: ann.encrypted,
                    member_count: ann.member_count,
                    creator_fingerprint: ann.creator_fingerprint.clone(),
                    last_seen: now_unix(),
                    restorable: false,
                    host_addrs: ann.host_addrs.clone(),
                    kind: ann.kind,
                    capabilities: ann.capabilities,
                };
                // If we're already in this room, cache the announcement so
                // others can still discover it through us, but don't emit
                // RoomDiscovered — it isn't "newly discovered" to us, and
                // emitting it spuriously re-opens the lobby join prompt.
                if self.active_rooms.lock().contains_key(&ann.room_id) {
                    self.discovered_rooms
                        .lock()
                        .insert(ann.room_id.clone(), discovered);
                    return;
                }
                // huddle 0.7 DM-visibility filter (consumer side): a
                // `Direct` announcement is only valid for the two members
                // implied by `canonical_dm_room_id`. If we're not one of
                // them, silently drop — DMs never appear in third
                // parties' discovery caches. A malicious 0.7+ peer can
                // ignore this, but they'd have to subscribe to the
                // canonical DM topic with full knowledge of both
                // fingerprints, which is a stronger threat than the v1
                // sidebar split is trying to mitigate.
                if ann.kind == RoomKind::Direct {
                    let our_fp_for_filter = self.identity.fingerprint().to_string();
                    if canonical_dm_room_id(&our_fp_for_filter, &ann.creator_fingerprint)
                        != ann.room_id
                    {
                        debug!(
                            announcer = %ann.creator_fingerprint,
                            room_id = %ann.room_id,
                            "dropping Direct announcement: not addressed to us"
                        );
                        return;
                    }
                    // Targeted at us. Cache the discovery so the sidebar
                    // can show "DM from <partner>" and auto-bootstrap a
                    // local active room so we can receive messages
                    // immediately without waiting for a user action.
                    //
                    // huddle 0.7.11: drop the auto-bootstrap if the
                    // partner is on the persistent blocklist. Without
                    // this gate, a blocked peer could re-introduce
                    // themselves into our sidebar simply by re-announcing
                    // the DM topic; we'd subscribe and persist a row for
                    // them before any user action.
                    if repo::is_peer_blocked(&self.db, &ann.creator_fingerprint).unwrap_or(false) {
                        debug!(
                            partner = %ann.creator_fingerprint,
                            "ignoring Direct announcement from blocked peer"
                        );
                        return;
                    }
                    self.discovered_rooms
                        .lock()
                        .insert(ann.room_id.clone(), discovered.clone());
                    let _ = self
                        .app_event_tx
                        .send(AppEvent::RoomDiscovered(discovered.clone()));
                    let app = self.clone();
                    let partner = ann.creator_fingerprint.clone();
                    let rid = ann.room_id.clone();
                    tokio::spawn(async move {
                        if let Err(e) = app.start_direct(&partner).await {
                            debug!(%e, room_id = %rid, "auto-bootstrap of inbound DM failed");
                        }
                    });
                    return;
                }
                {
                    let mut map = self.discovered_rooms.lock();
                    // huddle 2.0.3 (audit L-15 residual): cap the map so a flood
                    // of distinct group room_ids can't grow it without bound
                    // between TTL prunes; evict the stalest entry to make room.
                    if !map.contains_key(&ann.room_id) && map.len() >= MAX_DISCOVERED_ROOMS {
                        if let Some(stale) = map
                            .iter()
                            .min_by_key(|(_, r)| r.last_seen)
                            .map(|(k, _)| k.clone())
                        {
                            map.remove(&stale);
                        }
                    }
                    map.insert(ann.room_id.clone(), discovered.clone());
                }
                let _ = self.app_event_tx.send(AppEvent::RoomDiscovered(discovered));
            }
            NetworkEvent::RoomMessageReceived {
                room_id,
                payload,
                from_peer: _,
            } => {
                // v0.3.0+: every wire message is a `WireMessage` envelope.
                // `Plain` carries an unsigned `RoomMessage`; `Signed` is an
                // app-level Ed25519 envelope that we verify before
                // unwrapping. A failed verify is logged and dropped — we
                // never dispatch unverified-but-claiming-to-be-signed
                // messages.
                let wire: WireMessage = match serde_json::from_slice(&payload) {
                    Ok(w) => w,
                    Err(e) => {
                        warn!(%e, "bad wire envelope");
                        return;
                    }
                };
                let (msg, verified_signer, signed_at_ms) = match wire {
                    WireMessage::Plain(m) => (m, None, None),
                    WireMessage::Signed(env) => {
                        let claimed_pubkey = env.ed25519_pubkey_b64.clone();
                        // huddle 2.0.2 (audit M-6): the signature binds this
                        // timestamp, so it's a clock the relay can't forge.
                        let signed_at = env.signed_at_ms;
                        match crate::crypto::verify_signed(&env) {
                            Ok((m, fp)) => {
                                // Defense in depth: if we've persisted
                                // a pubkey for this fingerprint in this
                                // room before, the envelope's pubkey
                                // MUST match it. A different pubkey for
                                // the same fingerprint means identity
                                // drift — TOFU violation — drop.
                                match repo::get_member_ed25519_pubkey(&self.db, &room_id, &fp) {
                                    Ok(Some(known)) if known != claimed_pubkey => {
                                        // huddle 2.0.0 (F3): surface the drift
                                        // instead of silently dropping. The
                                        // offending message is STILL dropped (we
                                        // never trust the new key implicitly); the
                                        // UI prompts the user to re-verify (SAS),
                                        // accept the new key, or block the peer.
                                        warn!(
                                            %fp, %room_id,
                                            "pubkey mismatch vs stored; emitting SafetyNumberChanged and dropping signed message"
                                        );
                                        let display_name =
                                            repo::lookup_display_name(&self.db, &fp).ok().flatten();
                                        self.journal_event(
                                            "safety_number_changed",
                                            &format!("room={room_id} peer={fp}"),
                                        );
                                        let _ =
                                            self.app_event_tx.send(AppEvent::SafetyNumberChanged {
                                                room_id: room_id.clone(),
                                                fingerprint: fp.clone(),
                                                old_pubkey_b64: known,
                                                new_pubkey_b64: claimed_pubkey.clone(),
                                                display_name,
                                            });
                                        return;
                                    }
                                    _ => {}
                                }
                                (m, Some(fp), Some(signed_at))
                            }
                            Err(e) => {
                                warn!(%e, fp = %env.fingerprint, "signed envelope verify failed");
                                return;
                            }
                        }
                    }
                };
                self.handle_room_message(&room_id, msg, verified_signer, signed_at_ms)
                    .await;
            }
            NetworkEvent::DialSucceeded { peer_id, address } => {
                let addr_s = address.to_string();
                self.connected_dial_addrs
                    .lock()
                    .insert(addr_s.clone(), peer_id);
                // Fingerprint isn't known yet (Identify hasn't landed);
                // the PeerIdentified handler below upserts again to add
                // the fingerprint and flip trusted=true once it does.
                let _ = repo::upsert_known_peer(
                    &self.db,
                    &KnownPeer {
                        address: addr_s.clone(),
                        label: None,
                        last_connected_at: Some(now_unix()),
                        last_attempt_at: Some(now_unix()),
                        created_at: now_unix(),
                        fingerprint: None,
                        trusted: false,
                    },
                );
                let _ = self.app_event_tx.send(AppEvent::DialSucceeded {
                    address: addr_s,
                    peer_id,
                });
            }
            NetworkEvent::DialFailed { address, error } => {
                let addr_s = address.to_string();
                let _ = self.app_event_tx.send(AppEvent::DialFailed {
                    address: addr_s,
                    error,
                });
            }
            NetworkEvent::PeerIdentified {
                peer_id,
                fingerprint,
            } => {
                // For any address we user-dialed for this peer, retroactively
                // backfill the fingerprint and flip trusted=true. The
                // upsert's COALESCE preserves fingerprint once set and
                // its trusted-is-sticky-once-true clause means we don't
                // accidentally demote a row that was already trusted.
                let matched_addrs: Vec<String> = {
                    let map = self.connected_dial_addrs.lock();
                    map.iter()
                        .filter_map(|(addr, pid)| {
                            if *pid == peer_id {
                                Some(addr.clone())
                            } else {
                                None
                            }
                        })
                        .collect()
                };
                // Phase C follow-up: if any of these addresses came
                // from an invite, verify the invite's claimed fp
                // against what we just derived from the pubkey. A
                // mismatch means the invite's fp label disagrees with
                // libp2p's /p2p/<peer-id> cryptographic anchor —
                // structurally impossible when both fields are
                // generated from the same identity, but the explicit
                // assert defends against future invite-format
                // changes or hand-edited links.
                let mismatch = {
                    let mut map = self.pending_invite_dials.lock();
                    let mut found: Option<(String, String)> = None;
                    for addr in &matched_addrs {
                        if let Some(claimed) = map.remove(addr) {
                            if claimed != fingerprint {
                                found = Some((addr.clone(), claimed));
                                break;
                            }
                        }
                    }
                    found
                };
                if let Some((addr, claimed)) = mismatch {
                    warn!(
                        %addr, %claimed, actual=%fingerprint,
                        "invite fingerprint mismatch — disconnecting"
                    );
                    self.network.disconnect_peer(peer_id).await;
                    let _ = self.app_event_tx.send(AppEvent::InviteFingerprintMismatch {
                        address: addr,
                        claimed,
                        actual: fingerprint.clone(),
                    });
                    return;
                }
                // huddle 0.7.7: did the local user initiate any of these
                // dials? If so, consume the matching entries from
                // `pending_auto_dm_addrs` now so we don't auto-DM
                // again on a subsequent reconnect. The actual DM
                // start happens after the trust upsert below so the
                // peer is already marked trusted by the time we fire.
                let should_auto_dm = {
                    let mut pending = self.pending_auto_dm_addrs.lock();
                    let mut any_matched = false;
                    for addr in &matched_addrs {
                        if pending.remove(addr) {
                            any_matched = true;
                        }
                    }
                    any_matched
                };
                for addr in matched_addrs {
                    let _ = repo::upsert_known_peer(
                        &self.db,
                        &KnownPeer {
                            address: addr,
                            label: None,
                            last_connected_at: Some(now_unix()),
                            last_attempt_at: Some(now_unix()),
                            created_at: now_unix(),
                            fingerprint: Some(fingerprint.clone()),
                            trusted: true,
                        },
                    );
                }
                // huddle 0.7.7: open (or reuse) a DM with the freshly
                // identified peer and tell the TUI to switch panes.
                // `start_direct` is idempotent on `canonical_dm_room_id`,
                // so this is safe to call even if a DM already exists.
                //
                // huddle 0.7.11: explicitly gate on the persistent
                // blocklist here. The original comment claimed blocked
                // peers "fall through naturally" but that was only true
                // for *inbound* dials — the block check at line ~2237
                // is inbound-only. Outbound user-dials hit Identify and
                // landed here without ever consulting the blocklist,
                // bypassing the user's explicit block.
                let blocked = repo::is_peer_blocked(&self.db, &fingerprint).unwrap_or(false);
                if should_auto_dm && !blocked && fingerprint != self.identity.fingerprint() {
                    match self.start_direct(&fingerprint).await {
                        Ok(room_id) => {
                            let _ = self.app_event_tx.send(AppEvent::AutoOpenDm {
                                room_id,
                                fingerprint: fingerprint.clone(),
                            });
                        }
                        Err(e) => {
                            debug!(%e, fp = %fingerprint, "auto-DM after dial failed");
                        }
                    }
                }
                // huddle 0.5: tell the newly-identified peer our current
                // username via a signed ProfileUpdate, but only if we
                // have one set locally and we haven't already pushed
                // ours to this peer in the last
                // `PROFILE_REBROADCAST_FLOOR_MS`. Without the floor a
                // flapping transport (relay reconnect storms) would
                // republish on every identify event.
                let our_username = repo::get_display_name(&self.db).unwrap_or(None);
                if our_username.is_some() {
                    let now_ms = now_unix_ms();
                    let should_send = {
                        let mut last = self.last_profile_broadcast_at_ms.lock();
                        // huddle 1.3.4: evict entries older than the rebroadcast
                        // floor so this map can't grow without bound as distinct
                        // peer fingerprints churn through (e.g. an attacker
                        // cycling Ed25519 identities). Anything older than the
                        // floor would re-broadcast anyway, so dropping it is free.
                        last.retain(|_fp, t| now_ms - *t < PROFILE_REBROADCAST_FLOOR_MS);
                        match last.get(&fingerprint) {
                            Some(prev) if now_ms - prev < PROFILE_REBROADCAST_FLOOR_MS => false,
                            _ => {
                                last.insert(fingerprint.clone(), now_ms);
                                true
                            }
                        }
                    };
                    if should_send {
                        let msg = RoomMessage::ProfileUpdate {
                            sender_fingerprint: self.identity.fingerprint().to_string(),
                            username: our_username,
                            updated_at: now_ms,
                        };
                        if let Ok(env) = crate::crypto::sign_message(&self.identity, &msg) {
                            if let Ok(bytes) = crate::network::protocol::encode_wire_signed(&env) {
                                let rooms: Vec<String> =
                                    self.active_rooms.lock().keys().cloned().collect();
                                for room_id in rooms {
                                    self.network
                                        .publish_room_message(room_id, bytes.clone())
                                        .await;
                                }
                            }
                        }
                    }
                }
            }
            NetworkEvent::RelayReservationEstablished { address } => {
                // Treat the circuit address like any other listen
                // address — the TUI's ListeningOn handler dedups + adds
                // it to the addresses pane. Also emit a status hint via
                // ListeningOn so the lobby's reachability line updates.
                info!(addr = %address, "relay reservation established");
                self.relay_circuit_addrs.lock().insert(address.to_string());
                let _ = self.app_event_tx.send(AppEvent::ListeningOn {
                    address: address.to_string(),
                });
            }
            NetworkEvent::NatProbeResult {
                tested_addr,
                reachable,
            } => {
                let addr_s = tested_addr.to_string();
                let (transitioned, becomes_reachable) = {
                    let mut set = self.nat_reachable_addrs.lock();
                    let was_empty = set.is_empty();
                    if reachable {
                        set.insert(addr_s.clone());
                    } else {
                        set.remove(&addr_s);
                    }
                    let is_empty = set.is_empty();
                    (was_empty != is_empty, !is_empty)
                };
                if transitioned {
                    let label = if becomes_reachable {
                        "reachable".to_string()
                    } else {
                        "private".to_string()
                    };
                    info!(reachable = %becomes_reachable, "NAT reachability changed");
                    let _ = self.app_event_tx.send(AppEvent::NatStatusChanged {
                        label,
                        reachable: becomes_reachable,
                    });
                }
            }
            NetworkEvent::DcutrUpgrade {
                remote_peer,
                success,
            } => {
                if success {
                    // Render the peer as the last 8 chars of the
                    // PeerId for compactness — full peer id is too long
                    // for a status line.
                    let s = remote_peer.to_base58();
                    let tail: String = s
                        .chars()
                        .rev()
                        .take(8)
                        .collect::<String>()
                        .chars()
                        .rev()
                        .collect();
                    let _ = self
                        .app_event_tx
                        .send(AppEvent::DcutrSucceeded { peer_label: tail });
                }
            }
            NetworkEvent::InboundDial {
                peer_id,
                fingerprint,
                address,
            } => {
                // First: cheap server-side filters before bothering the user.
                if repo::is_peer_blocked(&self.db, &fingerprint).unwrap_or(false) {
                    info!(%fingerprint, "inbound dial auto-rejected: peer is blocked");
                    self.network.reject_inbound(peer_id).await;
                    return;
                }
                // Phase E: global verified-only inbound mode. If on,
                // reject any unverified fingerprint without prompting.
                // SAS-verified (Phase G) and already-trusted (Phase A)
                // peers still come through.
                let global_verified_only = repo::get_setting(&self.db, "verified_only_inbound")
                    .ok()
                    .flatten()
                    .map(|v| v == "1")
                    .unwrap_or(false);
                if global_verified_only {
                    let is_verified = repo::is_globally_verified(&self.db, &fingerprint)
                        .unwrap_or(false)
                        || repo::is_fingerprint_trusted(&self.db, &fingerprint).unwrap_or(false);
                    if !is_verified {
                        info!(
                            %fingerprint,
                            "inbound dial auto-rejected: verified-only mode"
                        );
                        self.network.reject_inbound(peer_id).await;
                        return;
                    }
                }
                if repo::is_fingerprint_trusted(&self.db, &fingerprint).unwrap_or(false) {
                    info!(%fingerprint, "inbound dial auto-accepted: peer is trusted");
                    // Persist the address → peer_id mapping just as a
                    // user-dial would, so the lobby's online dot lights up.
                    self.connected_dial_addrs
                        .lock()
                        .insert(address.to_string(), peer_id);
                    let _ = repo::upsert_known_peer(
                        &self.db,
                        &KnownPeer {
                            address: address.to_string(),
                            label: None,
                            last_connected_at: Some(now_unix()),
                            last_attempt_at: Some(now_unix()),
                            created_at: now_unix(),
                            fingerprint: Some(fingerprint),
                            trusted: true,
                        },
                    );
                    self.network.accept_inbound(peer_id).await;
                    return;
                }
                // Unknown peer — surface the modal in the TUI.
                self.journal_event(
                    "inbound_dial",
                    &format!("peer={peer_id} fp={fingerprint:?} addr={address}"),
                );
                let _ = self.app_event_tx.send(AppEvent::InboundDial {
                    peer_id,
                    fingerprint,
                    address: address.to_string(),
                });
            }
        }
    }

    /// `verified_signer` is `Some(fp)` if this message arrived inside a
    /// successfully-verified `WireMessage::Signed` envelope — in which
    /// case the inner sender_fingerprint *must* match. `None` for
    /// `WireMessage::Plain`. Phase B's `OwnerGrant`/`BanMember` arms
    /// require it to be `Some` AND the signer to be a current owner.
    ///
    /// INVARIANT (huddle 1.1.4): never hold a `Mutex` guard (`active_rooms`,
    /// `sas_flows`, the DB) across an `.await`. Always scope the guard in its
    /// own block or `drop()` it before awaiting — see the DM-key path below.
    /// This is also enforced mechanically: this fn runs inside a `Send` task, so
    /// a `!Send` `MutexGuard` held across `.await` would fail to compile.
    /// (huddle 2.1.3: these are `parking_lot::Mutex` — non-poisoning, but the
    /// guard is still `!Send`, so the across-await rule is unchanged.)
    /// huddle 2.0.2 (audit M-2): can we currently decrypt an `Encrypted` body
    /// tagged with `session_id` from `sender`? Returns false when the room,
    /// its crypto, or the inbound session isn't present yet.
    fn can_decrypt(&self, room_id: &str, sender: &str, session_id: &str) -> bool {
        self.active_rooms
            .lock()
            .get(room_id)
            .and_then(|r| r.crypto.as_ref())
            .map(|c| c.has_inbound_session(sender, session_id))
            .unwrap_or(false)
    }

    /// huddle 2.0.3 (audit N-M3): whether a mailbox-delivered signed affordance
    /// (`Edit`/`Delete`/`Reaction`) can be durably applied right now — i.e. its
    /// target message is already present. The handlers drop an affordance whose
    /// target hasn't arrived yet; if we ACK such a drop, a relay that reorders
    /// the mailbox (affordance before its target) permanently suppresses the
    /// edit/deletion/retraction. Non-affordances (and envelopes that don't
    /// verify) return `true` so the normal ACK proceeds.
    fn relay_affordance_resolved(
        &self,
        room_id: &str,
        env: &crate::network::protocol::SignedRoomMessage,
    ) -> bool {
        let Ok((msg, _signer)) = crate::crypto::verify_signed(env) else {
            return true;
        };
        let target = match &msg {
            RoomMessage::Edit { target_msg_id, .. }
            | RoomMessage::Delete { target_msg_id, .. }
            | RoomMessage::Reaction { target_msg_id, .. } => target_msg_id,
            _ => return true,
        };
        matches!(
            repo::find_message_by_client_id(&self.db, room_id, target),
            Ok(Some(_))
        )
    }

    /// huddle 2.0.2 (audit M-2): process a mailbox-delivered relay message and
    /// report whether the caller may ACK it (let the relay delete its copy). An
    /// `Encrypted` body we can't decrypt yet (its Megolm session key hasn't
    /// arrived) is still dispatched — which triggers a `SessionKeyRequest` heal —
    /// but is NOT ACKed, so the relay keeps the only copy for redelivery instead
    /// of dropping it. The relay's 24h sweep remains the backstop.
    pub(crate) async fn process_relay_message(&self, room_id: String, payload: Vec<u8>) -> bool {
        let ack_ok = match serde_json::from_slice::<WireMessage>(&payload) {
            Ok(WireMessage::Plain(RoomMessage::Encrypted {
                ref sender_fingerprint,
                ref session_id,
                ..
            })) => self.can_decrypt(&room_id, sender_fingerprint, session_id),
            // huddle 2.0.3 (audit N-M3): don't ACK a signed Edit/Delete/Reaction
            // whose target hasn't arrived — leave it for the relay to redeliver.
            Ok(WireMessage::Signed(ref env)) => self.relay_affordance_resolved(&room_id, env),
            _ => true,
        };
        self.process_network_event(NetworkEvent::RoomMessageReceived {
            room_id,
            payload,
            from_peer: PeerId::random(),
        })
        .await;
        ack_ok
    }

    async fn handle_room_message(
        &self,
        room_id: &str,
        msg: RoomMessage,
        verified_signer: Option<String>,
        // huddle 2.0.2 (audit M-6): the signature-bound send time (Some for a
        // verified Signed envelope), used as the authenticated last-write-wins
        // clock for edits so a relay can't revert content by reordering.
        signed_at_ms: Option<i64>,
    ) {
        let our_fp = self.identity.fingerprint().to_string();
        // huddle 1.2: lazily re-activate a known DM that isn't currently in
        // active_rooms before dispatching. Otherwise the first inbound message
        // or MemberAnnounce (which carries the session key!) for a DM that was
        // parked as `restorable` (partner pubkey unknown at restore) or simply
        // closed this session is silently dropped by the per-arm
        // `active_rooms.get(room_id) -> None => return` guards — and the DM
        // appears dead. Only DM rooms that ALREADY exist on disk with a known
        // partner are auto-activated here; group rooms (which need a
        // passphrase) and unknown rooms are left untouched.
        {
            let known_inactive = !self.active_rooms.lock().contains_key(room_id);
            if known_inactive {
                if let Ok(Some(info)) = repo::get_room(&self.db, room_id) {
                    if info.kind == RoomKind::Direct {
                        let partner = repo::list_room_members(&self.db, room_id)
                            .ok()
                            .into_iter()
                            .flatten()
                            .map(|m| m.fingerprint)
                            .find(|fp| *fp != our_fp);
                        if let Some(partner_fp) = partner {
                            if let Err(e) = self.bootstrap_direct_room(room_id, &partner_fp).await {
                                debug!(%e, %room_id, "lazy DM re-activation on inbound failed");
                            }
                        }
                    }
                }
            }
        }
        match msg {
            RoomMessage::MemberAnnounce {
                sender_fingerprint,
                wrapped_session_key,
                display_name,
                sender_ed25519_pubkey,
                sender_mlkem_pubkey,
                mlkem_ciphertext,
                capabilities,
            } => {
                if sender_fingerprint == our_fp {
                    return;
                }
                // huddle 0.7.11: MemberAnnounce must arrive inside a
                // signed envelope, and the signer's fingerprint must
                // match the claimed announcer. Closes the TOFU-pubkey
                // hijack: pre-0.7.11 a malicious peer could race a
                // victim's first announce on a room and pin a fabricated
                // ed25519 pubkey under the victim's fingerprint, so honest
                // peers would later reject the real victim's signed
                // messages. The hijack is closed by the `signer ==
                // sender_fingerprint` check below: a peer can only write its
                // OWN room_members row. The inner `sender_ed25519_pubkey` is
                // still persisted as the TOFU pin (below) and used for DM key
                // derivation; for honest peers it equals the envelope pubkey,
                // and a peer that sets inner != envelope only poisons its own
                // pin and is then locked out by the TOFU check on its future
                // signed messages.
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!(%sender_fingerprint, %room_id, "MemberAnnounce arrived unsigned; dropping");
                        return;
                    }
                };
                if signer != sender_fingerprint {
                    warn!(%signer, %sender_fingerprint, %room_id, "MemberAnnounce signer mismatch; dropping");
                    return;
                }
                // huddle 2.2 (M-C4): record the announcer's advertised caps now
                // that the signature + signer==sender checks have authenticated
                // them. Used to gate the PA-1 proof and FILES-2 private metadata.
                self.record_peer_capabilities(&sender_fingerprint, capabilities);
                // Drop announcements from banned fingerprints — they
                // can't rejoin until an owner unbans them (Phase B).
                if repo::is_member_banned(&self.db, room_id, &sender_fingerprint).unwrap_or(false) {
                    info!(%sender_fingerprint, %room_id, "dropping MemberAnnounce from banned peer");
                    return;
                }
                // Phase E per-room enforcement: if this room is
                // verified-only and the joiner isn't globally SAS-
                // verified, refuse to add them. The lowest-fp owner
                // (deterministic across honest peers) also sends a
                // signed `JoinRefused` so the joiner gets an explicit
                // message instead of a silent hang.
                if repo::get_room_verified_only(&self.db, room_id).unwrap_or(false)
                    && !repo::is_globally_verified(&self.db, &sender_fingerprint).unwrap_or(false)
                {
                    info!(
                        %sender_fingerprint, %room_id,
                        "dropping MemberAnnounce: room is verified-only and joiner isn't verified"
                    );
                    let owners = repo::list_room_owners(&self.db, room_id).unwrap_or_default();
                    let lowest_owner = owners.iter().min().cloned();
                    if lowest_owner.as_deref() == Some(&our_fp) {
                        let msg = RoomMessage::JoinRefused {
                            room_id: room_id.to_string(),
                            target_fingerprint: sender_fingerprint.clone(),
                            reason: "room requires SAS verification — ask an existing member to verify you".into(),
                        };
                        if let Ok(env) = crate::crypto::sign_message(&self.identity, &msg) {
                            if let Ok(bytes) = crate::network::protocol::encode_wire_signed(&env) {
                                self.network
                                    .publish_room_message(room_id.to_string(), bytes)
                                    .await;
                            }
                        }
                    }
                    return;
                }
                let need_inbound = {
                    let mut rooms = self.active_rooms.lock();
                    let room = match rooms.get_mut(room_id) {
                        Some(r) => r,
                        None => return,
                    };
                    // huddle 0.7: Direct rooms are 1-1 forever. If a
                    // third fingerprint announces, drop it locally and
                    // skip the persist/wrap-session path. This is honest-
                    // client enforcement — a malicious peer with the
                    // canonical DM passphrase-equivalent could still
                    // chat, but they'd never be visible in our sidebar
                    // or render in the DM pane.
                    if room.info.kind == RoomKind::Direct
                        && !room.members.contains(&sender_fingerprint)
                        && room.members.len() >= 2
                    {
                        info!(
                            %sender_fingerprint, %room_id,
                            "dropping MemberAnnounce on Direct room: already at 2-member cap"
                        );
                        return;
                    }
                    let newly_added = room.members.insert(sender_fingerprint.clone());
                    if newly_added {
                        let _ = self.app_event_tx.send(AppEvent::MemberJoined {
                            room_id: room_id.to_string(),
                            fingerprint: sender_fingerprint.clone(),
                        });
                    }
                    // Persist member with optional display name + pubkey.
                    // `ed25519_pubkey` is `None` for pre-0.3 peers; the
                    // upsert COALESCEs so once we learn it we never lose
                    // it on a later announce that drops the field.
                    let _ = repo::upsert_room_member(
                        &self.db,
                        &StoredRoomMember {
                            room_id: room_id.to_string(),
                            peer_id: String::new(), // unknown at this layer
                            fingerprint: sender_fingerprint.clone(),
                            last_seen: Some(now_unix()),
                            verified: false,
                            ed25519_pubkey: sender_ed25519_pubkey.clone(),
                            // Role is set on first insert only — the
                            // upsert ON CONFLICT clause preserves an
                            // existing 'owner' on re-announce. A genuine
                            // new fingerprint is a 'member' until an
                            // OwnerGrant lands.
                            role: "member".into(),
                            // huddle 1.3.1: persist the partner's ML-KEM key
                            // (Direct announces only) as the durable
                            // post-quantum-capability pin. COALESCE-preserved,
                            // so a later announce that omits it can't erase the
                            // pin and a relay can't replay an old classical
                            // announce to downgrade us. `None` for groups.
                            mlkem_pubkey: sender_mlkem_pubkey.clone(),
                        },
                    );
                    if let Some(name) = display_name.as_deref() {
                        let _ = repo::set_member_display_name(
                            &self.db,
                            room_id,
                            &sender_fingerprint,
                            Some(name),
                        );
                    }
                    room.info.encrypted && wrapped_session_key.is_some()
                };

                // huddle 1.3 / 1.3.1: for Direct rooms, (re)derive the DM wrap
                // key now — hybrid (X25519 + ML-KEM-768) when the partner is
                // post-quantum capable (announce or persisted pin), else
                // classical X25519. The partner's pubkey(s) and — when we are
                // the responder — the KEM ciphertext arrive in *this*
                // MemberAnnounce, so we compute the key before the unwrap path
                // runs. `ensure_dm_key` is idempotent, pins PQ capability, and
                // performs the one-way classical→hybrid upgrade.
                let is_direct_room = matches!(
                    self.active_rooms.lock().get(room_id).map(|r| r.info.kind),
                    Some(RoomKind::Direct)
                );
                if is_direct_room {
                    match self.ensure_dm_key(
                        room_id,
                        &sender_fingerprint,
                        sender_ed25519_pubkey.as_deref(),
                        sender_mlkem_pubkey.as_deref(),
                        mlkem_ciphertext.as_deref(),
                    ) {
                        DmKeyOutcome::ReBroadcast => {
                            // We just established (or upgraded) the DM wrap key —
                            // re-broadcast our MemberAnnounce so the partner gets
                            // our wrapped session key (and, if we are the
                            // initiator, the KEM ciphertext). Fire-and-forget.
                            let app = self.clone();
                            let rid = room_id.to_string();
                            tokio::spawn(async move {
                                if let Err(e) = app.broadcast_member_announce(&rid).await {
                                    warn!(%e, "re-broadcast DM announce after key derivation");
                                }
                            });
                        }
                        DmKeyOutcome::RequestCiphertext => {
                            // We are the responder and lack the KEM ciphertext —
                            // ask the initiator to re-announce it (its
                            // SessionKeyRequest handler re-broadcasts a full
                            // MemberAnnounce carrying the ciphertext). huddle 1.3.1:
                            // debounce per room (shared `key_request_cooldown`, like
                            // the decrypt-miss heal) so a stalled handshake's
                            // ciphertext-less re-announces can't drive an
                            // un-throttled request↔announce ping-pong; the bounded
                            // ticker nudge still guarantees convergence.
                            let now = now_unix();
                            let due = {
                                let mut cd = self.key_request_cooldown.lock();
                                // huddle 1.3.4: evict entries older than the
                                // cooldown so this map stays bounded as room ids
                                // churn; anything older than the window is "due"
                                // anyway, so dropping it changes no behavior.
                                cd.retain(|_room, t| now - *t < KEY_REQUEST_COOLDOWN_SECS);
                                let last = cd.get(room_id).copied().unwrap_or(0);
                                if now - last >= KEY_REQUEST_COOLDOWN_SECS {
                                    cd.insert(room_id.to_string(), now);
                                    true
                                } else {
                                    false
                                }
                            };
                            if due {
                                let app = self.clone();
                                let rid = room_id.to_string();
                                let our = our_fp.clone();
                                tokio::spawn(async move {
                                    let req = RoomMessage::SessionKeyRequest {
                                        requester_fingerprint: our,
                                    };
                                    if let Ok(bytes) = encode_wire(&req) {
                                        app.network.publish_room_message(rid, bytes).await;
                                    }
                                });
                            }
                        }
                        DmKeyOutcome::Noop => {}
                    }
                }

                if need_inbound {
                    let wrapped = wrapped_session_key.unwrap();
                    let result = {
                        let mut rooms = self.active_rooms.lock();
                        // huddle 1.3.1: the active_rooms lock was released after
                        // `need_inbound` was computed, so the room may have been
                        // concurrently removed (e.g. a UI-thread `leave_room`)
                        // before we re-acquire here. Guard like every sibling arm
                        // instead of `.unwrap()` so a concurrent leave can't panic
                        // (and permanently halt) the inbound message pipeline.
                        let room = match rooms.get_mut(room_id) {
                            Some(r) => r,
                            None => return,
                        };
                        let passphrase_key = match &room.passphrase_key {
                            Some(k) => k,
                            None => {
                                warn!("no passphrase key when receiving session key");
                                return;
                            }
                        };
                        match passphrase::unwrap(&wrapped, passphrase_key) {
                            Ok(plain) => match String::from_utf8(plain) {
                                Ok(key_b64) => {
                                    let crypto = room.crypto.as_mut().unwrap();
                                    crypto.add_inbound_session(&sender_fingerprint, &key_b64)
                                }
                                Err(e) => Err(HuddleError::Session(format!("utf8: {e}"))),
                            },
                            // huddle 2.0.4 (WS1.1): passphrase::unwrap now yields
                            // a ProtocolError; coerce to HuddleError for this arm.
                            Err(e) => Err(e.into()),
                        }
                    };
                    if let Err(e) = result {
                        error!(%e, "add inbound session failed");
                    }
                }
            }
            RoomMessage::SessionKeyRequest {
                requester_fingerprint,
            } => {
                if requester_fingerprint == our_fp {
                    return;
                }
                // huddle 2.0.2 (audit M-4): rate-limit our re-announce so an
                // unsigned SessionKeyRequest storm can't make us (and every other
                // member) flood the room with full MemberAnnounces. At most one
                // response per room per ANNOUNCE_ON_REQUEST_COOLDOWN_SECS; a genuine
                // joiner is still served on the next tick / their own re-announce.
                {
                    let now = now_unix();
                    let mut cd = self.announce_on_request_cooldown.lock();
                    if now - cd.get(room_id).copied().unwrap_or(0)
                        < ANNOUNCE_ON_REQUEST_COOLDOWN_SECS
                    {
                        return;
                    }
                    cd.insert(room_id.to_string(), now);
                }
                // Re-announce ourselves to share our session key with the new joiner.
                if let Err(e) = self.broadcast_member_announce(room_id).await {
                    warn!(%e, "broadcast member announce on request");
                }
            }
            RoomMessage::Encrypted {
                sender_fingerprint,
                session_id,
                ciphertext_b64,
                client_msg_id,
                reply_to,
            } => {
                if sender_fingerprint == our_fp {
                    return;
                }
                // huddle 0.7.11: ban filter on every content-bearing arm.
                // Pre-0.7.11 only MemberAnnounce was filtered, so banned
                // peers could still post Encrypted/Plain after a kick
                // (cosmetically in encrypted rooms post-rotation since
                // they have no inbound session, but in unencrypted rooms
                // their plaintext rendered freely — see RoomMessage::Plain
                // arm below).
                if repo::is_member_banned(&self.db, room_id, &sender_fingerprint).unwrap_or(false) {
                    debug!(%sender_fingerprint, %room_id, "dropping Encrypted from banned peer");
                    return;
                }
                let ct_bytes = match base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &ciphertext_b64,
                ) {
                    Ok(b) => b,
                    Err(e) => {
                        warn!(%e, "bad base64 ciphertext");
                        return;
                    }
                };
                let plaintext = {
                    let mut rooms = self.active_rooms.lock();
                    let room = match rooms.get_mut(room_id) {
                        Some(r) => r,
                        None => return,
                    };
                    let crypto = match room.crypto.as_mut() {
                        Some(c) => c,
                        None => return,
                    };
                    crypto.decrypt(&sender_fingerprint, &session_id, &ct_bytes)
                };
                match plaintext {
                    Ok((pt, message_index)) => {
                        // huddle 2.0.0 (F2): content-layer replay protection.
                        // The Megolm message_index uniquely names this ciphertext
                        // within (room, sender, session), so a durable seen-set
                        // lets us silently drop a wire-level replay of an
                        // already-processed content message — even across
                        // restarts or a cross-transport re-broadcast. ONLY
                        // content is deduped; control arms above/below skip this
                        // so legitimate recurring re-announces keep working.
                        match repo::check_content_replay_seen(
                            &self.db,
                            room_id,
                            &sender_fingerprint,
                            &session_id,
                            message_index,
                        ) {
                            Ok(true) => {
                                debug!(
                                    %sender_fingerprint, %room_id, %session_id, message_index,
                                    "dropping replayed Encrypted content"
                                );
                                return;
                            }
                            Ok(false) => {}
                            Err(e) => {
                                // Fail OPEN on a seen-set query error: a rare
                                // duplicate is preferable to silently dropping a
                                // genuine message because the DB hiccuped.
                                warn!(%e, "content replay check failed; processing message");
                            }
                        }
                        let body = String::from_utf8_lossy(&pt).to_string();
                        let sent_at = now_unix();
                        // Record BEFORE the insert so the seen-set is authoritative
                        // even if a later step fails; INSERT OR IGNORE on the
                        // composite PK keeps this idempotent under any race.
                        if let Err(e) = repo::record_content_seen(
                            &self.db,
                            room_id,
                            &sender_fingerprint,
                            &session_id,
                            message_index,
                            sent_at,
                        ) {
                            // A genuine DB error here (a constraint hit is INSERT OR
                            // IGNORE's silent no-op and returns Ok, not Err) means this
                            // index isn't durably marked seen, so a later resend could
                            // pass check_content_replay_seen again. We deliberately do
                            // NOT drop the message — fail-open, matching the seen-set
                            // *check* above — because the partial UNIQUE index on
                            // room_messages now makes the duplicate insert an idempotent
                            // no-op, so the worst case is a redundant AppEvent, not a
                            // duplicate row. Surface it instead of swallowing with let _.
                            warn!(
                                %e, %room_id, %sender_fingerprint, %session_id, message_index,
                                "F2: failed to record content-replay seen-set entry; \
                                 relying on room_messages dedup to stay idempotent"
                            );
                        }
                        let _ = repo::insert_room_message(
                            &self.db,
                            room_id,
                            &sender_fingerprint,
                            "in",
                            &body,
                            sent_at,
                            client_msg_id.as_deref(),
                            reply_to.as_deref(),
                        );
                        let _ = repo::update_room_last_active(&self.db, room_id, sent_at);
                        self.maybe_emit_mention(room_id, &body);
                        let _ = self.app_event_tx.send(AppEvent::MessageReceived {
                            room_id: room_id.to_string(),
                            sender_fingerprint,
                            body,
                            sent_at,
                        });
                    }
                    Err(e) => {
                        debug!(%e, "decrypt failed (probably missing session key)");
                        // huddle 1.3.1: a *missing inbound session* (as opposed to a
                        // genuine decryption error) means the sender is encrypting
                        // under a session key we never received — a late join, a key
                        // rotation, or (new in 1.3.1) a classical→hybrid upgrade that
                        // rotated the sender's outbound session and whose single
                        // re-announce was lost. Ask for keys: the `SessionKeyRequest`
                        // makes peers re-broadcast their `MemberAnnounce`, which
                        // re-delivers the current session key. Debounced per room so a
                        // burst of undecryptable messages sends at most one request,
                        // and self-terminating (decrypts succeed once the key lands).
                        if e.to_string()
                            .contains(crate::crypto::megolm::MISSING_INBOUND_SESSION_ERR)
                        {
                            let now = now_unix();
                            let due = {
                                let mut cd = self.key_request_cooldown.lock();
                                // huddle 1.3.4: evict entries older than the
                                // cooldown so this map stays bounded as room ids
                                // churn; anything older than the window is "due"
                                // anyway, so dropping it changes no behavior.
                                cd.retain(|_room, t| now - *t < KEY_REQUEST_COOLDOWN_SECS);
                                let last = cd.get(room_id).copied().unwrap_or(0);
                                if now - last >= KEY_REQUEST_COOLDOWN_SECS {
                                    cd.insert(room_id.to_string(), now);
                                    true
                                } else {
                                    false
                                }
                            };
                            if due {
                                let app = self.clone();
                                let rid = room_id.to_string();
                                let our = our_fp.clone();
                                tokio::spawn(async move {
                                    let req = RoomMessage::SessionKeyRequest {
                                        requester_fingerprint: our,
                                    };
                                    if let Ok(bytes) = encode_wire(&req) {
                                        app.network.publish_room_message(rid, bytes).await;
                                    }
                                });
                            }
                        }
                    }
                }
            }
            RoomMessage::Plain {
                sender_fingerprint,
                body,
                client_msg_id,
                reply_to,
            } => {
                if sender_fingerprint == our_fp {
                    return;
                }
                // huddle 2.0.2 (audit H-1): an encrypted room must only ever
                // carry `Encrypted` (Megolm-authenticated) content. A `Plain`
                // message here is unauthenticated — its `sender_fingerprint` is
                // attacker-controlled — so any node that learns the (discoverable)
                // room id could otherwise inject a forged message attributed to a
                // trusted member, rendered indistinguishably from real traffic.
                // Drop unsigned plaintext in encrypted rooms.
                if repo::get_room(&self.db, room_id)
                    .ok()
                    .flatten()
                    .map(|r| r.encrypted)
                    .unwrap_or(false)
                {
                    warn!(%sender_fingerprint, %room_id, "dropping unsigned Plain in an encrypted room (anti-spoof)");
                    return;
                }
                if repo::is_member_banned(&self.db, room_id, &sender_fingerprint).unwrap_or(false) {
                    debug!(%sender_fingerprint, %room_id, "dropping Plain from banned peer");
                    return;
                }
                let sent_at = now_unix();
                let _ = repo::insert_room_message(
                    &self.db,
                    room_id,
                    &sender_fingerprint,
                    "in",
                    &body,
                    sent_at,
                    client_msg_id.as_deref(),
                    reply_to.as_deref(),
                );
                let _ = repo::update_room_last_active(&self.db, room_id, sent_at);
                self.maybe_emit_mention(room_id, &body);
                let _ = self.app_event_tx.send(AppEvent::MessageReceived {
                    room_id: room_id.to_string(),
                    sender_fingerprint,
                    body,
                    sent_at,
                });
            }
            RoomMessage::Typing { sender_fingerprint } => {
                if sender_fingerprint == our_fp {
                    return;
                }
                if repo::is_member_banned(&self.db, room_id, &sender_fingerprint).unwrap_or(false) {
                    return;
                }
                let expiry = now_unix() + TYPING_TTL_SECS;
                let mut rooms = self.active_rooms.lock();
                if let Some(room) = rooms.get_mut(room_id) {
                    room.typers.insert(sender_fingerprint, expiry);
                }
                drop(rooms);
                let _ = self.app_event_tx.send(AppEvent::TypingChanged {
                    room_id: room_id.to_string(),
                });
            }
            RoomMessage::RotateRoomKey {
                rotator_fingerprint,
                new_salt,
                room_id: announced_room_id,
            } => {
                // huddle 2.0.3 (audit N-M2): a signed message that names its room
                // must match the topic it arrived on, else a hostile relay
                // replayed it cross-room.
                if let Some(rid) = &announced_room_id {
                    if rid != room_id {
                        warn!(%room_id, announced = %rid, "RotateRoomKey room mismatch; dropping cross-room replay");
                        return;
                    }
                }
                if rotator_fingerprint == our_fp {
                    return;
                }
                // Rotations are self-attested: the signer must be the
                // claimed rotator. Unsigned forgeries land in
                // `verified_signer = None` and are dropped here, as are
                // signed envelopes where the signer fp doesn't match.
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!(%room_id, "RotateRoomKey arrived unsigned; dropping");
                        return;
                    }
                };
                if signer != rotator_fingerprint {
                    warn!(
                        %signer, %rotator_fingerprint, %room_id,
                        "RotateRoomKey signer mismatch with claimed rotator; dropping"
                    );
                    return;
                }
                let _ = self.app_event_tx.send(AppEvent::RotationRequested {
                    room_id: room_id.to_string(),
                    rotator_fingerprint,
                    new_salt,
                });
            }
            RoomMessage::MemberLeave {
                sender_fingerprint,
                room_id: announced_room_id,
            } => {
                // huddle 2.0.3 (audit N-M2): drop a signed leave replayed onto a
                // different room's topic.
                if let Some(rid) = &announced_room_id {
                    if rid != room_id {
                        warn!(%room_id, announced = %rid, "MemberLeave room mismatch; dropping cross-room replay");
                        return;
                    }
                }
                if sender_fingerprint == our_fp {
                    return;
                }
                // huddle 0.7.11: MemberLeave must arrive inside a signed
                // envelope whose signer matches the claimed leaver.
                // Pre-0.7.11 plain leaves and forged leaves are dropped.
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!(%sender_fingerprint, %room_id, "MemberLeave arrived unsigned; dropping");
                        return;
                    }
                };
                if signer != sender_fingerprint {
                    warn!(%signer, %sender_fingerprint, %room_id, "MemberLeave signer mismatch; dropping");
                    return;
                }
                let removed = {
                    let mut rooms = self.active_rooms.lock();
                    if let Some(room) = rooms.get_mut(room_id) {
                        room.members.remove(&sender_fingerprint)
                    } else {
                        false
                    }
                };
                if removed {
                    let _ = self.app_event_tx.send(AppEvent::MemberLeft {
                        room_id: room_id.to_string(),
                        fingerprint: sender_fingerprint,
                    });
                }
            }
            RoomMessage::FileOffer {
                sender_fingerprint,
                file_id,
                name,
                size_bytes,
                mime,
                chunk_count,
                encrypted_meta,
            } => {
                if sender_fingerprint == our_fp {
                    return; // ignore our own broadcast
                }
                // huddle 0.7.11: FileOffer must be signed so peers can't
                // spoof attribution. The chunk stream itself stays plain
                // (sha256 over the assembly is the integrity gate), but
                // who *announced* the file is now bound to the signer.
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!(%sender_fingerprint, %room_id, %file_id, "FileOffer arrived unsigned; dropping");
                        return;
                    }
                };
                if signer != sender_fingerprint {
                    warn!(%signer, %sender_fingerprint, %room_id, %file_id, "FileOffer signer mismatch; dropping");
                    return;
                }
                // Drop offers from banned peers in the same shape as
                // MemberAnnounce — keeps moderation invariant tight.
                if repo::is_member_banned(&self.db, room_id, &sender_fingerprint).unwrap_or(false) {
                    info!(%sender_fingerprint, %room_id, %file_id, "dropping FileOffer from banned peer");
                    return;
                }
                self.handle_file_offer(
                    room_id,
                    sender_fingerprint,
                    file_id,
                    name,
                    size_bytes,
                    mime,
                    chunk_count,
                    encrypted_meta,
                );
            }
            RoomMessage::FileChunk {
                sender_fingerprint,
                file_id,
                chunk_index,
                total_chunks,
                data_b64,
            } => {
                if sender_fingerprint == our_fp {
                    return;
                }
                if repo::is_member_banned(&self.db, room_id, &sender_fingerprint).unwrap_or(false) {
                    return;
                }
                self.handle_file_chunk(
                    room_id,
                    sender_fingerprint,
                    file_id,
                    chunk_index,
                    total_chunks,
                    data_b64,
                );
            }
            RoomMessage::OwnerGrant {
                room_id: announced_room_id,
                target_fingerprint,
            } => {
                // Both: payload room_id must match the topic's room_id
                // (no cross-room replay), AND the signer must be a
                // current owner of this room. Unsigned forgeries land in
                // `verified_signer = None` and are dropped here.
                if announced_room_id != room_id {
                    warn!(payload_room = %announced_room_id, topic_room = %room_id, "OwnerGrant room mismatch");
                    return;
                }
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!(%room_id, "OwnerGrant arrived unsigned; dropping");
                        return;
                    }
                };
                if !self.is_owner(room_id, &signer) {
                    warn!(%signer, %room_id, "OwnerGrant signer isn't an owner; dropping");
                    return;
                }
                info!(%signer, %target_fingerprint, %room_id, "OwnerGrant applied");
                if let Err(e) =
                    repo::set_member_role(&self.db, room_id, &target_fingerprint, "owner")
                {
                    warn!(%e, "OwnerGrant: set_member_role failed");
                }
            }
            RoomMessage::BanMember {
                room_id: announced_room_id,
                target_fingerprint,
            } => {
                if announced_room_id != room_id {
                    warn!(payload_room = %announced_room_id, topic_room = %room_id, "BanMember room mismatch");
                    return;
                }
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!(%room_id, "BanMember arrived unsigned; dropping");
                        return;
                    }
                };
                if !self.is_owner(room_id, &signer) {
                    warn!(%signer, %room_id, "BanMember signer isn't an owner; dropping");
                    return;
                }
                if target_fingerprint == our_fp {
                    // We've been kicked. Locally evict ourselves so the
                    // TUI tabs close; the kicker's subsequent
                    // RotateRoomKey will arrive separately and we
                    // simply won't be able to decrypt the new key,
                    // matching the "soft kick" semantics.
                    info!(%room_id, %signer, "we were kicked from this room");
                    self.active_rooms.lock().remove(room_id);
                    let _ = self.app_event_tx.send(AppEvent::RoomLeft {
                        room_id: room_id.to_string(),
                    });
                    return;
                }
                info!(%signer, %target_fingerprint, %room_id, "BanMember applied");
                if let Err(e) = repo::add_room_ban(
                    &self.db,
                    room_id,
                    &target_fingerprint,
                    &signer,
                    "", // signature lives in the envelope, not the row
                    now_unix(),
                ) {
                    warn!(%e, "BanMember: add_room_ban failed");
                }
                // huddle 2.0.2 (audit M-10): demote the banned target out of the
                // `owner` role so they drop from `owner_fingerprints` announcements
                // and can never regain admin by un-ban races. (is_owner also now
                // excludes banned fps, so this is defense-in-depth + clean state.)
                if let Err(e) = repo::revoke_owner_role(&self.db, room_id, &target_fingerprint) {
                    warn!(%e, "BanMember: revoke_owner_role failed");
                }
                self.evict_banned_member(room_id, &target_fingerprint);
            }
            RoomMessage::SasInit {
                tx_id,
                ephemeral_x25519_pubkey_b64,
                target_fingerprint,
            } => {
                // huddle 2.0.5 (WS2 increment #1): delegate to the SAS actor; it
                // owns the state machine + crypto and returns publish/emit intents
                // (the partner's pinned ML-KEM ek is looked up here, the same point
                // as before, and injected so the actor stays I/O-free).
                let outcomes = self.sas.inbound_init(
                    room_id,
                    tx_id,
                    &ephemeral_x25519_pubkey_b64,
                    &target_fingerprint,
                    verified_signer.clone(),
                    now_unix(),
                    |fp| self.partner_mlkem_ek_bytes(fp),
                );
                if let Err(e) = self.apply_sas_outcomes(outcomes).await {
                    warn!(%e, "applying SasInit outcomes failed");
                }
            }
            RoomMessage::SasResponse {
                tx_id,
                ephemeral_x25519_pubkey_b64,
            } => {
                // huddle 2.0.5 (WS2 increment #1): delegate to the SAS actor (the
                // partner's pinned ML-KEM ek is injected via the closure, looked
                // up at the same point as before, so the actor stays I/O-free).
                let outcomes = self.sas.inbound_response(
                    room_id,
                    tx_id,
                    &ephemeral_x25519_pubkey_b64,
                    verified_signer.clone(),
                    now_unix(),
                    |fp| self.partner_mlkem_ek_bytes(fp),
                );
                if let Err(e) = self.apply_sas_outcomes(outcomes).await {
                    warn!(%e, "applying SasResponse outcomes failed");
                }
            }
            RoomMessage::CodeJoinRequest {
                room_id: announced_room_id,
                joiner_x25519_pubkey_b64,
                code,
                code_proof,
            } => {
                if announced_room_id != room_id {
                    return;
                }
                let joiner_fp = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!("CodeJoinRequest unsigned; dropping");
                        return;
                    }
                };
                // Only owners with an active code are interested in
                // responding. Other peers (incl. non-issuing owners)
                // simply ignore.
                let our_fp = self.identity.fingerprint().to_string();
                if !self.is_owner(room_id, &our_fp) {
                    return;
                }
                // huddle 2.2 (audit PA-1): the joiner's ephemeral pubkey bytes —
                // bound into the proof so a relay can't rebind it to a forged key.
                let joiner_pub_bytes: [u8; 32] = match B64
                    .decode(&joiner_x25519_pubkey_b64)
                    .ok()
                    .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
                {
                    Some(b) => b,
                    None => {
                        warn!("CodeJoinRequest: bad joiner pubkey; dropping");
                        return;
                    }
                };
                // Decode the proof (v2 path) once, rate-limited so a flood of
                // forged requests can't amplify into unbounded Argon2id work.
                let proof_bytes: Option<[u8; 32]> = match &code_proof {
                    Some(p) => {
                        if !self.allow_code_proof_attempt(room_id) {
                            info!(%joiner_fp, %room_id, "CodeJoinRequest: proof rate limit; dropping");
                            return;
                        }
                        match B64
                            .decode(p)
                            .ok()
                            .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
                        {
                            Some(b) => Some(b),
                            None => {
                                warn!("CodeJoinRequest: bad code_proof; dropping");
                                return;
                            }
                        }
                    }
                    None => None,
                };
                // Match + consume an unexpired issued code. Single use; strict
                // expiry is enforced by pruning so a code can never be honored
                // past its 10-minute life.
                let now = now_unix();
                // Snapshot the unexpired codes under the lock (cheap), then verify
                // OUTSIDE it: each v2 proof check is one memory-hard Argon2id, and
                // `active_rooms` is the central map locked on every send/receive/
                // announce — running the loop under the lock would let a (rate-
                // limited) flood of forged proofs stall all room operations.
                let snapshot: Vec<String> = {
                    let mut rooms = self.active_rooms.lock();
                    let room = match rooms.get_mut(room_id) {
                        Some(r) => r,
                        None => return,
                    };
                    if room.passphrase_key.is_none() {
                        warn!("CodeJoinRequest: no passphrase key locally; can't respond");
                        return;
                    }
                    room.issued_codes.retain(|(_, exp)| *exp > now);
                    room.issued_codes.iter().map(|(c, _)| c.clone()).collect()
                };
                let matched_code = match &proof_bytes {
                    // v2: the cleartext code never arrived — verify the memory-hard
                    // proof against each unexpired issued code (no lock held).
                    Some(proof) => snapshot.into_iter().find(|c| {
                        crate::crypto::code_join::verify_code_proof(
                            c,
                            room_id,
                            &joiner_pub_bytes,
                            proof,
                        )
                        .unwrap_or(false)
                    }),
                    // legacy (pre-2.2 joiner): exact cleartext match.
                    None => snapshot.into_iter().find(|c| c == &code),
                };
                let matched_code = match matched_code {
                    Some(c) => c,
                    None => {
                        info!(%joiner_fp, "CodeJoinRequest: code invalid or expired; ignoring");
                        return;
                    }
                };
                // Re-acquire the lock to consume the matched code (single-use) and
                // read the session. Re-check presence+expiry: a concurrent request
                // may have already consumed this code while we verified unlocked.
                let (our_session_id, wrap_input) = {
                    let mut rooms = self.active_rooms.lock();
                    let room = match rooms.get_mut(room_id) {
                        Some(r) => r,
                        None => return,
                    };
                    let now = now_unix();
                    let pos = room
                        .issued_codes
                        .iter()
                        .position(|(c, exp)| c == &matched_code && *exp > now);
                    let idx = match pos {
                        Some(i) => i,
                        None => {
                            info!(%joiner_fp, "CodeJoinRequest: code already consumed/expired; ignoring");
                            return;
                        }
                    };
                    room.issued_codes.remove(idx);
                    let crypto = room.crypto.as_ref().unwrap();
                    (crypto.our_session_id(), crypto.our_session_key_b64())
                };
                // ECDH with the joiner's ephemeral pubkey.
                let their_pub = match crate::crypto::sas::parse_pubkey(&joiner_x25519_pubkey_b64) {
                    Ok(pk) => pk,
                    Err(e) => {
                        warn!(%e, "CodeJoinRequest: bad pubkey");
                        return;
                    }
                };
                use x25519_dalek::{PublicKey, StaticSecret};
                let our_secret = StaticSecret::random_from_rng(rand::thread_rng());
                let our_pub = PublicKey::from(&our_secret);
                // huddle 2.0.7 (WS2 foundations): the ECDH+HKDF wrap-key derivation
                // is one tested helper in huddle-protocol (was open-coded here and
                // in the CodeJoinResponse handler).
                let wrap_key =
                    match crate::crypto::code_join::derive_wrap_key(&our_secret, &their_pub) {
                        Ok(k) => k,
                        Err(e) => {
                            warn!(%e, "CodeJoinRequest: wrap-key derivation failed");
                            return;
                        }
                    };
                // Wrap our session key under the ECDH-derived key,
                // reusing the existing AEAD primitives.
                let wrapped = match passphrase::wrap(wrap_input.as_bytes(), &wrap_key) {
                    Ok(w) => w,
                    Err(e) => {
                        warn!(%e, "CodeJoinRequest: wrap failed");
                        return;
                    }
                };
                let response = RoomMessage::CodeJoinResponse {
                    room_id: room_id.to_string(),
                    target_fingerprint: joiner_fp.clone(),
                    owner_x25519_pubkey_b64: B64.encode(our_pub.as_bytes()),
                    owner_session_id: our_session_id,
                    wrapped_session_key_b64: wrapped,
                    nonce_b64: String::new(), // nonce is embedded in `wrapped` per passphrase::wrap
                };
                if let Ok(env) = crate::crypto::sign_message(&self.identity, &response) {
                    if let Ok(bytes) = crate::network::protocol::encode_wire_signed(&env) {
                        self.network
                            .publish_room_message(room_id.to_string(), bytes)
                            .await;
                    }
                }
                info!(%joiner_fp, %room_id, "issued CodeJoinResponse");
            }
            RoomMessage::CodeJoinResponse {
                room_id: announced_room_id,
                target_fingerprint,
                owner_x25519_pubkey_b64,
                owner_session_id,
                wrapped_session_key_b64,
                nonce_b64: _,
            } => {
                if announced_room_id != room_id || target_fingerprint != our_fp {
                    return;
                }
                let owner_fp = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!("CodeJoinResponse unsigned; dropping");
                        return;
                    }
                };
                // huddle 2.1.2 (audit PA-2): authenticate the responder as a
                // legitimate owner before installing its session/membership — and
                // before consuming the pending code-join state. `creator_fingerprint`
                // is bound into `room_id` via `derive_room_id`, so it is the one
                // owner identity a fresh code-joiner can trust before it has learned
                // the (signed) owner roster; we also accept any owner already pinned
                // locally. Without this, ANY room-topic observer that saw the joiner's
                // broadcast ephemeral pubkey could forge a signed response, install an
                // attacker-keyed inbound session + phantom membership, and (by taking
                // the pending secret first) DoS the genuine owner's response.
                let authorized_owner = {
                    let creator = self
                        .active_rooms
                        .lock()
                        .get(room_id)
                        .map(|r| r.info.creator_fingerprint.clone());
                    creator.as_deref() == Some(owner_fp.as_str())
                        || self.is_owner(room_id, &owner_fp)
                };
                if !authorized_owner {
                    warn!(%owner_fp, %room_id, "CodeJoinResponse signer is not the room creator/owner; dropping");
                    return;
                }
                let our_secret = match self
                    .pending_code_secrets
                    .lock()
                    .remove(&(room_id.to_string(), our_fp.clone()))
                {
                    Some(s) => s,
                    None => {
                        warn!(%room_id, "CodeJoinResponse with no pending code-join state");
                        return;
                    }
                };
                let owner_pub = match crate::crypto::sas::parse_pubkey(&owner_x25519_pubkey_b64) {
                    Ok(pk) => pk,
                    Err(e) => {
                        warn!(%e, "CodeJoinResponse: bad owner pubkey");
                        return;
                    }
                };
                let wrap_key =
                    match crate::crypto::code_join::derive_wrap_key(&our_secret, &owner_pub) {
                        Ok(k) => k,
                        Err(e) => {
                            warn!(%e, "CodeJoinResponse: wrap-key derivation failed");
                            return;
                        }
                    };
                let session_key_bytes =
                    match passphrase::unwrap(&wrapped_session_key_b64, &wrap_key) {
                        Ok(b) => b,
                        Err(e) => {
                            warn!(%e, "CodeJoinResponse: unwrap failed");
                            return;
                        }
                    };
                let session_key_str = match String::from_utf8(session_key_bytes) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(%e, "CodeJoinResponse: session key wasn't valid utf8");
                        return;
                    }
                };
                // Install as an inbound session keyed by the owner's fp.
                let mut rooms = self.active_rooms.lock();
                if let Some(room) = rooms.get_mut(room_id) {
                    if let Some(crypto) = room.crypto.as_mut() {
                        if let Err(e) = crypto.add_inbound_session(&owner_fp, &session_key_str) {
                            warn!(%e, "CodeJoinResponse: add_inbound_session failed");
                        } else {
                            info!(%room_id, %owner_fp, %owner_session_id, "code-join completed; can decrypt owner's messages");
                            room.members.insert(owner_fp.clone());
                            let _ = self.app_event_tx.send(AppEvent::MemberJoined {
                                room_id: room_id.to_string(),
                                fingerprint: owner_fp,
                            });
                        }
                    }
                }
            }
            RoomMessage::JoinRefused {
                room_id: announced_room_id,
                target_fingerprint,
                reason,
            } => {
                if announced_room_id != room_id || target_fingerprint != our_fp {
                    return;
                }
                // huddle 2.0.3 (audit N-L1): JoinRefused MUST be owner-signed
                // (protocol.rs must-be-signed list), but the receiver previously
                // surfaced the attacker-controlled `reason` from *any* sender —
                // including an unsigned `Plain` — which is an attacker-controlled
                // phishing toast. Require a verified signature (kills the
                // anonymous spoof), and enforce room-owner authority when we know
                // the room's owners; if we don't yet (a refused first-contact),
                // a valid signature at least makes the reason attributable.
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!(%room_id, "dropping unsigned JoinRefused");
                        return;
                    }
                };
                let owners = self.room_owners(room_id);
                if !owners.is_empty() && !owners.iter().any(|o| o == &signer) {
                    warn!(%signer, %room_id, "JoinRefused from non-owner; dropping");
                    return;
                }
                // Surface the refusal as an Error so the user sees why
                // their join didn't take. The Phase 3 modal-queue rule
                // means this won't clobber typing in another modal.
                let _ = self.app_event_tx.send(AppEvent::Error {
                    description: format!("join refused: {reason}"),
                });
            }
            RoomMessage::SasConfirm { tx_id, matched } => {
                // huddle 2.0.5 (WS2 increment #1): delegate to the SAS actor; on
                // both-sides-confirmed it returns a Finalize the facade applies
                // (the `room_members`/`verified_peers` writes + `SasVerified`).
                let outcomes = self
                    .sas
                    .inbound_confirm(&tx_id, matched, verified_signer.clone());
                if let Err(e) = self.apply_sas_outcomes(outcomes).await {
                    warn!(%e, "applying SasConfirm outcomes failed");
                }
            }
            RoomMessage::ProfileUpdate {
                sender_fingerprint,
                username,
                updated_at,
            } => {
                // huddle 0.5: username spoof defense. Drop any
                // ProfileUpdate that didn't arrive inside a Signed
                // envelope, or whose signer doesn't match the claimed
                // sender_fingerprint. Without this anyone could pretend
                // to be "alice" by stuffing the field.
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!(
                            sender = %sender_fingerprint,
                            "dropping unsigned ProfileUpdate"
                        );
                        return;
                    }
                };
                if signer != sender_fingerprint {
                    warn!(
                        signer = %signer,
                        claimed = %sender_fingerprint,
                        "dropping ProfileUpdate with signer != sender"
                    );
                    return;
                }
                if let Err(e) = repo::upsert_peer_profile(
                    &self.db,
                    &sender_fingerprint,
                    username.as_deref(),
                    updated_at,
                ) {
                    warn!(%e, "upsert_peer_profile failed");
                    return;
                }
                let _ = self.app_event_tx.send(AppEvent::PeerProfileUpdated {
                    fingerprint: sender_fingerprint,
                    username,
                });
            }
            RoomMessage::ContactRequest {
                requester_fingerprint,
                display_name,
                note,
                sender_ed25519_pubkey: _,
            } => {
                // Only honor a contact request that arrived on OUR own inbox
                // room — never one published into a shared room topic.
                if room_id != crate::network::protocol::inbox_room_id(&our_fp) {
                    return;
                }
                // Must be signed, and the signer must BE the requester — the
                // signature is the whole proof of who's asking.
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!(%requester_fingerprint, "dropping unsigned ContactRequest");
                        return;
                    }
                };
                if signer != requester_fingerprint || requester_fingerprint == our_fp {
                    return;
                }
                if repo::is_peer_blocked(&self.db, &requester_fingerprint).unwrap_or(false) {
                    debug!(%requester_fingerprint, "ignoring ContactRequest from blocked peer");
                    return;
                }
                // Mutual case: if this fingerprint is already in our address
                // book (we requested them, or we're already connected), treat
                // their request as acceptance — open/refresh the DM directly,
                // no prompt. This is also how the acceptor's echo-back
                // converges the relay path: both sides end up subscribed to
                // the canonical DM room, after which the normal MemberAnnounce
                // exchange shares session keys.
                if self.is_contact(&requester_fingerprint) {
                    let _ = repo::delete_pending_contact_request(&self.db, &requester_fingerprint);
                    if let Err(e) = self.start_direct(&requester_fingerprint).await {
                        debug!(%e, "ContactRequest mutual: start_direct failed");
                    }
                    return;
                }
                // Fresh inbound request — persist + surface for the user to
                // accept or decline from the Contacts pane.
                if let Err(e) = repo::upsert_pending_contact_request(
                    &self.db,
                    &repo::PendingContactRequest {
                        fingerprint: requester_fingerprint.clone(),
                        display_name: display_name.clone(),
                        note: note.clone(),
                        received_at: now_unix(),
                    },
                ) {
                    warn!(%e, "upsert pending contact request failed");
                    return;
                }
                self.journal_event("contact_request", &format!("from={requester_fingerprint}"));
                let _ = self.app_event_tx.send(AppEvent::ContactRequestReceived {
                    fingerprint: requester_fingerprint,
                    display_name,
                    note,
                });
            }
            // huddle 2.0.0 (F10): add/remove an emoji reaction on another peer's
            // message. Must be signed by the reactor; the target must exist in
            // THIS room (so a stray UUID from another room can't seed a phantom
            // reaction). Idempotent at the repo layer.
            RoomMessage::Reaction {
                sender_fingerprint,
                target_msg_id,
                emoji,
                removed,
            } => {
                if sender_fingerprint == our_fp {
                    return;
                }
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!("dropping unsigned Reaction");
                        return;
                    }
                };
                if signer != sender_fingerprint {
                    warn!(%signer, %sender_fingerprint, "Reaction signer mismatch; dropping");
                    return;
                }
                if repo::is_member_banned(&self.db, room_id, &sender_fingerprint).unwrap_or(false) {
                    return;
                }
                match repo::find_message_by_client_id(&self.db, room_id, &target_msg_id) {
                    Ok(Some(_)) => {}
                    _ => {
                        debug!(%target_msg_id, %room_id, "Reaction target unknown in room; dropping");
                        return;
                    }
                }
                let res = if removed {
                    repo::remove_reaction(
                        &self.db,
                        room_id,
                        &target_msg_id,
                        &sender_fingerprint,
                        &emoji,
                    )
                } else {
                    repo::add_reaction(
                        &self.db,
                        room_id,
                        &target_msg_id,
                        &sender_fingerprint,
                        &emoji,
                        now_unix(),
                    )
                };
                if let Err(e) = res {
                    warn!(%e, "applying inbound reaction failed");
                    return;
                }
                let _ = self.app_event_tx.send(AppEvent::ReactionAdded {
                    room_id: room_id.to_string(),
                    message_id: target_msg_id,
                    sender_fingerprint,
                    emoji,
                    removed,
                });
            }
            // huddle 2.0.0 (F10): edit a message body, last-write-wins. Applied
            // only when the signer is the original sender OR a current room owner
            // (moderation). For encrypted rooms the new body rides as a fresh
            // Megolm ciphertext decrypted against the session the editor carries
            // in `session_id` (exactly like `Encrypted`); for plaintext rooms it
            // rides as `new_body`.
            RoomMessage::Edit {
                sender_fingerprint,
                target_msg_id,
                new_ciphertext_b64,
                session_id,
                new_body,
            } => {
                if sender_fingerprint == our_fp {
                    return;
                }
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!("dropping unsigned Edit");
                        return;
                    }
                };
                if signer != sender_fingerprint {
                    return;
                }
                if repo::is_member_banned(&self.db, room_id, &sender_fingerprint).unwrap_or(false) {
                    return;
                }
                let target =
                    match repo::find_message_by_client_id(&self.db, room_id, &target_msg_id) {
                        Ok(Some(m)) => m,
                        _ => {
                            debug!(%target_msg_id, %room_id, "Edit target unknown; dropping");
                            return;
                        }
                    };
                if target.sender_fingerprint != signer && !self.is_owner(room_id, &signer) {
                    warn!(%signer, %target_msg_id, "Edit not authorized (not sender or owner); dropping");
                    return;
                }
                // Resolve the replacement plaintext.
                let new_plaintext = match new_body {
                    Some(b) => b,
                    None => {
                        // Encrypted room: decrypt the fresh ciphertext against the
                        // session the editor carried in `session_id` — exactly like
                        // an `Encrypted` body. No in-memory "last inbound session"
                        // cache, so this still works after a Megolm rotation, across
                        // a restart, from a second device, or when the edit is the
                        // first message we see on that session.
                        let ct = match B64.decode(&new_ciphertext_b64) {
                            Ok(c) => c,
                            Err(e) => {
                                warn!(%e, "Edit: bad ciphertext base64; dropping");
                                return;
                            }
                        };
                        if session_id.is_empty() {
                            // A pre-session-id edit (e.g. an old 2.0.0-dev peer):
                            // we can't know which session it was encrypted under,
                            // so drop it gracefully rather than guess.
                            debug!(%room_id, %sender_fingerprint, "Edit: missing session_id; dropping");
                            return;
                        }
                        let dec = {
                            let mut rooms = self.active_rooms.lock();
                            let room = match rooms.get_mut(room_id) {
                                Some(r) => r,
                                None => return,
                            };
                            let crypto = match room.crypto.as_mut() {
                                Some(c) => c,
                                None => return,
                            };
                            crypto.decrypt(&sender_fingerprint, &session_id, &ct)
                        };
                        match dec {
                            Ok((pt, _)) => String::from_utf8_lossy(&pt).to_string(),
                            Err(e) => {
                                debug!(%e, "Edit: decrypt of new body failed; dropping");
                                return;
                            }
                        }
                    }
                };
                match repo::apply_message_edit(
                    &self.db,
                    room_id,
                    &target_msg_id,
                    &new_plaintext,
                    // huddle 2.0.2 (audit M-6): LWW on the signature-bound send
                    // time, not the receiver clock — a relay can no longer revert
                    // an edit by reordering/replaying signed envelopes.
                    signed_at_ms.unwrap_or_else(now_unix_ms),
                ) {
                    Ok(true) => {
                        let _ = self.app_event_tx.send(AppEvent::MessageEdited {
                            room_id: room_id.to_string(),
                            message_id: target_msg_id,
                            editor_fingerprint: signer,
                            new_body: new_plaintext,
                        });
                    }
                    Ok(false) => {
                        debug!(%target_msg_id, "Edit ignored (stale timestamp or deleted)");
                    }
                    Err(e) => warn!(%e, "apply_message_edit failed"),
                }
            }
            // huddle 2.0.0 (F10): tombstone a message. Applied only when the
            // signer is the original sender OR a current room owner. Idempotent.
            RoomMessage::Delete {
                sender_fingerprint,
                target_msg_id,
            } => {
                if sender_fingerprint == our_fp {
                    return;
                }
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!("dropping unsigned Delete");
                        return;
                    }
                };
                if signer != sender_fingerprint {
                    return;
                }
                // huddle 2.0.2 (audit L-22): mirror the banned-member filter that
                // every other content arm has — a banned peer (incl. a demoted
                // co-owner, see M-10) must not be able to tombstone messages.
                if repo::is_member_banned(&self.db, room_id, &signer).unwrap_or(false) {
                    debug!(%signer, %room_id, "dropping Delete from banned peer");
                    return;
                }
                let target =
                    match repo::find_message_by_client_id(&self.db, room_id, &target_msg_id) {
                        Ok(Some(m)) => m,
                        _ => {
                            debug!(%target_msg_id, %room_id, "Delete target unknown; dropping");
                            return;
                        }
                    };
                if target.sender_fingerprint != signer && !self.is_owner(room_id, &signer) {
                    warn!(%signer, %target_msg_id, "Delete not authorized (not sender or owner); dropping");
                    return;
                }
                match repo::mark_message_deleted(&self.db, room_id, &target_msg_id, now_unix_ms()) {
                    Ok(true) => {
                        let _ = self.app_event_tx.send(AppEvent::MessageDeleted {
                            room_id: room_id.to_string(),
                            message_id: target_msg_id,
                            deleter_fingerprint: signer,
                        });
                    }
                    Ok(false) => {}
                    Err(e) => warn!(%e, "mark_message_deleted failed"),
                }
            }
            // huddle 2.0.0 (F9): a signed disappearing-messages TTL update.
            // Applied only when the signer is the room creator or a current owner.
            RoomMessage::RoomSetting {
                sender_fingerprint,
                disappearing_ttl_secs,
                room_id: announced_room_id,
            } => {
                // huddle 2.0.3 (audit N-M2): drop a signed RoomSetting replayed
                // onto a different room's topic by a hostile relay.
                if let Some(rid) = &announced_room_id {
                    if rid != room_id {
                        warn!(%room_id, announced = %rid, "RoomSetting room mismatch; dropping cross-room replay");
                        return;
                    }
                }
                if sender_fingerprint == our_fp {
                    return;
                }
                let signer = match verified_signer {
                    Some(fp) => fp,
                    None => {
                        warn!("dropping unsigned RoomSetting");
                        return;
                    }
                };
                if signer != sender_fingerprint {
                    return;
                }
                // huddle 2.0.3 (audit N-M6): a banned principal — including the
                // room creator, who bypasses the `is_owner` ban-exclusion via the
                // `is_creator` shortcut below — must not be able to force a
                // (retroactive, history-purging) disappearing-TTL change.
                if repo::is_member_banned(&self.db, room_id, &signer).unwrap_or(false) {
                    warn!(%signer, %room_id, "RoomSetting from banned member; dropping");
                    return;
                }
                let is_creator = repo::get_room(&self.db, room_id)
                    .ok()
                    .flatten()
                    .map(|r| r.creator_fingerprint == signer)
                    .unwrap_or(false);
                if !is_creator && !self.is_owner(room_id, &signer) {
                    warn!(%signer, %room_id, "RoomSetting from non-owner; dropping");
                    return;
                }
                let ttl = if disappearing_ttl_secs == 0 {
                    None
                } else {
                    Some(disappearing_ttl_secs.min(u32::MAX as u64) as u32)
                };
                if let Err(e) = repo::set_room_disappearing_ttl(&self.db, room_id, ttl) {
                    warn!(%e, %room_id, "set_room_disappearing_ttl failed");
                    return;
                }
                info!(%room_id, ?ttl, "F9: applied inbound disappearing-messages TTL");
                let _ = self.app_event_tx.send(AppEvent::RoomTtlChanged {
                    room_id: room_id.to_string(),
                    ttl_secs: ttl,
                });
            }
            // huddle 2.1 (WS2-b): MLS group messages. The wire is defined in
            // huddle-protocol; the MLS engine (openmls / mls-rs, behind
            // huddle-core's `mls` feature) and the per-room-`seq`-ordered commit
            // processing are the sequenced rollout. Until the engine is wired,
            // drop with a trace so an MLS-room peer doesn't mistake silence for
            // delivery — and so classical peers ignore MLS traffic cleanly.
            RoomMessage::MlsKeyPackage { .. }
            | RoomMessage::MlsWelcome { .. }
            | RoomMessage::MlsCommit { .. }
            | RoomMessage::MlsApplication { .. } => {
                debug!(
                    %room_id,
                    "received an MLS message; the MLS engine is not yet enabled — dropping"
                );
            }
        }
    }
}
