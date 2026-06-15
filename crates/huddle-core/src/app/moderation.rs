//! `AppHandle` moderation (owner grants, kicks, bans, join-codes), the SAS
//! verification facade + event journal, and profile/username/block-list methods.
//! Split out of the `app/mod.rs` god file (huddle 2.1.x maintainability refactor)
//! as an additional inherent `impl AppHandle` block.

use super::*;

impl AppHandle {
    /// Phase B: promote `target_fingerprint` to owner. Builds a signed
    /// `OwnerGrant`, broadcasts it, and applies it locally. Returns an
    /// error if we ourselves aren't an owner — only owners can grant.
    pub async fn grant_owner(&self, room_id: &str, target_fingerprint: &str) -> Result<()> {
        let our_fp = self.identity.fingerprint().to_string();
        if !self.is_owner(room_id, &our_fp) {
            return Err(HuddleError::Other("only an owner can grant owner".into()));
        }
        let msg = RoomMessage::OwnerGrant {
            room_id: room_id.to_string(),
            target_fingerprint: target_fingerprint.to_string(),
        };
        let env = crate::crypto::sign_message(&self.identity, &msg)?;
        let bytes = crate::network::protocol::encode_wire_signed(&env)?;
        self.network
            .publish_room_message(room_id.to_string(), bytes)
            .await;
        // Apply locally too — peers will converge on the next announce.
        repo::set_member_role(&self.db, room_id, target_fingerprint, "owner")?;
        Ok(())
    }

    /// Phase B: kick `target_fingerprint` from `room_id`. Broadcasts a
    /// signed `BanMember`, records the ban locally, then immediately
    /// rotates the room key under a freshly-generated passphrase. Returns
    /// the new passphrase so the caller can show it to the owner for
    /// out-of-band sharing with remaining members.
    ///
    /// The rotation is the cryptographic enforcement: a banned peer can
    /// still subscribe to the gossipsub topic and see the ciphertext,
    /// but they can't unwrap the new session key without the new
    /// passphrase, so they can't decrypt anything sent after the kick.
    pub async fn kick_member(&self, room_id: &str, target_fingerprint: &str) -> Result<String> {
        let our_fp = self.identity.fingerprint().to_string();
        if !self.is_owner(room_id, &our_fp) {
            return Err(HuddleError::Other("only an owner can kick".into()));
        }
        if target_fingerprint == our_fp {
            return Err(HuddleError::Other("can't kick yourself".into()));
        }
        let info = self
            .active_rooms
            .lock()
            .get(room_id)
            .map(|r| r.info.clone())
            .ok_or_else(|| HuddleError::Other(format!("not in room {room_id}")))?;
        if !info.encrypted {
            // Without a key to rotate, a "kick" is purely advisory —
            // ban only. Honest clients drop their messages, but anyone
            // can still read the room. Honest in v1; documented.
            let msg = RoomMessage::BanMember {
                room_id: room_id.to_string(),
                target_fingerprint: target_fingerprint.to_string(),
            };
            let env = crate::crypto::sign_message(&self.identity, &msg)?;
            let bytes = crate::network::protocol::encode_wire_signed(&env)?;
            self.network
                .publish_room_message(room_id.to_string(), bytes)
                .await;
            repo::add_room_ban(
                &self.db,
                room_id,
                target_fingerprint,
                &our_fp,
                &env.signature_b64,
                now_unix(),
            )?;
            self.evict_banned_member(room_id, target_fingerprint);
            return Ok(String::new());
        }
        // Encrypted room — full kick path.
        let new_passphrase = generate_join_passphrase();
        let msg = RoomMessage::BanMember {
            room_id: room_id.to_string(),
            target_fingerprint: target_fingerprint.to_string(),
        };
        let env = crate::crypto::sign_message(&self.identity, &msg)?;
        let bytes = crate::network::protocol::encode_wire_signed(&env)?;
        self.network
            .publish_room_message(room_id.to_string(), bytes)
            .await;
        repo::add_room_ban(
            &self.db,
            room_id,
            target_fingerprint,
            &our_fp,
            &env.signature_b64,
            now_unix(),
        )?;
        self.evict_banned_member(room_id, target_fingerprint);
        // Reuse the existing rotation flow so all the existing salt /
        // session / persistence logic stays in one place.
        self.rotate_room(room_id, &new_passphrase).await?;
        Ok(new_passphrase)
    }

    /// Phase F: generate a join code for `room_id`, good for 10 minutes. Stored
    /// in memory only on the issuing owner's machine — a single use clears it.
    /// Caller is responsible for sharing the code OOB with the prospective joiner.
    ///
    /// huddle 2.2 (audit PA-1): the code carries the `CODE_JOIN_V2_PREFIX` marker
    /// (`v2-XXXX-XXXX`). The joiner detects the marker in the code we handed it
    /// out-of-band and sends a proof-of-knowledge instead of the cleartext code,
    /// so a malicious relay never learns it. The marker travels OOB, so the relay
    /// cannot strip it to force the legacy cleartext path (it could strip a
    /// network-advertised capability bit).
    ///
    /// Owner-only. Errors if `room_id` isn't active or we're not an owner.
    pub fn generate_join_code(&self, room_id: &str) -> Result<String> {
        let our_fp = self.identity.fingerprint().to_string();
        if !self.is_owner(room_id, &our_fp) {
            return Err(HuddleError::Other(
                "only an owner can issue join codes".into(),
            ));
        }
        let code = format!(
            "{}{}",
            crate::crypto::code_join::CODE_JOIN_V2_PREFIX,
            generate_alphanumeric_code(8)
        );
        let expires_at = now_unix() + 10 * 60;
        let mut rooms = self.active_rooms.lock();
        let room = rooms
            .get_mut(room_id)
            .ok_or_else(|| HuddleError::Other(format!("not in room {room_id}")))?;
        // Prune expired entries while we're here so the list doesn't grow.
        let now = now_unix();
        room.issued_codes.retain(|(_, exp)| *exp > now);
        room.issued_codes.push((code.clone(), expires_at));
        Ok(code)
    }

    /// Phase F: join `room_id` using a short-lived code instead of the
    /// passphrase. Generates an ephemeral X25519 keypair, broadcasts a
    /// signed `CodeJoinRequest`, and waits for the owner's
    /// `CodeJoinResponse`. The receive arm builds an `ActiveRoom`
    /// flagged read-only (no passphrase = can't share our outbound
    /// session key with others).
    pub async fn join_room_with_code(&self, room_id: &str, code: &str) -> Result<()> {
        // Resolve discovered metadata so we know name/encrypted/etc.
        let info = {
            let d = self.discovered_rooms.lock().get(room_id).cloned();
            match d {
                Some(d) => StoredRoom {
                    id: room_id.to_string(),
                    name: d.name,
                    creator_fingerprint: d.creator_fingerprint,
                    encrypted: d.encrypted,
                    passphrase_salt: None, // unused on code-join path
                    created_at: now_unix(),
                    last_active: Some(now_unix()),
                    // huddle 0.7: code-join is groups-only by design — DMs
                    // are 1-1 and don't use the code flow.
                    kind: d.kind,
                },
                None => {
                    return Err(HuddleError::Other(format!(
                        "room {room_id} not visible — wait for an announcement"
                    )))
                }
            }
        };
        if !info.encrypted {
            return Err(HuddleError::Other(
                "code-join only applies to encrypted rooms".into(),
            ));
        }
        let our_fp = self.identity.fingerprint().to_string();
        // Generate ephemeral X25519 keypair; remember the secret so the
        // CodeJoinResponse receive arm can complete ECDH on this peer.
        use x25519_dalek::{PublicKey, StaticSecret};
        let our_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let our_pub = PublicKey::from(&our_secret);
        // Stash the secret keyed by (room_id, our_fp); the response
        // handler removes the matching entry when a response targeted
        // at us arrives. The composite key means a second joiner can
        // be in flight in the same room without overwriting our state.
        let key = (room_id.to_string(), our_fp.clone());
        self.pending_code_secrets
            .lock()
            .insert(key.clone(), our_secret);
        // Code-join timeout: if no response in 30s, the entry will
        // still be in the map (the response handler removes it on
        // success). Surface a `CodeJoinTimedOut` to the TUI so the
        // user isn't stuck staring at an empty room expecting traffic.
        let map = self.pending_code_secrets.clone();
        let tx = self.app_event_tx.clone();
        let timeout_room = room_id.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let still_pending = map.lock().remove(&key).is_some();
            if still_pending {
                let _ = tx.send(AppEvent::CodeJoinTimedOut {
                    room_id: timeout_room,
                    reason: "no response from owner — code may be wrong or expired".into(),
                });
            }
        });
        // Persist the rooms row BEFORE constructing RoomCrypto, whose
        // `persist_outbound()` writes a `room_megolm_sessions` row with
        // a FK to `rooms(id)`. Without this, the FK fires and the
        // join aborts. The salt is left None for now — we don't have
        // the passphrase and the announcing peer's salt is cached in
        // ROOM_SALT_CACHE for whenever we get re-onboarded.
        repo::insert_room(&self.db, &info)?;
        // Create a placeholder ActiveRoom with no crypto yet; we'll
        // fill in the inbound session in the response handler.
        self.active_rooms.lock().insert(
            room_id.to_string(),
            ActiveRoom {
                info: info.clone(),
                crypto: Some(RoomCrypto::new_for_room(
                    self.db.clone(),
                    room_id.to_string(),
                    our_fp.clone(),
                    self.persist_key(),
                )?),
                passphrase_key: None,
                members: {
                    let mut s = HashSet::new();
                    s.insert(our_fp.clone());
                    s
                },
                typers: HashMap::new(),
                read_only: true,
                issued_codes: Vec::new(),
                dm_kem_ciphertext: None,
                dm_is_hybrid: false,
                dm_key_retry: 0,
            },
        );
        self.network.subscribe_room(room_id.to_string()).await;
        // huddle 2.2 (audit PA-1): decide the request form from the OUT-OF-BAND
        // code itself, not from any relay-mediated capability. A v2 owner's code
        // carries `CODE_JOIN_V2_PREFIX`; seeing it, we prove knowledge of the
        // code (bound to this ephemeral pubkey + room) and never put the code on
        // the wire — so a malicious relay can neither read it nor rebind the
        // proof to a forged key, AND cannot downgrade us, because it never saw
        // the OOB code and so cannot strip the marker. A code WITHOUT the marker
        // can only have come from a genuine pre-2.2 owner (the legacy alphabet is
        // uppercase-only and never produces the marker), so we fall back to the
        // cleartext code purely for interop with such owners.
        let code_is_v2 = code.starts_with(crate::crypto::code_join::CODE_JOIN_V2_PREFIX);
        let (code_field, code_proof_field) = if code_is_v2 {
            let proof =
                crate::crypto::code_join::derive_code_proof(code, room_id, our_pub.as_bytes())?;
            (String::new(), Some(B64.encode(proof)))
        } else {
            (code.to_string(), None)
        };
        // Broadcast the request.
        let req = RoomMessage::CodeJoinRequest {
            room_id: room_id.to_string(),
            joiner_x25519_pubkey_b64: B64.encode(our_pub.as_bytes()),
            code: code_field,
            code_proof: code_proof_field,
        };
        let env = crate::crypto::sign_message(&self.identity, &req)?;
        let bytes = crate::network::protocol::encode_wire_signed(&env)?;
        self.network
            .publish_room_message(room_id.to_string(), bytes)
            .await;
        // Emit RoomJoined so the TUI opens the tab. Subsequent ability
        // to read messages depends on receiving the owner's response.
        let _ = self.app_event_tx.send(AppEvent::RoomJoined {
            room_id: room_id.to_string(),
        });
        Ok(())
    }

    /// Phase G: start an SAS verification with `target_fingerprint` in
    /// `room_id`. Returns the tx_id so the caller can correlate
    /// subsequent events. The full flow is asynchronous — the partner
    /// must accept on their end, both compute the ECDH-derived SAS
    /// code, OOB-compare it, and each press Match.
    pub async fn sas_start(&self, room_id: &str, target_fingerprint: &str) -> Result<String> {
        let (tx_id, outcomes) = self.sas.start(room_id, target_fingerprint, now_unix());
        self.apply_sas_outcomes(outcomes).await?;
        Ok(tx_id)
    }

    /// Phase G: user pressed Match on the SAS code modal — broadcast our signed
    /// `SasConfirm{matched: true}`, completing verification on both sides if the
    /// partner has already matched.
    pub async fn sas_match(&self, tx_id: &str) -> Result<()> {
        let outcomes = self
            .sas
            .user_match(tx_id, now_unix())
            .map_err(|e| match e {
                SasError::UnknownTx => HuddleError::Other("unknown SAS tx_id".into()),
                SasError::CodeNotReady => HuddleError::Other(
                    "SAS code not computed yet — wait for the partner's response \
                 before confirming a match"
                        .into(),
                ),
            })?;
        self.apply_sas_outcomes(outcomes).await
    }

    /// Phase G: cancel an in-flight SAS — drop our local state. Quiet teardown.
    pub fn sas_cancel(&self, tx_id: &str) {
        self.sas.cancel(tx_id);
    }

    /// huddle 2.0.7 (WS2 foundations #3): durably record a security-relevant
    /// event in the append-only journal (best-effort; the live broadcast stays
    /// authoritative for the UI). Survives a dropped broadcast and is the
    /// backbone for future multi-device history sync.
    pub(crate) fn journal_event(&self, kind: &str, detail: &str) {
        if let Err(e) = repo::journal_append(&self.db, now_unix(), kind, detail) {
            warn!(%e, kind, "failed to append to the event journal");
        }
    }

    /// huddle 2.0.7: the most-recently journaled events, newest first.
    pub fn recent_journal_events(&self, limit: usize) -> Result<Vec<repo::JournalEntry>> {
        repo::journal_recent(&self.db, limit)
    }

    /// huddle 2.0.5 (WS2 increment #1): carry out the I/O the `SasActor` decided
    /// on — sign + publish a message, emit an event, or finalize verification
    /// (the `room_members` + `verified_peers` writes and the `SasVerified`
    /// event). The actor itself touches no DB, network, or signing key.
    pub(crate) async fn apply_sas_outcomes(&self, outcomes: Vec<SasOutcome>) -> Result<()> {
        for outcome in outcomes {
            match outcome {
                SasOutcome::Publish { room_id, msg } => {
                    let env = crate::crypto::sign_message(&self.identity, &msg)?;
                    let bytes = crate::network::protocol::encode_wire_signed(&env)?;
                    self.network.publish_room_message(room_id, bytes).await;
                }
                SasOutcome::Emit(ev) => {
                    let _ = self.app_event_tx.send(ev);
                }
                SasOutcome::Finalize {
                    room_id,
                    partner_fingerprint,
                    pq_capable,
                } => {
                    repo::set_member_verified(&self.db, &room_id, &partner_fingerprint, true)?;
                    // huddle 2.0.0 (F1): persist the durable `verified_peers.pq_capable`
                    // anchor (sticky-once-true in `add_verified_peer`).
                    repo::add_verified_peer(
                        &self.db,
                        &partner_fingerprint,
                        now_unix(),
                        pq_capable,
                    )?;
                    self.journal_event(
                        "sas_verified",
                        &format!("room={room_id} peer={partner_fingerprint}"),
                    );
                    let _ = self.app_event_tx.send(AppEvent::SasVerified {
                        room_id,
                        partner_fingerprint,
                    });
                }
            }
        }
        Ok(())
    }

    /// Phase B internal: drop a banned member's in-memory presence in a
    /// room. Persistent ban already went to `room_bans`. Called from
    /// `kick_member` (locally banning ourselves) and from the
    /// `RoomMessage::BanMember` receive arm (peer-initiated ban).
    pub(crate) fn evict_banned_member(&self, room_id: &str, fingerprint: &str) {
        if let Some(room) = self.active_rooms.lock().get_mut(room_id) {
            room.members.remove(fingerprint);
        }
        let _ = self.app_event_tx.send(AppEvent::MemberLeft {
            room_id: room_id.to_string(),
            fingerprint: fingerprint.to_string(),
        });
    }

    pub fn display_name(&self) -> Option<String> {
        repo::get_display_name(&self.db).unwrap_or(None)
    }

    pub fn set_display_name(&self, name: Option<&str>) -> Result<()> {
        repo::set_display_name(&self.db, name)
    }

    /// huddle 0.5: set the local user's self-declared username (or clear
    /// it with None) and broadcast a signed `ProfileUpdate` to every
    /// joined room. Receivers cache the latest per-fingerprint username
    /// in `peer_profiles`; unsigned envelopes are dropped at the receive
    /// arm so the username can't be spoofed.
    pub async fn set_username(&self, name: Option<&str>) -> Result<()> {
        repo::set_display_name(&self.db, name)?;
        let msg = RoomMessage::ProfileUpdate {
            sender_fingerprint: self.identity.fingerprint().to_string(),
            username: name.map(|s| s.to_string()),
            updated_at: now_unix_ms(),
        };
        let env = crate::crypto::sign_message(&self.identity, &msg)?;
        let bytes = crate::network::protocol::encode_wire_signed(&env)?;
        let rooms: Vec<String> = self.active_rooms.lock().keys().cloned().collect();
        for room_id in rooms {
            self.network
                .publish_room_message(room_id, bytes.clone())
                .await;
        }
        Ok(())
    }

    /// huddle 0.5: cached username for a peer (any peer we've ever
    /// received a signed `ProfileUpdate` from), or None if unknown or
    /// the peer cleared their username. Callers render `[anonymous]` on
    /// None.
    pub fn lookup_username(&self, fingerprint: &str) -> Option<String> {
        repo::get_peer_username(&self.db, fingerprint).unwrap_or(None)
    }

    /// Look up the display name we've seen for a peer. Forwards to
    /// `lookup_username` (the new signed-source-of-truth) so existing
    /// call sites get the authenticated value without churn.
    pub fn lookup_member_display_name(&self, fingerprint: &str) -> Option<String> {
        self.lookup_username(fingerprint)
    }

    /// huddle 0.7.12: reverse of `lookup_username` — every fingerprint
    /// that has broadcast `username` via a signed `ProfileUpdate`.
    /// Usernames aren't unique, so callers must handle 0 / 1 / many.
    /// Backs the Compose-DM resolver so typing a contact's name opens a
    /// DM over the existing mesh instead of falling through to a fresh
    /// dial (matching the resolution `dial_by_id_or_username` already
    /// does for the add-friend flow).
    pub fn peers_with_username(&self, username: &str) -> Vec<String> {
        repo::find_peers_by_username(&self.db, username).unwrap_or_default()
    }

    pub fn is_room_muted(&self, room_id: &str) -> bool {
        repo::is_room_muted(&self.db, room_id).unwrap_or(false)
    }

    /// Phase B: list the fingerprints currently banned from a room
    /// (newest first). Backs the `^B` in-room view; intended for
    /// owners but the read itself is harmless and we let callers
    /// gate via `we_are_owner` if they want owner-only display.
    pub fn list_room_bans(&self, room_id: &str) -> Vec<String> {
        repo::list_room_bans(&self.db, room_id).unwrap_or_default()
    }

    /// Phase A: list every globally-blocked peer (one fingerprint per
    /// row). Surfaced in the Settings modal alongside a clear-all
    /// action that calls `unblock_peer` in a loop.
    /// huddle 0.7: every globally SAS-verified peer. Surfaced in the
    /// People pane's "Verified" sub-list.
    pub fn list_verified_peers(&self) -> Vec<String> {
        repo::list_verified_peers(&self.db).unwrap_or_default()
    }

    pub fn list_blocked_peers(&self) -> Vec<String> {
        repo::list_blocked_peers(&self.db).unwrap_or_default()
    }

    /// Phase A: remove `fingerprint` from the persistent blocklist. The
    /// peer will no longer be auto-rejected on connection; they fall
    /// back to the regular inbound-dial accept/reject prompt.
    pub fn unblock_peer(&self, fingerprint: &str) -> Result<()> {
        repo::unblock_peer(&self.db, fingerprint)
    }

    /// huddle 0.7: add `fingerprint` to the persistent blocklist. Used
    /// by the People pane's per-row "block" action. Subsequent inbound
    /// dials from this fingerprint are auto-rejected without prompting.
    pub fn block_peer(&self, fingerprint: &str) -> Result<()> {
        repo::block_peer(&self.db, fingerprint, now_unix())
    }

    /// Phase F: rooms entered via a join code don't have the passphrase
    /// in memory, so the joining peer can't wrap their own outbound
    /// session key for newer members — they can read and send, they
    /// just can't onboard others. The TUI renders a `(read-only)`
    /// badge in the room tab so the user understands.
    pub fn is_room_read_only(&self, room_id: &str) -> bool {
        self.active_rooms
            .lock()
            .get(room_id)
            .map(|r| r.read_only)
            .unwrap_or(false)
    }

    pub fn set_room_muted(&self, room_id: &str, muted: bool) -> Result<()> {
        repo::set_room_muted(&self.db, room_id, muted)
    }
}
