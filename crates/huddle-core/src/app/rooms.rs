//! `AppHandle` room lifecycle, 1:1 DM key agreement, message send/edit/react, and
//! Megolm rotation. Split out of the `app/mod.rs` god file (huddle 2.1.x
//! maintainability refactor) as an additional inherent `impl AppHandle` block.

use super::*;

impl AppHandle {
    /// Create a new room. Returns its room_id.
    ///
    /// huddle 0.7: `kind` is now required. `RoomKind::Group` (the default)
    /// preserves pre-0.7 behavior. `RoomKind::Direct` is reserved for
    /// callers that have already computed a deterministic DM room_id via
    /// `canonical_dm_room_id` — most clients should call `start_direct`
    /// instead, which handles idempotency, kind, and naming.
    pub async fn start_room(
        &self,
        name: &str,
        encrypted: bool,
        passphrase: Option<&str>,
        kind: RoomKind,
    ) -> Result<String> {
        if encrypted && passphrase.is_none() {
            return Err(HuddleError::Other(
                "encrypted room requires a passphrase".into(),
            ));
        }
        // huddle 2.0.3 (audit N-L2): floor the room passphrase at creation — its
        // Argon2id salt rides the cleartext RoomAnnouncement, so a weak one is
        // directly offline-brute-forceable to break the room's confidentiality.
        if let Some(p) = passphrase {
            validate_passphrase_len(p)?;
        }

        let created_at = now_unix();
        let creator_fp = self.identity.fingerprint().to_string();
        let room_id = derive_room_id(&creator_fp, name, created_at);

        let (passphrase_salt, passphrase_key) = if encrypted {
            let salt = passphrase::random_salt();
            let key = passphrase::derive_key(passphrase.unwrap(), &salt)?;
            (Some(salt.to_vec()), Some(key))
        } else {
            (None, None)
        };

        let info = StoredRoom {
            id: room_id.clone(),
            name: name.to_string(),
            creator_fingerprint: creator_fp.clone(),
            encrypted,
            passphrase_salt: passphrase_salt.clone(),
            created_at,
            last_active: Some(created_at),
            kind,
        };
        repo::insert_room(&self.db, &info)?;

        let crypto = if encrypted {
            Some(RoomCrypto::new_for_room(
                self.db.clone(),
                room_id.clone(),
                creator_fp.clone(),
                self.persist_key(),
            )?)
        } else {
            None
        };

        let mut members = HashSet::new();
        members.insert(creator_fp.clone());

        // Phase B: the room creator is the first owner. Persisted now so
        // the very first announcement includes our fingerprint in
        // `owner_fingerprints`, letting joiners know who's authorized.
        repo::upsert_room_member(
            &self.db,
            &StoredRoomMember {
                room_id: room_id.clone(),
                peer_id: String::new(),
                fingerprint: creator_fp.clone(),
                last_seen: Some(created_at),
                verified: true, // we trust ourselves
                ed25519_pubkey: Some(B64.encode(self.identity.public_bytes())),
                role: "owner".into(),
                mlkem_pubkey: None, // our own row; we pin partners, not ourselves
            },
        )?;

        self.active_rooms.lock().insert(
            room_id.clone(),
            ActiveRoom {
                info: info.clone(),
                crypto,
                passphrase_key,
                members,
                typers: HashMap::new(),
                read_only: false,
                issued_codes: Vec::new(),
                dm_kem_ciphertext: None,
                dm_is_hybrid: false,
                dm_key_retry: 0,
            },
        );

        self.network.subscribe_room(room_id.clone()).await;
        self.announce_room_now(&info, 1).await;

        // Broadcast our presence in the room (with our wrapped session key
        // if encrypted). Use a small delay so the subscription propagates.
        let app = self.clone();
        let rid = room_id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if let Err(e) = app.broadcast_member_announce(&rid).await {
                warn!(%e, "broadcast member announce");
            }
        });

        let _ = self.app_event_tx.send(AppEvent::RoomJoined {
            room_id: room_id.clone(),
        });

        Ok(room_id)
    }

    /// huddle 0.7.1: start (or open) a 1-1 DM with `partner_fingerprint`.
    ///
    /// Idempotent across peers and reopens:
    /// 1. Refuses to DM yourself.
    /// 2. Computes `room_id = canonical_dm_room_id(our_fp, partner_fp)`.
    ///    Both peers, regardless of who clicks first, derive identical
    ///    IDs.
    /// 3. If a DM room already exists locally (active or stored), returns
    ///    its id — no new room, no second announcement.
    /// 4. Otherwise creates a `RoomKind::Direct`, **end-to-end encrypted**
    ///    room. The key is derived from Ed25519→X25519 ECDH between the
    ///    two parties' identity keys (see `crypto::dm::derive_dm_key`).
    ///    No shared passphrase, no central key agreement — both peers
    ///    independently derive the same 32-byte room key from their
    ///    own seed + the other's pubkey.
    /// 5. If we don't yet know the partner's Ed25519 pubkey, the room
    ///    is still created encrypted; the key is derived lazily once
    ///    `MemberAnnounce` arrives with the partner's pubkey, after
    ///    which we send our wrapped Megolm session key in a follow-up
    ///    announce.
    /// 6. Subscribes to the room topic and announces on the global topic.
    ///    The announcement is visibility-filtered at honest 0.7+ peers,
    ///    so only the partner sees it in their `discovered_rooms()`.
    pub async fn start_direct(&self, partner_fingerprint: &str) -> Result<String> {
        let our_fp = self.identity.fingerprint().to_string();
        if partner_fingerprint == our_fp {
            return Err(HuddleError::Other("cannot DM yourself".into()));
        }
        let room_id = canonical_dm_room_id(&our_fp, partner_fingerprint);
        // huddle 1.2: ensure relay traffic for this DM is delivered straight
        // to the partner's fingerprint (works even before they subscribe).
        self.network
            .register_dm(room_id.clone(), partner_fingerprint.to_string());

        // huddle 1.0: a DM is a relationship — record the partner in the
        // durable Contacts book so they persist (and stay chattable over the
        // relay) even after they leave the LAN. Idempotent; best-effort.
        let _ = self.add_contact(partner_fingerprint, "dm");

        // Idempotent reopen: if the room already exists on disk or in
        // memory, surface its id without creating a duplicate. This
        // handles both "I already DM'd them" and "they DM'd me first
        // and we auto-accepted" paths.
        if self.active_rooms.lock().contains_key(&room_id) {
            let _ = self.app_event_tx.send(AppEvent::RoomJoined {
                room_id: room_id.clone(),
            });
            return Ok(room_id);
        }
        if repo::get_room(&self.db, &room_id)?.is_some() {
            // Re-bootstrap the in-memory active room from disk.
            return self
                .bootstrap_direct_room(&room_id, partner_fingerprint)
                .await;
        }

        let created_at = now_unix();
        // The name is internal/derived — the DM pane renders the partner
        // username + HD-ID instead. Including the short fp keeps the row
        // navigable in `sqlite3` if someone digs into the DB.
        let name = format!("dm-{}", short_fp_for_msg(partner_fingerprint));

        // huddle 0.7.1: DMs are always encrypted. The salt slot stores
        // the canonical room_id (16 raw bytes from the SHA-256 prefix)
        // so a re-bootstrap can re-derive the same key. The actual key
        // comes from ECDH below, not from this salt — but we keep the
        // salt slot non-NULL so legacy code paths (which assume
        // encrypted rooms have salts) don't choke.
        let dm_salt = hex::decode(&room_id).unwrap_or_else(|_| room_id.as_bytes().to_vec());
        let info = StoredRoom {
            id: room_id.clone(),
            name,
            creator_fingerprint: our_fp.clone(),
            encrypted: true,
            passphrase_salt: Some(dm_salt),
            created_at,
            last_active: Some(created_at),
            kind: RoomKind::Direct,
        };
        repo::insert_room(&self.db, &info)?;

        let mut members = HashSet::new();
        members.insert(our_fp.clone());
        repo::upsert_room_member(
            &self.db,
            &StoredRoomMember {
                room_id: room_id.clone(),
                peer_id: String::new(),
                fingerprint: our_fp.clone(),
                last_seen: Some(created_at),
                verified: true,
                ed25519_pubkey: Some(B64.encode(self.identity.public_bytes())),
                role: "member".into(),
                mlkem_pubkey: None, // our own row
            },
        )?;

        // huddle 1.3: the DM wrap key is derived lazily in the `MemberAnnounce`
        // handler (`ensure_dm_key`), not here. We must first see the partner's
        // announce to learn whether they are post-quantum capable (whether they
        // publish an ML-KEM key) and, if we are the responder, to receive the
        // KEM ciphertext — so committing to a key now would risk locking in
        // classical and desyncing from a hybrid partner. Start with no key; the
        // partner's first announcement populates it.
        let passphrase_key: Option<[u8; KEY_LEN]> = None;

        // Always create our outbound Megolm session so we can encrypt
        // *something* the moment the key materializes. RoomCrypto
        // works the same as it does for group rooms — the only
        // difference is where `passphrase_key` comes from.
        let crypto = Some(RoomCrypto::new_for_room(
            self.db.clone(),
            room_id.clone(),
            our_fp.clone(),
            self.persist_key(),
        )?);

        self.active_rooms.lock().insert(
            room_id.clone(),
            ActiveRoom {
                info: info.clone(),
                crypto,
                passphrase_key,
                members,
                typers: HashMap::new(),
                read_only: false,
                issued_codes: Vec::new(),
                dm_kem_ciphertext: None,
                dm_is_hybrid: false,
                dm_key_retry: 0,
            },
        );

        self.network.subscribe_room(room_id.clone()).await;
        self.announce_room_now(&info, 1).await;

        let app = self.clone();
        let rid = room_id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if let Err(e) = app.broadcast_member_announce(&rid).await {
                warn!(%e, "broadcast member announce for DM");
            }
        });

        let _ = self.app_event_tx.send(AppEvent::RoomJoined {
            room_id: room_id.clone(),
        });
        Ok(room_id)
    }

    /// huddle 1.3 / hardened in 1.3.1: (re)derive the DM wrap key for a Direct
    /// room from a partner `MemberAnnounce`, choosing the **hybrid**
    /// (X25519 + ML-KEM-768) path when the partner is post-quantum capable,
    /// else the classical X25519 path.
    ///
    /// ## Post-quantum capability pinning (1.3.1)
    /// A peer is "PQ-capable" if their ML-KEM key is present **on this announce
    /// or persisted** (`room_members.mlkem_pubkey`, set the first time we ever
    /// saw it in a signed announce). Once pinned, we **refuse the classical
    /// fallback** for that peer — so an untrusted relay cannot replay a captured
    /// pre-1.3 (classical-only, validly-signed) announce to force a
    /// quantum-unsafe downgrade, and the pin survives restarts even though the
    /// in-memory wrap key does not.
    ///
    /// ## Lock-in, one-way upgrade, never downgrade
    /// The first key derived is locked in. We **never** downgrade hybrid →
    /// classical. We **do** perform a one-way classical → hybrid **upgrade**:
    /// if a DM was locked classical (partner looked pre-1.3, or a replayed
    /// classical announce won the race) and we later observe the partner's PQ
    /// capability, we re-derive the hybrid key and **rotate our outbound Megolm
    /// session** (`rotate_outbound`) so the session key previously shared
    /// wrapped under the classical key is retired — closing the HNDL window the
    /// classical phase opened. This also heals a rollout split-brain without a
    /// restart.
    ///
    /// The lower-fingerprint peer is the **initiator** (encapsulates a fresh KEM
    /// secret and ships the ciphertext); the higher-fingerprint peer is the
    /// **responder** (decapsulates it) and asks for that ciphertext
    /// (`RequestCiphertext`) rather than falling back to a classical key.
    ///
    /// ## Residual (documented, not fully closable without a wire/out-of-band change)
    /// On a peer we have **never** pinned (true first contact, or the one-time
    /// 1.3.0→1.3.1 window before the partner re-announces), a relay that both
    /// replays a captured pre-1.3 announce **and** suppresses every genuine
    /// hybrid announce can still force an initial classical lock. The only bound
    /// on it is the upgrade+rotate above (the moment any genuine hybrid announce
    /// gets through); the bounded `SessionKeyRequest` retry does NOT cover this
    /// state (a classical-keyed room with an un-pinned partner is not nudged, and
    /// classical traffic decrypts fine so the decrypt-miss heal never fires). A
    /// real fix needs an out-of-band capability anchor (e.g. binding PQ
    /// capability into SAS).
    ///
    /// ## Concurrency
    /// In libp2p (`--mode mdns|direct`) builds on the multi-threaded runtime,
    /// `process_network_event` — and thus this fn's single call site — is driven
    /// by TWO concurrent tasks: the gossipsub loop (`spawn_event_processor`) and
    /// the relay loop (`spawn_server_connection`). Because the relay mirrors the
    /// same DM traffic, two `ensure_dm_key` calls for one Direct room CAN run
    /// concurrently. Race-freedom does NOT come from single-threading; it comes
    /// from the Phase-2 commit re-reading the LIVE `(passphrase_key,
    /// dm_is_hybrid)` under the lock plus the strictly monotonic
    /// `is_first || is_upgrade` rule (upgrade is classical→hybrid only). Every
    /// interleaving converges to hybrid with no downgrade and at most one
    /// `rotate_outbound` — so do not weaken the commit re-check.

    /// huddle 2.0.0 (F1): the partner's pinned ML-KEM-768 encapsulation key
    /// bytes (decoded from the durable `room_members.mlkem_pubkey` pin), or
    /// `None` if we've never observed it. Bound into the SAS transcript so a
    /// verified peer's post-quantum capability becomes part of the out-of-band
    /// trust anchor — see [`crate::crypto::sas::derive_sas_code`]. A malformed
    /// (wrong-length) pin is treated as absent.
    pub(crate) fn partner_mlkem_ek_bytes(&self, fingerprint: &str) -> Option<Vec<u8>> {
        let b64 = repo::lookup_peer_mlkem_pubkey(&self.db, fingerprint)
            .ok()
            .flatten()?;
        let bytes = B64.decode(&b64).ok()?;
        if bytes.len() == crate::crypto::pqc::MLKEM_EK_LEN {
            Some(bytes)
        } else {
            None
        }
    }

    pub(crate) fn ensure_dm_key(
        &self,
        room_id: &str,
        partner_fp: &str,
        partner_ed_b64: Option<&str>,
        partner_mlkem_b64: Option<&str>,
        ciphertext_b64: Option<&str>,
    ) -> DmKeyOutcome {
        // Phase 1: snapshot current key state.
        let (already_keyed, already_hybrid) = {
            let rooms = self.active_rooms.lock();
            match rooms.get(room_id) {
                Some(r) => (r.passphrase_key.is_some(), r.dm_is_hybrid),
                None => return DmKeyOutcome::Noop,
            }
        };
        // The partner's Ed25519 pubkey is required for either path.
        let partner_ed = match partner_ed_b64 {
            Some(b64) => match B64.decode(b64).ok() {
                Some(b) if b.len() == 32 => {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&b);
                    a
                }
                _ => return DmKeyOutcome::Noop,
            },
            None => return DmKeyOutcome::Noop,
        };

        // PQ capability is sticky: this announce's ML-KEM key OR a previously
        // pinned one (persisted in room_members). Prefer the (freshly signed)
        // announce value; fall back to the durable pin.
        let stored_ek = repo::lookup_peer_mlkem_pubkey(&self.db, partner_fp)
            .ok()
            .flatten();
        let ek_b64: Option<String> = partner_mlkem_b64.map(|s| s.to_string()).or(stored_ek);
        let have_mlkem_ek = ek_b64.is_some();
        // huddle 2.0.0 (F1): the SAS verified-peer anchor is the THIRD capability
        // source, and the strongest — it survives a relay stripping both the live
        // announce key and the room_members pin. Folding it into
        // `partner_pq_capable` makes `plan_dm_key` refuse a classical fallback for
        // a peer we once SAS-verified as PQ-capable: with no ek available the plan
        // yields a hybrid action that can't derive (→ Noop, wait for a genuine
        // hybrid announce) rather than locking in a quantum-unsafe classical key.
        // `get_verified_peer_pq_capable` is fail-secure (reports `true` on a DB
        // error), so `.unwrap_or(true)` keeps the same loud-fail-over-silent-
        // downgrade posture. This is exactly `dm::must_refuse_classical_fallback`.
        let verified_pq_capable =
            repo::get_verified_peer_pq_capable(&self.db, partner_fp).unwrap_or(true);
        let partner_pq_capable = have_mlkem_ek || verified_pq_capable;
        debug_assert_eq!(
            crate::crypto::dm::must_refuse_classical_fallback(partner_pq_capable, have_mlkem_ek),
            partner_pq_capable && !have_mlkem_ek,
            "F1 downgrade guard must agree with the folded capability inputs"
        );
        let we_are_initiator = self.identity.fingerprint() < partner_fp;

        // The whole downgrade/upgrade policy lives in this pure decision.
        let action = plan_dm_key(
            already_keyed,
            already_hybrid,
            partner_pq_capable,
            we_are_initiator,
            ciphertext_b64.is_some(),
        );
        match action {
            DmKeyAction::Noop => return DmKeyOutcome::Noop,
            DmKeyAction::RequestCiphertext => return DmKeyOutcome::RequestCiphertext,
            DmKeyAction::Classical
            | DmKeyAction::HybridInitiator
            | DmKeyAction::HybridResponder => {}
        }

        // huddle 1.1.4: wipe our copy of the identity secret on drop.
        let our_seed = zeroize::Zeroizing::new(self.identity.secret_bytes());

        // Derive (no lock held), per the chosen action. `is_hybrid` records
        // which key we built so the commit can enforce never-downgrade.
        let (key, ct_b64, is_hybrid): ([u8; KEY_LEN], Option<String>, bool) = match action {
            DmKeyAction::HybridInitiator | DmKeyAction::HybridResponder => {
                // PQ-capable partner → hybrid ONLY; classical is refused.
                let ek = match ek_b64.as_deref().and_then(|s| B64.decode(s).ok()) {
                    Some(b) if b.len() == crate::crypto::pqc::MLKEM_EK_LEN => b,
                    _ => {
                        warn!(%partner_fp, "DM hybrid: malformed ML-KEM pubkey");
                        return DmKeyOutcome::Noop;
                    }
                };
                if let DmKeyAction::HybridInitiator = action {
                    match crate::crypto::dm::derive_dm_key_hybrid_initiator(
                        &our_seed,
                        &partner_ed,
                        &ek,
                        room_id,
                    ) {
                        Ok((key, ct)) => (key, Some(B64.encode(ct)), true),
                        Err(e) => {
                            warn!(%e, %partner_fp, "DM hybrid initiator derivation failed");
                            return DmKeyOutcome::Noop;
                        }
                    }
                } else {
                    // Responder: decode the initiator's ciphertext and decapsulate.
                    let ct = match ciphertext_b64.and_then(|c| B64.decode(c).ok()) {
                        Some(b) => b,
                        None => {
                            warn!(%partner_fp, "DM hybrid: malformed ML-KEM ciphertext");
                            return DmKeyOutcome::Noop;
                        }
                    };
                    match crate::crypto::dm::derive_dm_key_hybrid_responder(
                        &self.identity.pq_keypair(),
                        &our_seed,
                        &partner_ed,
                        &ct,
                        room_id,
                    ) {
                        Ok(key) => (key, None, true),
                        Err(e) => {
                            warn!(%e, %partner_fp, "DM hybrid responder derivation failed");
                            return DmKeyOutcome::Noop;
                        }
                    }
                }
            }
            DmKeyAction::Classical => {
                match crate::crypto::dm::derive_dm_key(&our_seed, &partner_ed, room_id) {
                    Ok(key) => (key, None, false),
                    Err(e) => {
                        warn!(%e, %partner_fp, "DM classical derivation failed");
                        return DmKeyOutcome::Noop;
                    }
                }
            }
            // Noop / RequestCiphertext already returned above.
            DmKeyAction::Noop | DmKeyAction::RequestCiphertext => unreachable!(),
        };

        // Phase 2: commit under the lock, re-checking the LIVE state.
        let mut rooms = self.active_rooms.lock();
        let room = match rooms.get_mut(room_id) {
            Some(r) => r,
            None => return DmKeyOutcome::Noop,
        };
        let live_keyed = room.passphrase_key.is_some();
        let live_hybrid = room.dm_is_hybrid;
        if live_keyed && live_hybrid {
            return DmKeyOutcome::Noop; // raced to hybrid
        }
        let is_first = !live_keyed;
        // Upgrade ONLY classical → hybrid; never the reverse.
        let is_upgrade = live_keyed && is_hybrid && !live_hybrid;
        if is_first || is_upgrade {
            room.passphrase_key = Some(key);
            room.dm_is_hybrid = is_hybrid;
            if ct_b64.is_some() {
                room.dm_kem_ciphertext = ct_b64;
            }
            if is_upgrade {
                // Retire the classically-wrapped outbound session key (HNDL).
                if let Some(c) = room.crypto.as_mut() {
                    if let Err(e) = c.rotate_outbound() {
                        warn!(%e, %room_id, "DM classical→hybrid upgrade: outbound rotate failed");
                    } else {
                        // F4: this rotation reset the epoch (0/now); persist it so
                        // the new epoch's schedule survives a restart.
                        self.persist_rotation_state(c);
                    }
                }
                info!(%room_id, %partner_fp, "DM upgraded classical→hybrid (post-quantum)");
            }
            DmKeyOutcome::ReBroadcast
        } else {
            DmKeyOutcome::Noop
        }
    }

    /// Internal: re-hydrate an existing on-disk DM room into
    /// `active_rooms` and re-subscribe / re-announce. Used by
    /// `start_direct` when the room exists on disk but not in memory
    /// (e.g. process restart) and by the auto-accept path when a DM
    /// announcement arrives from the partner.
    pub(crate) async fn bootstrap_direct_room(
        &self,
        room_id: &str,
        partner_fingerprint: &str,
    ) -> Result<String> {
        let our_fp = self.identity.fingerprint().to_string();
        // huddle 1.2: re-register direct-delivery routing for this restored DM
        // so its relay traffic addresses the partner by fingerprint.
        self.network
            .register_dm(room_id.to_string(), partner_fingerprint.to_string());
        let info = repo::get_room(&self.db, room_id)?
            .ok_or_else(|| HuddleError::Other(format!("DM room {room_id} not found on disk")))?;
        let mut members = HashSet::new();
        members.insert(our_fp.clone());
        members.insert(partner_fingerprint.to_string());

        // Pull persisted members so re-bootstrap doesn't lose them.
        if let Ok(stored_members) = repo::list_room_members(&self.db, room_id) {
            for m in stored_members {
                members.insert(m.fingerprint);
            }
        }

        // huddle 0.7.1: rehydrate the ECDH key + Megolm session if the
        // partner's pubkey is on disk (which it always is after at
        // least one previous MemberAnnounce). For older DMs that
        // pre-date 0.7.1 (when DMs were unencrypted on the room
        // layer), `info.encrypted` is false — preserve that and skip
        // the ECDH derivation; the room continues operating as it did
        // before. New 0.7.1+ DMs all have `encrypted = true`.
        let (passphrase_key, crypto) = if info.encrypted {
            // huddle 1.3: derive the DM wrap key lazily in the `MemberAnnounce`
            // handler once the partner re-announces (revealing PQ capability +,
            // for the responder, the KEM ciphertext). On restart the persisted
            // Megolm sessions already decrypt history; the wrap key is only
            // needed to process the partner's *next* session-key announce, which
            // re-arrives on reconnect.
            let pk: Option<[u8; KEY_LEN]> = None;
            // huddle 0.7.11: bubble up the error instead of .expect. The
            // inbound-DM auto-bootstrap path spawns this on its own task;
            // a transient DB write failure used to panic the task and
            // silently kill all subsequent DM bootstraps.
            let c = match RoomCrypto::load(
                self.db.clone(),
                room_id.to_string(),
                our_fp.clone(),
                self.persist_key(),
            )? {
                Some(mut c) => {
                    // F4: continue the rotation schedule from where it left off
                    // rather than resetting the counter to zero on this restart.
                    self.rehydrate_rotation_state(&mut c);
                    Some(c)
                }
                None => Some(RoomCrypto::new_for_room(
                    self.db.clone(),
                    room_id.to_string(),
                    our_fp.clone(),
                    self.persist_key(),
                )?),
            };
            (pk, c)
        } else {
            (None, None)
        };

        self.active_rooms.lock().insert(
            room_id.to_string(),
            ActiveRoom {
                info: info.clone(),
                crypto,
                passphrase_key,
                members,
                typers: HashMap::new(),
                read_only: false,
                issued_codes: Vec::new(),
                dm_kem_ciphertext: None,
                dm_is_hybrid: false,
                dm_key_retry: 0,
            },
        );

        self.network.subscribe_room(room_id.to_string()).await;
        self.announce_room_now(&info, 2).await;

        let app = self.clone();
        let rid = room_id.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if let Err(e) = app.broadcast_member_announce(&rid).await {
                warn!(%e, "broadcast member announce on DM bootstrap");
            }
        });

        let _ = self.app_event_tx.send(AppEvent::RoomJoined {
            room_id: room_id.to_string(),
        });
        Ok(room_id.to_string())
    }

    /// Join an existing room. The room may come from a live announcement
    /// (preferred), our restorable set, or the DB directly — whichever has
    /// the freshest copy. For encrypted rooms `passphrase` is required.
    pub async fn join_room(&self, room_id: &str, passphrase: Option<&str>) -> Result<()> {
        // Resolve room metadata from the freshest available source.
        let (name, creator_fingerprint, encrypted, salt_opt) = {
            if let Some(d) = self.discovered_rooms.lock().get(room_id).cloned() {
                let salt = self.get_room_salt(room_id);
                (d.name, d.creator_fingerprint, d.encrypted, salt)
            } else if let Some(stored) = self.restorable_rooms.lock().get(room_id).cloned() {
                (
                    stored.name,
                    stored.creator_fingerprint,
                    stored.encrypted,
                    stored.passphrase_salt,
                )
            } else if let Some(stored) = repo::get_room(&self.db, room_id)? {
                (
                    stored.name,
                    stored.creator_fingerprint,
                    stored.encrypted,
                    stored.passphrase_salt,
                )
            } else {
                return Err(HuddleError::Other(format!("room {room_id} not found")));
            }
        };

        if encrypted && passphrase.is_none() {
            return Err(HuddleError::Other(
                "encrypted room requires a passphrase".into(),
            ));
        }

        let passphrase_key = if encrypted {
            let salt = salt_opt
                .clone()
                .ok_or_else(|| HuddleError::Other("missing salt for encrypted room".into()))?;
            Some(passphrase::derive_key(passphrase.unwrap(), &salt)?)
        } else {
            None
        };

        // huddle 0.7: preserve the kind that came from the announcement
        // / restorable cache / DB. If we don't have it (very old row),
        // default to Group — matches the schema column default and the
        // back-fill policy.
        let kind = self
            .discovered_rooms
            .lock()
            .get(room_id)
            .map(|d| d.kind)
            .or_else(|| {
                repo::get_room(&self.db, room_id)
                    .ok()
                    .flatten()
                    .map(|r| r.kind)
            })
            .unwrap_or_default();

        let info = StoredRoom {
            id: room_id.to_string(),
            name,
            creator_fingerprint,
            encrypted,
            passphrase_salt: salt_opt.clone(),
            created_at: now_unix(),
            last_active: Some(now_unix()),
            kind,
        };
        repo::insert_room(&self.db, &info)?;

        let crypto = if encrypted {
            // Reuse persisted Megolm sessions on re-join; only mint a fresh
            // outbound session when nothing is stored for this room yet.
            let our_fp = self.identity.fingerprint().to_string();
            let existing = RoomCrypto::load(
                self.db.clone(),
                room_id.to_string(),
                our_fp.clone(),
                self.persist_key(),
            )?;
            Some(match existing {
                Some(mut c) => {
                    // F4: resume the rotation schedule across this restart/re-join
                    // instead of restarting the counter from zero.
                    self.rehydrate_rotation_state(&mut c);
                    c
                }
                None => RoomCrypto::new_for_room(
                    self.db.clone(),
                    room_id.to_string(),
                    our_fp,
                    self.persist_key(),
                )?,
            })
        } else {
            None
        };

        let mut members = HashSet::new();
        members.insert(self.identity.fingerprint().to_string());

        self.active_rooms.lock().insert(
            room_id.to_string(),
            ActiveRoom {
                info: info.clone(),
                crypto,
                passphrase_key,
                members,
                typers: HashMap::new(),
                read_only: false,
                issued_codes: Vec::new(),
                dm_kem_ciphertext: None,
                dm_is_hybrid: false,
                dm_key_retry: 0,
            },
        );
        // No longer "restorable" now that we've rejoined.
        self.restorable_rooms.lock().remove(room_id);

        self.network.subscribe_room(room_id.to_string()).await;

        let app = self.clone();
        let rid = room_id.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if let Err(e) = app.broadcast_member_announce(&rid).await {
                warn!(%e, "broadcast member announce");
            }
            // Ask existing members for their session keys.
            let req = RoomMessage::SessionKeyRequest {
                requester_fingerprint: app.identity.fingerprint().to_string(),
            };
            if let Ok(bytes) = encode_wire(&req) {
                app.network.publish_room_message(rid.clone(), bytes).await;
            }
        });

        let _ = self.app_event_tx.send(AppEvent::RoomJoined {
            room_id: room_id.to_string(),
        });

        Ok(())
    }

    /// Walk the rooms table at startup. Non-encrypted rooms and DMs are
    /// silently restored (subscribed + re-announced). Encrypted *group*
    /// rooms get added to `restorable_rooms` so the lobby surfaces them
    /// and the user can re-enter via the join flow with the passphrase.
    ///
    /// huddle 1.0: DMs (always encrypted) are now fully re-activated here
    /// rather than parked — their key derives from our identity + the
    /// partner's persisted pubkey, no passphrase needed — so DM chat keeps
    /// flowing continuously across restarts and across networks (relay
    /// mailbox + LAN), instead of going dormant until manually reopened.
    pub(crate) async fn restore_rooms_from_db(&self) {
        let rooms = match repo::list_rooms(&self.db) {
            Ok(v) => v,
            Err(e) => {
                warn!(%e, "list rooms on restore");
                return;
            }
        };
        let our_fp = self.identity.fingerprint().to_string();
        let count = rooms.len();
        for info in rooms {
            // DMs: re-activate fully (key derives from identity + the
            // partner's persisted pubkey, no passphrase). Keeps DMs live so
            // relay-delivered messages are handled, not dropped.
            if info.encrypted && info.kind == RoomKind::Direct {
                let partner = repo::list_room_members(&self.db, &info.id)
                    .ok()
                    .into_iter()
                    .flatten()
                    .map(|m| m.fingerprint)
                    .find(|fp| *fp != our_fp);
                match partner {
                    Some(partner_fp) => {
                        if let Err(e) = self.bootstrap_direct_room(&info.id, &partner_fp).await {
                            warn!(%e, room_id = %info.id, "restore: DM bootstrap failed; parking as restorable");
                            self.restorable_rooms.lock().insert(info.id.clone(), info);
                        } else {
                            info!(room_id = %info.id, "restored DM");
                        }
                    }
                    // DM created but never reciprocated — partner pubkey
                    // unknown, nothing to re-activate. Park it (no key, no
                    // history anyway).
                    None => {
                        self.restorable_rooms.lock().insert(info.id.clone(), info);
                    }
                }
                continue;
            }
            // Encrypted GROUP rooms need a passphrase held in memory to
            // decrypt — park them as restorable for the user to re-enter.
            if info.encrypted {
                self.restorable_rooms.lock().insert(info.id.clone(), info);
                continue;
            }
            let mut members = HashSet::new();
            members.insert(our_fp.clone());
            if let Ok(stored_members) = repo::list_room_members(&self.db, &info.id) {
                for m in stored_members {
                    members.insert(m.fingerprint);
                }
            }
            let member_count = members.len() as u32;
            self.active_rooms.lock().insert(
                info.id.clone(),
                ActiveRoom {
                    info: info.clone(),
                    crypto: None,
                    passphrase_key: None,
                    members,
                    typers: HashMap::new(),
                    read_only: false,
                    issued_codes: Vec::new(),
                    dm_kem_ciphertext: None,
                    dm_is_hybrid: false,
                    dm_key_retry: 0,
                },
            );
            self.network.subscribe_room(info.id.clone()).await;
            self.announce_room_now(&info, member_count).await;
            info!(room_id = %info.id, name = %info.name, "restored room");
        }
        if count > 0 {
            debug!(count, "restored rooms from db");
        }
    }

    /// Leave a room. Returns `true` when the `MemberLeave` notice was
    /// handed to the network layer, `false` when it couldn't be encoded
    /// (peers then only notice via the discovered-room TTL). The local
    /// leave always succeeds regardless.
    pub async fn leave_room(&self, room_id: &str) -> Result<bool> {
        // Broadcast a signed leave notice before unsubscribing. huddle
        // 0.7.11: MemberLeave is now signed so peers can't spoof another
        // member's leave to evict them from honest rosters.
        let leave_msg = RoomMessage::MemberLeave {
            sender_fingerprint: self.identity.fingerprint().to_string(),
            // huddle 2.0.3 (audit N-M2): bind the room to this signed leave.
            room_id: Some(room_id.to_string()),
        };
        let dispatched = match crate::crypto::sign_message(&self.identity, &leave_msg)
            .map_err(HuddleError::from)
            .and_then(|env| {
                crate::network::protocol::encode_wire_signed(&env)
                    .map_err(|e| HuddleError::Session(format!("encode signed leave: {e}")))
            }) {
            Ok(bytes) => {
                self.network
                    .publish_room_message(room_id.to_string(), bytes)
                    .await;
                true
            }
            Err(e) => {
                warn!(%e, %room_id, "failed to sign+encode MemberLeave notice");
                false
            }
        };

        self.active_rooms.lock().remove(room_id);
        self.network.unsubscribe_room(room_id.to_string()).await;

        let _ = self.app_event_tx.send(AppEvent::RoomLeft {
            room_id: room_id.to_string(),
        });
        Ok(dispatched)
    }

    /// Send a top-level message to a room. huddle 2.0.0 (F10): mints a stable
    /// `client_msg_id` so the message can later be reacted to / edited / deleted
    /// / replied to across peers.
    pub async fn send_room_message(&self, room_id: &str, body: &str) -> Result<()> {
        self.send_room_message_inner(room_id, body, None).await
    }

    /// huddle 2.0.0 (F10): send a reply to an existing message. `reply_to` is the
    /// `client_msg_id` of the message being replied to (the target may itself be
    /// a pre-2.0 message with no id or a since-deleted one — the UI degrades to a
    /// plain message then). Otherwise identical to [`send_room_message`].
    pub async fn send_reply(&self, room_id: &str, body: &str, reply_to: &str) -> Result<()> {
        self.send_room_message_inner(room_id, body, Some(reply_to))
            .await
    }

    /// Shared send path for top-level messages and replies. Mints the
    /// `client_msg_id`, encrypts (or not), publishes, persists with the id +
    /// `reply_to`, and — huddle 2.0.0 (F4) — rotates the outbound Megolm epoch
    /// after the configured message/age threshold, re-sharing the fresh session
    /// key via a `MemberAnnounce`.
    async fn send_room_message_inner(
        &self,
        room_id: &str,
        body: &str,
        reply_to: Option<&str>,
    ) -> Result<()> {
        let our_fp = self.identity.fingerprint().to_string();
        let client_msg_id = new_client_msg_id();
        // F4: read the rotation policy before taking the active_rooms lock (it
        // touches the DB) so we never nest the DB lock under active_rooms.
        let policy = self.megolm_rotation_policy();
        let (msg, needs_rotation) = {
            let mut rooms = self.active_rooms.lock();
            let room = rooms
                .get_mut(room_id)
                .ok_or_else(|| HuddleError::Other(format!("not in room {room_id}")))?;

            if room.read_only {
                return Err(HuddleError::Other(
                    "this room is read-only — you joined via code without the passphrase. Ask an owner for the passphrase or wait for a key rotation that includes you.".into(),
                ));
            }

            if room.info.encrypted {
                let crypto = room
                    .crypto
                    .as_mut()
                    .ok_or_else(|| HuddleError::Session("encrypted room missing crypto".into()))?;
                let (session_id, ct_bytes) = crypto.encrypt(body.as_bytes())?;
                // F4: the message we're about to send used `session_id` (the
                // current epoch). Decide rotation AFTER the encrypt so the
                // counter includes this message; rotate the outbound session
                // in-place (sync) and re-announce the fresh key below, after we
                // publish this message under the old session the peers can decrypt.
                let needs_rotation = policy.is_enabled() && crypto.should_rotate(&policy);
                let msg = RoomMessage::Encrypted {
                    sender_fingerprint: our_fp.clone(),
                    session_id,
                    ciphertext_b64: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &ct_bytes,
                    ),
                    client_msg_id: Some(client_msg_id.clone()),
                    reply_to: reply_to.map(|s| s.to_string()),
                };
                if needs_rotation {
                    if let Err(e) = crypto.rotate_outbound() {
                        // Non-fatal: the message still goes out on the old epoch;
                        // we just didn't advance. The time/count trigger will fire
                        // again on the next send or heartbeat.
                        warn!(%e, %room_id, "F4: scheduled Megolm rotation failed");
                    }
                }
                // F4: persist the (possibly post-rotation) epoch bookkeeping so
                // the count/age schedule survives a restart instead of resetting
                // to zero. This is the after-each-encrypt save the policy relies
                // on; rehydrated via `rehydrate_rotation_state` after load.
                self.persist_rotation_state(crypto);
                (msg, needs_rotation)
            } else {
                // Plaintext rooms have no Megolm session to rotate.
                let msg = RoomMessage::Plain {
                    sender_fingerprint: our_fp.clone(),
                    body: body.to_string(),
                    client_msg_id: Some(client_msg_id.clone()),
                    reply_to: reply_to.map(|s| s.to_string()),
                };
                (msg, false)
            }
        };

        let bytes = encode_wire(&msg)?;
        self.network
            .publish_room_message(room_id.to_string(), bytes)
            .await;

        // F4: share the post-rotation session key. Done AFTER the message above
        // so peers receive (old-session message, then new-session announce) in
        // order — the rotation is forward-only, so they keep the old inbound
        // session to decrypt the message we just sent.
        if needs_rotation {
            if let Err(e) = self.broadcast_member_announce(room_id).await {
                warn!(%e, %room_id, "F4: post-rotation MemberAnnounce failed");
            } else {
                info!(%room_id, "F4: rotated outbound Megolm epoch and re-announced");
            }
        }

        let now = now_unix();
        let msg_id = repo::insert_room_message(
            &self.db,
            room_id,
            &our_fp,
            "out",
            body,
            now,
            Some(client_msg_id.as_str()),
            reply_to,
        )?;
        repo::update_room_last_active(&self.db, room_id, now)?;

        let _ = self.app_event_tx.send(AppEvent::MessageSent {
            room_id: room_id.to_string(),
            body: body.to_string(),
            message_id: msg_id,
        });

        Ok(())
    }

    /// huddle 2.0.0 (F4): the scheduled forward-only Megolm rotation policy,
    /// read from `app_settings` (`megolm_rotation_max_messages`,
    /// `megolm_rotation_max_hours`) and defaulting to the blueprint's 1000
    /// messages / 24 hours when unset or unparsable. A `0` for either bound
    /// disables that trigger; both `0` disables scheduled rotation entirely
    /// (pre-2.0.0 behaviour).
    pub(crate) fn megolm_rotation_policy(&self) -> crate::crypto::megolm::RotationPolicy {
        use crate::crypto::megolm::RotationPolicy;
        let max_messages = repo::get_setting(&self.db, "megolm_rotation_max_messages")
            .ok()
            .flatten()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(RotationPolicy::DEFAULT_MAX_MESSAGES);
        let max_hours = repo::get_setting(&self.db, "megolm_rotation_max_hours")
            .ok()
            .flatten()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(RotationPolicy::DEFAULT_MAX_HOURS);
        RotationPolicy::from_messages_and_hours(max_messages, max_hours)
    }

    /// huddle 2.0.0 (F4): persist a room's live outbound epoch bookkeeping
    /// (`messages_since_rotation`, `last_rotation_at`) to the durable
    /// `room_megolm_rotation_state` table. Called after each encrypt and after
    /// every rotation so the scheduled-rotation timing survives a restart
    /// (paired with `rehydrate_rotation_state` at the `RoomCrypto::load` sites).
    /// Best-effort: a failed write only means the counter falls back to its
    /// last persisted value next launch — it never blocks sending.
    pub(crate) fn persist_rotation_state(&self, crypto: &RoomCrypto) {
        if let Err(e) = repo::set_megolm_rotation_state(
            &self.db,
            crypto.room_id(),
            crypto.our_fingerprint(),
            crypto.messages_since_rotation(),
            crypto.last_rotation_at(),
        ) {
            warn!(%e, room_id = %crypto.room_id(), "F4: persist Megolm rotation state failed");
        }
    }

    /// huddle 2.0.0 (F4): rehydrate a freshly-`load`ed `RoomCrypto`'s epoch
    /// bookkeeping from `room_megolm_rotation_state`. `RoomCrypto::load` only
    /// restores the Megolm ratchet, so without this the message counter and
    /// epoch start reset to 0/now every launch and the rotation schedule never
    /// converges across restarts (a room most of the way to its message cap
    /// would start counting from zero again). No-op when no row exists yet (a
    /// never-sent room keeps the fresh 0/now baseline).
    pub(crate) fn rehydrate_rotation_state(&self, crypto: &mut RoomCrypto) {
        match repo::get_megolm_rotation_state(&self.db, crypto.room_id(), crypto.our_fingerprint())
        {
            Ok(Some((count, at))) => crypto.restore_rotation_state(count, at),
            Ok(None) => {}
            Err(e) => {
                warn!(%e, room_id = %crypto.room_id(), "F4: restore Megolm rotation state failed")
            }
        }
    }

    /// huddle 2.0.0 (F4): the current scheduled-rotation config as
    /// `(max_messages, max_hours)` for Settings → Encryption to display.
    pub fn megolm_rotation_config(&self) -> (u32, i64) {
        let p = self.megolm_rotation_policy();
        (p.max_messages, p.max_age_secs / 3600)
    }

    /// huddle 2.0.0 (F4): set the message-count rotation threshold (0 disables
    /// the count trigger). Persisted to `app_settings`.
    pub fn set_megolm_rotation_max_messages(&self, n: u32) -> Result<()> {
        repo::set_setting(&self.db, "megolm_rotation_max_messages", &n.to_string())
    }

    /// huddle 2.0.0 (F4): set the age rotation threshold in hours (0 disables
    /// the time trigger). Persisted to `app_settings`.
    pub fn set_megolm_rotation_max_hours(&self, hours: i64) -> Result<()> {
        repo::set_setting(
            &self.db,
            "megolm_rotation_max_hours",
            &hours.max(0).to_string(),
        )
    }

    // -------------------------------------------------------------------
    // huddle 2.0.0 (F10): reactions, edits, deletes
    // -------------------------------------------------------------------

    /// All reactions currently stored for a room (oldest first), for the UI to
    /// group by `target_client_msg_id` into per-emoji counts.
    pub fn room_reactions(&self, room_id: &str) -> Vec<repo::StoredReaction> {
        repo::list_room_reactions(&self.db, room_id).unwrap_or_default()
    }

    /// huddle 2.0.0 (F10): react to a message. `removed = false` adds the emoji,
    /// `true` toggles it off. Signs + broadcasts a `Reaction` and applies it
    /// locally so our own badge updates immediately. `target_msg_id` is the
    /// message's `client_msg_id`.
    pub async fn send_reaction(
        &self,
        room_id: &str,
        target_msg_id: &str,
        emoji: &str,
        removed: bool,
    ) -> Result<()> {
        let our_fp = self.identity.fingerprint().to_string();
        // huddle 2.0.0 (F10): only react to a message we actually hold in this
        // room. Without this guard a stray `client_msg_id` would store an
        // orphan reaction locally and broadcast a signed `Reaction` that every
        // peer drops anyway — inbound reactions are validated the same way (see
        // the `RoomMessage::Reaction` handler). Mirrors `edit_message`.
        repo::find_message_by_client_id(&self.db, room_id, target_msg_id)?
            .ok_or_else(|| HuddleError::Other("reaction target message not found".into()))?;
        let msg = RoomMessage::Reaction {
            sender_fingerprint: our_fp.clone(),
            target_msg_id: target_msg_id.to_string(),
            emoji: emoji.to_string(),
            removed,
        };
        let env = crate::crypto::sign_message(&self.identity, &msg)?;
        let bytes = crate::network::protocol::encode_wire_signed(&env)?;
        self.network
            .publish_room_message(room_id.to_string(), bytes)
            .await;
        if removed {
            repo::remove_reaction(&self.db, room_id, target_msg_id, &our_fp, emoji)?;
        } else {
            repo::add_reaction(&self.db, room_id, target_msg_id, &our_fp, emoji, now_unix())?;
        }
        let _ = self.app_event_tx.send(AppEvent::ReactionAdded {
            room_id: room_id.to_string(),
            message_id: target_msg_id.to_string(),
            sender_fingerprint: our_fp,
            emoji: emoji.to_string(),
            removed,
        });
        Ok(())
    }

    /// huddle 2.0.0 (F10): edit the body of a message we sent (or, as a room
    /// owner, anyone's). For encrypted rooms the new body is re-encrypted under
    /// our outbound Megolm session; for plaintext rooms it rides in the clear.
    /// Applied locally + broadcast as a signed `Edit` (last-write-wins).
    pub async fn edit_message(
        &self,
        room_id: &str,
        target_msg_id: &str,
        new_body: &str,
    ) -> Result<()> {
        let our_fp = self.identity.fingerprint().to_string();
        let target = repo::find_message_by_client_id(&self.db, room_id, target_msg_id)?
            .ok_or_else(|| HuddleError::Other("edit target message not found".into()))?;
        if target.sender_fingerprint != our_fp && !self.we_are_owner(room_id) {
            return Err(HuddleError::Other(
                "not authorized to edit this message (not the sender or a room owner)".into(),
            ));
        }
        let encrypted = self
            .active_room_info(room_id)
            .map(|r| r.encrypted)
            .unwrap_or(false);
        let (new_ciphertext_b64, session_id, new_body_field) = if encrypted {
            let mut rooms = self.active_rooms.lock();
            let room = rooms
                .get_mut(room_id)
                .ok_or_else(|| HuddleError::Other(format!("not in room {room_id}")))?;
            let crypto = room
                .crypto
                .as_mut()
                .ok_or_else(|| HuddleError::Session("encrypted room missing crypto".into()))?;
            // huddle 2.0.0 (F10): carry the exact session we encrypt under so the
            // receiver decrypts the edit like an `Encrypted` body — no in-memory
            // "last inbound session" guess (which broke across rotation/restart).
            let (session_id, ct) = crypto.encrypt(new_body.as_bytes())?;
            (B64.encode(&ct), session_id, None)
        } else {
            (String::new(), String::new(), Some(new_body.to_string()))
        };
        let msg = RoomMessage::Edit {
            sender_fingerprint: our_fp.clone(),
            target_msg_id: target_msg_id.to_string(),
            new_ciphertext_b64,
            session_id,
            new_body: new_body_field,
        };
        let env = crate::crypto::sign_message(&self.identity, &msg)?;
        let bytes = crate::network::protocol::encode_wire_signed(&env)?;
        self.network
            .publish_room_message(room_id.to_string(), bytes)
            .await;
        repo::apply_message_edit(&self.db, room_id, target_msg_id, new_body, now_unix_ms())?;
        let _ = self.app_event_tx.send(AppEvent::MessageEdited {
            room_id: room_id.to_string(),
            message_id: target_msg_id.to_string(),
            editor_fingerprint: our_fp,
            new_body: new_body.to_string(),
        });
        Ok(())
    }

    /// huddle 2.0.0 (F10): delete (tombstone) a message we sent (or, as a room
    /// owner, anyone's). Broadcast as a signed `Delete`; the body is blanked
    /// everywhere and rendered as `[deleted]`.
    pub async fn delete_message(&self, room_id: &str, target_msg_id: &str) -> Result<()> {
        let our_fp = self.identity.fingerprint().to_string();
        let target = repo::find_message_by_client_id(&self.db, room_id, target_msg_id)?
            .ok_or_else(|| HuddleError::Other("delete target message not found".into()))?;
        if target.sender_fingerprint != our_fp && !self.we_are_owner(room_id) {
            return Err(HuddleError::Other(
                "not authorized to delete this message (not the sender or a room owner)".into(),
            ));
        }
        let msg = RoomMessage::Delete {
            sender_fingerprint: our_fp.clone(),
            target_msg_id: target_msg_id.to_string(),
        };
        let env = crate::crypto::sign_message(&self.identity, &msg)?;
        let bytes = crate::network::protocol::encode_wire_signed(&env)?;
        self.network
            .publish_room_message(room_id.to_string(), bytes)
            .await;
        repo::mark_message_deleted(&self.db, room_id, target_msg_id, now_unix_ms())?;
        let _ = self.app_event_tx.send(AppEvent::MessageDeleted {
            room_id: room_id.to_string(),
            message_id: target_msg_id.to_string(),
            deleter_fingerprint: our_fp,
        });
        Ok(())
    }

    // -------------------------------------------------------------------
    // huddle 2.0.0 (F9): disappearing messages — per-room TTL
    // -------------------------------------------------------------------

    /// The room's disappearing-messages TTL in seconds, or `None` when OFF.
    pub fn room_disappearing_ttl(&self, room_id: &str) -> Option<u32> {
        repo::get_room_disappearing_ttl(&self.db, room_id)
            .ok()
            .flatten()
    }

    /// huddle 2.0.0 (F9): set (or clear, with `None`) the room's
    /// disappearing-messages TTL. Persists locally, then broadcasts a signed
    /// `RoomSetting` so other members adopt it. Honest receivers apply it only
    /// when we're the room creator or an owner; the pruner then auto-deletes
    /// expired messages locally on every peer.
    pub async fn set_room_disappearing_ttl(
        &self,
        room_id: &str,
        ttl_secs: Option<u32>,
    ) -> Result<()> {
        repo::set_room_disappearing_ttl(&self.db, room_id, ttl_secs)?;
        let our_fp = self.identity.fingerprint().to_string();
        let msg = RoomMessage::RoomSetting {
            sender_fingerprint: our_fp,
            disappearing_ttl_secs: ttl_secs.map(u64::from).unwrap_or(0),
            // huddle 2.0.3 (audit N-M2): bind the room so the signed setting
            // can't be replayed onto another room's topic by a hostile relay.
            room_id: Some(room_id.to_string()),
        };
        let env = crate::crypto::sign_message(&self.identity, &msg)?;
        let bytes = crate::network::protocol::encode_wire_signed(&env)?;
        self.network
            .publish_room_message(room_id.to_string(), bytes)
            .await;
        let _ = self.app_event_tx.send(AppEvent::RoomTtlChanged {
            room_id: room_id.to_string(),
            ttl_secs,
        });
        Ok(())
    }
}
