//! `AppHandle` dialing, known-peers, contacts, connect-codes and friend-request
//! methods. Split out of the `app/mod.rs` god file (huddle 2.1.x maintainability
//! refactor) as an additional inherent `impl AppHandle` block.

use super::*;

impl AppHandle {
    // -------------------------------------------------------------------
    // Dial / known peers
    // -------------------------------------------------------------------

    /// Dial a peer by a user-entered address. Accepts:
    /// - `1.2.3.4:9000`
    /// - `[fe80::1]:9000`
    /// - `/ip4/.../tcp/...[/p2p/<peer>]` (raw multiaddr)
    /// huddle 0.5.1: resolve an HD- ID or username back to a dialable
    /// multiaddr and dial it.
    ///
    /// `input` is matched against, in order:
    /// 1. an `HD-XXXX-...` prefixed string → strip prefix + lowercase to
    ///    canonical fingerprint;
    /// 2. a raw 24-char hex run (with or without dashes) → group into
    ///    4-char blocks and lowercase;
    /// 3. otherwise → treat as a username and look up `peer_profiles`.
    ///
    /// Resolution to an address: scan `discovered_rooms` for a room
    /// whose `creator_fingerprint` matches; take the first `host_addrs`
    /// entry. Falls back to the `known_peers` table for users we've
    /// dialed before. Both paths require we've seen the peer on our
    /// gossipsub mesh or dialed them before — bare-ID dialing on a
    /// cold mesh is fundamentally impossible without a routing layer
    /// huddle deliberately doesn't run (DHT, central directory). For
    /// cross-internet first contact, paste an invite link instead.
    pub async fn dial_by_id_or_username(&self, input: &str) -> Result<()> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(HuddleError::Other("input is empty".into()));
        }
        let target_fp = if let Some(fp) = normalize_to_fingerprint(trimmed) {
            fp
        } else {
            let matches = repo::find_peers_by_username(&self.db, trimmed)?;
            if matches.is_empty() {
                return Err(HuddleError::Other(format!(
                    "no peer named `{}` known yet — paste their invite link instead",
                    trimmed
                )));
            }
            if matches.len() > 1 {
                return Err(HuddleError::Other(format!(
                    "username `{}` is ambiguous ({} peers share it) — use their HD- ID instead",
                    trimmed,
                    matches.len()
                )));
            }
            matches.into_iter().next().unwrap()
        };
        if target_fp == self.identity.fingerprint() {
            return Err(HuddleError::Other("that's your own ID".into()));
        }
        let candidates = self.resolve_dial_addrs(&target_fp);
        if candidates.is_empty() {
            return Err(HuddleError::Other(format!(
                "haven't seen `{}` on the network yet — ask them for an invite link",
                short_fp_for_msg(&target_fp)
            )));
        }
        // Pre-record every candidate so the lobby's known-peers panel
        // surfaces them even before the post-identify handler lands.
        // We bind each address to the resolved fingerprint so the
        // post-identify trust upgrade has the same fp to confirm.
        let now = now_unix();
        for addr in &candidates {
            let _ = repo::upsert_known_peer(
                &self.db,
                &KnownPeer {
                    address: addr.clone(),
                    label: None,
                    last_connected_at: None,
                    last_attempt_at: Some(now),
                    created_at: now,
                    fingerprint: Some(target_fp.clone()),
                    trusted: false,
                },
            );
        }
        // Parse to Multiaddrs, drop any that don't lex. Empty after
        // parsing would mean every candidate is malformed — unlikely
        // but defended-against.
        let multiaddrs: Vec<Multiaddr> = candidates
            .iter()
            .filter_map(|s| s.parse::<Multiaddr>().ok())
            .collect();
        if multiaddrs.is_empty() {
            return Err(HuddleError::Other(
                "every known address for that peer is malformed".into(),
            ));
        }
        let _ = self.app_event_tx.send(AppEvent::Dialing {
            address: candidates[0].clone(),
        });
        info!(
            target_fp = %target_fp,
            n = multiaddrs.len(),
            "dialing peer with {} candidate addresses",
            multiaddrs.len()
        );
        // huddle 0.7.7: user-initiated dial — register every candidate
        // canonical address so whichever wins the libp2p race triggers
        // the post-identify auto-DM. Reset & insert under one lock.
        {
            let mut pending = self.pending_auto_dm_addrs.lock();
            for m in &multiaddrs {
                pending.insert(m.to_string());
            }
        }
        self.network.dial_addresses(multiaddrs).await;
        Ok(())
    }

    /// huddle 0.5.2: every dialable multiaddr we know for `fingerprint`,
    /// sorted by transport preference so libp2p's parallel dialer races
    /// the cheapest paths first. Order: RFC1918 LAN ip4 → loopback (for
    /// tests) → public ip4 → ip6 / dns → relay-hopped (`/p2p-circuit`)
    /// last. libp2p races them concurrently anyway — sorting just
    /// gives the first-attempted slot to the address most likely to
    /// win on a tie.
    fn resolve_dial_addrs(&self, fingerprint: &str) -> Vec<String> {
        let mut set: std::collections::HashSet<String> = std::collections::HashSet::new();
        for room in self.discovered_rooms.lock().values() {
            if room.creator_fingerprint == fingerprint {
                for addr in &room.host_addrs {
                    set.insert(addr.clone());
                }
            }
        }
        if let Ok(known) = repo::list_known_peers(&self.db) {
            for peer in known {
                if peer.fingerprint.as_deref() == Some(fingerprint) {
                    set.insert(peer.address);
                }
            }
        }
        let mut v: Vec<String> = set.into_iter().collect();
        v.sort_by_key(|a| address_preference(a));
        v
    }

    pub async fn dial(&self, input: &str) -> Result<()> {
        let multiaddr = parse_dial_address(input)?;
        let canonical = multiaddr.to_string();
        // huddle 0.7.7: user-initiated entry point. Register the address
        // so the post-Identify handler auto-opens a DM with the peer.
        // The auto-reconnector goes through `dial_internal` instead and
        // therefore does NOT trigger an auto-DM on every startup.
        self.pending_auto_dm_addrs.lock().insert(canonical.clone());
        self.dial_internal(canonical, multiaddr).await
    }

    /// huddle 0.7.7: shared dial body used by the public `dial()` entry
    /// point and by internal reconnect paths. The two callers differ
    /// only in whether they register the address for auto-DM-after-
    /// identify; internal paths (startup reconnector, host-addr
    /// opportunistic dial) do not.
    pub(crate) async fn dial_internal(
        &self,
        canonical: String,
        multiaddr: Multiaddr,
    ) -> Result<()> {
        info!(%canonical, "dialing");
        repo::upsert_known_peer(
            &self.db,
            &KnownPeer {
                address: canonical.clone(),
                label: None,
                last_connected_at: None,
                last_attempt_at: Some(now_unix()),
                created_at: now_unix(),
                // Fingerprint isn't known until Identify lands after the
                // dial completes; the connection-success handler upserts
                // again with the fingerprint and trusted=true.
                fingerprint: None,
                trusted: false,
            },
        )?;

        let _ = self.app_event_tx.send(AppEvent::Dialing {
            address: canonical.clone(),
        });
        self.network.dial(multiaddr).await;
        Ok(())
    }

    /// Phase D follow-up: snapshot of the NAT reachability state.
    /// Returns the addresses AutoNAT has confirmed as externally
    /// reachable in this session. The lobby renders an emoji badge
    /// from this — non-empty ⇒ 'reachable', empty ⇒ 'LAN only'.
    pub fn nat_reachable_addrs(&self) -> Vec<String> {
        self.nat_reachable_addrs.lock().iter().cloned().collect()
    }

    /// Phase D follow-up: addresses suitable for putting on the wire
    /// so other peers can dial us. Union of:
    ///   - AutoNAT-confirmed external addresses (direct internet)
    ///   - active `/p2p-circuit` reservations on configured relays
    /// Capped at 4 entries to keep room announcements small.
    /// Relay-circuit addresses are listed first (they're more likely
    /// to work for NAT'd peers).
    pub fn dialable_addrs(&self) -> Vec<String> {
        let mut out: Vec<String> = self.relay_circuit_addrs.lock().iter().cloned().collect();
        for a in self.nat_reachable_addrs.lock().iter() {
            if !out.contains(a) {
                out.push(a.clone());
            }
        }
        out.truncate(4);
        out
    }

    /// Phase C follow-up: dial a peer whose multiaddr came from an
    /// invite link claiming `claimed_fp`. Behaves identically to
    /// `dial`, but additionally stashes `(canonical_addr → claimed_fp)`
    /// in `pending_invite_dials` so the `PeerIdentified` handler can
    /// assert the cryptographic fp matches the human-display one in
    /// the invite. Mismatch ⇒ disconnect + `InviteFingerprintMismatch`
    /// event.
    ///
    /// libp2p's `/p2p/<peer-id>` segment already enforces this at the
    /// transport level (and our invite generator always includes it),
    /// so this is defense in depth — but it makes the assert explicit
    /// rather than relying on a structural side effect.
    pub async fn dial_invite(&self, address: &str, claimed_fp: &str) -> Result<()> {
        let multiaddr = parse_dial_address(address)?;
        let canonical = multiaddr.to_string();
        self.pending_invite_dials
            .lock()
            .insert(canonical.clone(), claimed_fp.to_string());
        // Re-use the standard dial path so KnownPeer rows + status
        // events look identical to a plain dial.
        self.dial(address).await
    }

    /// huddle 0.7.12: pre-seed an invite's room so an immediate join
    /// works without waiting for the host's gossip announcement to
    /// arrive over the just-opened connection. Decodes the (optional)
    /// salt into `ROOM_SALT_CACHE` and inserts a `discovered_rooms`
    /// entry, so `join_room` can resolve the room's metadata AND derive
    /// the passphrase key the moment the user submits.
    ///
    /// Pre-0.7.12 the invite's `salt_b64` + room metadata were decoded
    /// and then thrown away; `join_room` could only learn the room from
    /// a live announcement, so submitting the passphrase before that
    /// announcement landed errored "room {id} not found". The invite
    /// already carries everything required — we just plumb it through.
    pub fn seed_invite_room(&self, room: &crate::invite::InviteRoom) {
        if let Some(salt) = room.salt_b64.as_deref().and_then(|b| B64.decode(b).ok()) {
            remember_room_salt(&room.id, salt);
        }
        let discovered = DiscoveredRoom {
            room_id: room.id.clone(),
            name: room.name.clone(),
            encrypted: room.encrypted,
            member_count: 0,
            creator_fingerprint: room.creator_fingerprint.clone(),
            last_seen: now_unix(),
            restorable: false,
            host_addrs: Vec::new(),
            // Invites are group-scoped — DMs are 1-1 and never invited.
            kind: RoomKind::Group,
        };
        self.discovered_rooms
            .lock()
            .insert(room.id.clone(), discovered);
    }

    pub fn known_peers(&self) -> Vec<KnownPeerStatus> {
        let connected = self.connected_dial_addrs.lock().clone();
        let stored = repo::list_known_peers(&self.db).unwrap_or_default();
        stored
            .into_iter()
            .map(|p| {
                let connected_peer = connected.get(&p.address).copied();
                KnownPeerStatus {
                    address: p.address,
                    label: p.label,
                    last_connected_at: p.last_connected_at,
                    connected_peer_id: connected_peer,
                    fingerprint: p.fingerprint,
                }
            })
            .collect()
    }

    pub async fn forget_peer(&self, address: &str) -> Result<()> {
        repo::forget_known_peer(&self.db, address)?;
        self.connected_dial_addrs.lock().remove(address);
        Ok(())
    }

    // -------------------------------------------------------------------
    // huddle 1.0: Contacts — the durable, fingerprint-keyed address book
    // -------------------------------------------------------------------

    /// Record (or refresh) a contact. Idempotent; safe to call from every
    /// relationship path (start_direct, trust_inbound, accepted requests).
    /// Caches the partner's Ed25519 pubkey when known and the canonical DM
    /// room id. Never adds ourselves.
    pub fn add_contact(&self, fingerprint: &str, source: &str) -> Result<()> {
        let our_fp = self.identity.fingerprint();
        if fingerprint == our_fp || fingerprint.is_empty() {
            return Ok(());
        }
        let dm_room_id = canonical_dm_room_id(our_fp, fingerprint);
        // huddle 1.2: route this contact's DM relay traffic by fingerprint
        // (direct delivery), not by room-membership fan-out — so DMs reach
        // them reliably even before both sides have subscribed the DM room.
        self.network
            .register_dm(dm_room_id.clone(), fingerprint.to_string());
        let pubkey = repo::lookup_peer_ed25519_pubkey(&self.db, fingerprint)
            .ok()
            .flatten();
        let now = now_unix();
        repo::upsert_contact(
            &self.db,
            &repo::Contact {
                fingerprint: fingerprint.to_string(),
                alias: None,
                ed25519_pubkey: pubkey,
                dm_room_id: Some(dm_room_id),
                source: source.to_string(),
                note: None,
                added_at: now,
                last_seen: Some(now),
            },
        )
    }

    pub fn set_contact_alias(&self, fingerprint: &str, alias: Option<&str>) -> Result<()> {
        repo::set_contact_alias(&self.db, fingerprint, alias)
    }

    pub fn remove_contact(&self, fingerprint: &str) -> Result<()> {
        repo::delete_contact(&self.db, fingerprint)
    }

    pub fn is_contact(&self, fingerprint: &str) -> bool {
        repo::is_contact(&self.db, fingerprint).unwrap_or(false)
    }

    /// The unified Contacts list: the durable address book joined with
    /// derived username / verified / trusted / reachability so the UI never
    /// has to stitch four tables together.
    pub fn list_contacts(&self) -> Vec<ContactView> {
        let our_fp = self.identity.fingerprint().to_string();
        let verified: HashSet<String> = repo::list_verified_peers(&self.db)
            .unwrap_or_default()
            .into_iter()
            .collect();
        // A peer is "LAN-connected" when any known_peer row bearing its
        // fingerprint currently maps to a live libp2p connection.
        let connected = self.connected_dial_addrs.lock().clone();
        let lan_fps: HashSet<String> = repo::list_known_peers(&self.db)
            .unwrap_or_default()
            .into_iter()
            .filter(|p| connected.contains_key(&p.address))
            .filter_map(|p| p.fingerprint)
            .collect();
        let relay_up = self.server_connected();
        repo::list_contacts(&self.db)
            .unwrap_or_default()
            .into_iter()
            .filter(|c| c.fingerprint != our_fp)
            .map(|c| {
                let lan_connected = lan_fps.contains(&c.fingerprint);
                ContactView {
                    dm_room_id: c
                        .dm_room_id
                        .clone()
                        .unwrap_or_else(|| canonical_dm_room_id(&our_fp, &c.fingerprint)),
                    username: repo::get_peer_username(&self.db, &c.fingerprint).unwrap_or(None),
                    verified: verified.contains(&c.fingerprint),
                    trusted: repo::is_fingerprint_trusted(&self.db, &c.fingerprint)
                        .unwrap_or(false),
                    reachable: lan_connected || relay_up,
                    lan_connected,
                    fingerprint: c.fingerprint,
                    alias: c.alias,
                    source: c.source,
                    added_at: c.added_at,
                    last_seen: c.last_seen,
                }
            })
            .collect()
    }

    // -------------------------------------------------------------------
    // huddle 1.0: contact requests over the relay inbox (Phase 1)
    // -------------------------------------------------------------------

    /// "Add by HD-ID" that works over the internet: publish a signed
    /// `ContactRequest` to the target's relay inbox. The target picks it up
    /// (live, or from the relay's offline mailbox) and surfaces it as a
    /// pending request to accept/decline. On the LAN, the same publish also
    /// rides gossipsub. Refuses self.
    pub async fn send_contact_request(
        &self,
        target_fingerprint: &str,
        note: Option<&str>,
    ) -> Result<()> {
        let our_fp = self.identity.fingerprint().to_string();
        if target_fingerprint == our_fp {
            return Err(HuddleError::Other("that's your own ID".into()));
        }
        // Record the target so their accept-echo is recognized as mutual (see
        // the ContactRequest receive arm) instead of re-prompting us.
        let _ = self.add_contact(target_fingerprint, "request-sent");
        let msg = RoomMessage::ContactRequest {
            requester_fingerprint: our_fp,
            display_name: repo::get_display_name(&self.db).unwrap_or(None),
            note: note.map(|s| s.to_string()),
            sender_ed25519_pubkey: Some(B64.encode(self.identity.public_bytes())),
        };
        let env = crate::crypto::sign_message(&self.identity, &msg)?;
        let bytes = crate::network::protocol::encode_wire_signed(&env)?;
        let inbox = crate::network::protocol::inbox_room_id(target_fingerprint);
        // huddle 1.2: deliver the request STRAIGHT to the target's fingerprint
        // over the relay (live, or queued in their mailbox if offline), tagged
        // with their inbox id so their client files it as a contact request.
        // This no longer depends on the target having an active inbox
        // subscription on the relay, and also rides libp2p gossipsub on the
        // inbox topic for LAN delivery.
        self.network
            .publish_direct(target_fingerprint.to_string(), inbox, bytes)
            .await;
        Ok(())
    }

    /// Inbound contact requests awaiting an accept/decline decision.
    pub fn list_pending_contact_requests(&self) -> Vec<repo::PendingContactRequest> {
        repo::list_pending_contact_requests(&self.db).unwrap_or_default()
    }

    /// Accept a pending contact request: record the contact and open the DM
    /// (idempotent on the canonical room id). Both sides converge — the
    /// requester opens the same DM when our resulting `MemberAnnounce` /
    /// announcement reaches them. Removes the pending row regardless.
    pub async fn accept_contact_request(&self, fingerprint: &str) -> Result<()> {
        repo::delete_pending_contact_request(&self.db, fingerprint)?;
        self.add_contact(fingerprint, "request")?;
        // start_direct subscribes the canonical DM room + broadcasts our
        // MemberAnnounce, making the DM live on our side.
        self.start_direct(fingerprint).await?;
        // Echo a request back to the requester's inbox so they converge: the
        // requester already has us in their address book (they initiated), so
        // their ContactRequest receive arm treats this as mutual and
        // subscribes the same DM room — essential for the relay path, where
        // our MemberAnnounce can't reach them until they're a room member.
        let _ = self.send_contact_request(fingerprint, None).await;
        Ok(())
    }

    /// huddle 1.2.1: ask the relay to mint a short-lived **connect code** bound
    /// to our identity, so a peer can add/DM us by typing the code instead of
    /// our full HD-ID. The code (and its expiry) arrive asynchronously as
    /// `AppEvent::ConnectCodeCreated`. Errors immediately if the relay isn't
    /// connected (codes are a relay feature — there's no one to mint them).
    pub fn create_connect_code(&self) -> Result<()> {
        if !self.network.create_connect_token() {
            return Err(HuddleError::Network(
                "not connected to the relay — can't create a connect code".into(),
            ));
        }
        Ok(())
    }

    /// huddle 1.2.1: redeem a connect code someone shared. The relay resolves
    /// it to their identity and we send them a contact request (which opens a
    /// DM once they accept). Progress arrives as `AppEvent::ConnectCodeRedeemed`
    /// / `ConnectCodeFailed`. Errors immediately for a malformed code or when
    /// the relay isn't connected.
    pub fn redeem_connect_code(&self, code: &str) -> Result<()> {
        let norm = normalize_connect_code(code)
            .ok_or_else(|| HuddleError::Other("that doesn't look like a connect code".into()))?;
        if !self.network.redeem_connect_token(&norm) {
            return Err(HuddleError::Network(
                "not connected to the relay — can't redeem a connect code".into(),
            ));
        }
        Ok(())
    }

    /// huddle 1.2.1: the relay resolved a connect code we redeemed. Validate the
    /// resolution, then send the owner a contact request (which opens a DM when
    /// they accept). Emits `ConnectCodeRedeemed` on success, `ConnectCodeFailed`
    /// otherwise.
    pub(crate) async fn on_connect_code_resolved(
        &self,
        fingerprint: Option<String>,
        pubkey_b64: Option<String>,
    ) {
        let our_fp = self.identity.fingerprint().to_string();
        let fp = match fingerprint {
            Some(fp) if !fp.is_empty() => fp,
            _ => {
                let _ = self.app_event_tx.send(AppEvent::ConnectCodeFailed {
                    reason: "invalid or expired connect code".into(),
                });
                return;
            }
        };
        if fp == our_fp {
            let _ = self.app_event_tx.send(AppEvent::ConnectCodeFailed {
                reason: "that's your own connect code".into(),
            });
            return;
        }
        // Integrity check: if the relay also returned the owner's pubkey, it
        // MUST hash to the fingerprint it claims — else the mapping is bogus
        // (a buggy or hostile relay). The real identity proof still comes from
        // the owner's signed reply; this just rejects an obviously-wrong map.
        if let Some(pk_b64) = pubkey_b64.as_deref() {
            if let Some(pk) = B64
                .decode(pk_b64)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            {
                if crate::identity::compute_fingerprint(&pk) != fp {
                    let _ = self.app_event_tx.send(AppEvent::ConnectCodeFailed {
                        reason: "connect code resolved to a mismatched identity".into(),
                    });
                    return;
                }
            }
        }
        match self.send_contact_request(&fp, None).await {
            Ok(()) => {
                let _ = self
                    .app_event_tx
                    .send(AppEvent::ConnectCodeRedeemed { fingerprint: fp });
            }
            Err(e) => {
                let _ = self.app_event_tx.send(AppEvent::ConnectCodeFailed {
                    reason: format!("couldn't send the request: {e}"),
                });
            }
        }
    }

    /// Decline a pending contact request. `block` also adds the requester to
    /// the persistent blocklist so they can't re-request.
    pub fn reject_contact_request(&self, fingerprint: &str, block: bool) -> Result<()> {
        repo::delete_pending_contact_request(&self.db, fingerprint)?;
        if block {
            repo::block_peer(&self.db, fingerprint, now_unix())?;
        }
        Ok(())
    }

    /// Re-dial a stored address — used by the lobby's "reconnect" action.
    pub async fn redial(&self, address: &str) -> Result<()> {
        self.dial(address).await
    }

    /// Phase A: user pressed Accept on the inbound-dial modal. Promotes
    /// the peer to the gossipsub mesh. Does NOT mark them trusted —
    /// that's `trust_inbound`, the explicit "remember and bypass next
    /// time" path.
    pub async fn accept_inbound(&self, peer_id: PeerId, address: &str) {
        self.network.accept_inbound(peer_id).await;
        self.connected_dial_addrs
            .lock()
            .insert(address.to_string(), peer_id);
    }

    /// Phase A: user pressed Reject on the inbound-dial modal. Disconnects
    /// the peer, adds them to the persistent blocklist, and ensures every
    /// subsequent connection attempt from this fingerprint is auto-
    /// dropped without re-prompting.
    pub async fn reject_inbound(&self, peer_id: PeerId, fingerprint: &str) -> Result<()> {
        self.network.reject_inbound(peer_id).await;
        repo::block_peer(&self.db, fingerprint, now_unix())?;
        Ok(())
    }

    /// Phase A: user pressed Trust+Accept — accept the connection AND
    /// remember the peer so subsequent connections bypass the modal.
    pub async fn trust_inbound(
        &self,
        peer_id: PeerId,
        fingerprint: &str,
        address: &str,
    ) -> Result<()> {
        self.network.accept_inbound(peer_id).await;
        self.connected_dial_addrs
            .lock()
            .insert(address.to_string(), peer_id);
        // Persist the row with trusted=true so future inbound from
        // this fingerprint short-circuits the modal in
        // `process_network_event`'s InboundDial handler.
        repo::upsert_known_peer(
            &self.db,
            &KnownPeer {
                address: address.to_string(),
                label: None,
                last_connected_at: Some(now_unix()),
                last_attempt_at: Some(now_unix()),
                created_at: now_unix(),
                fingerprint: Some(fingerprint.to_string()),
                trusted: true,
            },
        )?;
        // huddle 1.0: trusting a peer makes them a contact.
        let _ = self.add_contact(fingerprint, "dial");
        Ok(())
    }

    // =========================================================================
    // huddle 0.7.7: pending friend requests (3-day TTL)
    // =========================================================================

    /// Snapshot of every inbound dial we've spilled to disk but haven't
    /// yet accepted or rejected. The People pane renders this as its
    /// own section ("Pending requests (N)").
    pub fn list_pending_friend_requests(&self) -> Vec<repo::PendingFriendRequest> {
        repo::list_pending_friend_requests(&self.db).unwrap_or_default()
    }

    /// Persist an inbound request that the user didn't act on within the
    /// modal window. Called from the TUI's idle-timeout sweep; the live
    /// libp2p connection is also closed by the same path (the request
    /// is effectively rejected *for now* — accept later from People
    /// pane will re-dial the stored address).
    pub fn spill_pending_friend_request(
        &self,
        peer_id: PeerId,
        fingerprint: &str,
        address: &str,
    ) -> Result<()> {
        repo::upsert_pending_friend_request(
            &self.db,
            &repo::PendingFriendRequest {
                fingerprint: fingerprint.to_string(),
                address: address.to_string(),
                peer_id: peer_id.to_string(),
                received_at: now_unix(),
            },
        )?;
        Ok(())
    }

    /// User pressed Accept on a row in the Pending requests list. The
    /// original libp2p connection is long gone (we closed it on
    /// timeout); re-dial the stored address and mark the peer trusted
    /// so the post-Identify handler short-circuits the modal. The
    /// row is removed regardless of dial success — a failed dial is
    /// still a positive intent we don't want to keep re-prompting on.
    pub async fn accept_pending_friend_request(&self, fingerprint: &str) -> Result<()> {
        let mut chosen_addr: Option<String> = None;
        for req in self.list_pending_friend_requests() {
            if req.fingerprint == fingerprint {
                chosen_addr = Some(req.address);
                break;
            }
        }
        repo::delete_pending_friend_requests_for_fp(&self.db, fingerprint)?;
        // huddle 1.0: accepting a friend request makes them a contact.
        let _ = self.add_contact(fingerprint, "request");
        if let Some(addr) = chosen_addr {
            // Pre-mark trusted so the upcoming Identify handler skips
            // the inbound-dial modal. Matches the semantics of
            // `trust_inbound` without needing a live PeerId.
            repo::upsert_known_peer(
                &self.db,
                &KnownPeer {
                    address: addr.clone(),
                    label: None,
                    last_connected_at: None,
                    last_attempt_at: Some(now_unix()),
                    created_at: now_unix(),
                    fingerprint: Some(fingerprint.to_string()),
                    trusted: true,
                },
            )?;
            // User-initiated — register for auto-DM on connect.
            self.dial(&addr).await?;
        }
        Ok(())
    }

    /// User pressed Reject on a row in the Pending requests list.
    /// Mirrors `reject_inbound` semantics: delete the pending row(s)
    /// AND block the fingerprint so any future dial from this peer is
    /// auto-dropped without re-prompting.
    pub fn reject_pending_friend_request(&self, fingerprint: &str) -> Result<()> {
        repo::delete_pending_friend_requests_for_fp(&self.db, fingerprint)?;
        repo::block_peer(&self.db, fingerprint, now_unix())?;
        Ok(())
    }

    /// huddle 0.7.7: close a live libp2p connection without blocking the
    /// peer. Used by the TUI's 15s InboundDial timeout — we need to
    /// drop the dangling socket, but blocking the peer would
    /// contradict "save the request for 3 days, let the user decide
    /// later." `reject_inbound` is the right call when the user
    /// *explicitly* clicks Reject.
    pub async fn disconnect_peer(&self, peer_id: PeerId) {
        self.network.disconnect_peer(peer_id).await;
    }
}
