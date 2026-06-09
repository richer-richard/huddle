use libp2p::PeerId;

use crate::storage::repo::RoomKind;

#[derive(Debug, Clone)]
pub struct DiscoveredRoom {
    pub room_id: String,
    pub name: String,
    pub encrypted: bool,
    pub member_count: u32,
    pub creator_fingerprint: String,
    pub last_seen: i64,
    /// True for rooms loaded from local storage that we haven't rejoined
    /// yet this session (encrypted rooms whose passphrase key isn't in
    /// memory). The lobby renders these with a "saved" hint; pressing
    /// Enter goes through the join flow with passphrase prompt.
    pub restorable: bool,
    /// huddle 0.5.1: cached host multiaddrs from the announcing peer's
    /// `RoomAnnouncement.host_addrs`. Used by `dial_by_id_or_username`
    /// to resolve an HD- ID or username back to a dialable address
    /// when the target is on our gossipsub mesh.
    pub host_addrs: Vec<String>,
    /// huddle 0.7: routing hint for the sidebar — `Direct` lands in the
    /// "Direct messages" section, `Group` in "Group rooms". The
    /// `discovered_rooms()` accessor filters out Direct entries whose
    /// two members don't include us, so a DM never leaks into a third
    /// party's sidebar.
    pub kind: RoomKind,
}

#[derive(Debug, Clone)]
pub enum AppEvent {
    /// A room was discovered (announced on the global topic).
    RoomDiscovered(DiscoveredRoom),
    /// A previously-discovered room hasn't been re-announced — TTL expired.
    RoomLost { room_id: String },
    /// We successfully joined a room (subscribed to its topic).
    RoomJoined { room_id: String },
    /// We left a room.
    RoomLeft { room_id: String },
    /// A new member appeared in a room we're in.
    MemberJoined {
        room_id: String,
        fingerprint: String,
    },
    /// A member left a room we're in.
    MemberLeft {
        room_id: String,
        fingerprint: String,
    },
    /// A message arrived in a room.
    MessageReceived {
        room_id: String,
        sender_fingerprint: String,
        body: String,
        sent_at: i64,
    },
    /// Our own message was sent successfully.
    MessageSent {
        room_id: String,
        body: String,
        message_id: i64,
    },
    /// Listening on a network address.
    ListeningOn { address: String },
    /// A peer was discovered on the LAN.
    PeerDiscovered { peer_id: PeerId },
    /// A peer's mDNS presence expired — they left the LAN or stopped
    /// announcing. The lobby refreshes its online/offline indicators.
    PeerExpired { peer_id: PeerId },
    /// We've fired a dial command — useful for the UI to show "dialing...".
    Dialing { address: String },
    /// A user-initiated dial completed successfully.
    DialSucceeded { address: String, peer_id: PeerId },
    /// A user-initiated dial failed.
    DialFailed { address: String, error: String },
    /// Non-fatal error.
    Error { description: String },
    /// Someone (us or a peer) offered a file in a room.
    FileOffered {
        room_id: String,
        file_id: String,
        name: String,
        size_bytes: u64,
        sender_fingerprint: String,
    },
    /// A chunk of an incoming transfer arrived. `total_bytes` is the
    /// announced size from the offer.
    FileProgress {
        file_id: String,
        bytes_received: u64,
        total_bytes: u64,
    },
    /// All chunks of a transfer received and SHA-256 verified.
    FileReady { file_id: String },
    /// User saved a ready file to Downloads.
    FileSaved { file_id: String, path: String },
    /// A transfer failed (hash mismatch, decrypt error, IO error).
    FileFailed { file_id: String, reason: String },
    /// A peer initiated a key rotation in a room we're in. The UI
    /// surfaces a modal asking the user to enter the new passphrase.
    RotationRequested {
        room_id: String,
        rotator_fingerprint: String,
        new_salt: Vec<u8>,
    },
    /// Someone in a room started typing. The UI re-reads typing peers
    /// from `AppHandle::typers_in_room` on each render; the event is
    /// just a nudge.
    TypingChanged { room_id: String },
    /// A received message included our fingerprint (full or short
    /// form). The TUI uses this to ring the terminal bell, even in
    /// muted rooms.
    MentionReceived { room_id: String, body: String },
    /// Phase A: an unknown peer has dialed us and Identify has
    /// completed. The TUI shows an accept/reject/trust modal with the
    /// peer's short fingerprint. Routed through `replace_modal_if_idle`
    /// so it doesn't clobber whatever the user is typing.
    InboundDial {
        peer_id: PeerId,
        /// 24-char fingerprint, freshly derived from the peer's Ed25519
        /// pubkey via Identify — proves they hold the matching key.
        fingerprint: String,
        /// String form of the listener-side multiaddr (the address as
        /// seen from our side of the connection). Mostly informational
        /// for the user; we persist it on accept so the lobby online
        /// dot tracks the peer.
        address: String,
    },
    /// Phase G: SAS code is ready on both sides — both ephemeral
    /// X25519 pubkeys exchanged + ECDH derived. The TUI shows the SAS
    /// as its word list (`emoji_labels`) + `decimal` and the
    /// Match/Cancel buttons. huddle 0.9: the glyph form was dropped from
    /// the UI (emoji-free), so it's no longer carried here.
    SasCodeReady {
        room_id: String,
        partner_fingerprint: String,
        tx_id: String,
        emoji_labels: String,
        decimal: String,
    },
    /// Phase G: SAS completed — both sides confirmed the match. The
    /// partner's fingerprint is now verified (per-room + global).
    SasVerified {
        room_id: String,
        partner_fingerprint: String,
    },
    /// Phase F follow-up: 30 seconds passed since we broadcast a
    /// `CodeJoinRequest` and no `CodeJoinResponse` ever came back. The
    /// owner either ignored us (bad/expired code), wasn't online, or
    /// the network dropped our packet. Fired by the timeout task
    /// spawned in `join_room_with_code` once it confirms our pending
    /// secret is still sitting in the map.
    CodeJoinTimedOut { room_id: String, reason: String },
    /// Phase C follow-up: we dialed a peer via an invite link, the
    /// peer identified, and the fingerprint they cryptographically
    /// asserted doesn't match the one the invite claimed. The
    /// connection has already been dropped. The TUI shows an error
    /// modal so the user knows the link is forged or stale.
    InviteFingerprintMismatch {
        address: String,
        claimed: String,
        actual: String,
    },
    /// Phase D follow-up: aggregated NAT reachability state derived
    /// from the AutoNAT probe stream. The app layer maintains a small
    /// "do any probes say reachable?" tally; this event fires when
    /// that aggregate changes. The TUI renders it as a badge in the
    /// lobby header ('reachable' / 'private' / 'detecting').
    NatStatusChanged { label: String, reachable: bool },
    /// Phase D follow-up: a successful DCUtR upgrade — a relay-hopped
    /// connection became direct. The TUI shows a transient status
    /// line ("direct connection to <peer>"). Fires only on success;
    /// failures stay in the debug log.
    DcutrSucceeded { peer_label: String },
    /// huddle 0.5: a peer announced or cleared their self-declared
    /// username via a signed `ProfileUpdate`. `username = None` means
    /// the peer is now `[anonymous]`. TUI consumers redraw the chat
    /// + member list so the new label flows through.
    PeerProfileUpdated {
        fingerprint: String,
        username: Option<String>,
    },
    /// huddle 0.5: the local user's `go_dark` call succeeded — every
    /// joined room got a best-effort `MemberLeave`, the network task
    /// shut down, and the data dir was wiped. TUI shows a final
    /// "Goodbye" modal and exits the process.
    WentDark,
    /// huddle 0.7.7: a user-initiated dial (`d` / `a` / paste-invite /
    /// People-pane reconnect) connected, Identify completed, and we've
    /// idempotently opened a DM with the freshly-identified peer. The
    /// TUI listens for this and switches its pane to `Dm(room_id)` so
    /// the user lands in a chat surface instead of having to hunt for
    /// a way to message the peer they just dialed.
    ///
    /// Auto-reconnects on startup do NOT fire this — we consume the
    /// address from `pending_auto_dm_addrs` and only the user-initiated
    /// paths register there in the first place.
    AutoOpenDm {
        room_id: String,
        fingerprint: String,
    },
    /// huddle 1.0: a signed `ContactRequest` arrived on our relay inbox
    /// from a peer we haven't added yet (the "add by HD-ID over the
    /// internet" path). The TUI surfaces it in the Contacts pane's Requests
    /// section to accept (opens a DM) or decline. Mutual requests — where we
    /// already added the sender — auto-connect without firing this.
    ContactRequestReceived {
        fingerprint: String,
        display_name: Option<String>,
        note: Option<String>,
    },
    /// huddle 1.2.1: the relay minted a short-lived "connect code" we asked for
    /// (the DM "add by code" feature). The UI shows `code` for the user to
    /// share; it stops working at `expires_at` (epoch seconds).
    ConnectCodeCreated { code: String, expires_at: i64 },
    /// huddle 1.2.1: a connect code we redeemed resolved to `fingerprint`, and
    /// a contact request was sent to them. The UI can surface "request sent".
    ConnectCodeRedeemed { fingerprint: String },
    /// huddle 1.2.1: a connect code we tried to redeem was invalid or expired
    /// (or the relay wasn't reachable). `reason` is a short human message.
    ConnectCodeFailed { reason: String },
    /// huddle 2.0 (F3): TOFU drift — a signed message arrived for `fingerprint`
    /// whose Ed25519 pubkey differs from the one we pinned for this room. The
    /// offending message has already been dropped (never dispatched); the UI
    /// surfaces a modal letting the user re-verify (SAS), accept the new key, or
    /// block the peer. `display_name` is the peer's last-known label, if any.
    /// Fires only on the receiver side; old peers silently dropped (no event).
    SafetyNumberChanged {
        room_id: String,
        fingerprint: String,
        /// base64 Ed25519 pubkey we had pinned for this fingerprint.
        old_pubkey_b64: String,
        /// base64 Ed25519 pubkey the new (verified-signature) envelope carried.
        new_pubkey_b64: String,
        display_name: Option<String>,
    },
    /// huddle 2.0 (F5): the master passphrase was changed and the SQLCipher
    /// database + Megolm session pickles were re-keyed under the new key. The
    /// UI shows a transient "passphrase updated" confirmation.
    PassphraseChanged,
    /// huddle 2.0 (F10): a reaction was added (`removed = false`) or cleared
    /// (`removed = true`) on the message named by `message_id` (its sender-minted
    /// `client_msg_id`). Fired both for our own reactions and for inbound ones;
    /// the UI re-reads `AppHandle::room_reactions` to refresh the badges.
    ReactionAdded {
        room_id: String,
        message_id: String,
        sender_fingerprint: String,
        emoji: String,
        removed: bool,
    },
    /// huddle 2.0 (F10): the message named by `message_id` was edited (its body
    /// replaced, last-write-wins). `new_body` is the post-edit plaintext.
    /// `editor_fingerprint` is who applied the edit (the original sender or a
    /// room owner). The UI re-renders the message with an `[edited]` marker.
    MessageEdited {
        room_id: String,
        message_id: String,
        editor_fingerprint: String,
        new_body: String,
    },
    /// huddle 2.0 (F10): the message named by `message_id` was deleted
    /// (tombstoned — its body blanked). `deleter_fingerprint` is who deleted it
    /// (the original sender or a room owner). The UI renders `[deleted]`.
    MessageDeleted {
        room_id: String,
        message_id: String,
        deleter_fingerprint: String,
    },
    /// huddle 2.0 (F9): the per-room disappearing-messages TTL changed (locally
    /// or via a signed `RoomSetting` from a room owner). `ttl_secs = None` means
    /// expiry was turned OFF; `Some(secs)` arms it. The UI refreshes the room
    /// header indicator.
    RoomTtlChanged {
        room_id: String,
        ttl_secs: Option<u32>,
    },
    /// huddle 2.0 (F9): the disappearing-messages pruner physically deleted
    /// `count` expired messages (across all rooms) on its last sweep. The UI
    /// treats it as a nudge to re-fetch the open room's history so vanished
    /// messages disappear from view.
    MessagesExpired { count: usize },
}
