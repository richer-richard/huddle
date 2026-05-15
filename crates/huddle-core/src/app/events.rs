use libp2p::PeerId;

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
}
