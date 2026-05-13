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
    /// We've fired a dial command — useful for the UI to show "dialing...".
    Dialing { address: String },
    /// A user-initiated dial completed successfully.
    DialSucceeded { address: String, peer_id: PeerId },
    /// A user-initiated dial failed.
    DialFailed { address: String, error: String },
    /// Non-fatal error.
    Error { description: String },
}
