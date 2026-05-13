use libp2p::PeerId;

#[derive(Debug, Clone)]
pub enum AppEvent {
    PeerDiscovered {
        peer_id: PeerId,
        fingerprint: Option<String>,
    },
    PeerExpired {
        peer_id: PeerId,
    },
    SessionEstablished {
        peer_id: PeerId,
        fingerprint: String,
    },
    MessageReceived {
        peer_id: PeerId,
        body: String,
        sent_at: i64,
    },
    MessageSent {
        peer_id: PeerId,
        body: String,
        message_id: i64,
    },
    MessageAcked {
        peer_id: PeerId,
        message_id: i64,
    },
    ConnectionEstablished {
        peer_id: PeerId,
    },
    ConnectionClosed {
        peer_id: PeerId,
    },
    ListeningOn {
        address: String,
    },
    Error {
        description: String,
    },
}
