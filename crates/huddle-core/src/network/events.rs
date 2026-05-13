use libp2p::PeerId;

use crate::network::protocol::RoomAnnouncement;

#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// A peer was discovered on the LAN (mDNS).
    PeerDiscovered { peer_id: PeerId },
    /// A peer's mDNS record expired.
    PeerExpired { peer_id: PeerId },
    /// A room was announced on the global rooms topic.
    RoomAnnouncementReceived(RoomAnnouncement),
    /// A raw message arrived on a per-room topic. Payload is the
    /// JSON-encoded `RoomMessage` — decoded by the app layer.
    RoomMessageReceived {
        room_id: String,
        payload: Vec<u8>,
        from_peer: PeerId,
    },
    ListeningOn { address: libp2p::Multiaddr },
}
