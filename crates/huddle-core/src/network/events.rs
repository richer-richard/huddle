use libp2p::{Multiaddr, PeerId};

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
    ListeningOn { address: Multiaddr },
    /// A user-initiated dial to `address` succeeded — the remote peer
    /// is `peer_id` and the swarm now has an open connection.
    DialSucceeded { peer_id: PeerId, address: Multiaddr },
    /// A user-initiated dial failed before establishing a connection.
    DialFailed { address: Multiaddr, error: String },
    /// Phase A: Identify has completed for `peer_id` and we've decoded
    /// their Ed25519 fingerprint. Fired for every peer (inbound or
    /// outbound) so the app layer can populate `known_peers.fingerprint`
    /// and mark previously-dialed peers as `trusted=1`.
    PeerIdentified { peer_id: PeerId, fingerprint: String },
    /// Phase A: an unknown peer has dialed us (listener side) and their
    /// Identify just landed. The peer is NOT yet in our gossipsub
    /// explicit-peers set — the app layer must respond with either
    /// `AcceptInbound` or `RejectInbound` (or let the 15s TUI timeout
    /// auto-reject).
    InboundDial {
        peer_id: PeerId,
        fingerprint: String,
        address: Multiaddr,
    },
    /// Phase D: a `/p2p-circuit` reservation on a configured relay
    /// succeeded — peers across the internet can now dial us via this
    /// circuit address. Fires when libp2p emits `NewListenAddr` for an
    /// address with `/p2p-circuit/` in its path.
    RelayReservationEstablished { address: Multiaddr },
}
