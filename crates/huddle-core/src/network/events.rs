use libp2p::{Multiaddr, PeerId};

use crate::network::protocol::RoomAnnouncement;

#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// A peer was discovered on the LAN (mDNS).
    PeerDiscovered {
        peer_id: PeerId,
    },
    /// A peer's mDNS record expired.
    PeerExpired {
        peer_id: PeerId,
    },
    /// A room was announced on the global rooms topic.
    RoomAnnouncementReceived(RoomAnnouncement),
    /// A raw message arrived on a per-room topic. Payload is the
    /// JSON-encoded `RoomMessage` — decoded by the app layer.
    RoomMessageReceived {
        room_id: String,
        payload: Vec<u8>,
        from_peer: PeerId,
    },
    ListeningOn {
        address: Multiaddr,
    },
    /// A user-initiated dial to `address` succeeded — the remote peer
    /// is `peer_id` and the swarm now has an open connection.
    DialSucceeded {
        peer_id: PeerId,
        address: Multiaddr,
    },
    /// A user-initiated dial failed before establishing a connection.
    DialFailed {
        address: Multiaddr,
        error: String,
    },
    /// Phase A: Identify has completed for `peer_id` and we've decoded
    /// their Ed25519 fingerprint. Fired for every peer (inbound or
    /// outbound) so the app layer can populate `known_peers.fingerprint`
    /// and mark previously-dialed peers as `trusted=1`.
    PeerIdentified {
        peer_id: PeerId,
        fingerprint: String,
    },
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
    RelayReservationEstablished {
        address: Multiaddr,
    },
    /// Phase D follow-up: AutoNAT v2 client finished a reachability
    /// probe for one of our candidate external addresses. `reachable`
    /// is true if a remote AutoNAT server successfully dialed us back.
    /// One probe per address candidate; the app layer aggregates these
    /// into the overall reachability badge shown in the lobby.
    NatProbeResult {
        tested_addr: Multiaddr,
        reachable: bool,
    },
    /// Phase D follow-up: a Direct-Connection-Upgrade-through-Relay
    /// attempt completed. `success` is true if a direct connection was
    /// established (the relay hop is dropped at that point). The TUI
    /// shows transient status when this fires.
    DcutrUpgrade {
        remote_peer: PeerId,
        success: bool,
    },
    /// huddle 0.7.11: a connection to `peer_id` closed (last connection
    /// to that peer). Fires once per (peer disappears) regardless of how
    /// many underlying connections there were. The app layer uses this
    /// to clean `connected_dial_addrs` and update the lobby's online
    /// dots — pre-0.7.11 only mDNS PeerExpired was wired, so relay /
    /// internet peers stayed "online" in the lobby long after they
    /// dropped.
    PeerDisconnected {
        peer_id: PeerId,
    },
    // huddle 0.7.11 declared `RelayReservationLost { relay_peer }`
    // here but no producer in libp2p 0.56 actually emits it; we
    // removed the variant in 0.7.12 rather than ship dead code.
    // A future health-check timer can re-introduce it.
}
