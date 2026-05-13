use libp2p::PeerId;

use crate::network::protocol::HuddleResponse;
use crate::session::PrekeyBundle;

#[derive(Debug)]
pub enum NetworkEvent {
    PeerDiscovered {
        peer_id: PeerId,
    },
    PeerExpired {
        peer_id: PeerId,
    },
    HandshakeReceived {
        peer_id: PeerId,
        sender_fingerprint: String,
        prekey_bundle: PrekeyBundle,
        channel: ResponseChannel,
    },
    HandshakeCompleted {
        peer_id: PeerId,
        sender_fingerprint: String,
        prekey_bundle: PrekeyBundle,
    },
    EncryptedMessageReceived {
        peer_id: PeerId,
        ciphertext: Vec<u8>,
        msg_type: u8,
        channel: ResponseChannel,
    },
    AckReceived {
        peer_id: PeerId,
        message_id: Option<i64>,
    },
    ConnectionEstablished {
        peer_id: PeerId,
    },
    ConnectionClosed {
        peer_id: PeerId,
    },
    ListeningOn {
        address: libp2p::Multiaddr,
    },
}

pub type ResponseChannel = libp2p::request_response::ResponseChannel<HuddleResponse>;
