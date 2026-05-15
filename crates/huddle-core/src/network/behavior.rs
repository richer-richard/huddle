use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{autonat, dcutr, gossipsub, identify, mdns, ping, relay};

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "HuddleBehaviorEvent")]
pub struct HuddleBehavior {
    pub mdns: Toggle<mdns::tokio::Behaviour>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub gossipsub: gossipsub::Behaviour,
    // Phase D — internet reach. Relay-client lets us register with a
    // public relay (`listen_on(<relay>/p2p-circuit)`). AutoNAT
    // estimates whether we're behind NAT. DCUtR upgrades a relayed
    // connection to a direct one via hole-punching when possible.
    pub relay_client: relay::client::Behaviour,
    // AutoNAT v2 (upgraded from v1 in the 0.3.x follow-up). v2 split
    // the single v1 Behaviour into separate client + server halves;
    // for a P2P mesh where any node may be asked to probe another's
    // reachability, we include both — matching v1's symmetric design.
    // Client emits an `Event` per address probe (Ok ⇒ reachable); the
    // app layer consumes that to render the lobby reachability badge.
    // Server runs silently behind the scenes — nodes use it to test
    // each other.
    pub autonat_client: autonat::v2::client::Behaviour,
    pub autonat_server: autonat::v2::server::Behaviour,
    pub dcutr: dcutr::Behaviour,
}

#[derive(Debug)]
pub enum HuddleBehaviorEvent {
    Mdns(mdns::Event),
    Identify(identify::Event),
    Ping(ping::Event),
    Gossipsub(gossipsub::Event),
    RelayClient(relay::client::Event),
    AutonatClient(autonat::v2::client::Event),
    AutonatServer(autonat::v2::server::Event),
    Dcutr(dcutr::Event),
}

impl From<mdns::Event> for HuddleBehaviorEvent {
    fn from(event: mdns::Event) -> Self {
        Self::Mdns(event)
    }
}

impl From<identify::Event> for HuddleBehaviorEvent {
    fn from(event: identify::Event) -> Self {
        Self::Identify(event)
    }
}

impl From<ping::Event> for HuddleBehaviorEvent {
    fn from(event: ping::Event) -> Self {
        Self::Ping(event)
    }
}

impl From<gossipsub::Event> for HuddleBehaviorEvent {
    fn from(event: gossipsub::Event) -> Self {
        Self::Gossipsub(event)
    }
}

impl From<relay::client::Event> for HuddleBehaviorEvent {
    fn from(event: relay::client::Event) -> Self {
        Self::RelayClient(event)
    }
}

impl From<autonat::v2::client::Event> for HuddleBehaviorEvent {
    fn from(event: autonat::v2::client::Event) -> Self {
        Self::AutonatClient(event)
    }
}

impl From<autonat::v2::server::Event> for HuddleBehaviorEvent {
    fn from(event: autonat::v2::server::Event) -> Self {
        Self::AutonatServer(event)
    }
}

impl From<dcutr::Event> for HuddleBehaviorEvent {
    fn from(event: dcutr::Event) -> Self {
        Self::Dcutr(event)
    }
}
