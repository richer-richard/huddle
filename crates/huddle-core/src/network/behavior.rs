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
    pub autonat: autonat::v1::Behaviour,
    pub dcutr: dcutr::Behaviour,
}

#[derive(Debug)]
pub enum HuddleBehaviorEvent {
    Mdns(mdns::Event),
    Identify(identify::Event),
    Ping(ping::Event),
    Gossipsub(gossipsub::Event),
    RelayClient(relay::client::Event),
    Autonat(autonat::v1::Event),
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

impl From<autonat::v1::Event> for HuddleBehaviorEvent {
    fn from(event: autonat::v1::Event) -> Self {
        Self::Autonat(event)
    }
}

impl From<dcutr::Event> for HuddleBehaviorEvent {
    fn from(event: dcutr::Event) -> Self {
        Self::Dcutr(event)
    }
}
