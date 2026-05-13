use libp2p::swarm::NetworkBehaviour;
use libp2p::{identify, mdns, ping, request_response};

use crate::network::protocol::{HuddleCodec, HuddleRequest, HuddleResponse};

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "HuddleBehaviorEvent")]
pub struct HuddleBehavior {
    pub mdns: mdns::tokio::Behaviour,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub request_response: request_response::Behaviour<HuddleCodec>,
}

#[derive(Debug)]
pub enum HuddleBehaviorEvent {
    Mdns(mdns::Event),
    Identify(identify::Event),
    Ping(ping::Event),
    RequestResponse(request_response::Event<HuddleRequest, HuddleResponse>),
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

impl From<request_response::Event<HuddleRequest, HuddleResponse>> for HuddleBehaviorEvent {
    fn from(event: request_response::Event<HuddleRequest, HuddleResponse>) -> Self {
        Self::RequestResponse(event)
    }
}
