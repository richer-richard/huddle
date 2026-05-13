pub mod behavior;
pub mod events;
pub mod protocol;

use std::collections::HashSet;
use std::time::Duration;

use futures::StreamExt;
use libp2p::{
    gossipsub, identify, mdns, noise, ping, tcp, yamux, PeerId, Swarm, SwarmBuilder,
};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::identity::Identity;
use crate::network::behavior::{HuddleBehavior, HuddleBehaviorEvent};
use crate::network::events::NetworkEvent;
use crate::network::protocol::{room_topic, RoomAnnouncement, ROOMS_TOPIC};

#[derive(Debug)]
pub enum NetworkCommand {
    /// Subscribe to a room's per-room gossipsub topic.
    SubscribeRoom { room_id: String },
    /// Unsubscribe from a room's topic.
    UnsubscribeRoom { room_id: String },
    /// Publish a JSON-encoded `RoomMessage` to a room's topic.
    PublishRoomMessage { room_id: String, payload: Vec<u8> },
    /// Publish a room announcement on the global rooms topic.
    AnnounceRoom(RoomAnnouncement),
    Shutdown,
}

#[derive(Clone)]
pub struct NetworkHandle {
    cmd_tx: mpsc::Sender<NetworkCommand>,
}

impl NetworkHandle {
    pub async fn subscribe_room(&self, room_id: String) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::SubscribeRoom { room_id })
            .await;
    }

    pub async fn unsubscribe_room(&self, room_id: String) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::UnsubscribeRoom { room_id })
            .await;
    }

    pub async fn publish_room_message(&self, room_id: String, payload: Vec<u8>) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::PublishRoomMessage { room_id, payload })
            .await;
    }

    pub async fn announce_room(&self, ann: RoomAnnouncement) {
        let _ = self.cmd_tx.send(NetworkCommand::AnnounceRoom(ann)).await;
    }

    pub async fn shutdown(&self) {
        let _ = self.cmd_tx.send(NetworkCommand::Shutdown).await;
    }
}

struct NetworkTask {
    swarm: Swarm<HuddleBehavior>,
    cmd_rx: mpsc::Receiver<NetworkCommand>,
    event_tx: mpsc::Sender<NetworkEvent>,
    discovered_peers: HashSet<PeerId>,
}

pub fn start_network(
    identity: &Identity,
    event_tx: mpsc::Sender<NetworkEvent>,
) -> crate::error::Result<NetworkHandle> {
    let keypair = identity.keypair().clone();
    let local_peer_id = identity.peer_id();

    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| crate::error::HuddleError::Network(e.to_string()))?
        .with_behaviour(|key| {
            let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
                .expect("mDNS init failed");

            let identify = identify::Behaviour::new(
                identify::Config::new("/huddle/1.0.0".into(), key.public())
                    .with_agent_version("huddle/0.2".into()),
            );

            let ping = ping::Behaviour::default();

            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(1))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .build()
                .expect("valid gossipsub config");

            let mut gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .expect("valid gossipsub init");

            // Every node subscribes to the global rooms topic so the lobby
            // shows discovered rooms even before joining anything.
            let rooms_topic = gossipsub::IdentTopic::new(ROOMS_TOPIC);
            gossipsub
                .subscribe(&rooms_topic)
                .expect("subscribe rooms topic");

            HuddleBehavior {
                mdns,
                identify,
                ping,
                gossipsub,
            }
        })
        .map_err(|e| crate::error::HuddleError::Network(e.to_string()))?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();

    swarm
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .map_err(|e| crate::error::HuddleError::Network(e.to_string()))?;

    let (cmd_tx, cmd_rx) = mpsc::channel(256);
    let task = NetworkTask {
        swarm,
        cmd_rx,
        event_tx,
        discovered_peers: HashSet::new(),
    };
    tokio::spawn(task.run());

    Ok(NetworkHandle { cmd_tx })
}

impl NetworkTask {
    async fn run(mut self) {
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await;
                }
                Some(cmd) = self.cmd_rx.recv() => {
                    if matches!(cmd, NetworkCommand::Shutdown) {
                        info!("network task shutting down");
                        break;
                    }
                    self.handle_command(cmd);
                }
            }
        }
    }

    async fn handle_swarm_event(
        &mut self,
        event: libp2p::swarm::SwarmEvent<HuddleBehaviorEvent>,
    ) {
        match event {
            libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                info!(%address, "listening");
                let _ = self
                    .event_tx
                    .send(NetworkEvent::ListeningOn { address })
                    .await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(be) => self.handle_behavior_event(be).await,
            _ => {}
        }
    }

    async fn handle_behavior_event(&mut self, event: HuddleBehaviorEvent) {
        match event {
            HuddleBehaviorEvent::Mdns(mdns::Event::Discovered(peers)) => {
                for (peer_id, addr) in peers {
                    if self.discovered_peers.insert(peer_id) {
                        info!(%peer_id, %addr, "mDNS discovered");
                        self.swarm.add_peer_address(peer_id, addr);
                        // Explicitly add to gossipsub mesh.
                        self.swarm
                            .behaviour_mut()
                            .gossipsub
                            .add_explicit_peer(&peer_id);
                        let _ = self
                            .event_tx
                            .send(NetworkEvent::PeerDiscovered { peer_id })
                            .await;
                    }
                }
            }
            HuddleBehaviorEvent::Mdns(mdns::Event::Expired(peers)) => {
                for (peer_id, _) in peers {
                    if self.discovered_peers.remove(&peer_id) {
                        info!(%peer_id, "mDNS peer expired");
                        self.swarm
                            .behaviour_mut()
                            .gossipsub
                            .remove_explicit_peer(&peer_id);
                        let _ = self.event_tx.send(NetworkEvent::PeerExpired { peer_id }).await;
                    }
                }
            }
            HuddleBehaviorEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source,
                message,
                ..
            }) => {
                self.handle_gossipsub_message(propagation_source, message).await;
            }
            HuddleBehaviorEvent::Identify(identify::Event::Received {
                peer_id, info, ..
            }) => {
                debug!(%peer_id, agent = %info.agent_version, "identify received");
            }
            _ => {}
        }
    }

    async fn handle_gossipsub_message(
        &mut self,
        from_peer: PeerId,
        message: gossipsub::Message,
    ) {
        let topic = message.topic.to_string();
        if topic == ROOMS_TOPIC {
            match serde_json::from_slice::<RoomAnnouncement>(&message.data) {
                Ok(ann) => {
                    let _ = self
                        .event_tx
                        .send(NetworkEvent::RoomAnnouncementReceived(ann))
                        .await;
                }
                Err(e) => {
                    warn!(%e, "bad room announcement");
                }
            }
        } else if let Some(room_id) = topic.strip_prefix(protocol::ROOM_TOPIC_PREFIX) {
            let _ = self
                .event_tx
                .send(NetworkEvent::RoomMessageReceived {
                    room_id: room_id.to_string(),
                    payload: message.data,
                    from_peer,
                })
                .await;
        }
    }

    fn handle_command(&mut self, cmd: NetworkCommand) {
        match cmd {
            NetworkCommand::SubscribeRoom { room_id } => {
                let topic = gossipsub::IdentTopic::new(room_topic(&room_id));
                if let Err(e) = self.swarm.behaviour_mut().gossipsub.subscribe(&topic) {
                    warn!(%e, %room_id, "subscribe room failed");
                }
            }
            NetworkCommand::UnsubscribeRoom { room_id } => {
                let topic = gossipsub::IdentTopic::new(room_topic(&room_id));
                self.swarm.behaviour_mut().gossipsub.unsubscribe(&topic);
            }
            NetworkCommand::PublishRoomMessage { room_id, payload } => {
                let topic = gossipsub::IdentTopic::new(room_topic(&room_id));
                if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic, payload) {
                    debug!(%e, %room_id, "publish room message failed (no peers yet?)");
                }
            }
            NetworkCommand::AnnounceRoom(ann) => {
                let topic = gossipsub::IdentTopic::new(ROOMS_TOPIC);
                match serde_json::to_vec(&ann) {
                    Ok(payload) => {
                        if let Err(e) =
                            self.swarm.behaviour_mut().gossipsub.publish(topic, payload)
                        {
                            debug!(%e, "publish room announcement failed");
                        }
                    }
                    Err(e) => warn!(%e, "encode room announcement"),
                }
            }
            NetworkCommand::Shutdown => unreachable!(),
        }
    }
}
