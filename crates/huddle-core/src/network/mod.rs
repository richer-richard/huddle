pub mod behavior;
pub mod events;
pub mod protocol;

use std::collections::HashSet;
use std::time::Duration;

use futures::StreamExt;
use libp2p::{
    identify, mdns, noise, ping, request_response, tcp, yamux, PeerId, Swarm, SwarmBuilder,
};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info, warn};

use crate::identity::Identity;
use crate::network::behavior::{HuddleBehavior, HuddleBehaviorEvent};
use crate::network::events::NetworkEvent;
use crate::network::protocol::{HuddleRequest, HuddleResponse, HuddleCodec, HUDDLE_PROTOCOL};
use crate::session::PrekeyBundle;

#[derive(Debug)]
pub enum NetworkCommand {
    SendHandshake {
        peer_id: PeerId,
        fingerprint: String,
        prekey_bundle: PrekeyBundle,
    },
    SendEncryptedMessage {
        peer_id: PeerId,
        ciphertext: Vec<u8>,
        msg_type: u8,
    },
    RespondHandshake {
        channel: events::ResponseChannel,
        fingerprint: String,
        prekey_bundle: PrekeyBundle,
    },
    RespondAck {
        channel: events::ResponseChannel,
        message_id: Option<i64>,
    },
    Shutdown,
}

#[derive(Clone)]
pub struct NetworkHandle {
    cmd_tx: mpsc::Sender<NetworkCommand>,
}

impl NetworkHandle {
    pub async fn send_handshake(
        &self,
        peer_id: PeerId,
        fingerprint: String,
        prekey_bundle: PrekeyBundle,
    ) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::SendHandshake {
                peer_id,
                fingerprint,
                prekey_bundle,
            })
            .await;
    }

    pub async fn send_encrypted_message(
        &self,
        peer_id: PeerId,
        ciphertext: Vec<u8>,
        msg_type: u8,
    ) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::SendEncryptedMessage {
                peer_id,
                ciphertext,
                msg_type,
            })
            .await;
    }

    pub async fn respond_handshake(
        &self,
        channel: events::ResponseChannel,
        fingerprint: String,
        prekey_bundle: PrekeyBundle,
    ) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::RespondHandshake {
                channel,
                fingerprint,
                prekey_bundle,
            })
            .await;
    }

    pub async fn respond_ack(&self, channel: events::ResponseChannel, message_id: Option<i64>) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::RespondAck {
                channel,
                message_id,
            })
            .await;
    }

    pub async fn shutdown(&self) {
        let _ = self.cmd_tx.send(NetworkCommand::Shutdown).await;
    }
}

struct NetworkTask {
    swarm: Swarm<HuddleBehavior>,
    cmd_rx: mpsc::Receiver<NetworkCommand>,
    event_tx: broadcast::Sender<NetworkEvent>,
    discovered_peers: HashSet<PeerId>,
}

pub fn start_network(
    identity: &Identity,
    event_tx: broadcast::Sender<NetworkEvent>,
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
                    .with_agent_version("huddle/0.1".into()),
            );

            let ping = ping::Behaviour::default();

            let request_response = request_response::Behaviour::with_codec(
                HuddleCodec,
                [(HUDDLE_PROTOCOL, request_response::ProtocolSupport::Full)],
                Default::default(),
            );

            HuddleBehavior {
                mdns,
                identify,
                ping,
                request_response,
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
                    self.handle_swarm_event(event);
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

    fn handle_swarm_event(
        &mut self,
        event: libp2p::swarm::SwarmEvent<HuddleBehaviorEvent>,
    ) {
        match event {
            libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                info!(%address, "listening");
                let _ = self.event_tx.send(NetworkEvent::ListeningOn { address });
            }
            libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                debug!(%peer_id, "connection established");
                let _ = self
                    .event_tx
                    .send(NetworkEvent::ConnectionEstablished { peer_id });
            }
            libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, .. } => {
                debug!(%peer_id, "connection closed");
                let _ = self
                    .event_tx
                    .send(NetworkEvent::ConnectionClosed { peer_id });
            }
            libp2p::swarm::SwarmEvent::Behaviour(be) => self.handle_behavior_event(be),
            _ => {}
        }
    }

    fn handle_behavior_event(&mut self, event: HuddleBehaviorEvent) {
        match event {
            HuddleBehaviorEvent::Mdns(mdns::Event::Discovered(peers)) => {
                for (peer_id, addr) in peers {
                    if self.discovered_peers.insert(peer_id) {
                        info!(%peer_id, %addr, "mDNS discovered peer");
                        self.swarm.add_peer_address(peer_id, addr);
                        let _ = self.event_tx.send(NetworkEvent::PeerDiscovered { peer_id });
                    }
                }
            }
            HuddleBehaviorEvent::Mdns(mdns::Event::Expired(peers)) => {
                for (peer_id, _) in peers {
                    if self.discovered_peers.remove(&peer_id) {
                        info!(%peer_id, "mDNS peer expired");
                        let _ = self.event_tx.send(NetworkEvent::PeerExpired { peer_id });
                    }
                }
            }
            HuddleBehaviorEvent::RequestResponse(request_response::Event::Message {
                peer,
                message,
                ..
            }) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => match request {
                    HuddleRequest::Handshake {
                        sender_fingerprint,
                        prekey_bundle,
                    } => {
                        let _ = self.event_tx.send(NetworkEvent::HandshakeReceived {
                            peer_id: peer,
                            sender_fingerprint,
                            prekey_bundle,
                            channel,
                        });
                    }
                    HuddleRequest::EncryptedMessage {
                        ciphertext,
                        msg_type,
                    } => {
                        let _ = self.event_tx.send(NetworkEvent::EncryptedMessageReceived {
                            peer_id: peer,
                            ciphertext,
                            msg_type,
                            channel,
                        });
                    }
                },
                request_response::Message::Response { response, .. } => match response {
                    HuddleResponse::Handshake {
                        sender_fingerprint,
                        prekey_bundle,
                    } => {
                        let _ = self.event_tx.send(NetworkEvent::HandshakeCompleted {
                            peer_id: peer,
                            sender_fingerprint,
                            prekey_bundle,
                        });
                    }
                    HuddleResponse::Ack { message_id } => {
                        let _ = self.event_tx.send(NetworkEvent::AckReceived {
                            peer_id: peer,
                            message_id,
                        });
                    }
                },
            },
            HuddleBehaviorEvent::RequestResponse(
                request_response::Event::OutboundFailure { peer, error, .. },
            ) => {
                warn!(%peer, %error, "outbound request failed");
            }
            HuddleBehaviorEvent::Identify(identify::Event::Received {
                peer_id, info, ..
            }) => {
                debug!(%peer_id, agent = %info.agent_version, "identify received");
            }
            _ => {}
        }
    }

    fn handle_command(&mut self, cmd: NetworkCommand) {
        match cmd {
            NetworkCommand::SendHandshake {
                peer_id,
                fingerprint,
                prekey_bundle,
            } => {
                self.swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(
                        &peer_id,
                        HuddleRequest::Handshake {
                            sender_fingerprint: fingerprint,
                            prekey_bundle,
                        },
                    );
            }
            NetworkCommand::SendEncryptedMessage {
                peer_id,
                ciphertext,
                msg_type,
            } => {
                self.swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(
                        &peer_id,
                        HuddleRequest::EncryptedMessage {
                            ciphertext,
                            msg_type,
                        },
                    );
            }
            NetworkCommand::RespondHandshake {
                channel,
                fingerprint,
                prekey_bundle,
            } => {
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .request_response
                    .send_response(
                        channel,
                        HuddleResponse::Handshake {
                            sender_fingerprint: fingerprint,
                            prekey_bundle,
                        },
                    );
            }
            NetworkCommand::RespondAck {
                channel,
                message_id,
            } => {
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .request_response
                    .send_response(channel, HuddleResponse::Ack { message_id });
            }
            NetworkCommand::Shutdown => unreachable!(),
        }
    }
}
