pub mod behavior;
pub mod events;
pub mod protocol;

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use futures::StreamExt;
use libp2p::core::ConnectedPoint;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::ConnectionId;
use libp2p::{
    autonat, dcutr, gossipsub, identify, mdns, noise, ping, tcp, yamux, Multiaddr, PeerId, Swarm,
    SwarmBuilder,
};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// How the network discovers peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// mDNS on: announce ourselves on the LAN and pick up announcements.
    Mdns,
    /// mDNS off: invisible to LAN discovery; the only way to connect is
    /// for someone to dial our address (or for us to dial theirs).
    Direct,
}

impl NetworkMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            NetworkMode::Mdns => "mdns",
            NetworkMode::Direct => "direct",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "mdns" | "lan" | "open" => Some(NetworkMode::Mdns),
            "direct" | "dial" | "private" => Some(NetworkMode::Direct),
            _ => None,
        }
    }
}

use crate::identity::{compute_fingerprint, Identity};
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
    /// User-initiated dial of an explicit address. Used for cross-network
    /// reach when mDNS isn't enough.
    Dial { address: Multiaddr },
    /// Phase A: user accepted an inbound dial — promote the peer to
    /// explicit-peer status so room announcements flow.
    AcceptInbound { peer_id: PeerId },
    /// Phase A: user rejected an inbound dial — disconnect them and
    /// add the peer_id to the in-memory blocklist for this session
    /// (caller is responsible for the persistent blocked_peers row).
    RejectInbound { peer_id: PeerId },
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

    pub async fn dial(&self, address: Multiaddr) {
        let _ = self.cmd_tx.send(NetworkCommand::Dial { address }).await;
    }

    pub async fn accept_inbound(&self, peer_id: PeerId) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::AcceptInbound { peer_id })
            .await;
    }

    pub async fn reject_inbound(&self, peer_id: PeerId) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::RejectInbound { peer_id })
            .await;
    }

    pub async fn shutdown(&self) {
        let _ = self.cmd_tx.send(NetworkCommand::Shutdown).await;
    }
}

/// What kind of connection we're holding open until Identify gives us
/// the remote's Ed25519 fingerprint. Quarantined inbound dials are NOT
/// added to the gossipsub mesh until the user accepts; outbound user-
/// dials add to the mesh on connection but still wait on Identify so
/// the eventual `DialSucceeded` can carry the fingerprint.
#[derive(Debug)]
enum PendingPeer {
    /// Inbound dial from an unknown peer — modal-pending in the app.
    InboundUnknown { address: Multiaddr },
}

struct NetworkTask {
    swarm: Swarm<HuddleBehavior>,
    cmd_rx: mpsc::Receiver<NetworkCommand>,
    event_tx: mpsc::Sender<NetworkEvent>,
    discovered_peers: HashSet<PeerId>,
    /// Tracks user-initiated dials so we can correlate the eventual
    /// `ConnectionEstablished` / `OutgoingConnectionError` back to a
    /// specific address the user asked us to dial.
    dial_attempts: HashMap<ConnectionId, Multiaddr>,
    /// Phase A: peers connected but not yet promoted to the gossipsub
    /// mesh (inbound) — waiting either for `Identify` to land so we
    /// know their fingerprint, or for the user's accept/reject decision.
    /// On `ConnectionClosed` we drop entries here so a peer disconnecting
    /// mid-prompt doesn't leak state.
    pending_inbound: HashMap<PeerId, PendingPeer>,
    /// Phase A: peers the user has explicitly rejected this session —
    /// auto-disconnect every reconnect attempt without re-prompting.
    /// Persistent across runs via `blocked_peers`; this in-memory copy
    /// is loaded at startup (TODO: not yet wired; falls back to the DB
    /// check in the app layer for now) and updated on `RejectInbound`.
    session_blocklist: HashSet<PeerId>,
    /// Phase D: configured relay multiaddrs. When Identify lands for a
    /// peer whose multiaddr matches one of these, we call
    /// `listen_on("<addr>/p2p-circuit")` to register a reservation.
    /// Tracked as multiaddr strings (no PeerId yet — we don't know it
    /// until Identify) plus a set of peer_ids of confirmed relays so
    /// we only register once per relay.
    configured_relays: Vec<Multiaddr>,
    relay_peer_ids: HashSet<PeerId>,
}

pub fn start_network(
    identity: &Identity,
    event_tx: mpsc::Sender<NetworkEvent>,
) -> crate::error::Result<NetworkHandle> {
    start_network_with(identity, event_tx, NetworkMode::Mdns, 0, Vec::new())
}

/// Start the network task with explicit mode, TCP listen port, and any
/// pre-configured relay multiaddrs. `listen_port = 0` requests a
/// random port. Relays are dialed on startup; once `Identify` lands
/// from a relay peer, we call `listen_on("<relay>/p2p-circuit")` to
/// register a reservation so peers behind NAT can dial us through it.
pub fn start_network_with(
    identity: &Identity,
    event_tx: mpsc::Sender<NetworkEvent>,
    mode: NetworkMode,
    listen_port: u16,
    relays: Vec<Multiaddr>,
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
        // Phase D: wrap the transport with relay-client. This both
        // composes the transport (so we can dial `/p2p-circuit/`
        // addresses) and surfaces a `relay::client::Behaviour` into
        // the `with_behaviour` closure as the second argument.
        .with_relay_client(noise::Config::new, yamux::Config::default)
        .map_err(|e| crate::error::HuddleError::Network(e.to_string()))?
        .with_behaviour(|key, relay_client| {
            let mdns_opt = match mode {
                NetworkMode::Mdns => Some(
                    mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
                        .expect("mDNS init failed"),
                ),
                NetworkMode::Direct => None,
            };
            let mdns: libp2p::swarm::behaviour::toggle::Toggle<_> = mdns_opt.into();

            let identify = identify::Behaviour::new(
                identify::Config::new("/huddle/1.0.0".into(), key.public())
                    .with_agent_version("huddle/0.3".into()),
            );

            let ping = ping::Behaviour::default();

            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(1))
                .validation_mode(gossipsub::ValidationMode::Strict)
                // Default is 64 KiB. Raise it so base64-encoded file
                // chunks (see files::CHUNK_SIZE) keep ample headroom.
                .max_transmit_size(256 * 1024)
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

            let autonat = autonat::v1::Behaviour::new(local_peer_id, Default::default());
            let dcutr = dcutr::Behaviour::new(local_peer_id);

            HuddleBehavior {
                mdns,
                identify,
                ping,
                gossipsub,
                relay_client,
                autonat,
                dcutr,
            }
        })
        .map_err(|e| crate::error::HuddleError::Network(e.to_string()))?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();

    let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", listen_port)
        .parse()
        .expect("valid listen addr");
    swarm
        .listen_on(listen_addr)
        .map_err(|e| crate::error::HuddleError::Network(e.to_string()))?;
    // Also bind IPv6 on all interfaces so users can dial via IPv6.
    let listen_addr6: Multiaddr = format!("/ip6/::/tcp/{}", listen_port)
        .parse()
        .expect("valid ipv6 listen addr");
    if let Err(e) = swarm.listen_on(listen_addr6) {
        debug!(%e, "ipv6 listen skipped");
    }

    let (cmd_tx, cmd_rx) = mpsc::channel(256);
    let mut task = NetworkTask {
        swarm,
        cmd_rx,
        event_tx,
        discovered_peers: HashSet::new(),
        dial_attempts: HashMap::new(),
        pending_inbound: HashMap::new(),
        session_blocklist: HashSet::new(),
        configured_relays: relays.clone(),
        relay_peer_ids: HashSet::new(),
    };
    // Phase D: dial each configured relay so Identify can complete and
    // we can register a `/p2p-circuit` reservation. Failures here are
    // non-fatal — the user can still chat on LAN.
    for relay_addr in relays {
        info!(addr = %relay_addr, "dialing configured relay");
        let opts: libp2p::swarm::dial_opts::DialOpts = relay_addr.clone().into();
        let conn_id = opts.connection_id();
        match task.swarm.dial(opts) {
            Ok(()) => {
                task.dial_attempts.insert(conn_id, relay_addr);
            }
            Err(e) => warn!(%e, "dial relay failed"),
        }
    }
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
                // Phase D: a relay-circuit address is a reachability
                // milestone — surface it as its own event so the lobby
                // can show "reachable via N relays" status.
                use libp2p::multiaddr::Protocol;
                let is_circuit = address
                    .iter()
                    .any(|p| matches!(p, Protocol::P2pCircuit));
                if is_circuit {
                    let _ = self
                        .event_tx
                        .send(NetworkEvent::RelayReservationEstablished {
                            address: address.clone(),
                        })
                        .await;
                }
                let _ = self
                    .event_tx
                    .send(NetworkEvent::ListeningOn { address })
                    .await;
            }
            libp2p::swarm::SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            } => {
                if let Some(addr) = self.dial_attempts.remove(&connection_id) {
                    // Phase D: a connection that was for a configured
                    // relay shouldn't pollute the lobby with a normal
                    // DialSucceeded — relays aren't chat peers. We just
                    // remember the peer_id and wait for Identify, then
                    // register a /p2p-circuit reservation.
                    let is_relay = self.configured_relays.iter().any(|r| r == &addr);
                    if is_relay {
                        info!(%peer_id, %addr, "connected to configured relay");
                        self.relay_peer_ids.insert(peer_id);
                    } else {
                        info!(%peer_id, %addr, "user-dialed peer connected");
                        // Treat dialed peers like mDNS-discovered: add
                        // to gossipsub explicit peers so room
                        // announcements flow.
                        self.swarm
                            .behaviour_mut()
                            .gossipsub
                            .add_explicit_peer(&peer_id);
                        self.discovered_peers.insert(peer_id);
                        let _ = self
                            .event_tx
                            .send(NetworkEvent::DialSucceeded {
                                peer_id,
                                address: addr,
                            })
                            .await;
                    }
                } else if let ConnectedPoint::Dialer { .. } = endpoint {
                    // Outgoing connection we didn't track (e.g. mDNS auto-dial)
                    // — still add to mesh; no user-visible event needed.
                    self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .add_explicit_peer(&peer_id);
                } else {
                    // Inbound dial from an unknown peer (Phase A). We
                    // hold the connection but do NOT add them to the
                    // explicit-peer set yet — wait for Identify so we
                    // can show the user the peer's fingerprint, then
                    // either AcceptInbound (promote to mesh) or
                    // RejectInbound (disconnect + persist blocklist).
                    //
                    // Known limitation: gossipsub's score-based mesh
                    // formation may still forward topic messages to
                    // this peer via other peers we have in common.
                    // True hard-quarantine would need a custom
                    // ConnectionHandler — out of scope for v1.
                    if self.session_blocklist.contains(&peer_id) {
                        info!(%peer_id, "rejecting inbound from session-blocked peer");
                        let _ = self.swarm.disconnect_peer_id(peer_id);
                    } else {
                        let address = match &endpoint {
                            ConnectedPoint::Listener { send_back_addr, .. } => {
                                send_back_addr.clone()
                            }
                            _ => Multiaddr::empty(),
                        };
                        debug!(%peer_id, %address, "inbound peer pending decision");
                        self.pending_inbound
                            .insert(peer_id, PendingPeer::InboundUnknown { address });
                    }
                }
            }
            libp2p::swarm::SwarmEvent::OutgoingConnectionError {
                connection_id,
                error,
                ..
            } => {
                if let Some(addr) = self.dial_attempts.remove(&connection_id) {
                    warn!(%addr, %error, "user-dialed peer failed");
                    let _ = self
                        .event_tx
                        .send(NetworkEvent::DialFailed {
                            address: addr,
                            error: error.to_string(),
                        })
                        .await;
                }
            }
            libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, .. } => {
                // Drop any pending-inbound entry for this peer — they
                // disconnected before we could prompt the user (or
                // before the user accepted). Lets a re-connect start
                // fresh rather than reusing stale state.
                self.pending_inbound.remove(&peer_id);
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
                // Phase D: if this peer is a configured relay, register
                // a `/p2p-circuit` reservation on first identify. Idem-
                // potent — only fire if we haven't listened on this
                // relay already (identify fires periodically).
                if self.relay_peer_ids.contains(&peer_id) {
                    use libp2p::multiaddr::Protocol;
                    if let Some(relay_addr) = self
                        .configured_relays
                        .iter()
                        .find(|a| {
                            // Match by /p2p/<peer-id> suffix when
                            // present, else by the addr we dialed.
                            a.iter().any(|p| matches!(p, Protocol::P2p(pid) if pid == peer_id))
                                || self.dial_attempts.values().any(|d| d == *a)
                        })
                        .cloned()
                    {
                        let circuit = relay_addr.with(Protocol::P2pCircuit);
                        match self.swarm.listen_on(circuit.clone()) {
                            Ok(_) => info!(%circuit, "listening on relay circuit"),
                            Err(e) => warn!(%e, %circuit, "relay listen_on failed"),
                        }
                    }
                }
                // Decode the remote's Ed25519 pubkey and derive our
                // 24-char fingerprint from it. Non-Ed25519 keys (Secp,
                // Rsa, Ecdsa) shouldn't appear in practice — huddle
                // only generates Ed25519 identities — so we just log
                // and skip if the cast fails.
                let fingerprint = match info.public_key.clone().try_into_ed25519() {
                    Ok(ed_pk) => {
                        let bytes = ed_pk.to_bytes();
                        compute_fingerprint(&bytes)
                    }
                    Err(_) => {
                        warn!(%peer_id, "identify pubkey isn't Ed25519; skipping fingerprint");
                        return;
                    }
                };
                // Always notify the app layer so it can populate
                // `known_peers.fingerprint` and detect that an
                // outbound peer we dialed has fully identified.
                let _ = self
                    .event_tx
                    .send(NetworkEvent::PeerIdentified {
                        peer_id,
                        fingerprint: fingerprint.clone(),
                    })
                    .await;
                // If the peer is in pending_inbound, Identify completing
                // is the cue to surface the user prompt. Keep them in
                // pending_inbound until Accept or Reject — we don't
                // know yet which way the user will decide.
                if let Some(PendingPeer::InboundUnknown { address }) =
                    self.pending_inbound.get(&peer_id)
                {
                    let address = address.clone();
                    let _ = self
                        .event_tx
                        .send(NetworkEvent::InboundDial {
                            peer_id,
                            fingerprint,
                            address,
                        })
                        .await;
                }
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
                    // No subscribed peers is expected before the mesh
                    // forms; anything else (MessageTooLarge, full queues)
                    // is a real bug worth surfacing.
                    match e {
                        gossipsub::PublishError::NoPeersSubscribedToTopic => {
                            debug!(%room_id, "publish skipped: no peers subscribed to topic yet");
                        }
                        e => warn!(%e, %room_id, "publish room message failed"),
                    }
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
            NetworkCommand::AcceptInbound { peer_id } => {
                if self.pending_inbound.remove(&peer_id).is_some() {
                    info!(%peer_id, "inbound dial accepted — promoting to mesh");
                    self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .add_explicit_peer(&peer_id);
                    self.discovered_peers.insert(peer_id);
                } else {
                    debug!(%peer_id, "AcceptInbound for unknown peer (already promoted or disconnected)");
                }
            }
            NetworkCommand::RejectInbound { peer_id } => {
                self.pending_inbound.remove(&peer_id);
                self.session_blocklist.insert(peer_id);
                info!(%peer_id, "inbound dial rejected — disconnecting");
                let _ = self.swarm.disconnect_peer_id(peer_id);
            }
            NetworkCommand::Dial { address } => {
                let opts: DialOpts = address.clone().into();
                let conn_id = opts.connection_id();
                match self.swarm.dial(opts) {
                    Ok(()) => {
                        self.dial_attempts.insert(conn_id, address);
                    }
                    Err(e) => {
                        // Synchronous dial error (bad multiaddr, transport refused).
                        let tx = self.event_tx.clone();
                        let err = e.to_string();
                        tokio::spawn(async move {
                            let _ = tx
                                .send(NetworkEvent::DialFailed {
                                    address,
                                    error: err,
                                })
                                .await;
                        });
                    }
                }
            }
            NetworkCommand::Shutdown => unreachable!(),
        }
    }
}
