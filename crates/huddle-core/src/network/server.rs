//! Client connector to the centralized `huddle-server`.
//!
//! huddle's primary transport is libp2p (mDNS on the LAN, gossipsub
//! across direct/relayed connections). This module adds a *second* path:
//! a WebSocket to a single canonical server that the operator hosts. The
//! server is reachable only as a **Tor v3 onion**, so `.onion` URLs are
//! dialed through Tor's local SOCKS5 proxy; plain `ws://host:port` URLs
//! (used in tests) are dialed directly.
//!
//! The server is a dumb ciphertext mover: we hand it the same opaque
//! huddle wire bytes we would have published on a gossipsub topic,
//! tagged with the cleartext `room` id, base64-encoded. It fans them out
//! to the room's other members and queues them for offline ones. All
//! encryption/authentication stays in the layers above — this module
//! never inspects the payload.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::WebSocketStream;
use tracing::warn;

use crate::error::{HuddleError, Result};
use crate::identity::{relay_auth_msg, Identity};

/// Messages we send to the server. Mirrors `huddle-server`'s `ClientMsg`.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMsg {
    /// huddle 1.1.4: `Hello` now authenticates. It carries our Ed25519
    /// pubkey and a signature over `relay_auth_msg(nonce)` for the nonce the
    /// server sent in its opening `Challenge`. The relay verifies the
    /// signature and that the pubkey hashes to `fingerprint` before it lets
    /// us touch any mailbox.
    Hello {
        fingerprint: String,
        pubkey_b64: String,
        signature_b64: String,
        rooms: Vec<String>,
    },
    Subscribe { room: String },
    Unsubscribe { room: String },
    Publish { room: String, id: String, payload_b64: String },
    /// huddle 1.2: deliver straight to a recipient fingerprint (`to`),
    /// independent of room membership. Used for 1:1 DMs and friend requests,
    /// where we know exactly who the recipient is. `room` is the opaque tag
    /// the recipient files it under (DM room id, or their inbox id). Mirrors
    /// `huddle-server`'s `ClientMsg::SendDirect`.
    SendDirect { to: String, room: String, id: String, payload_b64: String },
    /// huddle 1.2.1: mint a short-lived connect code bound to our identity.
    CreateConnectToken,
    /// huddle 1.2.1: resolve a connect code → owner fingerprint + pubkey.
    RedeemConnectToken { token: String },
    Fetch,
    Ping,
}

/// Messages the server sends back. Mirrors `huddle-server`'s `ServerMsg`.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMsg {
    /// huddle 1.1.4: the relay opens the connection with a random challenge
    /// nonce. We sign it and answer with an authenticated `Hello`.
    Challenge { nonce_b64: String },
    // The server echoes our fingerprint on `ready`, but we already know
    // our own identity, so we keep only the tag and let serde ignore the
    // extra field.
    Ready,
    Message { room: String, id: String, payload_b64: String },
    Sent { id: String, delivered: usize, queued: usize },
    /// huddle 1.2.1: a freshly minted connect code + its lifetime in seconds.
    ConnectToken { token: String, ttl_secs: u64 },
    /// huddle 1.2.1: result of redeeming a connect code. `fingerprint`/`pubkey_b64`
    /// are `None` when the code was unknown or expired. (The relay also echoes
    /// the `token`, but we don't need it client-side — serde ignores it.)
    ConnectTokenResolved {
        #[serde(default)]
        fingerprint: Option<String>,
        #[serde(default)]
        pubkey_b64: Option<String>,
    },
    Pong,
    Error { message: String },
}

/// What the connector surfaces to the rest of huddle-core. The caller
/// drives these into the same path that handles a received gossipsub
/// message (decode → decrypt → `AppEvent`).
#[derive(Debug, Clone)]
pub enum ServerEvent {
    /// Handshake complete; the mailbox (if any) will follow as `Message`s.
    Ready,
    /// Delivery receipt for one of our `publish` calls: how many of the
    /// room's other members received it live vs. were queued because they
    /// were offline. Lets the UI mark a message delivered/pending.
    Sent { id: String, delivered: usize, queued: usize },
    /// A room message delivered (live or from the offline mailbox).
    Message { room: String, id: String, payload: Vec<u8> },
    /// huddle 1.2.1: the relay minted a connect code for us (with its TTL).
    ConnectToken { token: String, ttl_secs: u64 },
    /// huddle 1.2.1: the relay resolved a connect code we redeemed.
    /// `fingerprint`/`pubkey` are `None` when the code was unknown or expired.
    ConnectTokenResolved {
        fingerprint: Option<String>,
        pubkey_b64: Option<String>,
    },
    /// The socket closed; the caller may choose to reconnect.
    Disconnected,
}

/// A live connection to the server. Cloneable handle; cloning shares the
/// same underlying socket.
#[derive(Clone)]
pub struct ServerClient {
    out_tx: mpsc::UnboundedSender<ClientMsg>,
}

impl ServerClient {
    /// Open a connection, send the initial `hello`, and return the client
    /// plus a stream of [`ServerEvent`]s.
    ///
    /// - `url`: `ws://<onion>:80/ws` (onion), `wss://relay/ws` (clearnet TLS),
    ///   or `ws://host:port/ws` (clearnet plain / tests).
    /// - `dial`: how to physically reach it — one of the transport "doors"
    ///   (`Socks5` for onion via Tor, `Tls` for `wss://`, `Direct` for `ws://`).
    /// - `identity`: our identity, used to answer the relay's auth `Challenge`
    ///   (huddle 1.1.4). The connector signs the challenge nonce and sends the
    ///   pubkey + signature in `Hello`; the relay rejects us otherwise.
    pub async fn connect(
        url: &str,
        dial: &crate::network::transport::DialMode,
        identity: Arc<Identity>,
        rooms: Vec<String>,
    ) -> Result<(Self, mpsc::UnboundedReceiver<ServerEvent>)> {
        use crate::network::transport::DialMode;
        match dial {
            DialMode::Socks5 { proxy } => {
                let proxy: std::net::SocketAddr = proxy
                    .parse()
                    .map_err(|e| HuddleError::Network(format!("bad socks address: {e}")))?;
                let target = host_port_from_ws_url(url)?;
                let stream = tokio_socks::tcp::Socks5Stream::connect(proxy, target.as_str())
                    .await
                    .map_err(|e| HuddleError::Network(format!("tor socks connect: {e}")))?;
                let (ws, _resp) = tokio_tungstenite::client_async(url, stream)
                    .await
                    .map_err(|e| HuddleError::Network(format!("ws handshake: {e}")))?;
                Ok(Self::spawn(ws, identity, rooms))
            }
            // Plain `ws://` and `wss://` with the system trust store both go
            // through `connect_async`, which negotiates TLS from the URL
            // scheme (tokio-tungstenite's rustls-tls-native-roots feature).
            DialMode::Direct | DialMode::Tls { pinned_cert_der: None } => {
                let (ws, _resp) = tokio_tungstenite::connect_async(url)
                    .await
                    .map_err(|e| HuddleError::Network(format!("ws connect: {e}")))?;
                Ok(Self::spawn(ws, identity, rooms))
            }
            // Self-signed cert pinning is structured but not wired in this
            // build — the recommended clearnet-TLS path uses a real cert
            // (Caddy / Let's Encrypt / Cloudflare), which the arm above
            // handles. Onion doors remain available for stronger privacy.
            DialMode::Tls {
                pinned_cert_der: Some(_),
            } => Err(HuddleError::Network(
                "pinned-certificate wss is not supported in this build — use a real cert (Caddy/Let's Encrypt) or an onion door".into(),
            )),
            // huddle 1.0: in-process Tor via Arti. Bootstraps (once) an
            // embedded Tor client and opens the stream to the onion through
            // it, then speaks WebSocket over that stream — `spawn` is reused.
            #[cfg(feature = "arti")]
            DialMode::Arti { bridge } => {
                let client =
                    crate::network::transport::arti_client(bridge.as_deref()).await?;
                let hp = host_port_from_ws_url(url)?;
                let (host, port_s) = hp.rsplit_once(':').ok_or_else(|| {
                    HuddleError::Network(format!("bad host:port from {url}"))
                })?;
                let port: u16 = port_s
                    .parse()
                    .map_err(|_| HuddleError::Network(format!("bad port in {url}")))?;
                let stream = client
                    .connect((host, port))
                    .await
                    .map_err(|e| HuddleError::Network(format!("arti connect: {e}")))?;
                let (ws, _resp) = tokio_tungstenite::client_async(url, stream)
                    .await
                    .map_err(|e| HuddleError::Network(format!("ws handshake: {e}")))?;
                Ok(Self::spawn(ws, identity, rooms))
            }
        }
    }

    /// Spawn the read/write pumps for an established socket. Generic over
    /// the inner stream so the Tor-SOCKS and direct paths (different
    /// stream types) share one implementation.
    fn spawn<S>(
        ws: WebSocketStream<S>,
        identity: Arc<Identity>,
        rooms: Vec<String>,
    ) -> (Self, mpsc::UnboundedReceiver<ServerEvent>)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sink, mut stream) = ws.split();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<ClientMsg>();
        let (ev_tx, ev_rx) = mpsc::unbounded_channel::<ServerEvent>();

        // huddle 1.1.4: we do NOT send `Hello` up front anymore. The relay
        // opens with a `Challenge`; the reader pump (below) signs that nonce
        // and queues the authenticated `Hello`. Because the relay rejects
        // anything sent before a valid `Hello`, the writer pump holds back
        // any other outgoing frame (a publish/subscribe the app issues during
        // the handshake window) until the `Hello` has actually gone out.
        tokio::spawn(async move {
            let mut hello_sent = false;
            let mut pending: Vec<ClientMsg> = Vec::new();
            while let Some(msg) = out_rx.recv().await {
                let is_hello = matches!(msg, ClientMsg::Hello { .. });
                if !hello_sent && !is_hello {
                    pending.push(msg);
                    continue;
                }
                let json = match serde_json::to_string(&msg) {
                    Ok(j) => j,
                    Err(_) => continue,
                };
                if sink.send(WsMessage::Text(json.into())).await.is_err() {
                    return;
                }
                if is_hello {
                    hello_sent = true;
                    // Flush anything the app queued while we waited for the
                    // challenge, preserving its order after the Hello.
                    for m in pending.drain(..) {
                        let json = match serde_json::to_string(&m) {
                            Ok(j) => j,
                            Err(_) => continue,
                        };
                        if sink.send(WsMessage::Text(json.into())).await.is_err() {
                            return;
                        }
                    }
                }
            }
            // When `out_rx` ends (every `ServerClient` handle dropped) close
            // the socket so the server marks us offline and starts mailboxing.
            let _ = sink.close().await;
        });

        // Reader pump: parse server messages into ServerEvents. On the opening
        // `Challenge`, prove our identity by signing the nonce and sending the
        // authenticated `Hello` through the writer.
        // Held only long enough to send the one `Hello` in response to the
        // challenge, then dropped. Crucially it must NOT outlive that: if the
        // reader kept a permanent `out_tx` clone, dropping every public
        // `ServerClient` handle would no longer end the writer's `out_rx`, the
        // socket would never close, and the server would never mark us offline
        // (breaking offline mailboxing). `Option::take()` releases it after use.
        let mut hello_tx = Some(out_tx.clone());
        tokio::spawn(async move {
            while let Some(frame) = stream.next().await {
                let frame = match frame {
                    Ok(f) => f,
                    Err(_) => break,
                };
                let text = match frame {
                    WsMessage::Text(t) => t.as_str().to_string(),
                    WsMessage::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
                    WsMessage::Close(_) => break,
                    _ => continue,
                };
                match serde_json::from_str::<ServerMsg>(&text) {
                    Ok(ServerMsg::Challenge { nonce_b64 }) => {
                        if let Some(tx) = hello_tx.take() {
                            match B64.decode(nonce_b64.as_bytes()) {
                                Ok(nonce) => {
                                    let sig = identity.sign(&relay_auth_msg(&nonce));
                                    let hello = ClientMsg::Hello {
                                        fingerprint: identity.fingerprint().to_string(),
                                        pubkey_b64: B64.encode(identity.public_bytes()),
                                        signature_b64: B64.encode(sig),
                                        rooms: rooms.clone(),
                                    };
                                    // If the writer is gone the connection is dead anyway.
                                    let _ = tx.send(hello);
                                }
                                Err(e) => {
                                    warn!(error = %e, "relay sent an undecodable challenge nonce");
                                    break;
                                }
                            }
                        }
                        // `tx` dropped here — the reader no longer pins the
                        // outgoing channel open.
                    }
                    Ok(ServerMsg::Ready) => {
                        let _ = ev_tx.send(ServerEvent::Ready);
                    }
                    Ok(ServerMsg::Sent { id, delivered, queued }) => {
                        let _ = ev_tx.send(ServerEvent::Sent { id, delivered, queued });
                    }
                    Ok(ServerMsg::ConnectToken { token, ttl_secs }) => {
                        let _ = ev_tx.send(ServerEvent::ConnectToken { token, ttl_secs });
                    }
                    Ok(ServerMsg::ConnectTokenResolved { fingerprint, pubkey_b64 }) => {
                        let _ = ev_tx.send(ServerEvent::ConnectTokenResolved {
                            fingerprint,
                            pubkey_b64,
                        });
                    }
                    Ok(ServerMsg::Message { room, id, payload_b64 }) => {
                        match B64.decode(payload_b64.as_bytes()) {
                            Ok(payload) => {
                                let _ = ev_tx.send(ServerEvent::Message { room, id, payload });
                            }
                            Err(e) => warn!(error = %e, "server sent undecodable payload"),
                        }
                    }
                    Ok(ServerMsg::Error { message }) => warn!(%message, "huddle-server error"),
                    Ok(ServerMsg::Pong) => {}
                    Err(e) => warn!(error = %e, "unparseable server message"),
                }
            }
            let _ = ev_tx.send(ServerEvent::Disconnected);
        });

        (Self { out_tx }, ev_rx)
    }

    /// Send a room's opaque wire bytes to the server for fan-out.
    pub fn publish(&self, room: &str, id: &str, payload: &[u8]) -> Result<()> {
        self.send(ClientMsg::Publish {
            room: room.to_string(),
            id: id.to_string(),
            payload_b64: B64.encode(payload),
        })
    }

    /// huddle 1.2: deliver `payload` straight to recipient `to`'s
    /// fingerprint, independent of room membership (1:1 DMs, friend requests).
    /// The server delivers it live to every connection `to` has open, or
    /// queues it in their mailbox when they're offline. `room` is the opaque
    /// tag the recipient files it under.
    pub fn send_direct(&self, to: &str, room: &str, id: &str, payload: &[u8]) -> Result<()> {
        self.send(ClientMsg::SendDirect {
            to: to.to_string(),
            room: room.to_string(),
            id: id.to_string(),
            payload_b64: B64.encode(payload),
        })
    }

    /// Assert membership of a room so the server mailboxes us when offline.
    pub fn subscribe(&self, room: &str) -> Result<()> {
        self.send(ClientMsg::Subscribe { room: room.to_string() })
    }

    pub fn unsubscribe(&self, room: &str) -> Result<()> {
        self.send(ClientMsg::Unsubscribe { room: room.to_string() })
    }

    /// huddle 1.2.1: ask the relay to mint a short-lived connect code bound to
    /// our identity. The reply arrives as `ServerEvent::ConnectToken`.
    pub fn create_connect_token(&self) -> Result<()> {
        self.send(ClientMsg::CreateConnectToken)
    }

    /// huddle 1.2.1: ask the relay to resolve a connect code to its owner.
    /// The reply arrives as `ServerEvent::ConnectTokenResolved`.
    pub fn redeem_connect_token(&self, token: &str) -> Result<()> {
        self.send(ClientMsg::RedeemConnectToken { token: token.to_string() })
    }

    /// Ask the server to re-drain our mailbox.
    pub fn fetch(&self) -> Result<()> {
        self.send(ClientMsg::Fetch)
    }

    pub fn ping(&self) -> Result<()> {
        self.send(ClientMsg::Ping)
    }

    fn send(&self, msg: ClientMsg) -> Result<()> {
        self.out_tx
            .send(msg)
            .map_err(|_| HuddleError::Network("server connection closed".to_string()))
    }
}

/// Extract `host:port` from a `ws://`/`wss://` URL for the SOCKS target.
/// Defaults to port 80 for `ws://` (matches the onion's `HiddenServicePort
/// 80`) and 443 for `wss://` when no explicit port is given.
fn host_port_from_ws_url(url: &str) -> Result<String> {
    let (rest, default_port) = if let Some(r) = url.strip_prefix("wss://") {
        (r, 443)
    } else if let Some(r) = url.strip_prefix("ws://") {
        (r, 80)
    } else {
        return Err(HuddleError::Network(format!("expected ws:// url, got {url}")));
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.is_empty() {
        return Err(HuddleError::Network(format!("no host in url: {url}")));
    }
    if authority.contains(':') {
        Ok(authority.to_string())
    } else {
        Ok(format!("{authority}:{default_port}"))
    }
}

#[cfg(test)]
mod tests {
    use super::host_port_from_ws_url;

    #[test]
    fn parses_host_port() {
        assert_eq!(host_port_from_ws_url("ws://abc.onion/ws").unwrap(), "abc.onion:80");
        assert_eq!(
            host_port_from_ws_url("ws://127.0.0.1:8787/ws").unwrap(),
            "127.0.0.1:8787"
        );
        assert_eq!(host_port_from_ws_url("wss://h:443").unwrap(), "h:443");
        // huddle 1.0: bare wss:// defaults to 443, not 80.
        assert_eq!(host_port_from_ws_url("wss://relay.example/ws").unwrap(), "relay.example:443");
        assert!(host_port_from_ws_url("http://x").is_err());
    }
}
