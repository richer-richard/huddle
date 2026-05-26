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

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::WebSocketStream;
use tracing::warn;

use crate::error::{HuddleError, Result};

/// Messages we send to the server. Mirrors `huddle-server`'s `ClientMsg`.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMsg {
    Hello { fingerprint: String, rooms: Vec<String> },
    Subscribe { room: String },
    Unsubscribe { room: String },
    Publish { room: String, id: String, payload_b64: String },
    Fetch,
    Ping,
}

/// Messages the server sends back. Mirrors `huddle-server`'s `ServerMsg`.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMsg {
    // The server echoes our fingerprint on `ready`, but we already know
    // our own identity, so we keep only the tag and let serde ignore the
    // extra field.
    Ready,
    Message { room: String, id: String, payload_b64: String },
    Sent { id: String, delivered: usize, queued: usize },
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
    /// - `url`: `ws://<onion>:80/ws` in production, or `ws://127.0.0.1:8787/ws` in tests.
    /// - `socks`: `Some("127.0.0.1:9050")` to route through Tor (**required** for `.onion`);
    ///   `None` to dial directly.
    pub async fn connect(
        url: &str,
        socks: Option<&str>,
        fingerprint: String,
        rooms: Vec<String>,
    ) -> Result<(Self, mpsc::UnboundedReceiver<ServerEvent>)> {
        match socks {
            Some(proxy) => {
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
                Ok(Self::spawn(ws, fingerprint, rooms))
            }
            None => {
                let (ws, _resp) = tokio_tungstenite::connect_async(url)
                    .await
                    .map_err(|e| HuddleError::Network(format!("ws connect: {e}")))?;
                Ok(Self::spawn(ws, fingerprint, rooms))
            }
        }
    }

    /// Spawn the read/write pumps for an established socket. Generic over
    /// the inner stream so the Tor-SOCKS and direct paths (different
    /// stream types) share one implementation.
    fn spawn<S>(
        ws: WebSocketStream<S>,
        fingerprint: String,
        rooms: Vec<String>,
    ) -> (Self, mpsc::UnboundedReceiver<ServerEvent>)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sink, mut stream) = ws.split();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<ClientMsg>();
        let (ev_tx, ev_rx) = mpsc::unbounded_channel::<ServerEvent>();

        // Announce ourselves first; the server replies `ready` and then
        // flushes any queued mailbox messages.
        let _ = out_tx.send(ClientMsg::Hello { fingerprint, rooms });

        // Writer pump: serialize outgoing messages onto the socket. When
        // `out_rx` ends (every `ServerClient` handle was dropped) we must
        // actively close the socket — otherwise the reader task below keeps
        // the connection alive and the server never sees us disconnect (so
        // it never marks us offline / starts mailboxing). Closing here sends
        // a WebSocket Close frame; the server then tears down and our reader
        // observes the end of stream.
        tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                let json = match serde_json::to_string(&msg) {
                    Ok(j) => j,
                    Err(_) => continue,
                };
                if sink.send(WsMessage::Text(json.into())).await.is_err() {
                    return;
                }
            }
            let _ = sink.close().await;
        });

        // Reader pump: parse server messages into ServerEvents.
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
                    Ok(ServerMsg::Ready) => {
                        let _ = ev_tx.send(ServerEvent::Ready);
                    }
                    Ok(ServerMsg::Sent { id, delivered, queued }) => {
                        let _ = ev_tx.send(ServerEvent::Sent { id, delivered, queued });
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

    /// Assert membership of a room so the server mailboxes us when offline.
    pub fn subscribe(&self, room: &str) -> Result<()> {
        self.send(ClientMsg::Subscribe { room: room.to_string() })
    }

    pub fn unsubscribe(&self, room: &str) -> Result<()> {
        self.send(ClientMsg::Unsubscribe { room: room.to_string() })
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

/// Extract `host:port` from a `ws://`/`wss://` URL for the SOCKS target,
/// defaulting to port 80 when none is given (matches the onion's
/// `HiddenServicePort 80`).
fn host_port_from_ws_url(url: &str) -> Result<String> {
    let rest = url
        .strip_prefix("ws://")
        .or_else(|| url.strip_prefix("wss://"))
        .ok_or_else(|| HuddleError::Network(format!("expected ws:// url, got {url}")))?;
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.is_empty() {
        return Err(HuddleError::Network(format!("no host in url: {url}")));
    }
    if authority.contains(':') {
        Ok(authority.to_string())
    } else {
        Ok(format!("{authority}:80"))
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
        assert!(host_port_from_ws_url("http://x").is_err());
    }
}
