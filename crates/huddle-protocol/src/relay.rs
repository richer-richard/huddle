//! The relay control protocol: the JSON messages a huddle client and a
//! `huddle-server` relay exchange over the WebSocket door.
//!
//! Extracted here so the client (`huddle-core::network::server`) and the relay
//! (`huddle-server`) share ONE definition instead of the two hand-kept-in-sync
//! copies they carried before. [`ClientMsg`] is what the client sends and the
//! relay receives; [`ServerMsg`] is the reverse. Both derive `Serialize` +
//! `Deserialize` so each side uses whichever direction it needs.
//!
//! Wire-compat note: the field-level `#[serde(default)]` / `skip_serializing_if`
//! attributes match the relay's historical (authoritative) serialization, so
//! these unified types are byte-identical to both prior copies — old clients
//! and relays interoperate unchanged.

use serde::{Deserialize, Serialize};

/// Client → relay. The client serializes these; the relay deserializes them,
/// tolerating absent optional fields from older clients via `serde(default)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    /// Announce identity and (re)assert room memberships, then drain the
    /// mailbox. Must be the first message. huddle 1.1.4: it authenticates —
    /// `pubkey_b64` is the client's Ed25519 pubkey and `signature_b64` is a
    /// signature over `RELAY_AUTH_DOMAIN || nonce` for the nonce the relay sent
    /// in the opening `Challenge`. The relay verifies both before registering.
    Hello {
        fingerprint: String,
        #[serde(default)]
        pubkey_b64: String,
        #[serde(default)]
        signature_b64: String,
        #[serde(default)]
        rooms: Vec<String>,
        /// huddle 2.0: capability bit — the client implements at-least-once
        /// mailbox ACKs (it answers each queued `Message` with `ClientMsg::Ack`
        /// carrying the row's `mailbox_id`). When `true` the relay tags each
        /// mailbox delivery with its row id and keeps the row until the matching
        /// `Ack` arrives; when `false` (pre-2.0 clients — the serde default) the
        /// relay falls back to classical delete-on-deliver.
        #[serde(default)]
        acks: bool,
    },
    Subscribe {
        room: String,
    },
    Unsubscribe {
        room: String,
    },
    /// Send an opaque payload to every other member of `room`.
    Publish {
        room: String,
        id: String,
        payload_b64: String,
    },
    /// huddle 1.2: deliver an opaque payload to a SPECIFIC recipient
    /// fingerprint, independent of room membership — how 1:1 DMs and friend
    /// requests route reliably. `room` is an opaque tag the recipient's client
    /// uses to file the message; the relay never interprets it.
    SendDirect {
        to: String,
        room: String,
        id: String,
        payload_b64: String,
    },
    /// huddle 1.2.1: mint a short-lived connect code bound to this
    /// authenticated identity. The relay replies with `ConnectToken`.
    CreateConnectToken,
    /// huddle 1.2.1: resolve a connect code to its owner's fingerprint+pubkey.
    /// The relay replies with `ConnectTokenResolved` (fingerprint = None when
    /// unknown/expired).
    RedeemConnectToken {
        token: String,
    },
    /// Re-drain the mailbox on demand.
    Fetch,
    /// huddle 2.0: acknowledge durable receipt of a relay-delivered mailbox
    /// message. The relay deletes the row only after this ACK (at-least-once
    /// delivery). Scoped to the authenticated fingerprint.
    Ack {
        mailbox_id: i64,
    },
    Ping,
}

/// Relay → client. The relay serializes these; the client deserializes them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    /// huddle 1.1.4: sent immediately on connect. The client signs the nonce to
    /// prove control of its identity key before it can do anything.
    Challenge {
        nonce_b64: String,
    },
    /// Sent after a successful `Hello`. Carries the authenticated fingerprint
    /// (the client already knows its own identity, so it ignores the field).
    Ready {
        fingerprint: String,
    },
    /// A room message delivered live or from the offline mailbox. huddle 2.0:
    /// `mailbox_id` is `Some(row_id)` when the message came from the relay's
    /// on-disk queue AND the recipient advertised ACK support in its `Hello`;
    /// `None` for live fan-out and pre-2.0 clients. `skip_serializing_if` keeps
    /// the field off the wire for live/legacy messages so old clients see
    /// exactly the bytes they expect.
    Message {
        room: String,
        id: String,
        payload_b64: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mailbox_id: Option<i64>,
    },
    Sent {
        id: String,
        delivered: usize,
        queued: usize,
    },
    /// huddle 1.2.1: a freshly minted connect code + its lifetime (seconds).
    ConnectToken {
        token: String,
        ttl_secs: u64,
    },
    /// huddle 1.2.1: result of redeeming a connect code. `fingerprint` /
    /// `pubkey_b64` are `None` when the code is unknown or expired. The relay
    /// echoes the `token`; the client ignores it.
    ConnectTokenResolved {
        token: String,
        #[serde(default)]
        fingerprint: Option<String>,
        #[serde(default)]
        pubkey_b64: Option<String>,
    },
    Pong,
    Error {
        message: String,
    },
}
