//! Phase C: invite-link encoding / decoding.
//!
//! Format: `huddle://invite#<base64url-no-pad JSON>`. The fragment
//! (`#`) keeps the payload out of HTTP `Referer` headers if someone
//! pastes through a web form somewhere.
//!
//! What's in the JSON:
//! - `host_multiaddr`: the dial target, WITH `/p2p/<peer-id>` suffix —
//!   libp2p enforces remote-pubkey-matches-this on dial, so this is
//!   the actual MITM defense (not the fingerprint string below).
//! - `fingerprint`: the host's 24-char Ed25519 fingerprint, shown in
//!   the confirmation modal so the receiver can verify ("yep, that's
//!   the fp Alice texted me out-of-band").
//! - `room`: optional — when present, the receiver auto-joins after
//!   the dial completes and the room announcement arrives.
//!
//! Important: the passphrase is NEVER in the link. Encrypted rooms
//! still require the joiner to type the passphrase separately;
//! including it would defeat the point of OOB sharing.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{HuddleError, Result};

pub const INVITE_PREFIX: &str = "huddle://invite#";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteLink {
    /// Always 1 in this version. Receiver rejects unknown versions —
    /// a bumped invite format gets a new number.
    pub v: u32,
    pub host_multiaddr: String,
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room: Option<InviteRoom>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteRoom {
    pub id: String,
    pub name: String,
    pub encrypted: bool,
    /// Base64 of the room's passphrase salt. Only meaningful for
    /// encrypted rooms (where the joiner must type the passphrase
    /// after dialing). `None` for unencrypted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt_b64: Option<String>,
    pub creator_fingerprint: String,
    #[serde(default)]
    pub owner_fingerprints: Vec<String>,
}

/// Build the `huddle://invite#...` URL form from a parsed `InviteLink`.
pub fn encode(invite: &InviteLink) -> Result<String> {
    let json = serde_json::to_vec(invite)
        .map_err(|e| HuddleError::Other(format!("invite encode: {e}")))?;
    Ok(format!("{}{}", INVITE_PREFIX, B64.encode(&json)))
}

/// Parse a `huddle://invite#...` URL back into an `InviteLink`.
pub fn decode(url: &str) -> Result<InviteLink> {
    let body = url
        .strip_prefix(INVITE_PREFIX)
        .ok_or_else(|| HuddleError::Other("not a huddle invite link".into()))?;
    let json = B64
        .decode(body.trim())
        .map_err(|e| HuddleError::Other(format!("bad base64: {e}")))?;
    let invite: InviteLink = serde_json::from_slice(&json)
        .map_err(|e| HuddleError::Other(format!("bad invite json: {e}")))?;
    if invite.v != 1 {
        return Err(HuddleError::Other(format!(
            "unsupported invite version: {}",
            invite.v
        )));
    }
    Ok(invite)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_peer_only() {
        let inv = InviteLink {
            v: 1,
            host_multiaddr: "/ip4/1.2.3.4/tcp/9000/p2p/12D3KooW...".into(),
            fingerprint: "abcd-1234-efef-5678-9090-1111".into(),
            room: None,
        };
        let url = encode(&inv).unwrap();
        assert!(url.starts_with(INVITE_PREFIX));
        let back = decode(&url).unwrap();
        assert_eq!(back, inv);
    }

    #[test]
    fn round_trip_with_room() {
        let inv = InviteLink {
            v: 1,
            host_multiaddr: "/ip4/1.2.3.4/tcp/9000/p2p/12D3KooW...".into(),
            fingerprint: "abcd-1234-efef-5678-9090-1111".into(),
            room: Some(InviteRoom {
                id: "rid-x".into(),
                name: "Project Alpha".into(),
                encrypted: true,
                salt_b64: Some("AAAAAA==".into()),
                creator_fingerprint: "abcd-1234-efef-5678-9090-1111".into(),
                owner_fingerprints: vec!["abcd-1234-efef-5678-9090-1111".into()],
            }),
        };
        let url = encode(&inv).unwrap();
        let back = decode(&url).unwrap();
        assert_eq!(back, inv);
    }

    #[test]
    fn decode_unknown_version_rejects() {
        // Hand-craft a JSON with v=99 and verify decode bails.
        let bad = serde_json::json!({
            "v": 99,
            "host_multiaddr": "/ip4/1.1.1.1/tcp/1",
            "fingerprint": "x"
        });
        let url = format!("{}{}", INVITE_PREFIX, B64.encode(bad.to_string()));
        assert!(decode(&url).is_err());
    }

    #[test]
    fn decode_not_huddle_url_rejects() {
        assert!(decode("https://example.com/invite").is_err());
    }
}
