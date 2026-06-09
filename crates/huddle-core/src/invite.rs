//! Phase C: invite-link encoding / decoding.
//!
//! Format: `huddle://invite#<base64url-no-pad JSON>`. The fragment
//! (`#`) keeps the payload out of HTTP `Referer` headers if someone
//! pastes through a web form somewhere.
//!
//! What's in the JSON:
//! - `v`: format version. `1` was the original unsigned shape (still
//!   accepted on decode for back-compat); `2` (huddle 0.7.11+) adds an
//!   Ed25519 signature over the rest of the payload so tampering with
//!   any field — salt, owner list, room name — is detected by the
//!   receiver. `host_multiaddr`'s `/p2p/<peer-id>` suffix remains the
//!   primary MITM defense at the libp2p layer, but the signature now
//!   also catches edits that don't touch the multiaddr.
//! - `host_multiaddr`: the dial target, WITH `/p2p/<peer-id>` suffix —
//!   libp2p enforces remote-pubkey-matches-this on dial, so this is
//!   the cryptographic anchor for "who you actually connect to."
//! - `fingerprint`: the host's 24-char Ed25519 fingerprint, shown in
//!   the confirmation modal so the receiver can verify ("yep, that's
//!   the fp Alice texted me out-of-band").
//! - `room`: optional — when present, the receiver auto-joins after
//!   the dial completes and the room announcement arrives.
//! - `creator_pubkey_b64` (v2+): the host's raw Ed25519 pubkey. The
//!   receiver re-derives the fingerprint from it and rejects the
//!   invite if `compute_fingerprint(pubkey) != fingerprint`.
//! - `signed_at_ms` (v2+): epoch-ms at signing time. Used to keep
//!   replays of stale invites loosely bounded (24h window by default).
//! - `signature_b64` (v2+): Ed25519 signature over a deterministic
//!   serialization of the other fields.
//! - `mlkem_ek_b64` (v4+): optional base64 of the inviter's ML-KEM-768
//!   encapsulation (public) key. When present it's folded into the
//!   signed transcript (the header bumps to `huddle-invite-v4|`),
//!   binding the inviter's post-quantum capability so a relay can't
//!   silently strip it without breaking the signature. Absent on
//!   classical invites, which stay byte-compatible with v2/v3.
//!
//! Important: the passphrase is NEVER in the link. Encrypted rooms
//! still require the joiner to type the passphrase separately;
//! including it would defeat the point of OOB sharing.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{HuddleError, Result};
use crate::identity::{compute_fingerprint, Identity};

pub const INVITE_PREFIX: &str = "huddle://invite#";

/// Max accepted age for a v2 signed invite. 24h. Long enough that the
/// recipient can act in their own time, short enough that captured
/// invites can't be re-used indefinitely (and they're invalidated
/// completely after the inviter's listen address changes anyway).
pub const INVITE_MAX_AGE_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteLink {
    /// 1 = legacy unsigned (huddle 0.7.10 and earlier).
    /// 2 = signed (huddle 0.7.11+). 3 = signed + `relay_url` (huddle 1.0+).
    /// 4 = signed + ML-KEM encapsulation-key commitment (huddle 2.0+).
    pub v: u32,
    pub host_multiaddr: String,
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room: Option<InviteRoom>,
    /// huddle 0.7.11: creator's raw Ed25519 pubkey, base64. Required
    /// for v >= 2. The verifier re-derives the fingerprint from this
    /// and rejects the invite if it doesn't match `fingerprint`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator_pubkey_b64: Option<String>,
    /// huddle 0.7.11: epoch-ms at signing time.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub signed_at_ms: i64,
    /// huddle 0.7.11: Ed25519 signature over `signable_bytes`. Required
    /// for v >= 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_b64: Option<String>,
    /// huddle 1.0: optional clearnet relay URL the inviter is reachable on
    /// (`wss://host/ws` or `ws://ip:port/ws` — e.g. a cloudflared tunnel).
    /// When present, the joiner can connect to the inviter's relay with zero
    /// config. Bumps the invite to `v=3` and is covered by the signature, so
    /// it can't be swapped for an attacker's relay without breaking the sig.
    /// `None` for relay-less invites (which stay `v=2`, readable by older
    /// clients).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
    /// huddle 2.0: optional base64 of the inviter's ML-KEM-768
    /// encapsulation (public) key. When present, the invite commits to
    /// the inviter's post-quantum identity in the signed transcript, so a
    /// relay can't strip the inviter's PQ capability without breaking the
    /// signature. Bumps the invite to `v=4` and is folded into
    /// `signable_bytes` only when present, so classical (ML-KEM-less)
    /// invites stay byte-identical to v2/v3 and readable by older clients.
    /// `None` for classical invites.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mlkem_ek_b64: Option<String>,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
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

impl InviteLink {
    /// Deterministic bytes the v2 signature commits to. Field order
    /// MUST never change once shipped — receivers that ratchet to a
    /// newer version still need to verify v2 invites.
    fn signable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        // huddle 2.0: the transcript header bumps to v4 only when the
        // invite commits to the inviter's ML-KEM encapsulation key, so the
        // signed bytes differ from a classical invite. ML-KEM-less invites
        // keep the exact `huddle-invite-v2|` header (and tail) so their
        // signed input stays byte-identical to pre-2.0 v2/v3 signers and
        // still verifies across versions.
        if self.mlkem_ek_b64.is_some() {
            out.extend_from_slice(b"huddle-invite-v4|");
        } else {
            out.extend_from_slice(b"huddle-invite-v2|");
        }
        out.extend_from_slice(self.host_multiaddr.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.fingerprint.as_bytes());
        out.push(b'|');
        out.extend_from_slice(&self.signed_at_ms.to_be_bytes());
        out.push(b'|');
        if let Some(r) = &self.room {
            out.extend_from_slice(b"room|");
            out.extend_from_slice(r.id.as_bytes());
            out.push(b'|');
            out.extend_from_slice(r.name.as_bytes());
            out.push(b'|');
            out.push(if r.encrypted { b'E' } else { b'P' });
            out.push(b'|');
            if let Some(s) = &r.salt_b64 {
                out.extend_from_slice(s.as_bytes());
            }
            out.push(b'|');
            out.extend_from_slice(r.creator_fingerprint.as_bytes());
            out.push(b'|');
            // owner list: alphabetically sorted + comma joined for
            // determinism. Anyone constructing the invite must sort
            // before signing; the receiver re-sorts before verifying.
            let mut owners = r.owner_fingerprints.clone();
            owners.sort();
            out.extend_from_slice(owners.join(",").as_bytes());
        } else {
            out.extend_from_slice(b"no-room");
        }
        // huddle 1.0: append the relay only when present, so relay-less
        // invites produce byte-identical input to pre-1.0 v2 signers and
        // still verify across versions. Signer and verifier append it
        // identically, so it's covered by the signature.
        if let Some(relay) = &self.relay_url {
            out.extend_from_slice(b"|relay|");
            out.extend_from_slice(relay.as_bytes());
        }
        // huddle 2.0: append the ML-KEM encapsulation key only when present,
        // mirroring the relay tail above. Classical invites omit it entirely
        // (byte-compatible with v2/v3); when present, signer and verifier
        // append it identically so it's covered by the signature — a relay
        // can't strip or swap the inviter's PQ key without breaking the sig.
        if let Some(ek) = &self.mlkem_ek_b64 {
            out.extend_from_slice(b"|mlkem-ek|");
            out.extend_from_slice(ek.as_bytes());
        }
        out
    }
}

/// huddle 0.7.11: sign an invite. Sets `v=2`, `creator_pubkey_b64`,
/// `signed_at_ms`, and `signature_b64`. The input invite's `v` and
/// signature fields are overwritten.
pub fn sign_invite(identity: &Identity, mut invite: InviteLink) -> Result<InviteLink> {
    // huddle 2.0: v=4 when the invite commits to the inviter's ML-KEM
    // encapsulation key. Otherwise huddle 1.0's rule applies: v=3 when the
    // invite carries a relay URL, else v=2 so the plainest invites stay
    // readable by pre-1.0 clients. (An ML-KEM invite may also carry a relay;
    // the v4 header already supersedes v3 in that case.)
    invite.v = if invite.mlkem_ek_b64.is_some() {
        4
    } else if invite.relay_url.is_some() {
        3
    } else {
        2
    };
    invite.creator_pubkey_b64 = Some(B64.encode(identity.public_bytes()));
    invite.signed_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    invite.signature_b64 = None;
    // Canonical sort so the verifier can re-canonicalize identically.
    if let Some(r) = invite.room.as_mut() {
        r.owner_fingerprints.sort();
    }
    let payload = invite.signable_bytes();
    let sig = identity.sign(&payload);
    invite.signature_b64 = Some(B64.encode(sig));
    Ok(invite)
}

/// Build the `huddle://invite#...` URL form from a parsed `InviteLink`.
pub fn encode(invite: &InviteLink) -> Result<String> {
    let json = serde_json::to_vec(invite)
        .map_err(|e| HuddleError::Other(format!("invite encode: {e}")))?;
    Ok(format!("{}{}", INVITE_PREFIX, B64URL.encode(&json)))
}

/// Parse a `huddle://invite#...` URL back into an `InviteLink`.
///
/// huddle 0.7.11: when `v >= 2`, this *also* verifies the signature
/// against the embedded pubkey, re-derives the fingerprint, and rejects
/// invites whose `signed_at_ms` is older than `INVITE_MAX_AGE_MS`.
/// `v == 1` (legacy) parses unchanged so older invites still work,
/// but callers should display a "this invite is unsigned" warning.
pub fn decode(url: &str) -> Result<InviteLink> {
    let body = url
        .strip_prefix(INVITE_PREFIX)
        .ok_or_else(|| HuddleError::Other("not a huddle invite link".into()))?;
    let json = B64URL
        .decode(body.trim())
        .map_err(|e| HuddleError::Other(format!("bad base64: {e}")))?;
    let invite: InviteLink = serde_json::from_slice(&json)
        .map_err(|e| HuddleError::Other(format!("bad invite json: {e}")))?;
    match invite.v {
        1 => {
            // huddle 1.3.4: refuse a v2/v3 → v1 downgrade. The `v` field is
            // NOT covered by `signable_bytes`, so an attacker can flip a
            // signed v2/v3 invite to `v=1` to skip `verify_invite_signature`
            // / `verify_invite_freshness` entirely, then swap the relay URL,
            // fingerprint, or room. A *genuine* legacy v1 invite predates
            // signing and therefore carries none of the signature fields, so
            // the presence of any of them means this is a stripped signed
            // invite — reject it instead of accepting it unverified.
            if invite.creator_pubkey_b64.is_some()
                || invite.signature_b64.is_some()
                || invite.signed_at_ms != 0
            {
                return Err(HuddleError::Other(
                    "invite claims legacy v1 but carries signature fields \
                     (possible version-downgrade attack) — refusing"
                        .into(),
                ));
            }
            Ok(invite)
        }
        // huddle 1.0: v3 adds the signed `relay_url`; it verifies identically
        // to v2 because `signable_bytes` already folds the relay in when present.
        // huddle 2.0: v4 adds the signed `mlkem_ek_b64`; it likewise verifies
        // identically because `signable_bytes` swaps to the `huddle-invite-v4|`
        // header and folds the ML-KEM key in whenever it's present. Stripping
        // the key (a PQ-downgrade) changes the reconstructed bytes and fails
        // the signature — exactly the defense we want.
        2 | 3 | 4 => {
            verify_invite_signature(&invite)?;
            verify_invite_freshness(&invite)?;
            Ok(invite)
        }
        n => Err(HuddleError::Other(format!(
            "unsupported invite version: {n}"
        ))),
    }
}

/// True if this invite came in unsigned (legacy `v=1`). UI should show
/// a "this invite is unsigned — verify the fingerprint out-of-band"
/// warning when this returns true.
pub fn is_legacy_unsigned(invite: &InviteLink) -> bool {
    invite.v < 2
}

fn verify_invite_signature(invite: &InviteLink) -> Result<()> {
    let pubkey_b64 = invite
        .creator_pubkey_b64
        .as_ref()
        .ok_or_else(|| HuddleError::Other("v2 invite missing creator_pubkey_b64".into()))?;
    let sig_b64 = invite
        .signature_b64
        .as_ref()
        .ok_or_else(|| HuddleError::Other("v2 invite missing signature_b64".into()))?;
    let pubkey_bytes = B64
        .decode(pubkey_b64)
        .map_err(|e| HuddleError::Other(format!("bad creator_pubkey_b64: {e}")))?;
    if pubkey_bytes.len() != 32 {
        return Err(HuddleError::Other(format!(
            "creator_pubkey is {} bytes, expected 32",
            pubkey_bytes.len()
        )));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pubkey_bytes);
    let derived_fp = compute_fingerprint(&pk_arr);
    if derived_fp != invite.fingerprint {
        return Err(HuddleError::Other(format!(
            "invite fingerprint {} doesn't match pubkey-derived {}",
            invite.fingerprint, derived_fp
        )));
    }
    let sig_bytes = B64
        .decode(sig_b64)
        .map_err(|e| HuddleError::Other(format!("bad signature_b64: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(HuddleError::Other(format!(
            "signature is {} bytes, expected 64",
            sig_bytes.len()
        )));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);
    let vk = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| HuddleError::Other(format!("bad verifying key: {e}")))?;
    // Re-canonicalize before verification (in case owner_fingerprints
    // arrived un-sorted from a less-careful sender).
    let mut canon = invite.clone();
    if let Some(r) = canon.room.as_mut() {
        r.owner_fingerprints.sort();
    }
    vk.verify_strict(&canon.signable_bytes(), &signature)
        .map_err(|e| HuddleError::Other(format!("invite signature verify failed: {e}")))?;
    Ok(())
}

fn verify_invite_freshness(invite: &InviteLink) -> Result<()> {
    if invite.signed_at_ms == 0 {
        return Err(HuddleError::Other("v2 invite missing signed_at_ms".into()));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let age = now - invite.signed_at_ms;
    if age > INVITE_MAX_AGE_MS {
        return Err(HuddleError::Other(format!(
            "invite is {}h old — re-generate (max {}h)",
            age / 3_600_000,
            INVITE_MAX_AGE_MS / 3_600_000
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> InviteLink {
        InviteLink {
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
            creator_pubkey_b64: None,
            signed_at_ms: 0,
            signature_b64: None,
            relay_url: None,
            mlkem_ek_b64: None,
        }
    }

    #[test]
    fn legacy_v1_round_trip() {
        let inv = fixture();
        let url = encode(&inv).unwrap();
        let back = decode(&url).unwrap();
        assert_eq!(back.v, 1);
        assert!(is_legacy_unsigned(&back));
        assert_eq!(back, inv);
    }

    #[test]
    fn signed_v2_round_trip() {
        let id = Identity::generate().unwrap();
        let mut inv = fixture();
        inv.fingerprint = id.fingerprint().to_string();
        let signed = sign_invite(&id, inv).unwrap();
        assert_eq!(signed.v, 2);
        assert!(signed.signature_b64.is_some());
        let url = encode(&signed).unwrap();
        let back = decode(&url).unwrap();
        assert_eq!(back, signed);
        assert!(!is_legacy_unsigned(&back));
    }

    #[test]
    fn tampered_salt_fails() {
        let id = Identity::generate().unwrap();
        let mut inv = fixture();
        inv.fingerprint = id.fingerprint().to_string();
        let mut signed = sign_invite(&id, inv).unwrap();
        // Flip the salt; signature should no longer verify.
        if let Some(r) = signed.room.as_mut() {
            r.salt_b64 = Some("ZZZZZZZZ==".into());
        }
        let url = encode(&signed).unwrap();
        let err = decode(&url).unwrap_err();
        assert!(format!("{err}").contains("invite signature verify failed"));
    }

    #[test]
    fn tampered_owner_list_fails() {
        let id = Identity::generate().unwrap();
        let mut inv = fixture();
        inv.fingerprint = id.fingerprint().to_string();
        let mut signed = sign_invite(&id, inv).unwrap();
        if let Some(r) = signed.room.as_mut() {
            r.owner_fingerprints.push("attacker-fp".into());
        }
        let url = encode(&signed).unwrap();
        let err = decode(&url).unwrap_err();
        assert!(format!("{err}").contains("invite signature verify failed"));
    }

    #[test]
    fn substituted_pubkey_fails_fp_check() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let mut inv = fixture();
        inv.fingerprint = alice.fingerprint().to_string();
        let mut signed = sign_invite(&alice, inv).unwrap();
        // Swap in Bob's pubkey (so the derived fingerprint will not
        // match alice's — caught before signature verify is attempted).
        signed.creator_pubkey_b64 = Some(B64.encode(bob.public_bytes()));
        let url = encode(&signed).unwrap();
        let err = decode(&url).unwrap_err();
        assert!(format!("{err}").contains("doesn't match pubkey-derived"));
    }

    #[test]
    fn decode_unknown_version_rejects() {
        let bad = serde_json::json!({
            "v": 99,
            "host_multiaddr": "/ip4/1.1.1.1/tcp/1",
            "fingerprint": "x"
        });
        let url = format!("{}{}", INVITE_PREFIX, B64URL.encode(bad.to_string()));
        assert!(decode(&url).is_err());
    }

    #[test]
    fn decode_not_huddle_url_rejects() {
        assert!(decode("https://example.com/invite").is_err());
    }

    // huddle 1.0: v3 invites carry a signed clearnet relay URL.
    #[test]
    fn signed_v3_with_relay_round_trips() {
        let id = Identity::generate().unwrap();
        let mut inv = fixture();
        inv.fingerprint = id.fingerprint().to_string();
        inv.relay_url = Some("wss://abc.trycloudflare.com/ws".into());
        let signed = sign_invite(&id, inv).unwrap();
        assert_eq!(signed.v, 3, "an invite with a relay must be v3");
        let url = encode(&signed).unwrap();
        let back = decode(&url).unwrap();
        assert_eq!(back, signed);
        assert_eq!(
            back.relay_url.as_deref(),
            Some("wss://abc.trycloudflare.com/ws")
        );
    }

    #[test]
    fn relay_less_invite_stays_v2() {
        // A relay-less invite must remain v2 so older clients still accept it.
        let id = Identity::generate().unwrap();
        let mut inv = fixture();
        inv.fingerprint = id.fingerprint().to_string();
        assert!(inv.relay_url.is_none());
        let signed = sign_invite(&id, inv).unwrap();
        assert_eq!(signed.v, 2);
    }

    #[test]
    fn tampered_relay_fails() {
        let id = Identity::generate().unwrap();
        let mut inv = fixture();
        inv.fingerprint = id.fingerprint().to_string();
        inv.relay_url = Some("wss://mine.example/ws".into());
        let mut signed = sign_invite(&id, inv).unwrap();
        // Swap in an attacker's relay; the signature must no longer verify.
        signed.relay_url = Some("wss://attacker.example/ws".into());
        let url = encode(&signed).unwrap();
        let err = decode(&url).unwrap_err();
        assert!(format!("{err}").contains("invite signature verify failed"));
    }

    // huddle 1.3.4: a signed v2/v3 invite flipped to v=1 must be rejected,
    // not silently accepted unverified. The `v` field is not signature-bound,
    // so this is the version-downgrade attack — caught by the "v1 may not
    // carry signature fields" guard in `decode`.
    #[test]
    fn version_downgrade_to_v1_is_rejected() {
        let id = Identity::generate().unwrap();
        let mut inv = fixture();
        inv.fingerprint = id.fingerprint().to_string();
        inv.relay_url = Some("wss://mine.example/ws".into());
        let mut signed = sign_invite(&id, inv).unwrap();
        assert_eq!(signed.v, 3);
        // Attacker flips the (unsigned) version field and swaps the relay.
        signed.v = 1;
        signed.relay_url = Some("wss://attacker.example/ws".into());
        let url = encode(&signed).unwrap();
        let err = decode(&url).unwrap_err();
        assert!(
            format!("{err}").contains("downgrade"),
            "expected a downgrade rejection, got: {err}"
        );
    }

    // A v2 invite downgraded to v1 (no relay) is likewise refused because it
    // still carries the signature fields a real legacy v1 never had.
    #[test]
    fn v2_stripped_to_v1_is_rejected() {
        let id = Identity::generate().unwrap();
        let mut inv = fixture();
        inv.fingerprint = id.fingerprint().to_string();
        let mut signed = sign_invite(&id, inv).unwrap();
        assert_eq!(signed.v, 2);
        signed.v = 1;
        let url = encode(&signed).unwrap();
        assert!(decode(&url).is_err());
    }

    // huddle 2.0: a v4 invite commits to the inviter's ML-KEM encapsulation
    // key in the signed transcript and round-trips through encode/decode.
    #[test]
    fn signed_v4_with_mlkem_round_trips() {
        let id = Identity::generate().unwrap();
        let mut inv = fixture();
        inv.fingerprint = id.fingerprint().to_string();
        inv.mlkem_ek_b64 = Some(B64.encode([7u8; 1184])); // ML-KEM-768 ek size
        let signed = sign_invite(&id, inv).unwrap();
        assert_eq!(
            signed.v, 4,
            "an invite committing to an ML-KEM key must be v4"
        );
        let url = encode(&signed).unwrap();
        let back = decode(&url).unwrap();
        assert_eq!(back, signed);
        assert_eq!(back.mlkem_ek_b64, Some(B64.encode([7u8; 1184])));
        assert!(!is_legacy_unsigned(&back));
    }

    // An invite carrying both a relay and an ML-KEM key is v4 (the PQ header
    // supersedes v3) and still round-trips with the relay intact.
    #[test]
    fn v4_with_relay_and_mlkem_round_trips() {
        let id = Identity::generate().unwrap();
        let mut inv = fixture();
        inv.fingerprint = id.fingerprint().to_string();
        inv.relay_url = Some("wss://abc.trycloudflare.com/ws".into());
        inv.mlkem_ek_b64 = Some(B64.encode([3u8; 1184]));
        let signed = sign_invite(&id, inv).unwrap();
        assert_eq!(signed.v, 4);
        let url = encode(&signed).unwrap();
        let back = decode(&url).unwrap();
        assert_eq!(back, signed);
        assert_eq!(
            back.relay_url.as_deref(),
            Some("wss://abc.trycloudflare.com/ws")
        );
        assert!(back.mlkem_ek_b64.is_some());
    }

    // Tampering with the committed ML-KEM key breaks the signature — this is
    // the PQ-downgrade defense: a relay can't swap the inviter's PQ key.
    #[test]
    fn tampered_mlkem_fails() {
        let id = Identity::generate().unwrap();
        let mut inv = fixture();
        inv.fingerprint = id.fingerprint().to_string();
        inv.mlkem_ek_b64 = Some(B64.encode([1u8; 1184]));
        let mut signed = sign_invite(&id, inv).unwrap();
        // Swap in an attacker's ML-KEM key; the signature must no longer verify.
        signed.mlkem_ek_b64 = Some(B64.encode([2u8; 1184]));
        let url = encode(&signed).unwrap();
        let err = decode(&url).unwrap_err();
        assert!(format!("{err}").contains("invite signature verify failed"));
    }

    // Stripping the ML-KEM key from a v4 invite (the actual PQ-downgrade) is
    // caught: the verifier reconstructs the classical `huddle-invite-v2|`
    // bytes without the key tail, which no longer matches the v4 signature.
    // Flipping the (unsigned) version field too doesn't help the attacker.
    #[test]
    fn stripped_mlkem_downgrade_is_rejected() {
        let id = Identity::generate().unwrap();
        let mut inv = fixture();
        inv.fingerprint = id.fingerprint().to_string();
        inv.mlkem_ek_b64 = Some(B64.encode([9u8; 1184]));
        let mut signed = sign_invite(&id, inv).unwrap();
        assert_eq!(signed.v, 4);
        // Attacker strips the PQ commitment and flips the version to v2.
        signed.mlkem_ek_b64 = None;
        signed.v = 2;
        let url = encode(&signed).unwrap();
        let err = decode(&url).unwrap_err();
        assert!(format!("{err}").contains("invite signature verify failed"));
    }

    // A classical invite (no ML-KEM key) keeps the exact pre-2.0 v2 signed
    // bytes, so its signature is byte-compatible across versions: signing the
    // same invite without and with an unrelated relay must still produce v2/v3,
    // never v4.
    #[test]
    fn classical_invite_stays_v2_or_v3() {
        let id = Identity::generate().unwrap();
        let mut inv = fixture();
        inv.fingerprint = id.fingerprint().to_string();
        let signed = sign_invite(&id, inv).unwrap();
        assert_eq!(signed.v, 2);
        assert!(signed.mlkem_ek_b64.is_none());

        let mut inv = fixture();
        inv.fingerprint = id.fingerprint().to_string();
        inv.relay_url = Some("wss://mine.example/ws".into());
        let signed = sign_invite(&id, inv).unwrap();
        assert_eq!(signed.v, 3);
        assert!(signed.mlkem_ek_b64.is_none());
    }
}
