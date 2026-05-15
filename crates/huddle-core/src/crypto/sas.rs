//! Short-Authentication-String (SAS) verification — Phase G.
//!
//! Two peers OOB-compare a short derived code to confirm they each
//! hold the matching Ed25519 keys (defense against MITM during initial
//! contact, before fingerprint trust is established).
//!
//! Protocol shape (each step is a signed `RoomMessage` on the room's
//! gossipsub topic):
//!
//! 1. Initiator picks a random 16-byte `tx_id` + an ephemeral X25519
//!    keypair. Sends `SasInit { tx_id, ephemeral_x25519_pubkey, target_fp }`.
//! 2. Responder generates their own ephemeral X25519 keypair, computes
//!    ECDH with the initiator's pubkey, derives the SAS code via
//!    `derive_sas_code(shared, tx_id)`, and replies with
//!    `SasResponse { tx_id, ephemeral_x25519_pubkey }`. The responder
//!    sees the code locally and shows it.
//! 3. The initiator computes ECDH the other direction, derives the
//!    same code, shows it.
//! 4. Both users compare codes OOB. Each side presses Match → broadcasts
//!    `SasConfirm { tx_id, matched: true }`.
//! 5. On receiving the other side's `matched=true`, set the partner's
//!    fingerprint as `verified=true` (per-room + global `verified_peers`).
//!
//! The signatures on each envelope bind the ephemeral X25519 pubkeys to
//! the sender's Ed25519 identity. A MITM who substitutes their own
//! ephemeral key into the exchange ends up with a *different* SAS code
//! than the legitimate peer would compute, so the OOB comparison fails.

use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{HuddleError, Result};

/// Length of the transaction id used as HKDF salt. 16 bytes (128 bits)
/// is plenty of unforgeability; sized to be base64-friendly.
pub const TX_ID_LEN: usize = 16;

/// SAS code information given to both sides for OOB comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SasCode {
    /// 6 emoji indices into [`SAS_EMOJI`] (each 0..64). Human-friendly
    /// for visual comparison; works in any modern terminal with emoji
    /// support.
    pub emoji_indices: [u8; 6],
    /// 6-decimal-digit version. Fallback for terminals without emoji
    /// rendering and easier to read aloud over a noisy call.
    pub decimal: String,
}

impl SasCode {
    pub fn emoji_string(&self) -> String {
        self.emoji_indices
            .iter()
            .map(|i| SAS_EMOJI[*i as usize].0)
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn emoji_labels(&self) -> String {
        self.emoji_indices
            .iter()
            .map(|i| SAS_EMOJI[*i as usize].1)
            .collect::<Vec<_>>()
            .join(" / ")
    }
}

/// Fresh X25519 ephemeral keypair + random tx_id. The secret stays on
/// the initiator's machine until the SAS finishes; the pubkey is
/// transmitted in the signed envelope.
pub fn new_session() -> ([u8; TX_ID_LEN], StaticSecret, PublicKey) {
    let mut tx_id = [0u8; TX_ID_LEN];
    rand::thread_rng().fill_bytes(&mut tx_id);
    // StaticSecret here is the X25519 "long-term" type from x25519-dalek;
    // we use it as ephemeral (drop after the SAS). Need the
    // `static_secrets` feature flag because the `EphemeralSecret` type
    // is more restrictive in v2 — `StaticSecret` lets us hold onto it
    // across a few async hops.
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);
    (tx_id, secret, public)
}

/// Derive the 6-emoji + 6-digit SAS code from the X25519 shared secret
/// and the agreed-upon `tx_id`. Both peers compute this independently
/// and must end up with the same answer for OOB comparison to succeed.
pub fn derive_sas_code(
    our_secret: &StaticSecret,
    their_public: &PublicKey,
    tx_id: &[u8; TX_ID_LEN],
) -> SasCode {
    let shared = our_secret.diffie_hellman(their_public);
    // HKDF over the shared secret. tx_id as salt prevents replay
    // (two SAS flows between the same pair must produce different
    // codes); info domain-separates from any other HKDF use.
    let hk = Hkdf::<Sha256>::new(Some(tx_id), shared.as_bytes());
    // 6 emoji bytes (each in 0..64 → 6 bits each = 36 bits) +
    // 3 bytes for the 6-digit decimal (~24 bits, plenty).
    let mut okm = [0u8; 9];
    hk.expand(b"huddle-sas-v1", &mut okm)
        .expect("9 bytes is well within HKDF output limit");
    let mut emoji_indices = [0u8; 6];
    for i in 0..6 {
        emoji_indices[i] = okm[i] & 0x3f; // mask to 0..64
    }
    let decimal = format!(
        "{:06}",
        (u32::from(okm[6]) << 16 | u32::from(okm[7]) << 8 | u32::from(okm[8])) % 1_000_000
    );
    SasCode {
        emoji_indices,
        decimal,
    }
}

/// 64 emoji / label pairs — every entry is visually distinct and the
/// label is a short English word so users can also read the code aloud.
/// Lifted in spirit from Matrix MSC 2241; reordered + relabelled to
/// keep words ASCII and one-syllable where possible.
pub const SAS_EMOJI: [(&str, &str); 64] = [
    ("🐶", "dog"),
    ("🐱", "cat"),
    ("🦁", "lion"),
    ("🐴", "horse"),
    ("🦄", "unicorn"),
    ("🐷", "pig"),
    ("🐘", "elephant"),
    ("🐰", "rabbit"),
    ("🐼", "panda"),
    ("🐔", "rooster"),
    ("🐧", "penguin"),
    ("🐢", "turtle"),
    ("🐟", "fish"),
    ("🐙", "octopus"),
    ("🦋", "butterfly"),
    ("🌷", "flower"),
    ("🌳", "tree"),
    ("🌵", "cactus"),
    ("🍄", "mushroom"),
    ("🌍", "globe"),
    ("🌙", "moon"),
    ("☁️", "cloud"),
    ("🔥", "fire"),
    ("🍌", "banana"),
    ("🍎", "apple"),
    ("🍓", "strawberry"),
    ("🌽", "corn"),
    ("🍕", "pizza"),
    ("🎂", "cake"),
    ("❤️", "heart"),
    ("🙂", "smiley"),
    ("🤖", "robot"),
    ("🎩", "hat"),
    ("👓", "glasses"),
    ("🔧", "spanner"),
    ("🎅", "santa"),
    ("👍", "thumbs up"),
    ("☂️", "umbrella"),
    ("⌛", "hourglass"),
    ("⏰", "clock"),
    ("🎁", "gift"),
    ("💡", "lightbulb"),
    ("📕", "book"),
    ("✏️", "pencil"),
    ("📎", "paperclip"),
    ("✂️", "scissors"),
    ("🔒", "lock"),
    ("🔑", "key"),
    ("🔨", "hammer"),
    ("☎️", "telephone"),
    ("🏁", "flag"),
    ("🚂", "train"),
    ("🚲", "bicycle"),
    ("✈️", "plane"),
    ("🚀", "rocket"),
    ("🏆", "trophy"),
    ("⚽", "ball"),
    ("🎸", "guitar"),
    ("🎺", "trumpet"),
    ("🔔", "bell"),
    ("⚓", "anchor"),
    ("🎧", "headphones"),
    ("📁", "folder"),
    ("📌", "pin"),
];

/// Decode a base64-encoded 32-byte X25519 pubkey received over the wire.
pub fn parse_pubkey(b64: &str) -> Result<PublicKey> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    let bytes = B64
        .decode(b64)
        .map_err(|e| HuddleError::Session(format!("bad x25519 pubkey b64: {e}")))?;
    if bytes.len() != 32 {
        return Err(HuddleError::Session(format!(
            "x25519 pubkey is {} bytes, expected 32",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(PublicKey::from(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_same_code() {
        let (tx_id, alice_secret, alice_pub) = new_session();
        let (_, bob_secret, bob_pub) = new_session();

        let alice_code = derive_sas_code(&alice_secret, &bob_pub, &tx_id);
        let bob_code = derive_sas_code(&bob_secret, &alice_pub, &tx_id);
        assert_eq!(alice_code, bob_code);
        assert_eq!(alice_code.decimal.len(), 6);
        assert!(alice_code.decimal.chars().all(|c| c.is_ascii_digit()));
        // Indices must all be in 0..64.
        for i in alice_code.emoji_indices {
            assert!((i as usize) < SAS_EMOJI.len());
        }
    }

    #[test]
    fn different_tx_id_yields_different_code() {
        let (tx_id_a, alice_secret, _) = new_session();
        let (_, bob_secret, bob_pub) = new_session();
        let alice_code = derive_sas_code(&alice_secret, &bob_pub, &tx_id_a);

        let mut tx_id_b = tx_id_a;
        tx_id_b[0] ^= 0xff;
        let alice_code_b = derive_sas_code(&alice_secret, &bob_pub, &tx_id_b);
        let _ = bob_secret;
        assert_ne!(alice_code, alice_code_b);
    }

    #[test]
    fn mitm_substitute_yields_different_code() {
        // Mallory MITMs: Alice's traffic to Bob is replaced with
        // Mallory's pubkey, and vice versa. Alice computes ECDH with
        // Mallory's pub; Bob computes ECDH with Mallory's pub. Their
        // SAS codes will both differ from each other and from a
        // legitimate same-pubkey-pair derivation — so OOB comparison
        // catches the attack.
        let (tx_id, alice_secret, alice_pub) = new_session();
        let (_, bob_secret, bob_pub) = new_session();
        let (_, _mallory_secret, mallory_pub) = new_session();

        let alice_thinks_bob = derive_sas_code(&alice_secret, &mallory_pub, &tx_id);
        let bob_thinks_alice = derive_sas_code(&bob_secret, &mallory_pub, &tx_id);
        assert_ne!(alice_thinks_bob, bob_thinks_alice);

        // Sanity: without MITM, both sides agree.
        let alice_real = derive_sas_code(&alice_secret, &bob_pub, &tx_id);
        let bob_real = derive_sas_code(&bob_secret, &alice_pub, &tx_id);
        assert_eq!(alice_real, bob_real);
    }

    #[test]
    fn pubkey_round_trip() {
        let (_, _, pub_) = new_session();
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        let encoded = B64.encode(pub_.as_bytes());
        let decoded = parse_pubkey(&encoded).unwrap();
        assert_eq!(decoded.as_bytes(), pub_.as_bytes());
    }
}
