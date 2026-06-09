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
//!
//! ## SAS table — a huddle-internal scheme (NOT Matrix wire-compatible)
//!
//! huddle uses its own 49-emoji subset of the Matrix MSC 2241 list under a
//! huddle-specific HKDF info string (`b"huddle-sas-v1"`) and maps 6-bit chunks
//! into 0..49 by **rejection sampling** (see `derive_emoji_indices_rejection`).
//! This does **not** interoperate with Matrix SAS: canonical MSC 2241 uses a
//! 64-entry table indexed directly by each 6-bit chunk (no modulus, no
//! rejection sampling) under its own info string, so a Matrix client would
//! derive entirely different emoji. The derivation produces 7 emoji (42 bits /
//! 6 = 7 chunks) and 3 four-digit decimal groups (39 bits / 13 = 3 chunks, each
//! offset +1000 so values land in 1000..=9191); the decimal shape matches the
//! MSC 2241 decimal SAS, but the emoji scheme is huddle↔huddle only. Since both
//! peers run identical deterministic code, MITM detection is unaffected.
//!
//! ## huddle 2.0: optional post-quantum capability binding
//!
//! [`derive_sas_code`] takes an optional `partner_mlkem_ek`. When the partner
//! is post-quantum capable (their signed `MemberAnnounce` carries an ML-KEM
//! encapsulation key), the caller passes `Some(ek)`, which mixes a
//! `b"huddle-sas-pqbind-v1"` domain tag plus `SHA-256(ek)` into the HKDF `info`
//! — so the partner's *PQ capability* becomes part of the out-of-band trust
//! anchor. A relay that strips the ML-KEM pubkey from one side's announce
//! drives that side to derive with `None` while the other still binds with
//! `Some(ek)`; the two SAS codes then diverge and the OOB comparison catches
//! the silent classical downgrade. The salt (`tx_id`) and PRF (HKDF-SHA256) are
//! unchanged — only the `info` domain tag + hash are added. With `None` (group
//! members, pre-1.3 partners, or the classical fallback) the derivation is
//! byte-for-byte identical to the 1.x `b"huddle-sas-v1"` transcript, so old and
//! new peers that both lack the ek still agree.

use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{HuddleError, Result};

/// Length of the transaction id used as HKDF salt. 16 bytes (128 bits)
/// is plenty of unforgeability; sized to be base64-friendly.
pub const TX_ID_LEN: usize = 16;

/// HKDF `info` for the classical (no PQ binding) SAS transcript. Frozen since
/// huddle 0.7 — kept byte-for-byte so a `partner_mlkem_ek = None` derivation
/// stays compatible with every prior release.
const SAS_INFO_V1: &[u8] = b"huddle-sas-v1";

/// huddle 2.0: domain tag prefixed to `SHA-256(partner_mlkem_ek)` when the SAS
/// transcript binds the partner's post-quantum (ML-KEM) capability. Distinct
/// from [`SAS_INFO_V1`] so a bound and an unbound derivation can never collide.
const SAS_INFO_PQBIND: &[u8] = b"huddle-sas-pqbind-v1";

/// SAS code information given to both sides for OOB comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SasCode {
    /// 7 emoji indices into [`SAS_EMOJI`] (each 0..49). Human-friendly
    /// for visual comparison; works in any modern terminal with emoji
    /// support. Matches Matrix MSC 2241 shape.
    pub emoji_indices: [u8; 7],
    /// Three 4-digit groups separated by `-`, each in `1000..=9191`,
    /// per MSC 2241. Easier to read aloud than a flat 7-digit number.
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

/// Derive the 7-emoji + 3-group-decimal SAS code from the X25519
/// shared secret and the agreed-upon `tx_id`. Both peers compute this
/// independently and must end up with the same answer for OOB
/// comparison to succeed.
///
/// Matches the MSC 2241 SAS *shape* (not wire-compatible — see the module
/// doc): HKDF-SHA256 with `tx_id` as salt and the SAS info string as info,
/// expanded to 11 bytes. First 6 bytes → 7 6-bit chunks, rejection-sampled
/// into 0..49 → emoji indices. Next 5 bytes → 3 13-bit chunks (+ 1000) → 3
/// four-digit decimal groups.
///
/// `partner_mlkem_ek` is huddle 2.0's optional post-quantum capability binding
/// (see the module doc). Pass `Some(ek)` with the partner's ML-KEM
/// encapsulation key when they are PQ-capable — its `SHA-256` hash and a domain
/// tag are folded into the HKDF `info`, anchoring "this peer is PQ-capable" into
/// the verified SAS so a relay can't silently downgrade them to classical-only.
/// Pass `None` for group members, pre-1.3 partners, or the classical fallback;
/// that path is byte-for-byte identical to the 1.x derivation. Both peers must
/// pass the *same* `ek` (or both `None`) to derive the same code.
pub fn derive_sas_code(
    our_secret: &StaticSecret,
    their_public: &PublicKey,
    tx_id: &[u8; TX_ID_LEN],
    partner_mlkem_ek: Option<&[u8]>,
) -> Result<SasCode> {
    let shared = our_secret.diffie_hellman(their_public);
    // huddle 1.1.4: reject a non-contributory (small-order) peer ephemeral.
    // Such a "pubkey" forces a predictable shared secret, which would let a
    // MITM steer both sides to a derivable SAS code and defeat the OOB
    // comparison. Honest peers always produce a contributory secret.
    if !shared.was_contributory() {
        return Err(HuddleError::Session(
            "SAS rejected: peer X25519 ephemeral is non-contributory (small-order point)".into(),
        ));
    }
    // HKDF over the shared secret. tx_id as salt prevents replay
    // (two SAS flows between the same pair must produce different
    // codes); info domain-separates from any other HKDF use and — in
    // huddle 2.0 — optionally binds the partner's ML-KEM capability.
    let hk = Hkdf::<Sha256>::new(Some(tx_id), shared.as_bytes());
    let info = sas_info(partner_mlkem_ek);
    let mut okm = [0u8; 11];
    hk.expand(&info, &mut okm)
        .expect("11 bytes is well within HKDF output limit");

    // First 6 bytes = 48 bits. Use the high 42 bits (7 × 6) for emoji.
    // Bit extraction (big-endian, MSB-first):
    let b = &okm[..6];
    let mut raw_emoji = [0u8; 7];
    raw_emoji[0] = b[0] >> 2;
    raw_emoji[1] = ((b[0] & 0x03) << 4) | (b[1] >> 4);
    raw_emoji[2] = ((b[1] & 0x0f) << 2) | (b[2] >> 6);
    raw_emoji[3] = b[2] & 0x3f;
    raw_emoji[4] = b[3] >> 2;
    raw_emoji[5] = ((b[3] & 0x03) << 4) | (b[4] >> 4);
    raw_emoji[6] = ((b[4] & 0x0f) << 2) | (b[5] >> 6);
    // huddle 0.7.11: rejection sampling instead of `raw % 49`.
    // 6-bit values in 0..64 mod 49 makes indices 0..14 twice as likely
    // (hit by raw 0..14 AND raw 49..63), measurably under-sampling the
    // 49^7 SAS space and reducing effective entropy. Now we expand
    // additional HKDF output to refill any byte that falls in 49..63
    // — the canonical MSC 2241 approach. The expansion is cheap and
    // deterministic, so both sides still derive the same code.
    let emoji_indices = derive_emoji_indices_rejection(&hk, raw_emoji);

    // Bytes 6..11 = 40 bits. Use the high 39 bits for the decimal
    // (3 × 13-bit chunks, each offset by 1000).
    let d = &okm[6..11];
    let chunk0 = ((u32::from(d[0]) << 5) | (u32::from(d[1]) >> 3)) & 0x1fff;
    let chunk1 = ((u32::from(d[1] & 0x07) << 10)
        | (u32::from(d[2]) << 2)
        | (u32::from(d[3]) >> 6))
        & 0x1fff;
    let chunk2 = ((u32::from(d[3] & 0x3f) << 7) | (u32::from(d[4]) >> 1)) & 0x1fff;
    let decimal = format!("{}-{}-{}", chunk0 + 1000, chunk1 + 1000, chunk2 + 1000);

    Ok(SasCode {
        emoji_indices,
        decimal,
    })
}

/// Build the HKDF `info` for the main SAS expansion.
///
/// `None` reproduces the classical 1.x transcript byte-for-byte
/// ([`SAS_INFO_V1`]). `Some(ek)` binds the partner's post-quantum capability by
/// concatenating the [`SAS_INFO_PQBIND`] domain tag with `SHA-256(ek)`, so a
/// bound derivation can never collide with an unbound one and stripping the
/// ML-KEM key from one side makes the two SAS codes diverge (see the module
/// doc). Only the `info` changes; the `tx_id` salt and the HKDF-SHA256 PRF are
/// untouched.
fn sas_info(partner_mlkem_ek: Option<&[u8]>) -> Vec<u8> {
    match partner_mlkem_ek {
        None => SAS_INFO_V1.to_vec(),
        Some(ek) => {
            let digest = Sha256::digest(ek);
            let mut info = Vec::with_capacity(SAS_INFO_PQBIND.len() + digest.len());
            info.extend_from_slice(SAS_INFO_PQBIND);
            info.extend_from_slice(&digest);
            info
        }
    }
}

/// huddle's 49-emoji subset of the Matrix MSC 2241 list, English labels.
/// Indices 0-48; the derivation above rejection-samples 6-bit HKDF chunks
/// into 0..49 (not Matrix's direct 6-bit indexing — see the module doc).
pub const SAS_EMOJI: [(&str, &str); 49] = [
    ("🐶", "dog"),
    ("🐱", "cat"),
    ("🦁", "lion"),
    ("🐎", "horse"),
    ("🦄", "unicorn"),
    ("🐷", "pig"),
    ("🐘", "elephant"),
    ("🐰", "rabbit"),
    ("🐼", "panda"),
    ("🐓", "rooster"),
    ("🐧", "penguin"),
    ("🐢", "turtle"),
    ("🐟", "fish"),
    ("🐙", "octopus"),
    ("🦋", "butterfly"),
    ("🌷", "flower"),
    ("🌳", "tree"),
    ("🌵", "cactus"),
    ("🍄", "mushroom"),
    ("🌏", "globe"),
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
    ("💡", "light bulb"),
    ("📕", "book"),
    ("✏️", "pencil"),
    ("📎", "paperclip"),
    ("✂️", "scissors"),
    ("🔒", "lock"),
    ("🔑", "key"),
    ("🔨", "hammer"),
];

/// huddle 0.7.11: rejection-sampling emoji-index derivation. Refills any
/// index ≥ 49 with deterministic additional HKDF expansion so the
/// distribution over the 49-element table is uniform.
fn derive_emoji_indices_rejection(
    hk: &Hkdf<Sha256>,
    initial: [u8; 7],
) -> [u8; 7] {
    let mut out = [0u8; 7];
    let mut accepted = 0usize;
    // Use the initial bytes first.
    for &v in &initial {
        if v < 49 {
            out[accepted] = v;
            accepted += 1;
            if accepted == 7 {
                return out;
            }
        }
    }
    // Refill by expanding additional 6-bit chunks. We pull in 6-byte
    // blocks of HKDF output, each yielding 8 candidate 6-bit values
    // (high-bit pair discarded — each byte gives one 6-bit candidate
    // via `v & 0x3f`). The info string includes a salt counter so
    // multiple refills don't repeat the same bytes.
    let mut counter: u32 = 0;
    while accepted < 7 {
        let info = {
            let mut buf = [0u8; 24];
            buf[..16].copy_from_slice(b"huddle-sas-v1-rs");
            buf[16..20].copy_from_slice(&counter.to_be_bytes());
            buf
        };
        let mut block = [0u8; 32];
        if hk.expand(&info, &mut block).is_err() {
            // The expander only fails when len > 255 * HashLen (8160
            // bytes for SHA-256); 32 is far under, so this branch is
            // unreachable in practice. Fall back to modulo if it
            // somehow happens — degrades to pre-0.7.11 behavior but
            // never panics or hangs.
            for v in &mut initial.iter().copied() {
                if accepted < 7 {
                    out[accepted] = v % 49;
                    accepted += 1;
                }
            }
            break;
        }
        for &byte in block.iter() {
            let candidate = byte & 0x3f;
            if candidate < 49 {
                out[accepted] = candidate;
                accepted += 1;
                if accepted == 7 {
                    return out;
                }
            }
        }
        counter += 1;
    }
    out
}

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

        let alice_code = derive_sas_code(&alice_secret, &bob_pub, &tx_id, None).unwrap();
        let bob_code = derive_sas_code(&bob_secret, &alice_pub, &tx_id, None).unwrap();
        assert_eq!(alice_code, bob_code);
        // Decimal shape: three 4-digit groups joined by '-', each in
        // [1000, 9191].
        let parts: Vec<&str> = alice_code.decimal.split('-').collect();
        assert_eq!(parts.len(), 3);
        for p in parts {
            assert_eq!(p.len(), 4);
            let n: u32 = p.parse().unwrap();
            assert!((1000..=9191).contains(&n));
        }
        // Indices must all be in 0..49 (MSC 2241 table size).
        for i in alice_code.emoji_indices {
            assert!((i as usize) < SAS_EMOJI.len());
        }
    }

    #[test]
    fn different_tx_id_yields_different_code() {
        let (tx_id_a, alice_secret, _) = new_session();
        let (_, bob_secret, bob_pub) = new_session();
        let alice_code = derive_sas_code(&alice_secret, &bob_pub, &tx_id_a, None).unwrap();

        let mut tx_id_b = tx_id_a;
        tx_id_b[0] ^= 0xff;
        let alice_code_b = derive_sas_code(&alice_secret, &bob_pub, &tx_id_b, None).unwrap();
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

        let alice_thinks_bob = derive_sas_code(&alice_secret, &mallory_pub, &tx_id, None).unwrap();
        let bob_thinks_alice = derive_sas_code(&bob_secret, &mallory_pub, &tx_id, None).unwrap();
        assert_ne!(alice_thinks_bob, bob_thinks_alice);

        // Sanity: without MITM, both sides agree.
        let alice_real = derive_sas_code(&alice_secret, &bob_pub, &tx_id, None).unwrap();
        let bob_real = derive_sas_code(&bob_secret, &alice_pub, &tx_id, None).unwrap();
        assert_eq!(alice_real, bob_real);
    }

    #[test]
    fn rejects_small_order_ephemeral() {
        // The X25519 all-zero point is non-contributory (small-order):
        // ECDH with it yields an all-zero shared secret regardless of our
        // secret. derive_sas_code must reject it rather than emit a code.
        let (tx_id, our_secret, _) = new_session();
        let zero_pub = PublicKey::from([0u8; 32]);
        assert!(derive_sas_code(&our_secret, &zero_pub, &tx_id, None).is_err());
    }

    // ---- huddle 2.0: post-quantum capability binding ----

    /// A stand-in 1184-byte ML-KEM-768 encapsulation key. The binding hashes
    /// whatever bytes it is given, so the exact contents are irrelevant here —
    /// only that both sides feed the *same* bytes.
    fn fake_ek(fill: u8) -> Vec<u8> {
        vec![fill; crate::crypto::pqc::MLKEM_EK_LEN]
    }

    #[test]
    fn pq_binding_changes_the_code() {
        // Same shared secret + tx_id, but binding the partner's ML-KEM ek must
        // yield a different SAS code than the classical (None) derivation.
        let (tx_id, alice_secret, _) = new_session();
        let (_, _bob_secret, bob_pub) = new_session();
        let ek = fake_ek(0xA5);

        let classical = derive_sas_code(&alice_secret, &bob_pub, &tx_id, None).unwrap();
        let bound = derive_sas_code(&alice_secret, &bob_pub, &tx_id, Some(&ek)).unwrap();
        assert_ne!(
            classical, bound,
            "binding the ML-KEM ek must change the derived SAS code"
        );
    }

    #[test]
    fn both_sides_same_ek_agree() {
        // Two honest PQ-capable peers that both bind the SAME partner ek derive
        // the same code — the verification still succeeds end to end.
        let (tx_id, alice_secret, alice_pub) = new_session();
        let (_, bob_secret, bob_pub) = new_session();
        let ek = fake_ek(0x11);

        let alice = derive_sas_code(&alice_secret, &bob_pub, &tx_id, Some(&ek)).unwrap();
        let bob = derive_sas_code(&bob_secret, &alice_pub, &tx_id, Some(&ek)).unwrap();
        assert_eq!(alice, bob, "both sides binding the same ek must agree");
    }

    #[test]
    fn one_side_bound_other_not_diverges() {
        // The downgrade-detection invariant: a relay strips the ML-KEM key from
        // one side's announce, so that side derives with None while the other
        // still binds Some(ek). The codes diverge → OOB comparison catches it.
        let (tx_id, alice_secret, alice_pub) = new_session();
        let (_, bob_secret, bob_pub) = new_session();
        let ek = fake_ek(0x77);

        let alice_bound = derive_sas_code(&alice_secret, &bob_pub, &tx_id, Some(&ek)).unwrap();
        let bob_stripped = derive_sas_code(&bob_secret, &alice_pub, &tx_id, None).unwrap();
        assert_ne!(
            alice_bound, bob_stripped,
            "a stripped (None) side must not match a bound (Some) side"
        );
    }

    #[test]
    fn different_ek_yields_different_code() {
        // Binding two different ML-KEM keys produces two different codes, so the
        // hash genuinely covers the ek bytes (not just a fixed pqbind tag).
        let (tx_id, secret, _) = new_session();
        let (_, _b, peer_pub) = new_session();
        let a = derive_sas_code(&secret, &peer_pub, &tx_id, Some(&fake_ek(0x01))).unwrap();
        let b = derive_sas_code(&secret, &peer_pub, &tx_id, Some(&fake_ek(0x02))).unwrap();
        assert_ne!(a, b, "different bound eks must yield different codes");
    }

    #[test]
    fn classical_none_path_is_unchanged_golden() {
        // Lock the classical (None) info to the exact frozen 1.x bytes, so a
        // future refactor can't silently shift the wire-visible transcript and
        // break verification against pre-2.0 peers.
        assert_eq!(sas_info(None), b"huddle-sas-v1".to_vec());
        // And Some(ek) is the domain tag followed by SHA-256(ek) (32 bytes).
        let ek = fake_ek(0x5C);
        let info = sas_info(Some(&ek));
        assert_eq!(info.len(), SAS_INFO_PQBIND.len() + 32);
        assert!(info.starts_with(SAS_INFO_PQBIND));
        assert_eq!(&info[SAS_INFO_PQBIND.len()..], &Sha256::digest(&ek)[..]);
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
