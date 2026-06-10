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
//! [`derive_sas_code`] takes both peers' ML-KEM encapsulation keys
//! (`our_mlkem_ek`, `their_mlkem_ek`). The binding is **gated on the partner's**
//! key: when we hold a pinned ML-KEM ek for the peer (`their_mlkem_ek = Some`),
//! the transcript mixes a `b"huddle-sas-pqbind-v1"` domain tag plus
//! `SHA-256` of **both** eks concatenated **in byte-sorted order** into the HKDF
//! `info` — so the pair's *PQ capability* becomes part of the out-of-band trust
//! anchor. Sorting makes the binding symmetric: each peer sees the two keys in
//! the opposite (our, their) roles, but sorting yields identical `info` on both
//! sides, so two honest PQ-capable peers derive the *same* code. A relay that
//! strips the ML-KEM pubkey from one side's announce drives that side's
//! `their_mlkem_ek` to `None` (classical transcript) while the other still
//! binds; the two SAS codes then diverge and the OOB comparison catches the
//! silent classical downgrade. The salt (`tx_id`) and PRF (HKDF-SHA256) are
//! unchanged — only the `info` domain tag + hash are added. When the *partner*
//! has no pinned ek (`their_mlkem_ek = None` — group members, pre-1.3 partners,
//! or the classical fallback) the derivation is byte-for-byte identical to the
//! 1.x `b"huddle-sas-v1"` transcript regardless of our own key, so old and new
//! peers still agree.

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
/// `our_mlkem_ek` / `their_mlkem_ek` are huddle 2.0's optional post-quantum
/// capability binding (see the module doc). The binding is gated on the
/// **partner's** key: pass `their_mlkem_ek = Some(ek)` when we hold the peer's
/// pinned ML-KEM encapsulation key, and `our_mlkem_ek = Some(ek)` for our own
/// (always available for a 2.0 identity). Both eks are then folded into the HKDF
/// `info` as `domain-tag || SHA-256(sorted(our_ek, their_ek))`, anchoring the
/// pair's PQ capability into the verified SAS so a relay can't silently
/// downgrade them to classical-only. Pass `their_mlkem_ek = None` for group
/// members, pre-1.3 partners, or the classical fallback; that path is
/// byte-for-byte identical to the 1.x derivation regardless of `our_mlkem_ek`.
/// Because the eks are sorted, both peers derive the same code without needing
/// to agree on an order.
pub fn derive_sas_code(
    our_secret: &StaticSecret,
    their_public: &PublicKey,
    tx_id: &[u8; TX_ID_LEN],
    our_mlkem_ek: Option<&[u8]>,
    their_mlkem_ek: Option<&[u8]>,
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
    let info = sas_info(our_mlkem_ek, their_mlkem_ek);
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
    let chunk1 =
        ((u32::from(d[1] & 0x07) << 10) | (u32::from(d[2]) << 2) | (u32::from(d[3]) >> 6)) & 0x1fff;
    let chunk2 = ((u32::from(d[3] & 0x3f) << 7) | (u32::from(d[4]) >> 1)) & 0x1fff;
    let decimal = format!("{}-{}-{}", chunk0 + 1000, chunk1 + 1000, chunk2 + 1000);

    Ok(SasCode {
        emoji_indices,
        decimal,
    })
}

/// Build the HKDF `info` for the main SAS expansion.
///
/// Gated on the **partner's** key: `their_mlkem_ek = None` reproduces the
/// classical 1.x transcript byte-for-byte ([`SAS_INFO_V1`]) regardless of
/// `our_mlkem_ek`, so a PQ-capable peer talking to a classical/group/pre-1.3
/// partner still agrees with them. When `their_mlkem_ek = Some`, the binding
/// concatenates the [`SAS_INFO_PQBIND`] domain tag with `SHA-256` of every
/// present ek in **byte-sorted** order — so each peer, which holds the two keys
/// in the opposite (our, their) roles, produces identical `info` and the two
/// SAS codes match. A bound derivation can never collide with an unbound one
/// (distinct domain tag), and stripping the ML-KEM key from one side flips that
/// side to the classical transcript, making the codes diverge (see the module
/// doc). Only the `info` changes; the `tx_id` salt and the HKDF-SHA256 PRF are
/// untouched.
fn sas_info(our_mlkem_ek: Option<&[u8]>, their_mlkem_ek: Option<&[u8]>) -> Vec<u8> {
    // Gate strictly on the partner's pinned capability.
    let their_ek = match their_mlkem_ek {
        None => return SAS_INFO_V1.to_vec(),
        Some(ek) => ek,
    };
    // Symmetric binding: hash both present eks in a canonical (byte-sorted)
    // order so both peers — who see the keys in opposite roles — agree.
    let mut eks: Vec<&[u8]> = Vec::with_capacity(2);
    if let Some(ours) = our_mlkem_ek {
        eks.push(ours);
    }
    eks.push(their_ek);
    eks.sort_unstable();
    let mut hasher = Sha256::new();
    for ek in &eks {
        hasher.update(ek);
    }
    let digest = hasher.finalize();
    let mut info = Vec::with_capacity(SAS_INFO_PQBIND.len() + digest.len());
    info.extend_from_slice(SAS_INFO_PQBIND);
    info.extend_from_slice(&digest);
    info
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
fn derive_emoji_indices_rejection(hk: &Hkdf<Sha256>, initial: [u8; 7]) -> [u8; 7] {
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

        let alice_code = derive_sas_code(&alice_secret, &bob_pub, &tx_id, None, None).unwrap();
        let bob_code = derive_sas_code(&bob_secret, &alice_pub, &tx_id, None, None).unwrap();
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
        let alice_code = derive_sas_code(&alice_secret, &bob_pub, &tx_id_a, None, None).unwrap();

        let mut tx_id_b = tx_id_a;
        tx_id_b[0] ^= 0xff;
        let alice_code_b = derive_sas_code(&alice_secret, &bob_pub, &tx_id_b, None, None).unwrap();
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

        let alice_thinks_bob =
            derive_sas_code(&alice_secret, &mallory_pub, &tx_id, None, None).unwrap();
        let bob_thinks_alice =
            derive_sas_code(&bob_secret, &mallory_pub, &tx_id, None, None).unwrap();
        assert_ne!(alice_thinks_bob, bob_thinks_alice);

        // Sanity: without MITM, both sides agree.
        let alice_real = derive_sas_code(&alice_secret, &bob_pub, &tx_id, None, None).unwrap();
        let bob_real = derive_sas_code(&bob_secret, &alice_pub, &tx_id, None, None).unwrap();
        assert_eq!(alice_real, bob_real);
    }

    #[test]
    fn rejects_small_order_ephemeral() {
        // The X25519 all-zero point is non-contributory (small-order):
        // ECDH with it yields an all-zero shared secret regardless of our
        // secret. derive_sas_code must reject it rather than emit a code.
        let (tx_id, our_secret, _) = new_session();
        let zero_pub = PublicKey::from([0u8; 32]);
        assert!(derive_sas_code(&our_secret, &zero_pub, &tx_id, None, None).is_err());
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
        // yield a different SAS code than the classical (None partner) derivation.
        let (tx_id, alice_secret, _) = new_session();
        let (_, _bob_secret, bob_pub) = new_session();
        let our = fake_ek(0xA4);
        let ek = fake_ek(0xA5);

        let classical = derive_sas_code(&alice_secret, &bob_pub, &tx_id, None, None).unwrap();
        let bound =
            derive_sas_code(&alice_secret, &bob_pub, &tx_id, Some(&our), Some(&ek)).unwrap();
        assert_ne!(
            classical, bound,
            "binding the ML-KEM ek must change the derived SAS code"
        );
    }

    #[test]
    fn both_sides_distinct_eks_agree() {
        // Two honest PQ-capable peers each bind (our_ek, their_ek) with the keys
        // in OPPOSITE roles — exactly what the app does. The byte-sorted binding
        // makes the two derivations produce the SAME code, so verification
        // succeeds end to end. (This replaces the old both_sides_same_ek_agree,
        // which only passed because it fed ONE shared ek to both derivations —
        // a configuration the app never produces.)
        let (tx_id, alice_secret, alice_pub) = new_session();
        let (_, bob_secret, bob_pub) = new_session();
        let ek_a = fake_ek(0x11);
        let ek_b = fake_ek(0x22);

        // alice = initiator (our = ek_a) binds bob's ek_b
        let alice =
            derive_sas_code(&alice_secret, &bob_pub, &tx_id, Some(&ek_a), Some(&ek_b)).unwrap();
        // bob = responder (our = ek_b) binds alice's ek_a
        let bob =
            derive_sas_code(&bob_secret, &alice_pub, &tx_id, Some(&ek_b), Some(&ek_a)).unwrap();
        assert_eq!(
            alice, bob,
            "sorted dual-ek binding must agree across peers in opposite roles"
        );
    }

    #[test]
    fn one_side_bound_other_not_diverges() {
        // The downgrade-detection invariant: a relay strips the ML-KEM key from
        // one side's announce, so that side sees the partner as classical
        // (their_ek = None → classical transcript) while the other still binds
        // the partner's ek. The codes diverge → OOB comparison catches it.
        let (tx_id, alice_secret, alice_pub) = new_session();
        let (_, bob_secret, bob_pub) = new_session();
        let ek_a = fake_ek(0x77);
        let ek_b = fake_ek(0x88);

        let alice_bound =
            derive_sas_code(&alice_secret, &bob_pub, &tx_id, Some(&ek_a), Some(&ek_b)).unwrap();
        // bob never received alice's ek announce → their_ek = None for bob.
        let bob_stripped =
            derive_sas_code(&bob_secret, &alice_pub, &tx_id, Some(&ek_b), None).unwrap();
        assert_ne!(
            alice_bound, bob_stripped,
            "a stripped (classical) side must not match a bound side"
        );
    }

    #[test]
    fn different_ek_yields_different_code() {
        // Binding two different partner ML-KEM keys produces two different codes,
        // so the hash genuinely covers the ek bytes (not just a fixed pqbind tag).
        let (tx_id, secret, _) = new_session();
        let (_, _b, peer_pub) = new_session();
        let our = fake_ek(0x00);
        let a =
            derive_sas_code(&secret, &peer_pub, &tx_id, Some(&our), Some(&fake_ek(0x01))).unwrap();
        let b =
            derive_sas_code(&secret, &peer_pub, &tx_id, Some(&our), Some(&fake_ek(0x02))).unwrap();
        assert_ne!(a, b, "different bound eks must yield different codes");
    }

    #[test]
    fn pqbind_is_order_independent() {
        // sas_info must be symmetric in (our, their): swapping the roles yields
        // identical info — the property that makes the two peers agree.
        let ek_a = fake_ek(0x33);
        let ek_b = fake_ek(0x44);
        assert_eq!(
            sas_info(Some(&ek_a), Some(&ek_b)),
            sas_info(Some(&ek_b), Some(&ek_a)),
            "dual-ek binding must be order-independent"
        );
    }

    #[test]
    fn classical_none_path_is_unchanged_golden() {
        // Lock the classical info to the exact frozen 1.x bytes, so a future
        // refactor can't silently shift the wire-visible transcript and break
        // verification against pre-2.0 peers. The gate is on the PARTNER's ek:
        // a PQ-capable self talking to a classical (None) partner stays classical.
        assert_eq!(sas_info(None, None), b"huddle-sas-v1".to_vec());
        assert_eq!(
            sas_info(Some(&fake_ek(0x01)), None),
            b"huddle-sas-v1".to_vec(),
            "PQ-capable self + classical partner must stay on the 1.x transcript"
        );
        // With a partner ek, info = domain tag || SHA-256(sorted(our, their)).
        let ek_a = fake_ek(0x5C);
        let ek_b = fake_ek(0x6D);
        let info = sas_info(Some(&ek_a), Some(&ek_b));
        assert_eq!(info.len(), SAS_INFO_PQBIND.len() + 32);
        assert!(info.starts_with(SAS_INFO_PQBIND));
        let mut sorted = [ek_a.as_slice(), ek_b.as_slice()];
        sorted.sort_unstable();
        let mut h = Sha256::new();
        for e in sorted {
            h.update(e);
        }
        assert_eq!(&info[SAS_INFO_PQBIND.len()..], &h.finalize()[..]);
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
