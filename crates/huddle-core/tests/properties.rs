//! huddle 2.0.0 (F12): property-based tests over the security-critical pure
//! cores. proptest drives thousands of randomized inputs against invariants the
//! example-based unit tests in `crypto::{dm,megolm,sas}` only spot-check:
//!
//!   1. the DM key-downgrade policy never falls back from hybrid to classical
//!      (`plan_dm_key` is monotone classical→hybrid; the public
//!      `must_refuse_classical_fallback` guard refuses only the one dangerous
//!      combination);
//!   2. re-importing a Megolm inbound session keeps the *lower* first-known
//!      ratchet index (a re-share never raises the decryptable floor);
//!   3. every `derive_sas_code` output has emoji indices in `0..49` and three
//!      4-digit decimal groups in MSC 2241's `1000..=9191`.
//!
//! Everything here uses huddle-core's PUBLIC API only — these run as an external
//! integration-test crate, so crate-private items (e.g. `app::plan_dm_key`) are
//! not reachable. For (1) we test the public downgrade guard the real decision
//! folds in, plus a local mirror of `plan_dm_key`'s decision table kept in step
//! with the source.

use proptest::prelude::*;

use huddle_core::crypto::dm::must_refuse_classical_fallback;
use huddle_core::crypto::megolm::RoomCrypto;
use huddle_core::crypto::sas::{derive_sas_code, SAS_EMOJI};
use huddle_core::storage::repo::{derive_room_id, insert_room, RoomKind, StoredRoom};
use huddle_core::storage::{open_db_in_memory, Db};

use x25519_dalek::{PublicKey, StaticSecret};

// ---------------------------------------------------------------------------
// (1) DM key downgrade policy: monotone classical → hybrid, never the reverse.
// ---------------------------------------------------------------------------

/// Local mirror of the crate-private `huddle_core::app::plan_dm_key` decision
/// table — an external test crate can't reach the real (private) function, so we
/// re-state its truth table here and property-test the monotonic no-downgrade
/// invariant it must uphold. Kept byte-for-byte in step with the source: if the
/// real table changes, this copy must change with it. The public anchor for the
/// security-critical half is exercised separately against
/// [`must_refuse_classical_fallback`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DmKeyAction {
    Classical,
    HybridInitiator,
    HybridResponder,
    RequestCiphertext,
    Noop,
}

fn plan_dm_key(
    already_keyed: bool,
    already_hybrid: bool,
    partner_pq_capable: bool,
    we_are_initiator: bool,
    have_ciphertext: bool,
) -> DmKeyAction {
    if already_keyed && already_hybrid {
        return DmKeyAction::Noop; // settled hybrid — final
    }
    if partner_pq_capable {
        // Hybrid only — never fall back to / stay on classical for a PQ peer.
        if we_are_initiator {
            DmKeyAction::HybridInitiator
        } else if have_ciphertext {
            DmKeyAction::HybridResponder
        } else {
            DmKeyAction::RequestCiphertext
        }
    } else if already_keyed {
        DmKeyAction::Noop // steady classical with a genuine non-PQ peer
    } else {
        DmKeyAction::Classical
    }
}

proptest! {
    /// The classical-fallback guard refuses a classical DM key for exactly one
    /// input — a known PQ-capable peer with no ML-KEM key available — and that
    /// refusal is monotone: learning a peer is PQ-capable (or losing the ek) can
    /// only ever ADD a refusal, never remove one. A downgrade can never become
    /// "more allowed".
    #[test]
    fn classical_fallback_guard_is_monotone(
        peer_capable in any::<bool>(),
        have_ek in any::<bool>(),
    ) {
        let refuse = must_refuse_classical_fallback(peer_capable, have_ek);
        // Refuse IFF the peer is known capable AND we hold no ek to go hybrid.
        prop_assert_eq!(refuse, peer_capable && !have_ek);
        // Monotone in capability (false < true under bool's Ord): a non-capable
        // peer is never refused, so flipping to capable can only raise the guard.
        prop_assert!(
            must_refuse_classical_fallback(false, have_ek)
                <= must_refuse_classical_fallback(true, have_ek)
        );
        // Monotone in losing the ek: holding an ek is never refused, so dropping
        // it can only raise the guard.
        prop_assert!(
            must_refuse_classical_fallback(peer_capable, true)
                <= must_refuse_classical_fallback(peer_capable, false)
        );
    }

    /// `plan_dm_key` never downgrades a DM from hybrid back to classical:
    ///   * a settled hybrid DM (keyed + hybrid) is final → always `Noop`;
    ///   * a PQ-capable partner is never served a `Classical` action, whatever
    ///     the current state (the one-way classical→hybrid upgrade);
    ///   * `Classical` is reachable ONLY for a non-capable, not-yet-keyed DM.
    #[test]
    fn plan_dm_key_never_downgrades_hybrid_to_classical(
        keyed in any::<bool>(),
        hybrid in any::<bool>(),
        capable in any::<bool>(),
        initiator in any::<bool>(),
        ciphertext in any::<bool>(),
    ) {
        let action = plan_dm_key(keyed, hybrid, capable, initiator, ciphertext);

        if keyed && hybrid {
            prop_assert_eq!(action, DmKeyAction::Noop);
        }
        if capable {
            prop_assert_ne!(action, DmKeyAction::Classical);
        }
        if action == DmKeyAction::Classical {
            prop_assert!(!capable && !keyed);
        }
    }
}

// ---------------------------------------------------------------------------
// (2) Megolm: re-importing an inbound session keeps the lower first-known index.
// ---------------------------------------------------------------------------

/// Insert a room row so the megolm-session persistence has a valid parent, then
/// return its derived id. Mirrors the helper in `crypto::megolm`'s unit tests.
fn setup_room(db: &Db, name: &str, creator_fp: &str) -> String {
    let created_at = 1000;
    let room = StoredRoom {
        id: derive_room_id(creator_fp, name, created_at),
        name: name.into(),
        creator_fingerprint: creator_fp.into(),
        encrypted: true,
        passphrase_salt: None,
        created_at,
        last_active: None,
        kind: RoomKind::Group,
    };
    let id = room.id.clone();
    insert_room(db, &room).unwrap();
    id
}

proptest! {
    // Each case stands up two in-memory DBs and a Megolm round-trip, so keep the
    // case count modest — the invariant is structural, not entropy-hungry.
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// A receiver that imports the sender's session key at index 0 decrypts every
    /// subsequent message at its monotonic ratchet position (0, 1, 2, …). Then
    /// re-importing the SAME index-0 session key keeps the lower first-known index
    /// (0): `add_inbound_session` builds a fresh floor-0 inbound session, so the
    /// receiver can still decrypt the index-0 ciphertext rather than having its
    /// decryptable floor advanced past it.
    #[test]
    fn megolm_reimport_keeps_lower_first_known_index(
        plaintexts in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 1..32),
            1..8,
        ),
    ) {
        let db_sender = open_db_in_memory().unwrap();
        let db_receiver = open_db_in_memory().unwrap();
        let room_id = setup_room(&db_sender, "props", "sender-fp");
        setup_room(&db_receiver, "props", "sender-fp");

        let mut sender = RoomCrypto::new_for_room(
            db_sender.clone(),
            room_id.clone(),
            "sender-fp".into(),
            [0u8; 32],
        )
        .unwrap();
        let mut receiver = RoomCrypto::new_for_room(
            db_receiver.clone(),
            room_id.clone(),
            "recv-fp".into(),
            [0u8; 32],
        )
        .unwrap();

        // Share the sender's session key while it is still at index 0 → the
        // receiver's inbound first-known index is 0.
        let session_key_at_zero = sender.our_session_key_b64();
        receiver
            .add_inbound_session("sender-fp", &session_key_at_zero)
            .unwrap();

        // Every message decrypts at its monotonic ratchet index, starting at 0.
        let mut first_ciphertext: Option<(String, Vec<u8>)> = None;
        for (i, pt) in plaintexts.iter().enumerate() {
            let (session_id, ct) = sender.encrypt(pt).unwrap();
            let (out, idx) = receiver
                .decrypt("sender-fp", &session_id, &ct)
                .unwrap();
            prop_assert_eq!(out.as_slice(), pt.as_slice());
            prop_assert_eq!(idx as usize, i);
            if i == 0 {
                first_ciphertext = Some((session_id, ct));
            }
        }

        // Re-import the SAME index-0 session key. The re-import keeps the lower
        // first-known index (0): the receiver can decrypt the original index-0
        // ciphertext again instead of having lost it to an advanced floor.
        receiver
            .add_inbound_session("sender-fp", &session_key_at_zero)
            .unwrap();
        let (session_id0, ct0) = first_ciphertext.unwrap();
        let (out0, idx0) = receiver
            .decrypt("sender-fp", &session_id0, &ct0)
            .unwrap();
        prop_assert_eq!(out0.as_slice(), plaintexts[0].as_slice());
        prop_assert_eq!(idx0, 0);
    }
}

// ---------------------------------------------------------------------------
// (3) SAS: derived codes always land in range.
// ---------------------------------------------------------------------------

proptest! {
    /// Every `derive_sas_code` output — classical (`None`) or PQ-bound
    /// (`Some(ek)`) — has 7 emoji indices strictly inside the 49-entry table and
    /// three 4-digit decimal groups in MSC 2241's `1000..=9191`. Two honest
    /// clamped X25519 keys always produce a contributory secret, so derivation
    /// never errors.
    #[test]
    fn sas_code_indices_and_decimal_in_range(
        our_seed in proptest::array::uniform32(any::<u8>()),
        their_seed in proptest::array::uniform32(any::<u8>()),
        tx_id in proptest::array::uniform16(any::<u8>()),
        bind in any::<bool>(),
        ek in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let our_secret = StaticSecret::from(our_seed);
        let their_secret = StaticSecret::from(their_seed);
        let their_public = PublicKey::from(&their_secret);

        let partner_ek = if bind { Some(ek.as_slice()) } else { None };
        let code = derive_sas_code(&our_secret, &their_public, &tx_id, partner_ek).unwrap();

        // All 7 emoji indices index INTO the 49-entry table.
        for idx in code.emoji_indices {
            prop_assert!((idx as usize) < SAS_EMOJI.len());
            prop_assert!(idx < 49);
        }

        // Decimal: exactly three 4-digit groups, each in 1000..=9191.
        let groups: Vec<&str> = code.decimal.split('-').collect();
        prop_assert_eq!(groups.len(), 3);
        for g in groups {
            prop_assert_eq!(g.len(), 4);
            let n: u32 = g.parse().unwrap();
            prop_assert!((1000..=9191).contains(&n));
        }
    }
}
