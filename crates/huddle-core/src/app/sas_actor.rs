//! huddle 2.0.5 (WS2 foundations, increment #1): the SAS-verification subsystem
//! extracted from the `AppHandle` god-object behind an actor/command seam.
//!
//! `SasActor` owns the in-flight SAS handshake state (`flows`, previously
//! `AppHandle::sas_flows`) and implements the **pure** state machine: each entry
//! point validates input, mutates flow state + derives the SAS code (crypto is
//! pure), and returns a `Vec<SasOutcome>` of *intents* — publish a (still
//! unsigned) message, emit an event, or finalize verification. The `AppHandle`
//! facade performs all I/O (signing + network send, event emission, the two DB
//! writes in finalize), so this actor needs no DB, network, or identity-secret
//! access and is unit-testable in isolation. This is the template every later
//! actor (files, contacts, rooms) follows.
//!
//! Behaviour is byte-for-byte the pre-extraction `AppHandle` SAS path; the DB
//! lookup of a partner's ML-KEM key is injected as a closure so it happens at
//! exactly the same point (and only when needed) as before.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use tracing::warn;

use super::events::AppEvent;
use crate::crypto::pqc::MLKEM_EK_LEN;
use crate::crypto::sas::{self, SasCode};
use crate::network::protocol::RoomMessage;

/// huddle 1.3.1: idle TTL for an abandoned flow; the cap, not this, is the real
/// memory bound, so 15 min is safe.
const SAS_FLOW_TTL_SECS: i64 = 900;
/// huddle 1.3.1: global cap on concurrent flows (the `tx_id` key is
/// attacker-chosen).
const SAS_FLOWS_CAP: usize = 256;
/// huddle 1.3.3: per-partner sub-cap so one authenticated co-member can't fill
/// the global pool with distinct tx_ids and starve everyone else's SAS.
const SAS_FLOWS_PER_PEER: usize = 8;

/// Phase G: in-flight SAS verification state, keyed by tx_id. Held in memory
/// only; survives just long enough for the two-message handshake + the user
/// pressing Match on both sides.
struct SasFlow {
    room_id: String,
    partner_fingerprint: String,
    our_secret: x25519_dalek::StaticSecret,
    /// Set once we know both sides' pubkeys → the derived SAS code.
    sas_code: Option<SasCode>,
    our_confirmed: bool,
    their_confirmed: bool,
    /// huddle 0.7.11: latch that flips true the first time finalize fires for
    /// this flow, so the local `match` path and the inbound `SasConfirm` path
    /// can't both finalize (double `SasVerified` + double DB writes).
    finalized: bool,
    /// huddle 1.3.1: unix time of last progress, so the reaper measures
    /// idle-since-last-activity and bounds this otherwise-unbounded map.
    created_at: i64,
    /// huddle 2.0.0 (F1): true iff we bound the partner's ML-KEM ek into this
    /// SAS code; carried into `verified_peers.pq_capable` on success so a later
    /// classical DM fallback for this peer is refused (downgrade defence).
    partner_pq_capable: bool,
}

/// An intent returned by the actor for the `AppHandle` facade to carry out.
/// The actor performs no I/O itself.
pub enum SasOutcome {
    /// Sign with our identity and publish to `room_id`.
    Publish { room_id: String, msg: RoomMessage },
    /// Send on the app event channel (e.g. `SasCodeReady`).
    Emit(AppEvent),
    /// Both sides matched: the facade writes `set_member_verified` +
    /// `add_verified_peer(pq_capable)` and emits `SasVerified`.
    Finalize {
        room_id: String,
        partner_fingerprint: String,
        pq_capable: bool,
    },
}

/// Typed errors for the user-facing entry points (mapped to `HuddleError` at the
/// facade), replacing the stringly `HuddleError::Other(..)` the methods used.
#[derive(Debug)]
pub enum SasError {
    UnknownTx,
    CodeNotReady,
}

/// Owns the SAS handshake state. Shared across `AppHandle` clones via `Arc`.
pub struct SasActor {
    flows: Mutex<HashMap<String, SasFlow>>,
    our_fingerprint: String,
    /// Our ML-KEM-768 encapsulation key (stable for this identity); bound into
    /// every transcript so both peers derive the same code.
    our_mlkem_ek: [u8; MLKEM_EK_LEN],
}

impl SasActor {
    pub fn new(our_fingerprint: String, our_mlkem_ek: [u8; MLKEM_EK_LEN]) -> Self {
        Self {
            flows: Mutex::new(HashMap::new()),
            our_fingerprint,
            our_mlkem_ek,
        }
    }

    /// TTL sweep, called from the announcement ticker. Reaps flows idle past the
    /// TTL (measured from `created_at`, refreshed on real progress).
    pub fn reap(&self, now: i64) {
        self.flows
            .lock()
            .unwrap()
            .retain(|_, f| now - f.created_at <= SAS_FLOW_TTL_SECS);
    }

    /// Phase G: locally initiate a verification. Returns the tx_id (for the
    /// caller to correlate events) plus the outcomes (publish a `SasInit`).
    pub fn start(
        &self,
        room_id: &str,
        target_fingerprint: &str,
        now: i64,
    ) -> (String, Vec<SasOutcome>) {
        let (tx_id_bytes, our_secret, our_pub) = sas::new_session();
        let tx_id = B64.encode(tx_id_bytes);
        self.flows.lock().unwrap().insert(
            tx_id.clone(),
            SasFlow {
                room_id: room_id.to_string(),
                partner_fingerprint: target_fingerprint.to_string(),
                our_secret,
                sas_code: None,
                our_confirmed: false,
                their_confirmed: false,
                finalized: false,
                created_at: now,
                partner_pq_capable: false,
            },
        );
        let msg = RoomMessage::SasInit {
            tx_id: tx_id.clone(),
            ephemeral_x25519_pubkey_b64: B64.encode(our_pub.as_bytes()),
            target_fingerprint: target_fingerprint.to_string(),
        };
        (
            tx_id,
            vec![SasOutcome::Publish {
                room_id: room_id.to_string(),
                msg,
            }],
        )
    }

    /// Phase G: user pressed Match — broadcast a signed `SasConfirm{matched:true}`,
    /// finalizing if the partner already matched.
    pub fn user_match(&self, tx_id: &str, _now: i64) -> Result<Vec<SasOutcome>, SasError> {
        let (room_id, partner_fp, do_finish, pq_capable) = {
            let mut flows = self.flows.lock().unwrap();
            let flow = flows.get_mut(tx_id).ok_or(SasError::UnknownTx)?;
            // huddle 1.3.4: never confirm before the code has actually been
            // derived from the partner's ephemeral key — otherwise a user could
            // confirm a match they never saw, defeating the OOB-comparison MITM
            // defence.
            if flow.sas_code.is_none() {
                return Err(SasError::CodeNotReady);
            }
            flow.our_confirmed = true;
            let do_finish = flow.our_confirmed && flow.their_confirmed && !flow.finalized;
            if do_finish {
                flow.finalized = true;
            }
            (
                flow.room_id.clone(),
                flow.partner_fingerprint.clone(),
                do_finish,
                flow.partner_pq_capable,
            )
        };
        let mut outcomes = vec![SasOutcome::Publish {
            room_id: room_id.clone(),
            msg: RoomMessage::SasConfirm {
                tx_id: tx_id.to_string(),
                matched: true,
            },
        }];
        if do_finish {
            self.flows.lock().unwrap().remove(tx_id);
            outcomes.push(SasOutcome::Finalize {
                room_id,
                partner_fingerprint: partner_fp,
                pq_capable,
            });
        }
        Ok(outcomes)
    }

    /// Phase G: cancel an in-flight SAS — drop our local state (quiet teardown).
    pub fn cancel(&self, tx_id: &str) {
        self.flows.lock().unwrap().remove(tx_id);
    }

    /// Inbound `SasInit` (post-`verify_signed`). `partner_ek_lookup` resolves the
    /// signer's pinned ML-KEM key from the DB — called by the facade at the same
    /// point the pre-extraction handler did.
    // The fields are the SasInit message + the dispatch context (verified signer,
    // clock) + the DB-lookup injection; bundling them would obscure the 1:1 map to
    // the pre-extraction handler this preserves.
    #[allow(clippy::too_many_arguments)]
    pub fn inbound_init(
        &self,
        room_id: &str,
        tx_id: String,
        ephemeral_x25519_pubkey_b64: &str,
        target_fingerprint: &str,
        signer: Option<String>,
        now: i64,
        partner_ek_lookup: impl FnOnce(&str) -> Option<Vec<u8>>,
    ) -> Vec<SasOutcome> {
        if target_fingerprint != self.our_fingerprint {
            // Not addressed to us — Phase G is point-to-point over the room topic.
            return vec![];
        }
        let signer = match signer {
            Some(fp) => fp,
            None => {
                warn!("SasInit arrived unsigned; dropping");
                return vec![];
            }
        };
        let their_pub = match sas::parse_pubkey(ephemeral_x25519_pubkey_b64) {
            Ok(pk) => pk,
            Err(e) => {
                warn!(%e, "SasInit: bad x25519 pubkey");
                return vec![];
            }
        };
        let tx_id_bytes = match decode_tx_id(&tx_id) {
            Some(b) => b,
            None => {
                warn!(%tx_id, "SasInit: bad tx_id length");
                return vec![];
            }
        };
        // huddle 1.3.1/1.3.3: bound the flows map against an inbound flood — a
        // global cap plus a per-partner sub-cap, so one peer streaming distinct
        // tx_ids can't starve everyone else.
        {
            let flows = self.flows.lock().unwrap();
            if !flows.contains_key(&tx_id) {
                if flows.len() >= SAS_FLOWS_CAP {
                    warn!(%tx_id, "sas_flows at global cap; dropping inbound SasInit");
                    return vec![];
                }
                let from_peer = flows
                    .values()
                    .filter(|f| f.partner_fingerprint == signer)
                    .count();
                if from_peer >= SAS_FLOWS_PER_PEER {
                    warn!(%signer, "sas_flows per-peer cap; dropping inbound SasInit");
                    return vec![];
                }
            }
        }
        let (_, our_secret, our_pub) = sas::new_session();
        // huddle 2.0.0 (F1): bind the initiator's ML-KEM ek (if we hold their
        // pin) into the transcript, plus our own (sorted-canonical) so the two
        // peers derive the same code. A relay that strips one side's key diverges
        // the codes — caught by the human comparison.
        let partner_ek = partner_ek_lookup(&signer);
        let partner_pq_capable = partner_ek.is_some();
        let sas_code = match sas::derive_sas_code(
            &our_secret,
            &their_pub,
            &tx_id_bytes,
            Some(&self.our_mlkem_ek),
            partner_ek.as_deref(),
        ) {
            Ok(c) => c,
            Err(e) => {
                warn!(%e, "SasInit: rejecting non-contributory ephemeral; dropping");
                return vec![];
            }
        };
        self.flows.lock().unwrap().insert(
            tx_id.clone(),
            SasFlow {
                room_id: room_id.to_string(),
                partner_fingerprint: signer.clone(),
                our_secret,
                sas_code: Some(sas_code.clone()),
                our_confirmed: false,
                their_confirmed: false,
                finalized: false,
                created_at: now,
                partner_pq_capable,
            },
        );
        vec![
            SasOutcome::Publish {
                room_id: room_id.to_string(),
                msg: RoomMessage::SasResponse {
                    tx_id: tx_id.clone(),
                    ephemeral_x25519_pubkey_b64: B64.encode(our_pub.as_bytes()),
                },
            },
            SasOutcome::Emit(AppEvent::SasCodeReady {
                room_id: room_id.to_string(),
                partner_fingerprint: signer,
                tx_id,
                emoji_labels: sas_code.emoji_labels(),
                decimal: sas_code.decimal,
            }),
        ]
    }

    /// Inbound `SasResponse` (post-`verify_signed`).
    pub fn inbound_response(
        &self,
        room_id: &str,
        tx_id: String,
        ephemeral_x25519_pubkey_b64: &str,
        signer: Option<String>,
        now: i64,
        partner_ek_lookup: impl FnOnce(&str) -> Option<Vec<u8>>,
    ) -> Vec<SasOutcome> {
        let signer = match signer {
            Some(fp) => fp,
            None => {
                warn!("SasResponse arrived unsigned; dropping");
                return vec![];
            }
        };
        let their_pub = match sas::parse_pubkey(ephemeral_x25519_pubkey_b64) {
            Ok(pk) => pk,
            Err(e) => {
                warn!(%e, "SasResponse: bad x25519 pubkey");
                return vec![];
            }
        };
        let tx_id_bytes = match decode_tx_id(&tx_id) {
            Some(b) => b,
            None => return vec![],
        };
        // Looked up outside the flows lock (no DB access while the mutex is held).
        let partner_ek = partner_ek_lookup(&signer);
        let partner_pq_capable = partner_ek.is_some();
        let code = {
            let mut flows = self.flows.lock().unwrap();
            let flow = match flows.get_mut(&tx_id) {
                Some(f) => f,
                None => {
                    warn!(%tx_id, "SasResponse for unknown tx_id");
                    return vec![];
                }
            };
            if flow.partner_fingerprint != signer {
                warn!(
                    expected = %flow.partner_fingerprint, got = %signer,
                    "SasResponse signer doesn't match flow's partner; dropping"
                );
                return vec![];
            }
            let code = match sas::derive_sas_code(
                &flow.our_secret,
                &their_pub,
                &tx_id_bytes,
                Some(&self.our_mlkem_ek),
                partner_ek.as_deref(),
            ) {
                Ok(c) => c,
                Err(e) => {
                    warn!(%e, "SasResponse: rejecting non-contributory ephemeral; dropping");
                    return vec![];
                }
            };
            flow.sas_code = Some(code.clone());
            flow.partner_pq_capable = partner_pq_capable;
            // huddle 1.3.3: refresh the TTL clock on real progress.
            flow.created_at = now;
            code
        };
        vec![SasOutcome::Emit(AppEvent::SasCodeReady {
            room_id: room_id.to_string(),
            partner_fingerprint: signer,
            tx_id,
            emoji_labels: code.emoji_labels(),
            decimal: code.decimal,
        })]
    }

    /// Inbound `SasConfirm` (post-`verify_signed`).
    pub fn inbound_confirm(
        &self,
        tx_id: &str,
        matched: bool,
        signer: Option<String>,
    ) -> Vec<SasOutcome> {
        let signer = match signer {
            Some(fp) => fp,
            None => return vec![],
        };
        let mut flows = self.flows.lock().unwrap();
        let flow = match flows.get_mut(tx_id) {
            Some(f) => f,
            None => return vec![],
        };
        if flow.partner_fingerprint != signer {
            return vec![];
        }
        if !matched {
            // Partner declined / mismatch — drop the flow.
            flows.remove(tx_id);
            return vec![];
        }
        flow.their_confirmed = true;
        if flow.our_confirmed && flow.their_confirmed && !flow.finalized {
            flow.finalized = true;
            let room_id = flow.room_id.clone();
            let partner_fingerprint = flow.partner_fingerprint.clone();
            let pq_capable = flow.partner_pq_capable;
            flows.remove(tx_id);
            vec![SasOutcome::Finalize {
                room_id,
                partner_fingerprint,
                pq_capable,
            }]
        } else {
            vec![]
        }
    }
}

fn decode_tx_id(tx_id: &str) -> Option<[u8; sas::TX_ID_LEN]> {
    match B64.decode(tx_id) {
        Ok(b) if b.len() == sas::TX_ID_LEN => {
            let mut arr = [0u8; sas::TX_ID_LEN];
            arr.copy_from_slice(&b);
            Some(arr)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn actor_for(id: &Identity) -> SasActor {
        SasActor::new(id.fingerprint().to_string(), id.mlkem_public_bytes())
    }

    // The payoff of the extraction: the handshake state machine is now testable
    // in isolation, with no AppHandle / DB / network.
    #[test]
    fn full_handshake_converges_to_matching_codes_and_finalizes() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let a = actor_for(&alice);
        let b = actor_for(&bob);
        let no_ek = |_: &str| None;

        // Alice initiates.
        let (tx, out) = a.start("room", bob.fingerprint(), 0);
        let init = expect_publish(&out);
        let (init_tx, init_pub, init_target) = match init {
            RoomMessage::SasInit {
                tx_id,
                ephemeral_x25519_pubkey_b64,
                target_fingerprint,
            } => (tx_id, ephemeral_x25519_pubkey_b64, target_fingerprint),
            _ => panic!("expected SasInit"),
        };
        assert_eq!(init_tx, &tx);
        assert_eq!(init_target, bob.fingerprint());

        // Bob handles the init, responds, and shows a code.
        let bob_out = b.inbound_init(
            "room",
            init_tx.clone(),
            init_pub,
            init_target,
            Some(alice.fingerprint().to_string()),
            0,
            no_ek,
        );
        let resp = expect_publish(&bob_out);
        let (resp_pub,) = match resp {
            RoomMessage::SasResponse {
                ephemeral_x25519_pubkey_b64,
                ..
            } => (ephemeral_x25519_pubkey_b64,),
            _ => panic!("expected SasResponse"),
        };
        let bob_code = expect_code_ready(&bob_out);

        // Alice handles the response and shows a code — must match Bob's.
        let alice_out = a.inbound_response(
            "room",
            tx.clone(),
            resp_pub,
            Some(bob.fingerprint().to_string()),
            0,
            no_ek,
        );
        let alice_code = expect_code_ready(&alice_out);
        assert_eq!(
            alice_code, bob_code,
            "both sides must derive the same SAS code"
        );

        // Both press Match. Alice first (no finalize yet — Bob hasn't confirmed).
        let a_match = a.user_match(&tx, 0).unwrap();
        assert!(
            !has_finalize(&a_match),
            "alice can't finalize before bob confirms"
        );
        // Bob receives Alice's confirm, then Bob matches → Bob finalizes.
        let _ = b.inbound_confirm(&tx, true, Some(alice.fingerprint().to_string()));
        let b_match = b.user_match(&tx, 0).unwrap();
        assert!(has_finalize(&b_match), "bob finalizes once both confirmed");
        // Alice receives Bob's confirm → Alice finalizes (the other side).
        let a_final = a.inbound_confirm(&tx, true, Some(bob.fingerprint().to_string()));
        assert!(has_finalize(&a_final), "alice finalizes on bob's confirm");
    }

    #[test]
    fn match_before_code_is_refused() {
        let alice = Identity::generate().unwrap();
        let a = actor_for(&alice);
        let bob = Identity::generate().unwrap();
        let (tx, _) = a.start("room", bob.fingerprint(), 0);
        // No response yet → sas_code is None → match must error.
        assert!(matches!(a.user_match(&tx, 0), Err(SasError::CodeNotReady)));
    }

    #[test]
    fn unknown_tx_match_errors() {
        let a = actor_for(&Identity::generate().unwrap());
        assert!(matches!(a.user_match("nope", 0), Err(SasError::UnknownTx)));
    }

    #[test]
    fn init_not_addressed_to_us_is_ignored() {
        let me = Identity::generate().unwrap();
        let a = actor_for(&me);
        let out = a.inbound_init(
            "room",
            B64.encode([1u8; sas::TX_ID_LEN]),
            &B64.encode([2u8; 32]),
            "someone-else",
            Some("signer".into()),
            0,
            |_| None,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn reap_drops_stale_flows() {
        let a = actor_for(&Identity::generate().unwrap());
        let (tx, _) = a.start("room", "partner", 0);
        a.reap(SAS_FLOW_TTL_SECS); // exactly at TTL — kept
        assert!(a.user_match(&tx, 0).is_err()); // (CodeNotReady, but flow exists)
        a.reap(SAS_FLOW_TTL_SECS + 1); // past TTL — reaped
        assert!(matches!(a.user_match(&tx, 0), Err(SasError::UnknownTx)));
    }

    fn expect_publish(out: &[SasOutcome]) -> &RoomMessage {
        out.iter()
            .find_map(|o| match o {
                SasOutcome::Publish { msg, .. } => Some(msg),
                _ => None,
            })
            .expect("expected a Publish outcome")
    }

    fn expect_code_ready(out: &[SasOutcome]) -> String {
        out.iter()
            .find_map(|o| match o {
                SasOutcome::Emit(AppEvent::SasCodeReady { decimal, .. }) => Some(decimal.clone()),
                _ => None,
            })
            .expect("expected a SasCodeReady event")
    }

    fn has_finalize(out: &[SasOutcome]) -> bool {
        out.iter().any(|o| matches!(o, SasOutcome::Finalize { .. }))
    }
}
