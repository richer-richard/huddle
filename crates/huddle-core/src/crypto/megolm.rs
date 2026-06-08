//! Megolm group session management per room.
//!
//! Each peer has one outbound `GroupSession` per room (used to encrypt
//! messages they send) and an `InboundGroupSession` for every other
//! member they've received a session key from (used to decrypt those
//! members' messages).
//!
//! The outbound session key is shared with new members at join time.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use vodozemac::megolm::{
    GroupSession, GroupSessionPickle, InboundGroupSession, InboundGroupSessionPickle,
    MegolmMessage, SessionConfig, SessionKey,
};

use tracing::warn;

use crate::error::{HuddleError, Result};
use crate::storage::repo::{self, StoredMegolmSession};

use crate::storage::Db;

/// huddle 1.3.1: marker substring in the "missing inbound session" decrypt
/// error. The app layer matches on it (in the `Encrypted` handler) to trigger a
/// `SessionKeyRequest` heal, so the two must stay in sync — this const is the
/// single source of truth rather than a duplicated string literal.
pub const MISSING_INBOUND_SESSION_ERR: &str = "no inbound megolm session";

/// Per-room Megolm crypto: one outbound session (ours) + many inbound (others').
pub struct RoomCrypto {
    room_id: String,
    our_fingerprint: String,
    outbound: GroupSession,
    /// Keyed by (sender_fingerprint, session_id).
    inbound: HashMap<(String, String), InboundGroupSession>,
    db: Db,
    /// 32-byte key the session pickles are encrypted under at rest.
    /// Derived from the master passphrase (an HKDF subkey); all-zero on
    /// the `--no-master-passphrase` / unencrypted-DB path. Threaded in
    /// explicitly rather than read from process-global state.
    persist_key: [u8; 32],
}

impl RoomCrypto {
    /// Create a fresh outbound session and persist it. `persist_key` is
    /// the 32-byte key the at-rest session pickles are encrypted under.
    pub fn new_for_room(
        db: Db,
        room_id: String,
        our_fingerprint: String,
        persist_key: [u8; 32],
    ) -> Result<Self> {
        let outbound = GroupSession::new(SessionConfig::version_1());
        let crypto = Self {
            room_id,
            our_fingerprint,
            outbound,
            inbound: HashMap::new(),
            db,
            persist_key,
        };
        crypto.persist_outbound()?;
        Ok(crypto)
    }

    /// Load any persisted sessions for the room. Returns `None` when no
    /// usable outbound session is stored (we haven't joined or created it,
    /// or the only outbound pickle is unreadable).
    ///
    /// Resilient by design: a single session that fails to decode or
    /// decrypt is logged and skipped rather than aborting the whole room
    /// load. One corrupt row should not lock the user out.
    pub fn load(
        db: Db,
        room_id: String,
        our_fingerprint: String,
        persist_key: [u8; 32],
    ) -> Result<Option<Self>> {
        let sessions = repo::load_megolm_sessions_for_room(&db, &room_id)?;
        let mut outbound: Option<GroupSession> = None;
        let mut inbound: HashMap<(String, String), InboundGroupSession> = HashMap::new();

        for s in sessions {
            let data_str = match String::from_utf8(s.session_data) {
                Ok(d) => d,
                Err(e) => {
                    warn!(%e, room_id = %room_id, "skipping persisted megolm session: invalid utf8");
                    continue;
                }
            };
            if s.is_outbound {
                match GroupSessionPickle::from_encrypted(&data_str, &persist_key) {
                    Ok(p) => outbound = Some(GroupSession::from_pickle(p)),
                    Err(e) => {
                        warn!(%e, room_id = %room_id, "skipping persisted outbound megolm session: restore failed");
                    }
                }
            } else {
                match InboundGroupSessionPickle::from_encrypted(&data_str, &persist_key) {
                    Ok(p) => {
                        inbound.insert(
                            (s.sender_fingerprint, s.session_id),
                            InboundGroupSession::from_pickle(p),
                        );
                    }
                    Err(e) => {
                        warn!(%e, room_id = %room_id, "skipping persisted inbound megolm session: restore failed");
                    }
                }
            }
        }

        match outbound {
            Some(outbound) => Ok(Some(Self {
                room_id,
                our_fingerprint,
                outbound,
                inbound,
                db,
                persist_key,
            })),
            None => Ok(None),
        }
    }

    /// Encrypt a plaintext using our outbound session. Returns
    /// (session_id, MegolmMessage bytes).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(String, Vec<u8>)> {
        let msg = self.outbound.encrypt(plaintext);
        let session_id = self.outbound.session_id();
        self.persist_outbound()?;
        Ok((session_id, msg.to_bytes()))
    }

    /// Decrypt a message from a specific sender.
    pub fn decrypt(
        &mut self,
        sender_fingerprint: &str,
        session_id: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let key = (sender_fingerprint.to_string(), session_id.to_string());
        let session = self.inbound.get_mut(&key).ok_or_else(|| {
            HuddleError::Session(format!(
                "{MISSING_INBOUND_SESSION_ERR} for {sender_fingerprint} / {session_id}"
            ))
        })?;
        let msg = MegolmMessage::from_bytes(ciphertext)
            .map_err(|e| HuddleError::Session(format!("bad megolm message: {e}")))?;
        let decrypted = session
            .decrypt(&msg)
            .map_err(|e| HuddleError::Session(format!("megolm decrypt failed: {e}")))?;

        // Persist the advanced inbound ratchet state.
        let persisted = session.pickle().encrypt(&self.persist_key);
        repo::save_megolm_session(
            &self.db,
            &StoredMegolmSession {
                room_id: self.room_id.clone(),
                sender_fingerprint: sender_fingerprint.to_string(),
                session_id: session_id.to_string(),
                session_data: persisted.into_bytes(),
                is_outbound: false,
                created_at: now_unix(),
            },
        )?;

        Ok(decrypted.plaintext)
    }

    /// Add an inbound session from another member. `session_key_b64` is the
    /// base64-encoded Megolm SessionKey they shared with us.
    pub fn add_inbound_session(
        &mut self,
        sender_fingerprint: &str,
        session_key_b64: &str,
    ) -> Result<()> {
        let key = SessionKey::from_base64(session_key_b64)
            .map_err(|e| HuddleError::Session(format!("bad session key: {e}")))?;
        let session = InboundGroupSession::new(&key, SessionConfig::version_1());
        let session_id = session.session_id();

        let persisted = session.pickle().encrypt(&self.persist_key);
        repo::save_megolm_session(
            &self.db,
            &StoredMegolmSession {
                room_id: self.room_id.clone(),
                sender_fingerprint: sender_fingerprint.to_string(),
                session_id: session_id.clone(),
                session_data: persisted.into_bytes(),
                is_outbound: false,
                created_at: now_unix(),
            },
        )?;

        self.inbound
            .insert((sender_fingerprint.to_string(), session_id), session);
        Ok(())
    }

    /// huddle 1.3.1: rotate ONLY our outbound session, preserving every
    /// inbound session. Used when a Direct room's wrap key is upgraded
    /// classical→hybrid: the previous outbound session key was shared wrapped
    /// under the quantum-breakable classical key, so an attacker who harvested
    /// that wrapped copy could (post-quantum) recover it and, because Megolm
    /// forward-derives all later ratchet keys from it, decrypt the entire
    /// session. Minting a fresh outbound session and retiring the old one
    /// closes that window — future messages use a key only ever shared wrapped
    /// under the hybrid PQ key.
    ///
    /// We DELETE the old outbound row before persisting the new one (the new
    /// session has a different `session_id`, which is part of the megolm-table
    /// PK, so a plain re-persist would leave a duplicate outbound row and
    /// `load` could nondeterministically restore the retired session). Unlike
    /// `new_for_room`, the in-memory `inbound` map is left intact.
    pub fn rotate_outbound(&mut self) -> Result<()> {
        repo::delete_outbound_megolm_sessions(&self.db, &self.room_id, &self.our_fingerprint)?;
        self.outbound = GroupSession::new(SessionConfig::version_1());
        self.persist_outbound()?;
        Ok(())
    }

    /// Get our outbound session key for sharing with new members (base64).
    pub fn our_session_key_b64(&self) -> String {
        self.outbound.session_key().to_base64()
    }

    pub fn our_session_id(&self) -> String {
        self.outbound.session_id()
    }

    pub fn our_fingerprint(&self) -> &str {
        &self.our_fingerprint
    }

    pub fn room_id(&self) -> &str {
        &self.room_id
    }

    fn persist_outbound(&self) -> Result<()> {
        let persisted = self.outbound.pickle().encrypt(&self.persist_key);
        repo::save_megolm_session(
            &self.db,
            &StoredMegolmSession {
                room_id: self.room_id.clone(),
                sender_fingerprint: self.our_fingerprint.clone(),
                session_id: self.outbound.session_id(),
                session_data: persisted.into_bytes(),
                is_outbound: true,
                created_at: now_unix(),
            },
        )?;
        Ok(())
    }
}

fn now_unix() -> i64 {
    // huddle 0.7.11: do NOT panic if the wall clock is set before the
    // UNIX epoch (rare but reachable: VM clones with reset RTCs, ARM
    // SBCs without a battery-backed clock, ntpd not yet synced).
    // `unwrap()` here used to take down the network task on every
    // encrypt / decrypt / persist; saturating to 0 is safe — the value
    // is only used as a stored last-seen timestamp.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::open_db_in_memory;
    use crate::storage::repo::{derive_room_id, insert_room, RoomKind, StoredRoom};

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

    #[test]
    fn outbound_encrypt_inbound_decrypt() {
        let db_alice = open_db_in_memory().unwrap();
        let db_bob = open_db_in_memory().unwrap();
        let room_id = setup_room(&db_alice, "test", "alice-fp");
        setup_room(&db_bob, "test", "alice-fp");

        let mut alice =
            RoomCrypto::new_for_room(db_alice.clone(), room_id.clone(), "alice-fp".into(), [0u8; 32])
                .unwrap();
        let mut bob =
            RoomCrypto::new_for_room(db_bob.clone(), room_id.clone(), "bob-fp".into(), [0u8; 32]).unwrap();

        bob.add_inbound_session("alice-fp", &alice.our_session_key_b64())
            .unwrap();

        let (session_id, ciphertext) = alice.encrypt(b"hello group").unwrap();
        let plaintext = bob.decrypt("alice-fp", &session_id, &ciphertext).unwrap();
        assert_eq!(plaintext, b"hello group");
    }

    #[test]
    fn bidirectional_round_trip() {
        let db_a = open_db_in_memory().unwrap();
        let db_b = open_db_in_memory().unwrap();
        let room_id = setup_room(&db_a, "r", "a-fp");
        setup_room(&db_b, "r", "a-fp");

        let mut alice =
            RoomCrypto::new_for_room(db_a.clone(), room_id.clone(), "a-fp".into(), [0u8; 32]).unwrap();
        let mut bob =
            RoomCrypto::new_for_room(db_b.clone(), room_id.clone(), "b-fp".into(), [0u8; 32]).unwrap();

        alice
            .add_inbound_session("b-fp", &bob.our_session_key_b64())
            .unwrap();
        bob.add_inbound_session("a-fp", &alice.our_session_key_b64())
            .unwrap();

        let (sid_a, ct_a) = alice.encrypt(b"from alice").unwrap();
        assert_eq!(bob.decrypt("a-fp", &sid_a, &ct_a).unwrap(), b"from alice");

        let (sid_b, ct_b) = bob.encrypt(b"from bob").unwrap();
        assert_eq!(alice.decrypt("b-fp", &sid_b, &ct_b).unwrap(), b"from bob");
    }

    #[test]
    fn outbound_persists_and_reloads() {
        let db = open_db_in_memory().unwrap();
        let room_id = setup_room(&db, "r", "me-fp");

        let mut crypto =
            RoomCrypto::new_for_room(db.clone(), room_id.clone(), "me-fp".into(), [0u8; 32]).unwrap();
        let original_session_id = crypto.our_session_id();
        let (_, _) = crypto.encrypt(b"advance the ratchet").unwrap();
        drop(crypto);

        let reloaded = RoomCrypto::load(db.clone(), room_id.clone(), "me-fp".into(), [0u8; 32])
            .unwrap()
            .expect("should have outbound session");
        assert_eq!(reloaded.our_session_id(), original_session_id);
    }

    #[test]
    fn rotate_outbound_mints_new_session_preserves_inbound_and_dedups_row() {
        // huddle 1.3.1: classical→hybrid upgrade rotates ONLY the outbound
        // session — the old (classically-wrapped) key is retired, inbound
        // sessions survive, and exactly one outbound row remains so a reload
        // can't restore the retired session.
        let db_alice = open_db_in_memory().unwrap();
        let db_bob = open_db_in_memory().unwrap();
        let room_id = setup_room(&db_alice, "r", "alice-fp");
        setup_room(&db_bob, "r", "alice-fp");

        let mut alice =
            RoomCrypto::new_for_room(db_alice.clone(), room_id.clone(), "alice-fp".into(), [0u8; 32])
                .unwrap();
        let mut bob =
            RoomCrypto::new_for_room(db_bob.clone(), room_id.clone(), "bob-fp".into(), [0u8; 32]).unwrap();

        // Alice holds an inbound session from Bob and can decrypt his messages.
        alice
            .add_inbound_session("bob-fp", &bob.our_session_key_b64())
            .unwrap();
        let (sid1, ct1) = bob.encrypt(b"before rotate").unwrap();
        assert_eq!(alice.decrypt("bob-fp", &sid1, &ct1).unwrap(), b"before rotate");

        let old_outbound = alice.our_session_id();

        // Rotate Alice's outbound session.
        alice.rotate_outbound().unwrap();
        let new_outbound = alice.our_session_id();
        assert_ne!(old_outbound, new_outbound, "rotate must mint a fresh outbound session");

        // Inbound from Bob is preserved — Alice still decrypts his next message.
        let (sid2, ct2) = bob.encrypt(b"after rotate").unwrap();
        assert_eq!(
            alice.decrypt("bob-fp", &sid2, &ct2).unwrap(),
            b"after rotate",
            "rotate_outbound must NOT discard inbound sessions"
        );

        // Exactly one outbound row persists (old one deleted), and it is the new session.
        let rows = repo::load_megolm_sessions_for_room(&db_alice, &room_id).unwrap();
        let outbound: Vec<_> = rows.iter().filter(|s| s.is_outbound).collect();
        assert_eq!(outbound.len(), 1, "exactly one outbound row after rotate");
        assert_eq!(outbound[0].session_id, new_outbound);

        // Reload deterministically restores the NEW outbound session.
        drop(alice);
        let reloaded = RoomCrypto::load(db_alice.clone(), room_id.clone(), "alice-fp".into(), [0u8; 32])
            .unwrap()
            .expect("outbound session present");
        assert_eq!(reloaded.our_session_id(), new_outbound);
    }

    #[test]
    fn decrypt_unknown_sender_errors() {
        let db = open_db_in_memory().unwrap();
        let room_id = setup_room(&db, "r", "me-fp");
        let mut crypto =
            RoomCrypto::new_for_room(db.clone(), room_id.clone(), "me-fp".into(), [0u8; 32]).unwrap();
        let err = crypto.decrypt("unknown-fp", "session-id", b"junk");
        assert!(err.is_err());
        // huddle 1.3.1: the app's decrypt-miss key-request heal matches on this
        // marker, so a missing-session error MUST carry it. Locks the contract.
        assert!(
            err.unwrap_err()
                .to_string()
                .contains(MISSING_INBOUND_SESSION_ERR),
            "missing-session error must contain MISSING_INBOUND_SESSION_ERR"
        );
    }
}
