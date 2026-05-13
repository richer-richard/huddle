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

use crate::error::{HuddleError, Result};
use crate::storage::repo::{self, StoredMegolmSession};
use crate::storage::Db;

// TODO: Phase 4 — derive from user passphrase via Argon2id
const SESSION_PERSIST_KEY: &[u8; 32] =
    b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

/// Per-room Megolm crypto: one outbound session (ours) + many inbound (others').
pub struct RoomCrypto {
    room_id: String,
    our_fingerprint: String,
    outbound: GroupSession,
    /// Keyed by (sender_fingerprint, session_id).
    inbound: HashMap<(String, String), InboundGroupSession>,
    db: Db,
}

impl RoomCrypto {
    /// Create a fresh outbound session and persist it.
    pub fn new_for_room(db: Db, room_id: String, our_fingerprint: String) -> Result<Self> {
        let outbound = GroupSession::new(SessionConfig::version_1());
        let crypto = Self {
            room_id,
            our_fingerprint,
            outbound,
            inbound: HashMap::new(),
            db,
        };
        crypto.persist_outbound()?;
        Ok(crypto)
    }

    /// Load any persisted sessions for the room. Returns None if no outbound
    /// session is stored (meaning we haven't joined or created it).
    pub fn load(db: Db, room_id: String, our_fingerprint: String) -> Result<Option<Self>> {
        let sessions = repo::load_megolm_sessions_for_room(&db, &room_id)?;
        let mut outbound: Option<GroupSession> = None;
        let mut inbound: HashMap<(String, String), InboundGroupSession> = HashMap::new();

        for s in sessions {
            let data_str = String::from_utf8(s.session_data)
                .map_err(|e| HuddleError::Session(format!("session data utf8: {e}")))?;
            if s.is_outbound {
                let p = GroupSessionPickle::from_encrypted(&data_str, SESSION_PERSIST_KEY)
                    .map_err(|e| HuddleError::Session(format!("restore outbound: {e}")))?;
                outbound = Some(GroupSession::from_pickle(p));
            } else {
                let p = InboundGroupSessionPickle::from_encrypted(&data_str, SESSION_PERSIST_KEY)
                    .map_err(|e| HuddleError::Session(format!("restore inbound: {e}")))?;
                let session = InboundGroupSession::from_pickle(p);
                inbound.insert((s.sender_fingerprint, s.session_id), session);
            }
        }

        match outbound {
            Some(outbound) => Ok(Some(Self {
                room_id,
                our_fingerprint,
                outbound,
                inbound,
                db,
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
                "no inbound megolm session for {sender_fingerprint} / {session_id}"
            ))
        })?;
        let msg = MegolmMessage::from_bytes(ciphertext)
            .map_err(|e| HuddleError::Session(format!("bad megolm message: {e}")))?;
        let decrypted = session
            .decrypt(&msg)
            .map_err(|e| HuddleError::Session(format!("megolm decrypt failed: {e}")))?;

        // Persist the advanced inbound ratchet state.
        let persisted = session.pickle().encrypt(SESSION_PERSIST_KEY);
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

        let persisted = session.pickle().encrypt(SESSION_PERSIST_KEY);
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
        let persisted = self.outbound.pickle().encrypt(SESSION_PERSIST_KEY);
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::open_db_in_memory;
    use crate::storage::repo::{derive_room_id, insert_room, StoredRoom};

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
            RoomCrypto::new_for_room(db_alice.clone(), room_id.clone(), "alice-fp".into())
                .unwrap();
        let mut bob =
            RoomCrypto::new_for_room(db_bob.clone(), room_id.clone(), "bob-fp".into()).unwrap();

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
            RoomCrypto::new_for_room(db_a.clone(), room_id.clone(), "a-fp".into()).unwrap();
        let mut bob =
            RoomCrypto::new_for_room(db_b.clone(), room_id.clone(), "b-fp".into()).unwrap();

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
            RoomCrypto::new_for_room(db.clone(), room_id.clone(), "me-fp".into()).unwrap();
        let original_session_id = crypto.our_session_id();
        let (_, _) = crypto.encrypt(b"advance the ratchet").unwrap();
        drop(crypto);

        let reloaded = RoomCrypto::load(db.clone(), room_id.clone(), "me-fp".into())
            .unwrap()
            .expect("should have outbound session");
        assert_eq!(reloaded.our_session_id(), original_session_id);
    }

    #[test]
    fn decrypt_unknown_sender_errors() {
        let db = open_db_in_memory().unwrap();
        let room_id = setup_room(&db, "r", "me-fp");
        let mut crypto =
            RoomCrypto::new_for_room(db.clone(), room_id.clone(), "me-fp".into()).unwrap();
        let err = crypto.decrypt("unknown-fp", "session-id", b"junk");
        assert!(err.is_err());
    }
}
