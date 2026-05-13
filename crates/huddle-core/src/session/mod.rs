pub mod store;

use std::collections::HashMap;

use vodozemac::olm::{Account, InboundCreationResult, OlmMessage, Session, SessionConfig};
use vodozemac::Curve25519PublicKey;

use crate::error::{HuddleError, Result};
use crate::storage::Db;

pub struct SessionManager {
    account: Account,
    sessions: HashMap<String, Session>,
    db: Db,
    ed25519_secret: [u8; 32],
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PrekeyBundle {
    pub identity_key: String,
    pub one_time_key: String,
}

impl SessionManager {
    pub fn new(account: Account, db: Db, ed25519_secret: [u8; 32]) -> Self {
        Self {
            account,
            sessions: HashMap::new(),
            db,
            ed25519_secret,
        }
    }

    pub fn our_prekey_bundle(&mut self) -> Result<PrekeyBundle> {
        if self.account.one_time_keys().is_empty() {
            self.account.generate_one_time_keys(10);
            store::persist_account(&self.db, &self.account, &self.ed25519_secret)?;
        }
        let identity_key = self.account.curve25519_key().to_base64();
        let one_time_key = self
            .account
            .one_time_keys()
            .values()
            .next()
            .ok_or_else(|| HuddleError::Session("no one-time keys available".into()))?
            .to_base64();
        Ok(PrekeyBundle {
            identity_key,
            one_time_key,
        })
    }

    pub fn create_outbound_session(
        &mut self,
        peer_id: &str,
        their_bundle: &PrekeyBundle,
    ) -> Result<()> {
        let identity_key = Curve25519PublicKey::from_base64(&their_bundle.identity_key)
            .map_err(|e| HuddleError::Session(format!("bad identity key: {e}")))?;
        let one_time_key = Curve25519PublicKey::from_base64(&their_bundle.one_time_key)
            .map_err(|e| HuddleError::Session(format!("bad one-time key: {e}")))?;

        let session = self
            .account
            .create_outbound_session(SessionConfig::version_1(), identity_key, one_time_key)
            .map_err(|e| HuddleError::Session(format!("outbound session failed: {e}")))?;
        store::persist_session(&self.db, peer_id, &session)?;
        self.sessions.insert(peer_id.to_string(), session);
        Ok(())
    }

    pub fn create_inbound_session(
        &mut self,
        peer_id: &str,
        their_identity_key: &str,
        pre_key_message_bytes: &[u8],
    ) -> Result<Vec<u8>> {
        let identity_key = Curve25519PublicKey::from_base64(their_identity_key)
            .map_err(|e| HuddleError::Session(format!("bad identity key: {e}")))?;
        let pre_key_msg = vodozemac::olm::PreKeyMessage::from_bytes(pre_key_message_bytes)
            .map_err(|e| HuddleError::Session(format!("bad pre-key message: {e}")))?;

        let InboundCreationResult { session, plaintext } = self
            .account
            .create_inbound_session(SessionConfig::version_1(), identity_key, &pre_key_msg)
            .map_err(|e| HuddleError::Session(format!("inbound session failed: {e}")))?;

        store::persist_session(&self.db, peer_id, &session)?;
        store::persist_account(&self.db, &self.account, &self.ed25519_secret)?;
        self.sessions.insert(peer_id.to_string(), session);
        Ok(plaintext)
    }

    pub fn encrypt(&mut self, peer_id: &str, plaintext: &[u8]) -> Result<(Vec<u8>, u8)> {
        self.ensure_session_loaded(peer_id)?;
        let session = self.sessions.get_mut(peer_id)
            .ok_or_else(|| HuddleError::Session(format!("no session with peer {peer_id}")))?;

        let olm_msg = session
            .encrypt(plaintext)
            .map_err(|e| HuddleError::Session(format!("encrypt failed: {e}")))?;

        let (msg_type, bytes) = olm_msg.to_parts();
        store::persist_session(&self.db, peer_id, session)?;
        Ok((bytes, msg_type as u8))
    }

    pub fn decrypt(&mut self, peer_id: &str, ciphertext: &[u8], msg_type: u8) -> Result<Vec<u8>> {
        self.ensure_session_loaded(peer_id)?;

        let olm_msg = OlmMessage::from_parts(msg_type as usize, ciphertext)
            .map_err(|e| HuddleError::Session(format!("bad message: {e}")))?;

        let session = self.sessions.get_mut(peer_id)
            .ok_or_else(|| HuddleError::Session(format!("no session with peer {peer_id}")))?;

        let plaintext = session
            .decrypt(&olm_msg)
            .map_err(|e| HuddleError::Session(format!("decrypt failed: {e}")))?;

        store::persist_session(&self.db, peer_id, session)?;
        Ok(plaintext)
    }

    pub fn has_session(&self, peer_id: &str) -> bool {
        self.sessions.contains_key(peer_id)
    }

    pub fn identity_key_base64(&self) -> String {
        self.account.curve25519_key().to_base64()
    }

    fn ensure_session_loaded(&mut self, peer_id: &str) -> Result<()> {
        if !self.sessions.contains_key(peer_id) {
            if let Some(session) = store::load_session(&self.db, peer_id)? {
                self.sessions.insert(peer_id.to_string(), session);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::open_db_in_memory;
    use crate::storage::repo;
    use vodozemac::olm::Account;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let db_a = open_db_in_memory().unwrap();
        let db_b = open_db_in_memory().unwrap();

        let account_a = Account::new();
        let account_b = Account::new();

        let secret_a = [1u8; 32];
        let secret_b = [2u8; 32];

        let mut mgr_a = SessionManager::new(account_a, db_a.clone(), secret_a);
        let mut mgr_b = SessionManager::new(account_b, db_b.clone(), secret_b);

        let peer_a_id = "peer_a";
        let peer_b_id = "peer_b";
        repo::upsert_peer(
            &db_a,
            &repo::StoredPeer {
                peer_id: peer_b_id.into(),
                fingerprint: "b-fp".into(),
                display_name: None,
                olm_session_data: None,
                last_seen: None,
            },
        )
        .unwrap();
        repo::upsert_peer(
            &db_b,
            &repo::StoredPeer {
                peer_id: peer_a_id.into(),
                fingerprint: "a-fp".into(),
                display_name: None,
                olm_session_data: None,
                last_seen: None,
            },
        )
        .unwrap();

        let bundle_b = mgr_b.our_prekey_bundle().unwrap();
        mgr_a
            .create_outbound_session(peer_b_id, &bundle_b)
            .unwrap();

        let (ciphertext, msg_type) = mgr_a.encrypt(peer_b_id, b"hello bob").unwrap();
        assert_eq!(msg_type, 0);

        let plaintext = mgr_b
            .create_inbound_session(peer_a_id, &mgr_a.identity_key_base64(), &ciphertext)
            .unwrap();
        assert_eq!(plaintext, b"hello bob");

        let (reply_ct, reply_type) = mgr_b.encrypt(peer_a_id, b"hi alice").unwrap();
        assert_eq!(reply_type, 1);

        let reply_pt = mgr_a.decrypt(peer_b_id, &reply_ct, reply_type).unwrap();
        assert_eq!(reply_pt, b"hi alice");
    }
}
