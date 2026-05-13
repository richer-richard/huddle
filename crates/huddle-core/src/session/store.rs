use vodozemac::olm::{Account, AccountPickle, Session, SessionConfig, SessionPickle};

use crate::error::{HuddleError, Result};
use crate::storage::repo;
use crate::storage::Db;

// TODO: Phase 4 — derive from user passphrase via Argon2id
const SERIALIZATION_KEY: &[u8; 32] =
    b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

pub fn create_and_persist_account(db: &Db, ed25519_secret: &[u8; 32]) -> Result<Account> {
    let account = Account::new();
    let encrypted = account.pickle().encrypt(SERIALIZATION_KEY);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    repo::save_identity(db, ed25519_secret, encrypted.as_bytes(), now)?;
    Ok(account)
}

pub fn load_account(db: &Db) -> Result<Option<Account>> {
    let stored = repo::load_identity(db)?;
    match stored {
        Some(si) => {
            let data_str = String::from_utf8(si.olm_account_data)
                .map_err(|e| HuddleError::Session(e.to_string()))?;
            let ap = AccountPickle::from_encrypted(&data_str, SERIALIZATION_KEY)
                .map_err(|e| HuddleError::Session(format!("restore account: {e}")))?;
            Ok(Some(Account::from_pickle(ap)))
        }
        None => Ok(None),
    }
}

pub fn persist_account(db: &Db, account: &Account, ed25519_secret: &[u8; 32]) -> Result<()> {
    let encrypted = account.pickle().encrypt(SERIALIZATION_KEY);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    repo::save_identity(db, ed25519_secret, encrypted.as_bytes(), now)?;
    Ok(())
}

pub fn persist_session(db: &Db, peer_id: &str, session: &Session) -> Result<()> {
    let encrypted = session.pickle().encrypt(SERIALIZATION_KEY);
    repo::update_peer_session(db, peer_id, encrypted.as_bytes())?;
    Ok(())
}

pub fn load_session(db: &Db, peer_id: &str) -> Result<Option<Session>> {
    let peer = repo::get_peer(db, peer_id)?;
    match peer {
        Some(p) => match p.olm_session_data {
            Some(data_bytes) => {
                let data_str = String::from_utf8(data_bytes)
                    .map_err(|e| HuddleError::Session(e.to_string()))?;
                let sp = SessionPickle::from_encrypted(&data_str, SERIALIZATION_KEY)
                    .map_err(|e| HuddleError::Session(format!("restore session: {e}")))?;
                Ok(Some(Session::from_pickle(sp)))
            }
            None => Ok(None),
        },
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::open_db_in_memory;

    #[test]
    fn account_create_persist_reload() {
        let db = open_db_in_memory().unwrap();
        let secret = [42u8; 32];
        let account = create_and_persist_account(&db, &secret).unwrap();
        let curve_key = account.curve25519_key();

        let loaded = load_account(&db).unwrap().unwrap();
        assert_eq!(loaded.curve25519_key(), curve_key);
    }

    #[test]
    fn session_persist_reload() {
        let db = open_db_in_memory().unwrap();

        let alice_account = Account::new();
        let mut bob_account = Account::new();

        bob_account.generate_one_time_keys(1);
        let bob_otk = *bob_account.one_time_keys().values().next().unwrap();
        let bob_identity = bob_account.curve25519_key();

        let alice_session = alice_account
            .create_outbound_session(SessionConfig::version_1(), bob_identity, bob_otk)
            .unwrap();

        repo::upsert_peer(
            &db,
            &repo::StoredPeer {
                peer_id: "bob_peer_id".into(),
                fingerprint: "test-fp".into(),
                display_name: None,
                olm_session_data: None,
                last_seen: None,
            },
        )
        .unwrap();

        persist_session(&db, "bob_peer_id", &alice_session).unwrap();
        let loaded = load_session(&db, "bob_peer_id").unwrap().unwrap();
        assert_eq!(loaded.session_id(), alice_session.session_id());
    }
}
