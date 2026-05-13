use rusqlite::params;

use crate::error::Result;
use crate::storage::Db;

#[derive(Debug, Clone)]
pub struct StoredIdentity {
    pub ed25519_secret: Vec<u8>,
    pub olm_account_data: Vec<u8>,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct StoredPeer {
    pub peer_id: String,
    pub fingerprint: String,
    pub display_name: Option<String>,
    pub olm_session_data: Option<Vec<u8>>,
    pub last_seen: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct StoredMessage {
    pub id: i64,
    pub peer_id: String,
    pub direction: String,
    pub body: String,
    pub sent_at: i64,
    pub delivered_at: Option<i64>,
}

pub fn save_identity(db: &Db, secret: &[u8], account_data: &[u8], created_at: i64) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO identity (id, ed25519_secret, olm_account_data, created_at) VALUES (1, ?1, ?2, ?3)",
        params![secret, account_data, created_at],
    )?;
    Ok(())
}

pub fn load_identity(db: &Db) -> Result<Option<StoredIdentity>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT ed25519_secret, olm_account_data, created_at FROM identity WHERE id = 1",
    )?;
    let mut rows = stmt.query_map([], |row| {
        Ok(StoredIdentity {
            ed25519_secret: row.get(0)?,
            olm_account_data: row.get(1)?,
            created_at: row.get(2)?,
        })
    })?;
    match rows.next() {
        Some(row) => Ok(Some(row?)),
        None => Ok(None),
    }
}

pub fn upsert_peer(db: &Db, peer: &StoredPeer) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO peers (peer_id, fingerprint, display_name, olm_session_data, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(peer_id) DO UPDATE SET
           fingerprint = excluded.fingerprint,
           display_name = COALESCE(excluded.display_name, peers.display_name),
           olm_session_data = COALESCE(excluded.olm_session_data, peers.olm_session_data),
           last_seen = excluded.last_seen",
        params![
            peer.peer_id,
            peer.fingerprint,
            peer.display_name,
            peer.olm_session_data,
            peer.last_seen
        ],
    )?;
    Ok(())
}

pub fn get_peer(db: &Db, peer_id: &str) -> Result<Option<StoredPeer>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT peer_id, fingerprint, display_name, olm_session_data, last_seen FROM peers WHERE peer_id = ?1",
    )?;
    let mut rows = stmt.query_map(params![peer_id], |row| {
        Ok(StoredPeer {
            peer_id: row.get(0)?,
            fingerprint: row.get(1)?,
            display_name: row.get(2)?,
            olm_session_data: row.get(3)?,
            last_seen: row.get(4)?,
        })
    })?;
    match rows.next() {
        Some(row) => Ok(Some(row?)),
        None => Ok(None),
    }
}

pub fn update_peer_session(db: &Db, peer_id: &str, session_data: &[u8]) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "UPDATE peers SET olm_session_data = ?1 WHERE peer_id = ?2",
        params![session_data, peer_id],
    )?;
    Ok(())
}

pub fn insert_message(
    db: &Db,
    peer_id: &str,
    direction: &str,
    body: &str,
    sent_at: i64,
) -> Result<i64> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO messages (peer_id, direction, body, sent_at) VALUES (?1, ?2, ?3, ?4)",
        params![peer_id, direction, body, sent_at],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn get_messages(db: &Db, peer_id: &str, limit: i64) -> Result<Vec<StoredMessage>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, peer_id, direction, body, sent_at, delivered_at
         FROM messages WHERE peer_id = ?1 ORDER BY sent_at DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![peer_id, limit], |row| {
        Ok(StoredMessage {
            id: row.get(0)?,
            peer_id: row.get(1)?,
            direction: row.get(2)?,
            body: row.get(3)?,
            sent_at: row.get(4)?,
            delivered_at: row.get(5)?,
        })
    })?;
    let mut msgs: Vec<StoredMessage> = rows.collect::<std::result::Result<Vec<_>, _>>()?;
    msgs.reverse();
    Ok(msgs)
}

pub fn mark_delivered(db: &Db, message_id: i64, delivered_at: i64) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "UPDATE messages SET delivered_at = ?1 WHERE id = ?2",
        params![delivered_at, message_id],
    )?;
    Ok(())
}

pub fn list_peers(db: &Db) -> Result<Vec<StoredPeer>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT peer_id, fingerprint, display_name, olm_session_data, last_seen FROM peers ORDER BY last_seen DESC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(StoredPeer {
            peer_id: row.get(0)?,
            fingerprint: row.get(1)?,
            display_name: row.get(2)?,
            olm_session_data: row.get(3)?,
            last_seen: row.get(4)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::open_db_in_memory;

    #[test]
    fn identity_round_trip() {
        let db = open_db_in_memory().unwrap();
        save_identity(&db, b"secret_key_bytes_here_pad_to_32!", b"account_data", 1000).unwrap();
        let loaded = load_identity(&db).unwrap().unwrap();
        assert_eq!(loaded.ed25519_secret, b"secret_key_bytes_here_pad_to_32!");
        assert_eq!(loaded.olm_account_data, b"account_data");
        assert_eq!(loaded.created_at, 1000);
    }

    #[test]
    fn peer_upsert_and_get() {
        let db = open_db_in_memory().unwrap();
        let peer = StoredPeer {
            peer_id: "12D3KooWTest".into(),
            fingerprint: "abcd-1234-ef56-7890-abcd-ef12".into(),
            display_name: None,
            olm_session_data: None,
            last_seen: Some(2000),
        };
        upsert_peer(&db, &peer).unwrap();
        let loaded = get_peer(&db, "12D3KooWTest").unwrap().unwrap();
        assert_eq!(loaded.fingerprint, "abcd-1234-ef56-7890-abcd-ef12");
        assert_eq!(loaded.last_seen, Some(2000));
    }

    #[test]
    fn message_insert_and_query() {
        let db = open_db_in_memory().unwrap();
        upsert_peer(
            &db,
            &StoredPeer {
                peer_id: "12D3KooWTest".into(),
                fingerprint: "abcd-1234-ef56-7890-abcd-ef12".into(),
                display_name: None,
                olm_session_data: None,
                last_seen: Some(2000),
            },
        )
        .unwrap();

        let id1 = insert_message(&db, "12D3KooWTest", "out", "hello", 3000).unwrap();
        let id2 = insert_message(&db, "12D3KooWTest", "in", "hi back", 3001).unwrap();
        assert!(id1 > 0);
        assert!(id2 > id1);

        let msgs = get_messages(&db, "12D3KooWTest", 50).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].body, "hello");
        assert_eq!(msgs[0].direction, "out");
        assert_eq!(msgs[1].body, "hi back");
        assert_eq!(msgs[1].direction, "in");
    }

    #[test]
    fn message_delivery_tracking() {
        let db = open_db_in_memory().unwrap();
        upsert_peer(
            &db,
            &StoredPeer {
                peer_id: "peer1".into(),
                fingerprint: "aaaa-bbbb-cccc-dddd-eeee-ffff".into(),
                display_name: None,
                olm_session_data: None,
                last_seen: None,
            },
        )
        .unwrap();
        let msg_id = insert_message(&db, "peer1", "out", "test", 1000).unwrap();
        mark_delivered(&db, msg_id, 1001).unwrap();
        let msgs = get_messages(&db, "peer1", 10).unwrap();
        assert_eq!(msgs[0].delivered_at, Some(1001));
    }

    #[test]
    fn peer_session_update() {
        let db = open_db_in_memory().unwrap();
        upsert_peer(
            &db,
            &StoredPeer {
                peer_id: "peer1".into(),
                fingerprint: "aaaa-bbbb-cccc-dddd-eeee-ffff".into(),
                display_name: None,
                olm_session_data: None,
                last_seen: None,
            },
        )
        .unwrap();
        update_peer_session(&db, "peer1", b"session_data_bytes").unwrap();
        let loaded = get_peer(&db, "peer1").unwrap().unwrap();
        assert_eq!(loaded.olm_session_data.unwrap(), b"session_data_bytes");
    }
}
