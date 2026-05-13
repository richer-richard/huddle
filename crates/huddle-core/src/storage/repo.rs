use rusqlite::params;
use sha2::{Digest, Sha256};

use crate::error::Result;
use crate::storage::Db;

// =========================================================================
// Identity (unchanged — single row, our own Ed25519 + vodozemac account)
// =========================================================================

#[derive(Debug, Clone)]
pub struct StoredIdentity {
    pub ed25519_secret: Vec<u8>,
    pub olm_account_data: Vec<u8>,
    pub created_at: i64,
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

// =========================================================================
// Rooms
// =========================================================================

#[derive(Debug, Clone)]
pub struct StoredRoom {
    pub id: String,
    pub name: String,
    pub creator_fingerprint: String,
    pub encrypted: bool,
    pub passphrase_salt: Option<Vec<u8>>,
    pub created_at: i64,
    pub last_active: Option<i64>,
}

/// Derive a stable room ID from creator fingerprint, name, and creation time.
pub fn derive_room_id(creator_fp: &str, name: &str, created_at: i64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(creator_fp.as_bytes());
    hasher.update(b"\0");
    hasher.update(name.as_bytes());
    hasher.update(b"\0");
    hasher.update(created_at.to_be_bytes());
    hex::encode(&hasher.finalize()[..16])
}

pub fn insert_room(db: &Db, room: &StoredRoom) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO rooms (id, name, creator_fingerprint, encrypted, passphrase_salt, created_at, last_active)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            room.id,
            room.name,
            room.creator_fingerprint,
            room.encrypted as i64,
            room.passphrase_salt,
            room.created_at,
            room.last_active,
        ],
    )?;
    Ok(())
}

pub fn get_room(db: &Db, room_id: &str) -> Result<Option<StoredRoom>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, name, creator_fingerprint, encrypted, passphrase_salt, created_at, last_active
         FROM rooms WHERE id = ?1",
    )?;
    let mut rows = stmt.query_map(params![room_id], |row| {
        Ok(StoredRoom {
            id: row.get(0)?,
            name: row.get(1)?,
            creator_fingerprint: row.get(2)?,
            encrypted: row.get::<_, i64>(3)? != 0,
            passphrase_salt: row.get(4)?,
            created_at: row.get(5)?,
            last_active: row.get(6)?,
        })
    })?;
    match rows.next() {
        Some(row) => Ok(Some(row?)),
        None => Ok(None),
    }
}

pub fn list_rooms(db: &Db) -> Result<Vec<StoredRoom>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, name, creator_fingerprint, encrypted, passphrase_salt, created_at, last_active
         FROM rooms ORDER BY last_active DESC NULLS LAST, created_at DESC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(StoredRoom {
            id: row.get(0)?,
            name: row.get(1)?,
            creator_fingerprint: row.get(2)?,
            encrypted: row.get::<_, i64>(3)? != 0,
            passphrase_salt: row.get(4)?,
            created_at: row.get(5)?,
            last_active: row.get(6)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub fn update_room_last_active(db: &Db, room_id: &str, ts: i64) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "UPDATE rooms SET last_active = ?1 WHERE id = ?2",
        params![ts, room_id],
    )?;
    Ok(())
}

// =========================================================================
// Room members
// =========================================================================

#[derive(Debug, Clone)]
pub struct StoredRoomMember {
    pub room_id: String,
    pub peer_id: String,
    pub fingerprint: String,
    pub last_seen: Option<i64>,
}

pub fn upsert_room_member(db: &Db, member: &StoredRoomMember) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO room_members (room_id, peer_id, fingerprint, last_seen) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(room_id, peer_id) DO UPDATE SET
            fingerprint = excluded.fingerprint,
            last_seen = excluded.last_seen",
        params![
            member.room_id,
            member.peer_id,
            member.fingerprint,
            member.last_seen
        ],
    )?;
    Ok(())
}

pub fn list_room_members(db: &Db, room_id: &str) -> Result<Vec<StoredRoomMember>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT room_id, peer_id, fingerprint, last_seen FROM room_members WHERE room_id = ?1",
    )?;
    let rows = stmt.query_map(params![room_id], |row| {
        Ok(StoredRoomMember {
            room_id: row.get(0)?,
            peer_id: row.get(1)?,
            fingerprint: row.get(2)?,
            last_seen: row.get(3)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub fn remove_room_member(db: &Db, room_id: &str, peer_id: &str) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM room_members WHERE room_id = ?1 AND peer_id = ?2",
        params![room_id, peer_id],
    )?;
    Ok(())
}

// =========================================================================
// Megolm sessions
// =========================================================================

#[derive(Debug, Clone)]
pub struct StoredMegolmSession {
    pub room_id: String,
    pub sender_fingerprint: String,
    pub session_id: String,
    pub session_data: Vec<u8>,
    pub is_outbound: bool,
    pub created_at: i64,
}

pub fn save_megolm_session(db: &Db, session: &StoredMegolmSession) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO room_megolm_sessions
            (room_id, sender_fingerprint, session_id, session_data, is_outbound, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            session.room_id,
            session.sender_fingerprint,
            session.session_id,
            session.session_data,
            session.is_outbound as i64,
            session.created_at,
        ],
    )?;
    Ok(())
}

pub fn load_megolm_sessions_for_room(
    db: &Db,
    room_id: &str,
) -> Result<Vec<StoredMegolmSession>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT room_id, sender_fingerprint, session_id, session_data, is_outbound, created_at
         FROM room_megolm_sessions WHERE room_id = ?1",
    )?;
    let rows = stmt.query_map(params![room_id], |row| {
        Ok(StoredMegolmSession {
            room_id: row.get(0)?,
            sender_fingerprint: row.get(1)?,
            session_id: row.get(2)?,
            session_data: row.get(3)?,
            is_outbound: row.get::<_, i64>(4)? != 0,
            created_at: row.get(5)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

// =========================================================================
// Room messages
// =========================================================================

#[derive(Debug, Clone)]
pub struct StoredRoomMessage {
    pub id: i64,
    pub room_id: String,
    pub sender_fingerprint: String,
    pub direction: String,
    pub body: String,
    pub sent_at: i64,
}

pub fn insert_room_message(
    db: &Db,
    room_id: &str,
    sender_fingerprint: &str,
    direction: &str,
    body: &str,
    sent_at: i64,
) -> Result<i64> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO room_messages (room_id, sender_fingerprint, direction, body, sent_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![room_id, sender_fingerprint, direction, body, sent_at],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn get_room_messages(db: &Db, room_id: &str, limit: i64) -> Result<Vec<StoredRoomMessage>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, room_id, sender_fingerprint, direction, body, sent_at
         FROM room_messages WHERE room_id = ?1 ORDER BY sent_at DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![room_id, limit], |row| {
        Ok(StoredRoomMessage {
            id: row.get(0)?,
            room_id: row.get(1)?,
            sender_fingerprint: row.get(2)?,
            direction: row.get(3)?,
            body: row.get(4)?,
            sent_at: row.get(5)?,
        })
    })?;
    let mut msgs: Vec<StoredRoomMessage> = rows.collect::<std::result::Result<Vec<_>, _>>()?;
    msgs.reverse();
    Ok(msgs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::open_db_in_memory;

    fn make_room(name: &str) -> StoredRoom {
        let creator_fp = "test-creator-fp";
        let created_at = 1000;
        StoredRoom {
            id: derive_room_id(creator_fp, name, created_at),
            name: name.into(),
            creator_fingerprint: creator_fp.into(),
            encrypted: false,
            passphrase_salt: None,
            created_at,
            last_active: None,
        }
    }

    #[test]
    fn room_id_is_deterministic() {
        let id1 = derive_room_id("creator-fp", "test-room", 1000);
        let id2 = derive_room_id("creator-fp", "test-room", 1000);
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 32); // 16 bytes hex-encoded
    }

    #[test]
    fn room_id_differs_with_inputs() {
        let id1 = derive_room_id("creator-a", "test", 1000);
        let id2 = derive_room_id("creator-b", "test", 1000);
        let id3 = derive_room_id("creator-a", "test", 1001);
        assert_ne!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn room_insert_and_get() {
        let db = open_db_in_memory().unwrap();
        let room = make_room("lunch-talk");
        insert_room(&db, &room).unwrap();
        let loaded = get_room(&db, &room.id).unwrap().unwrap();
        assert_eq!(loaded.name, "lunch-talk");
        assert!(!loaded.encrypted);
    }

    #[test]
    fn room_list_orders_by_last_active() {
        let db = open_db_in_memory().unwrap();
        let mut a = make_room("alpha");
        a.last_active = Some(100);
        let mut b = make_room("beta");
        b.last_active = Some(200);
        insert_room(&db, &a).unwrap();
        insert_room(&db, &b).unwrap();
        let rooms = list_rooms(&db).unwrap();
        assert_eq!(rooms[0].name, "beta");
        assert_eq!(rooms[1].name, "alpha");
    }

    #[test]
    fn room_member_upsert() {
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();

        upsert_room_member(
            &db,
            &StoredRoomMember {
                room_id: room.id.clone(),
                peer_id: "peer-x".into(),
                fingerprint: "fp-x".into(),
                last_seen: Some(500),
            },
        )
        .unwrap();
        let members = list_room_members(&db, &room.id).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].fingerprint, "fp-x");
    }

    #[test]
    fn megolm_session_round_trip() {
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();

        let session = StoredMegolmSession {
            room_id: room.id.clone(),
            sender_fingerprint: "fp-sender".into(),
            session_id: "session-1".into(),
            session_data: vec![1, 2, 3, 4],
            is_outbound: true,
            created_at: 100,
        };
        save_megolm_session(&db, &session).unwrap();
        let loaded = load_megolm_sessions_for_room(&db, &room.id).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].session_data, vec![1, 2, 3, 4]);
        assert!(loaded[0].is_outbound);
    }

    #[test]
    fn room_messages_query_returns_chronological() {
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();

        insert_room_message(&db, &room.id, "alice-fp", "in", "hi", 100).unwrap();
        insert_room_message(&db, &room.id, "me-fp", "out", "hello", 101).unwrap();
        insert_room_message(&db, &room.id, "alice-fp", "in", "bye", 102).unwrap();

        let msgs = get_room_messages(&db, &room.id, 10).unwrap();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].body, "hi");
        assert_eq!(msgs[1].body, "hello");
        assert_eq!(msgs[2].body, "bye");
    }
}
