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
    pub created_at: i64,
}

pub fn save_identity(db: &Db, secret: &[u8], created_at: i64) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO identity (id, ed25519_secret, olm_account_data, created_at) VALUES (1, ?1, NULL, ?2)",
        params![secret, created_at],
    )?;
    Ok(())
}

pub fn load_identity(db: &Db) -> Result<Option<StoredIdentity>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare("SELECT ed25519_secret, created_at FROM identity WHERE id = 1")?;
    let mut rows = stmt.query_map([], |row| {
        Ok(StoredIdentity {
            ed25519_secret: row.get(0)?,
            created_at: row.get(1)?,
        })
    })?;
    match rows.next() {
        Some(row) => Ok(Some(row?)),
        None => Ok(None),
    }
}

pub fn get_display_name(db: &Db) -> Result<Option<String>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare("SELECT display_name FROM identity WHERE id = 1")?;
    let mut rows = stmt.query_map([], |row| row.get::<_, Option<String>>(0))?;
    Ok(rows.next().and_then(|r| r.ok()).flatten())
}

pub fn set_display_name(db: &Db, name: Option<&str>) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "UPDATE identity SET display_name = ?1 WHERE id = 1",
        params![name],
    )?;
    Ok(())
}

/// Look up the most-recently-seen display name for a given fingerprint
/// in a room (or anywhere if room_id is empty).
pub fn lookup_display_name(db: &Db, fingerprint: &str) -> Result<Option<String>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT display_name FROM room_members
         WHERE fingerprint = ?1 AND display_name IS NOT NULL
         ORDER BY last_seen DESC LIMIT 1",
    )?;
    let mut rows = stmt.query_map(params![fingerprint], |row| row.get::<_, Option<String>>(0))?;
    Ok(rows.next().and_then(|r| r.ok()).flatten())
}

pub fn set_member_display_name(
    db: &Db,
    room_id: &str,
    fingerprint: &str,
    name: Option<&str>,
) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "UPDATE room_members SET display_name = ?1 WHERE room_id = ?2 AND fingerprint = ?3",
        params![name, room_id, fingerprint],
    )?;
    Ok(())
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

/// Insert a room, or update it in place on id collision. Uses a real
/// UPSERT (not `INSERT OR REPLACE`) so no implicit DELETE fires — the
/// `ON DELETE CASCADE` on room_megolm_sessions / room_members /
/// room_messages / room_attachments must never be triggered here.
/// `created_at`, `creator_fingerprint`, and `encrypted` are immutable
/// once set and are deliberately not updated on conflict.
pub fn insert_room(db: &Db, room: &StoredRoom) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO rooms (id, name, creator_fingerprint, encrypted, passphrase_salt, created_at, last_active)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(id) DO UPDATE SET
            name = excluded.name,
            passphrase_salt = excluded.passphrase_salt,
            last_active = excluded.last_active",
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

pub fn set_room_muted(db: &Db, room_id: &str, muted: bool) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "UPDATE rooms SET muted = ?1 WHERE id = ?2",
        params![muted as i64, room_id],
    )?;
    Ok(())
}

pub fn is_room_muted(db: &Db, room_id: &str) -> Result<bool> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare("SELECT muted FROM rooms WHERE id = ?1")?;
    let mut rows = stmt.query_map(params![room_id], |row| row.get::<_, i64>(0))?;
    Ok(rows.next().map(|r| r.unwrap_or(0) != 0).unwrap_or(false))
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
    pub verified: bool,
    /// Base64-encoded Ed25519 public key. Populated from the member's
    /// `MemberAnnounce.sender_ed25519_pubkey` on first contact; required
    /// to verify `SignedRoomMessage` envelopes from this fingerprint.
    /// `None` for pre-Phase-0 rows or for peers running older builds.
    pub ed25519_pubkey: Option<String>,
}

/// Insert a member, or update in place on (room_id, fingerprint) collision.
/// `verified` is set only on first insert and is intentionally absent from
/// the conflict-update clause: a re-announcement can never silently reset
/// a member's verified flag, and a genuinely new fingerprint is a new
/// (unverified) row. `peer_id` and `ed25519_pubkey` are only overwritten
/// when the incoming value is non-null/non-empty — a re-announce that
/// drops the pubkey field must not erase the one we already learned.
pub fn upsert_room_member(db: &Db, member: &StoredRoomMember) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO room_members (room_id, peer_id, fingerprint, last_seen, verified, ed25519_pubkey)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(room_id, fingerprint) DO UPDATE SET
            last_seen = excluded.last_seen,
            peer_id = CASE
                WHEN excluded.peer_id != '' THEN excluded.peer_id
                ELSE room_members.peer_id
            END,
            ed25519_pubkey = COALESCE(excluded.ed25519_pubkey, room_members.ed25519_pubkey)",
        params![
            member.room_id,
            member.peer_id,
            member.fingerprint,
            member.last_seen,
            member.verified as i64,
            member.ed25519_pubkey,
        ],
    )?;
    Ok(())
}

pub fn list_room_members(db: &Db, room_id: &str) -> Result<Vec<StoredRoomMember>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT room_id, peer_id, fingerprint, last_seen, verified, ed25519_pubkey FROM room_members WHERE room_id = ?1",
    )?;
    let rows = stmt.query_map(params![room_id], |row| {
        Ok(StoredRoomMember {
            room_id: row.get(0)?,
            peer_id: row.get(1)?,
            fingerprint: row.get(2)?,
            last_seen: row.get(3)?,
            verified: row.get::<_, i64>(4).unwrap_or(0) != 0,
            ed25519_pubkey: row.get(5).ok().flatten(),
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

/// Look up the persisted Ed25519 pubkey (base64) for a member by their
/// fingerprint. Used by signed-envelope verification: when a peer's
/// `SignedRoomMessage` arrives, the receiver checks the envelope's
/// pubkey against this stored one (defense in depth, in case the
/// envelope's self-asserted pubkey is fresh / unfamiliar).
///
/// Returns `Ok(None)` if the member exists but pre-dates Phase 0 and
/// hasn't re-announced with their pubkey yet — caller should still
/// accept the envelope's claimed pubkey on TOFU and persist it via
/// `upsert_room_member`.
#[allow(dead_code)]
pub fn get_member_ed25519_pubkey(
    db: &Db,
    room_id: &str,
    fingerprint: &str,
) -> Result<Option<String>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT ed25519_pubkey FROM room_members WHERE room_id = ?1 AND fingerprint = ?2",
    )?;
    let row = stmt
        .query_row(params![room_id, fingerprint], |row| {
            row.get::<_, Option<String>>(0)
        })
        .ok();
    Ok(row.flatten())
}

pub fn remove_room_member(db: &Db, room_id: &str, fingerprint: &str) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM room_members WHERE room_id = ?1 AND fingerprint = ?2",
        params![room_id, fingerprint],
    )?;
    Ok(())
}

/// Mark a member as verified-by-fingerprint. Matches by fingerprint
/// rather than peer_id so a re-join (new peer_id) keeps verification.
pub fn set_member_verified(
    db: &Db,
    room_id: &str,
    fingerprint: &str,
    verified: bool,
) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "UPDATE room_members SET verified = ?1 WHERE room_id = ?2 AND fingerprint = ?3",
        params![verified as i64, room_id, fingerprint],
    )?;
    Ok(())
}

pub fn list_verified_fingerprints(db: &Db, room_id: &str) -> Result<Vec<String>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT DISTINCT fingerprint FROM room_members WHERE room_id = ?1 AND verified = 1",
    )?;
    let rows = stmt.query_map(params![room_id], |row| row.get::<_, String>(0))?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
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

/// LIKE-based message search within a room. Case-insensitive. The query
/// is treated as a literal substring — `%`, `_`, and `\` are escaped so
/// they cannot act as LIKE wildcards.
pub fn search_room_messages(
    db: &Db,
    room_id: &str,
    query: &str,
    limit: i64,
) -> Result<Vec<StoredRoomMessage>> {
    // Escape `\` first so the escapes added for `%` / `_` aren't doubled.
    let escaped = query
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    let pattern = format!("%{}%", escaped);
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, room_id, sender_fingerprint, direction, body, sent_at
         FROM room_messages
         WHERE room_id = ?1 AND body LIKE ?2 ESCAPE '\\' COLLATE NOCASE
         ORDER BY sent_at DESC LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![room_id, pattern, limit], |row| {
        Ok(StoredRoomMessage {
            id: row.get(0)?,
            room_id: row.get(1)?,
            sender_fingerprint: row.get(2)?,
            direction: row.get(3)?,
            body: row.get(4)?,
            sent_at: row.get(5)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
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

// =========================================================================
// Known peers (manually dialed addresses we want to auto-reconnect to)
// =========================================================================

#[derive(Debug, Clone)]
pub struct KnownPeer {
    pub address: String,
    pub label: Option<String>,
    pub last_connected_at: Option<i64>,
    pub last_attempt_at: Option<i64>,
    pub created_at: i64,
    /// Phase A: the peer's Ed25519 fingerprint, learned from Identify
    /// after the first successful connection. `None` for rows from
    /// pre-Phase-A and for peers that haven't been reached yet.
    pub fingerprint: Option<String>,
    /// Phase A: `true` once the user explicitly trusted this peer
    /// ("Trust + Accept" on the inbound-dial modal, or any successful
    /// user-initiated outbound dial). Trusted peers bypass the inbound
    /// prompt on reconnect.
    pub trusted: bool,
}

pub fn upsert_known_peer(db: &Db, peer: &KnownPeer) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO known_peers (address, label, last_connected_at, last_attempt_at, created_at, fingerprint, trusted)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(address) DO UPDATE SET
           label = COALESCE(excluded.label, known_peers.label),
           last_connected_at = COALESCE(excluded.last_connected_at, known_peers.last_connected_at),
           last_attempt_at = COALESCE(excluded.last_attempt_at, known_peers.last_attempt_at),
           fingerprint = COALESCE(excluded.fingerprint, known_peers.fingerprint),
           -- trusted is sticky-once-true: a fresh upsert with trusted=false
           -- (the default on auto-reconnect) must not demote a previously
           -- trusted row.
           trusted = CASE
             WHEN excluded.trusted = 1 THEN 1
             ELSE known_peers.trusted
           END",
        params![
            peer.address,
            peer.label,
            peer.last_connected_at,
            peer.last_attempt_at,
            peer.created_at,
            peer.fingerprint,
            peer.trusted as i64,
        ],
    )?;
    Ok(())
}

pub fn list_known_peers(db: &Db) -> Result<Vec<KnownPeer>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT address, label, last_connected_at, last_attempt_at, created_at, fingerprint, trusted
         FROM known_peers ORDER BY COALESCE(last_connected_at, 0) DESC, created_at DESC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(KnownPeer {
            address: row.get(0)?,
            label: row.get(1)?,
            last_connected_at: row.get(2)?,
            last_attempt_at: row.get(3)?,
            created_at: row.get(4)?,
            fingerprint: row.get(5).ok().flatten(),
            trusted: row.get::<_, i64>(6).unwrap_or(0) != 0,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub fn forget_known_peer(db: &Db, address: &str) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute("DELETE FROM known_peers WHERE address = ?1", params![address])?;
    Ok(())
}

/// Phase A: look up whether we've already trusted a peer by fingerprint.
/// Used by the network task when an inbound connection's Identify lands —
/// trusted fingerprints bypass the user-prompt modal.
pub fn is_fingerprint_trusted(db: &Db, fingerprint: &str) -> Result<bool> {
    let conn = db.lock().unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM known_peers WHERE fingerprint = ?1 AND trusted = 1",
            params![fingerprint],
            |r| r.get(0),
        )
        .unwrap_or(0);
    Ok(count > 0)
}

/// Phase A: persistent blocklist. A fingerprint here means we explicitly
/// rejected an inbound dial from this peer — every subsequent connection
/// attempt is auto-disconnected without raising the modal.
pub fn block_peer(db: &Db, fingerprint: &str, now: i64) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO blocked_peers (fingerprint, blocked_at) VALUES (?1, ?2)
         ON CONFLICT(fingerprint) DO UPDATE SET blocked_at = excluded.blocked_at",
        params![fingerprint, now],
    )?;
    Ok(())
}

pub fn is_peer_blocked(db: &Db, fingerprint: &str) -> Result<bool> {
    let conn = db.lock().unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM blocked_peers WHERE fingerprint = ?1",
            params![fingerprint],
            |r| r.get(0),
        )
        .unwrap_or(0);
    Ok(count > 0)
}

#[allow(dead_code)]
pub fn unblock_peer(db: &Db, fingerprint: &str) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM blocked_peers WHERE fingerprint = ?1",
        params![fingerprint],
    )?;
    Ok(())
}

// =========================================================================
// Room attachments
// =========================================================================

/// Lifecycle of a file transfer card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentStatus {
    Offered,
    Downloading,
    Ready,
    Saved,
    Failed,
    Cancelled,
}

impl AttachmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Downloading => "downloading",
            Self::Ready => "ready",
            Self::Saved => "saved",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "offered" => Self::Offered,
            "downloading" => Self::Downloading,
            "ready" => Self::Ready,
            "saved" => Self::Saved,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct StoredAttachment {
    pub id: i64,
    pub room_id: String,
    pub message_id: Option<i64>,
    pub sender_fingerprint: String,
    pub file_id: String,
    pub name: String,
    pub mime: Option<String>,
    pub size_bytes: i64,
    pub status: AttachmentStatus,
    pub cache_path: Option<String>,
    pub saved_path: Option<String>,
    pub error: Option<String>,
    pub encrypted: bool,
    pub wrapped_key: Option<String>,
    pub nonce: Option<String>,
    pub megolm_session_id: Option<String>,
    /// SHA-256 of the plaintext (hex), for encrypted attachments. Bound
    /// as AEAD associated data so the wrapped key + nonce + ciphertext
    /// can't be replayed against different content.
    pub content_hash: Option<String>,
    pub created_at: i64,
}

/// Insert (or update on file_id collision within the same room).
pub fn upsert_attachment(db: &Db, a: &StoredAttachment) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO room_attachments
            (room_id, message_id, sender_fingerprint, file_id, name, mime,
             size_bytes, status, cache_path, saved_path, error,
             encrypted, wrapped_key, nonce, megolm_session_id, created_at,
             content_hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
         ON CONFLICT(room_id, file_id) DO UPDATE SET
            name = excluded.name,
            mime = excluded.mime,
            size_bytes = excluded.size_bytes,
            -- Don't downgrade a more advanced status.
            status = CASE
                WHEN room_attachments.status IN ('saved','ready')
                     AND excluded.status IN ('offered','downloading')
                THEN room_attachments.status
                ELSE excluded.status
            END,
            cache_path = COALESCE(excluded.cache_path, room_attachments.cache_path),
            saved_path = COALESCE(excluded.saved_path, room_attachments.saved_path),
            error      = excluded.error,
            wrapped_key = COALESCE(excluded.wrapped_key, room_attachments.wrapped_key),
            nonce       = COALESCE(excluded.nonce, room_attachments.nonce),
            megolm_session_id = COALESCE(excluded.megolm_session_id, room_attachments.megolm_session_id),
            content_hash = COALESCE(excluded.content_hash, room_attachments.content_hash)",
        params![
            a.room_id,
            a.message_id,
            a.sender_fingerprint,
            a.file_id,
            a.name,
            a.mime,
            a.size_bytes,
            a.status.as_str(),
            a.cache_path,
            a.saved_path,
            a.error,
            a.encrypted as i64,
            a.wrapped_key,
            a.nonce,
            a.megolm_session_id,
            a.created_at,
            a.content_hash,
        ],
    )?;
    Ok(())
}

fn row_to_attachment(row: &rusqlite::Row) -> rusqlite::Result<StoredAttachment> {
    let status_s: String = row.get(8)?;
    let status = AttachmentStatus::from_str(&status_s).unwrap_or(AttachmentStatus::Failed);
    Ok(StoredAttachment {
        id: row.get(0)?,
        room_id: row.get(1)?,
        message_id: row.get(2)?,
        sender_fingerprint: row.get(3)?,
        file_id: row.get(4)?,
        name: row.get(5)?,
        mime: row.get(6)?,
        size_bytes: row.get(7)?,
        status,
        cache_path: row.get(9)?,
        saved_path: row.get(10)?,
        error: row.get(11)?,
        encrypted: row.get::<_, i64>(12)? != 0,
        wrapped_key: row.get(13)?,
        nonce: row.get(14)?,
        megolm_session_id: row.get(15)?,
        created_at: row.get(16)?,
        content_hash: row.get(17)?,
    })
}

pub fn get_attachment(db: &Db, room_id: &str, file_id: &str) -> Result<Option<StoredAttachment>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, room_id, message_id, sender_fingerprint, file_id, name, mime,
                size_bytes, status, cache_path, saved_path, error,
                encrypted, wrapped_key, nonce, megolm_session_id, created_at,
                content_hash
         FROM room_attachments WHERE room_id = ?1 AND file_id = ?2",
    )?;
    let mut rows = stmt.query_map(params![room_id, file_id], row_to_attachment)?;
    match rows.next() {
        Some(r) => Ok(Some(r?)),
        None => Ok(None),
    }
}

pub fn list_room_attachments(db: &Db, room_id: &str) -> Result<Vec<StoredAttachment>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, room_id, message_id, sender_fingerprint, file_id, name, mime,
                size_bytes, status, cache_path, saved_path, error,
                encrypted, wrapped_key, nonce, megolm_session_id, created_at,
                content_hash
         FROM room_attachments WHERE room_id = ?1 ORDER BY created_at ASC",
    )?;
    let rows = stmt.query_map(params![room_id], row_to_attachment)?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub fn update_attachment_status(
    db: &Db,
    room_id: &str,
    file_id: &str,
    status: AttachmentStatus,
    error: Option<&str>,
) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "UPDATE room_attachments SET status = ?1, error = ?2
         WHERE room_id = ?3 AND file_id = ?4",
        params![status.as_str(), error, room_id, file_id],
    )?;
    Ok(())
}

pub fn update_attachment_paths(
    db: &Db,
    room_id: &str,
    file_id: &str,
    cache_path: Option<&str>,
    saved_path: Option<&str>,
) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "UPDATE room_attachments
         SET cache_path = COALESCE(?1, cache_path),
             saved_path = COALESCE(?2, saved_path)
         WHERE room_id = ?3 AND file_id = ?4",
        params![cache_path, saved_path, room_id, file_id],
    )?;
    Ok(())
}

pub fn delete_attachment(db: &Db, room_id: &str, file_id: &str) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM room_attachments WHERE room_id = ?1 AND file_id = ?2",
        params![room_id, file_id],
    )?;
    Ok(())
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
    fn identity_round_trip() {
        let db = open_db_in_memory().unwrap();
        save_identity(&db, b"secret-bytes-32-chars-long-xxxxx", 1000).unwrap();
        let loaded = load_identity(&db).unwrap().unwrap();
        assert_eq!(loaded.ed25519_secret, b"secret-bytes-32-chars-long-xxxxx");
        assert_eq!(loaded.created_at, 1000);
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
                verified: false,
                ed25519_pubkey: None,
            },
        )
        .unwrap();
        let members = list_room_members(&db, &room.id).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].fingerprint, "fp-x");
        assert!(!members[0].verified);
    }

    #[test]
    fn set_and_query_verified() {
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();
        upsert_room_member(
            &db,
            &StoredRoomMember {
                room_id: room.id.clone(),
                peer_id: "p1".into(),
                fingerprint: "fp-1".into(),
                last_seen: None,
                verified: false,
                ed25519_pubkey: None,
            },
        )
        .unwrap();
        set_member_verified(&db, &room.id, "fp-1", true).unwrap();
        let verified = list_verified_fingerprints(&db, &room.id).unwrap();
        assert_eq!(verified, vec!["fp-1".to_string()]);
        let m = list_room_members(&db, &room.id).unwrap();
        assert!(m[0].verified);
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

    fn make_attachment(room_id: &str, file_id: &str, name: &str) -> StoredAttachment {
        StoredAttachment {
            id: 0,
            room_id: room_id.into(),
            message_id: None,
            sender_fingerprint: "sender-fp".into(),
            file_id: file_id.into(),
            name: name.into(),
            mime: Some("image/png".into()),
            size_bytes: 1234,
            status: AttachmentStatus::Offered,
            cache_path: None,
            saved_path: None,
            error: None,
            encrypted: false,
            wrapped_key: None,
            nonce: None,
            megolm_session_id: None,
            content_hash: None,
            created_at: 100,
        }
    }

    #[test]
    fn attachment_upsert_and_get() {
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();
        let a = make_attachment(&room.id, "file-abc", "photo.png");
        upsert_attachment(&db, &a).unwrap();

        let loaded = get_attachment(&db, &room.id, "file-abc").unwrap().unwrap();
        assert_eq!(loaded.name, "photo.png");
        assert_eq!(loaded.status, AttachmentStatus::Offered);
        assert_eq!(loaded.size_bytes, 1234);
    }

    #[test]
    fn attachment_status_transitions() {
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();
        let a = make_attachment(&room.id, "fid", "f.bin");
        upsert_attachment(&db, &a).unwrap();

        update_attachment_status(&db, &room.id, "fid", AttachmentStatus::Downloading, None)
            .unwrap();
        assert_eq!(
            get_attachment(&db, &room.id, "fid")
                .unwrap()
                .unwrap()
                .status,
            AttachmentStatus::Downloading
        );

        update_attachment_status(&db, &room.id, "fid", AttachmentStatus::Ready, None).unwrap();
        update_attachment_paths(
            &db,
            &room.id,
            "fid",
            Some("/cache/fid"),
            Some("/Downloads/f.bin"),
        )
        .unwrap();
        let loaded = get_attachment(&db, &room.id, "fid").unwrap().unwrap();
        assert_eq!(loaded.status, AttachmentStatus::Ready);
        assert_eq!(loaded.cache_path.as_deref(), Some("/cache/fid"));
        assert_eq!(loaded.saved_path.as_deref(), Some("/Downloads/f.bin"));
    }

    #[test]
    fn upsert_does_not_downgrade_status() {
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();
        let mut a = make_attachment(&room.id, "fid", "f.bin");
        a.status = AttachmentStatus::Saved;
        upsert_attachment(&db, &a).unwrap();

        a.status = AttachmentStatus::Offered;
        upsert_attachment(&db, &a).unwrap();
        assert_eq!(
            get_attachment(&db, &room.id, "fid")
                .unwrap()
                .unwrap()
                .status,
            AttachmentStatus::Saved
        );
    }

    #[test]
    fn list_attachments_for_room() {
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();
        upsert_attachment(&db, &make_attachment(&room.id, "fid-a", "a.bin")).unwrap();
        upsert_attachment(&db, &make_attachment(&room.id, "fid-b", "b.bin")).unwrap();
        let list = list_room_attachments(&db, &room.id).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].file_id, "fid-a");
        assert_eq!(list[1].file_id, "fid-b");
    }

    #[test]
    fn attachment_status_string_round_trip() {
        for &s in &[
            AttachmentStatus::Offered,
            AttachmentStatus::Downloading,
            AttachmentStatus::Ready,
            AttachmentStatus::Saved,
            AttachmentStatus::Failed,
            AttachmentStatus::Cancelled,
        ] {
            assert_eq!(AttachmentStatus::from_str(s.as_str()), Some(s));
        }
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

    #[test]
    fn search_escapes_like_wildcards() {
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();
        insert_room_message(&db, &room.id, "fp", "in", "literal percent: 50%", 100).unwrap();
        insert_room_message(&db, &room.id, "fp", "in", "no special chars here", 101).unwrap();

        // "%" must match a literal "%", not act as a wildcard-matches-all.
        let pct = search_room_messages(&db, &room.id, "%", 10).unwrap();
        assert_eq!(pct.len(), 1);
        assert!(pct[0].body.contains("50%"));

        // "_" likewise must not match an arbitrary single character.
        let underscore = search_room_messages(&db, &room.id, "_", 10).unwrap();
        assert!(underscore.is_empty());
    }
}
