use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::error::Result;
use crate::storage::Db;

/// huddle 1.3.4: a `COUNT(*)` security check must never silently treat a DB
/// error (corruption, IO fault, locked page) as "0 rows", which several checks
/// did via `.unwrap_or(0)` — making `is_member_banned` / `is_peer_blocked`
/// fail *open* (a banned/blocked peer reported as allowed). This applies a
/// fail-SECURE default instead and logs rather than swallowing the error.
///
/// `fail_secure_count` is the count to assume on error: `1` for a *deny* check
/// (banned/blocked → treat as restricted), `0` for a *grant* check
/// (contact/verified/trusted → treat as not-privileged).
fn security_count(res: rusqlite::Result<i64>, check: &str, fail_secure_count: i64) -> i64 {
    res.unwrap_or_else(|e| {
        warn!(error = %e, check, "security-check query failed; applying fail-secure default");
        fail_secure_count
    })
}

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
/// across all rooms. huddle 0.7.11: pre-0.7.11 the doc comment claimed
/// per-room scoping ("in a room (or anywhere if room_id is empty)"),
/// but the function signature takes no room_id. The implementation has
/// always been room-agnostic — pick the freshest `last_seen` regardless
/// of which room set the display name. Doc updated to match reality.
/// Callers that need per-room scoping should use the room_members table
/// directly with an explicit `room_id` filter.
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

/// huddle 0.7: explicit room kind. `Direct` = 1-1 DM (encrypted, no name,
/// no member-list chrome, no kick/grant). `Group` = N-way room (full
/// moderation, named, optionally encrypted). Persisted on `rooms.kind` and
/// echoed on `RoomAnnouncement.kind` (with `#[serde(default)]` so pre-0.7
/// peers' announcements deserialize as `Group`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoomKind {
    Direct,
    #[default]
    Group,
}

impl RoomKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            RoomKind::Direct => "direct",
            RoomKind::Group => "group",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "direct" => RoomKind::Direct,
            _ => RoomKind::Group,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StoredRoom {
    pub id: String,
    pub name: String,
    pub creator_fingerprint: String,
    pub encrypted: bool,
    pub passphrase_salt: Option<Vec<u8>>,
    pub created_at: i64,
    pub last_active: Option<i64>,
    /// huddle 0.7: explicit room kind. Defaults to `Group` for back-fill
    /// safety on pre-0.7 databases (the column has `DEFAULT 'group'`).
    pub kind: RoomKind,
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
        "INSERT INTO rooms (id, name, creator_fingerprint, encrypted, passphrase_salt, created_at, last_active, kind)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
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
            room.kind.as_str(),
        ],
    )?;
    Ok(())
}

pub fn get_room(db: &Db, room_id: &str) -> Result<Option<StoredRoom>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, name, creator_fingerprint, encrypted, passphrase_salt, created_at, last_active, kind
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
            kind: RoomKind::from_str(&row.get::<_, String>(7).unwrap_or_else(|_| "group".into())),
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
        "SELECT id, name, creator_fingerprint, encrypted, passphrase_salt, created_at, last_active, kind
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
            kind: RoomKind::from_str(&row.get::<_, String>(7).unwrap_or_else(|_| "group".into())),
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

/// huddle 0.7: find an existing `RoomKind::Direct` room between `our_fp`
/// and `partner_fp`. Used by `AppHandle::start_direct` to short-circuit
/// when the DM already exists locally, so the call is idempotent across
/// reopens.
pub fn find_dm_with(db: &Db, our_fp: &str, partner_fp: &str) -> Result<Option<StoredRoom>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT r.id, r.name, r.creator_fingerprint, r.encrypted, r.passphrase_salt,
                r.created_at, r.last_active, r.kind
         FROM rooms r
         WHERE r.kind = 'direct'
           AND EXISTS (SELECT 1 FROM room_members m
                       WHERE m.room_id = r.id AND m.fingerprint = ?1)
           AND EXISTS (SELECT 1 FROM room_members m
                       WHERE m.room_id = r.id AND m.fingerprint = ?2)
         LIMIT 1",
    )?;
    let mut rows = stmt.query_map(params![our_fp, partner_fp], |row| {
        Ok(StoredRoom {
            id: row.get(0)?,
            name: row.get(1)?,
            creator_fingerprint: row.get(2)?,
            encrypted: row.get::<_, i64>(3)? != 0,
            passphrase_salt: row.get(4)?,
            created_at: row.get(5)?,
            last_active: row.get(6)?,
            kind: RoomKind::from_str(&row.get::<_, String>(7).unwrap_or_else(|_| "group".into())),
        })
    })?;
    match rows.next() {
        Some(row) => Ok(Some(row?)),
        None => Ok(None),
    }
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
    /// Phase B: `"owner"` or `"member"`. Set on first insert
    /// (`start_room` sets the creator to `"owner"`); never overwritten
    /// by re-announcements so OwnerGrant is the only way to promote
    /// after the fact.
    pub role: String,
    /// huddle 1.3.1: base64 ML-KEM-768 encapsulation key, learned from a
    /// signed `MemberAnnounce.sender_mlkem_pubkey` (Direct rooms only). The
    /// durable post-quantum-capability pin — see `lookup_peer_mlkem_pubkey`.
    /// `None` for pre-1.3 peers and group members.
    pub mlkem_pubkey: Option<String>,
}

/// Insert a member, or update in place on (room_id, fingerprint) collision.
/// `verified` and `role` are set only on first insert and intentionally
/// absent from the conflict-update clause: a re-announcement can never
/// silently reset a member's verified flag or demote an owner to member.
/// A genuinely new fingerprint is a new (unverified, member) row.
/// `peer_id` and `ed25519_pubkey` are only overwritten when the incoming
/// value is non-null/non-empty — a re-announce that drops the pubkey
/// field must not erase the one we already learned.
pub fn upsert_room_member(db: &Db, member: &StoredRoomMember) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO room_members (room_id, peer_id, fingerprint, last_seen, verified, ed25519_pubkey, role, mlkem_pubkey)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(room_id, fingerprint) DO UPDATE SET
            last_seen = excluded.last_seen,
            peer_id = CASE
                WHEN excluded.peer_id != '' THEN excluded.peer_id
                ELSE room_members.peer_id
            END,
            ed25519_pubkey = COALESCE(excluded.ed25519_pubkey, room_members.ed25519_pubkey),
            mlkem_pubkey = COALESCE(excluded.mlkem_pubkey, room_members.mlkem_pubkey)",
        params![
            member.room_id,
            member.peer_id,
            member.fingerprint,
            member.last_seen,
            member.verified as i64,
            member.ed25519_pubkey,
            member.role,
            member.mlkem_pubkey,
        ],
    )?;
    Ok(())
}

/// huddle 0.7.1: find an Ed25519 pubkey for a fingerprint across all
/// rooms we've ever seen the peer in. A peer's identity key is global
/// (not per-room), so any non-null row works. Used by DM E2E to derive
/// the ECDH room key without re-asking the network.
pub fn lookup_peer_ed25519_pubkey(db: &Db, fingerprint: &str) -> Result<Option<String>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT ed25519_pubkey FROM room_members
         WHERE fingerprint = ?1 AND ed25519_pubkey IS NOT NULL
         LIMIT 1",
    )?;
    let mut rows = stmt.query_map(params![fingerprint], |row| row.get::<_, Option<String>>(0))?;
    Ok(rows.next().and_then(|r| r.ok()).flatten())
}

/// huddle 1.3.1: find an ML-KEM-768 encapsulation key for a fingerprint
/// across all rooms. Mirrors `lookup_peer_ed25519_pubkey`: a peer's ML-KEM
/// key is global (deterministically derived from their identity seed), so any
/// non-null row works. A `Some` result means we have durably observed this
/// peer's post-quantum capability — the DM key agreement then **refuses the
/// classical fallback** for them, defeating a relay replaying a captured
/// pre-1.3 (classical-only) announce to force a quantum-unsafe downgrade.
pub fn lookup_peer_mlkem_pubkey(db: &Db, fingerprint: &str) -> Result<Option<String>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT mlkem_pubkey FROM room_members
         WHERE fingerprint = ?1 AND mlkem_pubkey IS NOT NULL
         LIMIT 1",
    )?;
    let mut rows = stmt.query_map(params![fingerprint], |row| row.get::<_, Option<String>>(0))?;
    Ok(rows.next().and_then(|r| r.ok()).flatten())
}

pub fn list_room_members(db: &Db, room_id: &str) -> Result<Vec<StoredRoomMember>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT room_id, peer_id, fingerprint, last_seen, verified, ed25519_pubkey, role, mlkem_pubkey FROM room_members WHERE room_id = ?1",
    )?;
    let rows = stmt.query_map(params![room_id], |row| {
        Ok(StoredRoomMember {
            room_id: row.get(0)?,
            peer_id: row.get(1)?,
            fingerprint: row.get(2)?,
            last_seen: row.get(3)?,
            verified: row.get::<_, i64>(4).unwrap_or(0) != 0,
            ed25519_pubkey: row.get(5).ok().flatten(),
            role: row.get(6).unwrap_or_else(|_| "member".to_string()),
            mlkem_pubkey: row.get(7).ok().flatten(),
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

/// Phase B: promote / demote a member's role. Used by the `OwnerGrant`
/// handler. Callers must verify the grant signature came from an owner
/// before invoking — the repo function trusts its inputs.
pub fn set_member_role(db: &Db, room_id: &str, fingerprint: &str, role: &str) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "UPDATE room_members SET role = ?1 WHERE room_id = ?2 AND fingerprint = ?3",
        params![role, room_id, fingerprint],
    )?;
    Ok(())
}

/// Phase B: list owners of a room — fingerprints with role = 'owner'.
/// Used for `RoomAnnouncement.owner_fingerprints` and for verifying
/// that an incoming `OwnerGrant` / `BanMember` came from a current owner.
pub fn list_room_owners(db: &Db, room_id: &str) -> Result<Vec<String>> {
    let conn = db.lock().unwrap();
    let mut stmt =
        conn.prepare("SELECT fingerprint FROM room_members WHERE room_id = ?1 AND role = 'owner'")?;
    let rows = stmt.query_map(params![room_id], |row| row.get::<_, String>(0))?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

/// Phase B: persistent room-level ban. Banned members are ignored on
/// receive (MemberAnnounce dropped, messages skipped) and excluded from
/// future session-key wraps. Idempotent.
pub fn add_room_ban(
    db: &Db,
    room_id: &str,
    banned_fingerprint: &str,
    banned_by_fingerprint: &str,
    signature_b64: &str,
    banned_at: i64,
) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO room_bans (room_id, banned_fingerprint, banned_by_fingerprint, signature_b64, banned_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(room_id, banned_fingerprint) DO UPDATE SET
            banned_by_fingerprint = excluded.banned_by_fingerprint,
            signature_b64 = excluded.signature_b64,
            banned_at = excluded.banned_at",
        params![
            room_id,
            banned_fingerprint,
            banned_by_fingerprint,
            signature_b64,
            banned_at,
        ],
    )?;
    Ok(())
}

/// huddle 2.0.2 (audit M-10): demote a member out of the `owner` role. Called
/// on ban so a banned co-owner can't retain administrative power and is dropped
/// from future `owner_fingerprints` announcements. Idempotent; no-op if they
/// weren't an owner or aren't a member.
pub fn revoke_owner_role(db: &Db, room_id: &str, fingerprint: &str) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "UPDATE room_members SET role = 'member' WHERE room_id = ?1 AND fingerprint = ?2 AND role = 'owner'",
        params![room_id, fingerprint],
    )?;
    Ok(())
}

pub fn is_member_banned(db: &Db, room_id: &str, fingerprint: &str) -> Result<bool> {
    let conn = db.lock().unwrap();
    let count: i64 = security_count(
        conn.query_row(
            "SELECT COUNT(*) FROM room_bans WHERE room_id = ?1 AND banned_fingerprint = ?2",
            params![room_id, fingerprint],
            |r| r.get(0),
        ),
        "is_member_banned",
        1, // deny-check: assume banned if the DB can't confirm otherwise
    );
    Ok(count > 0)
}

/// List fingerprints currently banned from a room, newest first. Used
/// by the `^B` in-room bans view (owners-only) so they can audit who's
/// been kicked.
pub fn list_room_bans(db: &Db, room_id: &str) -> Result<Vec<String>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT banned_fingerprint FROM room_bans WHERE room_id = ?1 ORDER BY banned_at DESC",
    )?;
    let rows = stmt.query_map(params![room_id], |row| row.get::<_, String>(0))?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

/// Look up the persisted Ed25519 pubkey (base64) for a member by their
/// fingerprint. Defense-in-depth check during `SignedRoomMessage`
/// verification: when a signed envelope arrives, we re-derive the
/// fingerprint from the envelope's claimed pubkey AND, if we already
/// know a pubkey for this fingerprint, refuse to accept a different
/// one. Mismatch ⇒ identity drift / TOFU violation ⇒ drop the message.
///
/// Returns `Ok(None)` if the member exists but pre-dates Phase 0 and
/// hasn't re-announced with their pubkey yet — caller falls back to
/// TOFU: accept the envelope's claimed pubkey on first contact and
/// persist it via `upsert_room_member`.
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

/// huddle 1.3.1: delete our persisted **outbound** Megolm session row(s) for a
/// room. Used by `RoomCrypto::rotate_outbound` when a DM is upgraded
/// classical→hybrid: the old outbound session key was shared wrapped under the
/// quantum-breakable classical key, so it must be retired. Deleting the row
/// (rather than leaving it) also prevents `RoomCrypto::load` from
/// nondeterministically reloading the retired session after a restart, since
/// the new session has a different `session_id` (the PK includes it).
pub fn delete_outbound_megolm_sessions(
    db: &Db,
    room_id: &str,
    our_fingerprint: &str,
) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM room_megolm_sessions
         WHERE room_id = ?1 AND sender_fingerprint = ?2 AND is_outbound = 1",
        params![room_id, our_fingerprint],
    )?;
    Ok(())
}

pub fn load_megolm_sessions_for_room(db: &Db, room_id: &str) -> Result<Vec<StoredMegolmSession>> {
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
// Megolm rotation state (huddle 2.0.0, F4)
//
// The durable copy of the outbound epoch bookkeeping `RoomCrypto` keeps in
// memory — `messages_since_rotation` (encrypt calls on the current outbound
// session) and `last_rotation_at` (unix seconds the epoch began). These drive
// the scheduled forward-only `RotationPolicy`; persisting them is what lets the
// rotation schedule continue across a restart instead of resetting to 0/now.
// The session *ratchet* itself lives in `room_megolm_sessions`; this is a
// separate, advisory table that never affects encrypt/decrypt/replay.
// =========================================================================

/// huddle 2.0.0 (F4): persist a room's outbound Megolm epoch bookkeeping —
/// the message counter and epoch start time — keyed by (room_id, fingerprint)
/// so there is one row per room per local identity. Upsert (INSERT … ON
/// CONFLICT) so repeated saves on the hot send path stay O(1).
/// `messages_since_rotation` is a Megolm u32 stored as INTEGER.
pub fn set_megolm_rotation_state(
    db: &Db,
    room_id: &str,
    fingerprint: &str,
    messages_since_rotation: u32,
    last_rotation_at: i64,
) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO room_megolm_rotation_state
            (room_id, fingerprint, messages_since_rotation, last_rotation_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(room_id, fingerprint) DO UPDATE SET
            messages_since_rotation = excluded.messages_since_rotation,
            last_rotation_at = excluded.last_rotation_at",
        params![
            room_id,
            fingerprint,
            messages_since_rotation as i64,
            last_rotation_at
        ],
    )?;
    Ok(())
}

/// huddle 2.0.0 (F4): read back the persisted `(messages_since_rotation,
/// last_rotation_at)` for a room's outbound session, or `None` when nothing has
/// been persisted yet (a never-sent room — the caller keeps `RoomCrypto`'s
/// fresh 0/now baseline). The app calls this right after `RoomCrypto::load` and
/// feeds the result to `restore_rotation_state` so the rotation schedule
/// continues across restarts rather than counting from zero again.
pub fn get_megolm_rotation_state(
    db: &Db,
    room_id: &str,
    fingerprint: &str,
) -> Result<Option<(u32, i64)>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT messages_since_rotation, last_rotation_at
         FROM room_megolm_rotation_state WHERE room_id = ?1 AND fingerprint = ?2",
    )?;
    let row = stmt
        .query_row(params![room_id, fingerprint], |r| {
            Ok((r.get::<_, i64>(0)? as u32, r.get::<_, i64>(1)?))
        })
        .ok();
    Ok(row)
}

// =========================================================================
// Content-layer replay protection (huddle 2.0.0, F2)
//
// A durable seen-set of (room_id, sender_fingerprint, session_id,
// message_index) for *content* (`RoomMessage::Encrypted`) messages. Megolm's
// message_index is a monotonic ratchet position whose KDF output never repeats
// for a given (session, index) pair, so the tuple uniquely names one ciphertext
// for the life of the session: once recorded, any wire-level replay of that
// ciphertext decrypts to the same plaintext but is dropped at the app layer
// (see `app::mod::handle_room_message`'s `Encrypted` arm). Control messages are
// deliberately NOT recorded here, so legitimate recurring re-broadcasts
// (rotation re-announces, key-request heals, …) keep working.
//
// The table is bounded by a time-based GC sweep (`gc_content_replay_seen`, run
// once at startup like the pending-request sweeps above) — see the schema.rs
// migration and idx_content_replay_by_time.
// =========================================================================

/// Retention window for the content-replay seen-set, in seconds (90 days).
/// [`gc_content_replay_seen`] drops rows whose `created_at` is older than this.
/// Generous on purpose: a replay that arrives months late is still rejected,
/// and at a busy 100 msg/day/room the table stays in the low tens of thousands
/// of rows — trivially indexed. Entries from rotated-out sessions (a
/// `RotateRoomKey` mints a new session_id, making the old indices irrelevant)
/// also age out here rather than needing their own cleanup path.
pub const CONTENT_REPLAY_RETENTION_SECS: i64 = 90 * 24 * 60 * 60;

/// True when we've already processed the content message identified by
/// (room_id, sender_fingerprint, session_id, message_index) — i.e. this is a
/// replay and the caller should drop it silently.
pub fn check_content_replay_seen(
    db: &Db,
    room_id: &str,
    sender_fingerprint: &str,
    session_id: &str,
    message_index: u32,
) -> Result<bool> {
    let conn = db.lock().unwrap();
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM content_replay_seen
         WHERE room_id = ?1 AND sender_fingerprint = ?2
           AND session_id = ?3 AND message_index = ?4",
        params![
            room_id,
            sender_fingerprint,
            session_id,
            message_index as i64
        ],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// Record that we've processed a content message. Idempotent: a duplicate
/// insert is silently ignored via the composite PRIMARY KEY (`INSERT OR
/// IGNORE`), so a race between the check and the insert can neither error nor
/// double-count. `message_index` is a Megolm u32; SQLite stores it as INTEGER.
pub fn record_content_seen(
    db: &Db,
    room_id: &str,
    sender_fingerprint: &str,
    session_id: &str,
    message_index: u32,
    created_at: i64,
) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT OR IGNORE INTO content_replay_seen
            (room_id, sender_fingerprint, session_id, message_index, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            room_id,
            sender_fingerprint,
            session_id,
            message_index as i64,
            created_at
        ],
    )?;
    Ok(())
}

/// Drop seen-set rows older than `cutoff_ts` (`created_at < cutoff_ts`). Called
/// once at startup with `now - CONTENT_REPLAY_RETENTION_SECS`. Returns the
/// number of rows pruned. Backed by idx_content_replay_by_time so the sweep is
/// cheap even on a large table.
pub fn gc_content_replay_seen(db: &Db, cutoff_ts: i64) -> Result<usize> {
    let conn = db.lock().unwrap();
    let removed = conn.execute(
        "DELETE FROM content_replay_seen WHERE created_at < ?1",
        params![cutoff_ts],
    )?;
    Ok(removed)
}

/// Min/max recorded `message_index` for a (room, sender, session), or `None`
/// when that session has no rows yet. Exposed for advanced GC / diagnostics
/// (e.g. index-window pruning of a very long-lived session); not used on the
/// hot receive path.
pub fn content_seen_index_bounds(
    db: &Db,
    room_id: &str,
    sender_fingerprint: &str,
    session_id: &str,
) -> Result<Option<(u32, u32)>> {
    let conn = db.lock().unwrap();
    // COUNT/MIN/MAX always return one row; MIN/MAX are NULL on an empty set.
    let bounds = conn.query_row(
        "SELECT MIN(message_index), MAX(message_index) FROM content_replay_seen
         WHERE room_id = ?1 AND sender_fingerprint = ?2 AND session_id = ?3",
        params![room_id, sender_fingerprint, session_id],
        |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?)),
    )?;
    match bounds {
        (Some(min), Some(max)) => Ok(Some((min as u32, max as u32))),
        _ => Ok(None),
    }
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
    /// huddle 2.0.0 (F10): the sender-minted stable id (UUID v4) for this
    /// message, echoed on the wire so every peer names the same logical
    /// message. `None` for pre-2.0 messages — they carry no target handle, so
    /// reactions / replies / edits / deletes can't address them.
    pub client_msg_id: Option<String>,
    /// huddle 2.0.0 (F10): the `client_msg_id` this message replies to, or
    /// `None`. The reply target may itself be a pre-2.0 message (no id) or a
    /// since-deleted one; the UI degrades to a plain message in that case.
    pub reply_to: Option<String>,
    /// huddle 2.0.0 (F10): wall-clock ms of the most recent applied edit, or
    /// `None` if never edited. Last-write-wins is gated on this in
    /// `apply_message_edit`. A non-`None` value drives the `[edited]` marker.
    pub edited_at: Option<i64>,
    /// huddle 2.0.0 (F10): tombstone timestamp. When `Some`, the message was
    /// deleted: its `body` has been blanked and the UI renders `[deleted]`.
    pub deleted_at: Option<i64>,
}

/// Shared row→`StoredRoomMessage` mapper. Every `room_messages` read path
/// (history, LIKE search, FTS search, by-client-id lookup) selects the same
/// column list in this exact order, so they stay in lock-step as the table
/// gains columns. Column order:
/// `id, room_id, sender_fingerprint, direction, body, sent_at,
///  client_msg_id, reply_to, edited_at, deleted_at`.
fn row_to_room_message(row: &rusqlite::Row) -> rusqlite::Result<StoredRoomMessage> {
    Ok(StoredRoomMessage {
        id: row.get(0)?,
        room_id: row.get(1)?,
        sender_fingerprint: row.get(2)?,
        direction: row.get(3)?,
        body: row.get(4)?,
        sent_at: row.get(5)?,
        client_msg_id: row.get(6)?,
        reply_to: row.get(7)?,
        edited_at: row.get(8)?,
        deleted_at: row.get(9)?,
    })
}

/// Insert a room message. huddle 2.0.0 (F10): `client_msg_id` (the sender's
/// stable UUID v4) and `reply_to` (the id of the message being replied to) are
/// both set at insert time; pass `None`/`None` for plain non-reply messages and
/// for inbound pre-2.0 messages that carry no id.
///
/// huddle 2.0.0 (F2 dedup): the write is `INSERT OR IGNORE`, so two concurrent
/// identical deliveries (same room + sender + client_msg_id) can never create
/// duplicate rows — the partial UNIQUE index `idx_room_messages_dedup` turns the
/// second write into a no-op. `INSERT OR IGNORE` only suppresses *that*
/// constraint; messages with a NULL `client_msg_id` (every pre-2.0 message, and
/// outbound/plain sends without an id) aren't covered by the partial index and
/// always insert exactly as before. Returns the id of the persisted row — the
/// freshly inserted one, or, when a duplicate was deduped, the id of the row
/// already present for that (room, sender, client_msg_id), so the caller always
/// gets a stable handle instead of a stale `last_insert_rowid()`.
pub fn insert_room_message(
    db: &Db,
    room_id: &str,
    sender_fingerprint: &str,
    direction: &str,
    body: &str,
    sent_at: i64,
    client_msg_id: Option<&str>,
    reply_to: Option<&str>,
) -> Result<i64> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT OR IGNORE INTO room_messages
            (room_id, sender_fingerprint, direction, body, sent_at, client_msg_id, reply_to)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            room_id,
            sender_fingerprint,
            direction,
            body,
            sent_at,
            client_msg_id,
            reply_to
        ],
    )?;
    if conn.changes() > 0 {
        return Ok(conn.last_insert_rowid());
    }
    // The insert was a deduped no-op (only possible for a non-NULL client_msg_id,
    // since NULL rows aren't covered by idx_room_messages_dedup). Return the id of
    // the row that already won the race rather than a stale last_insert_rowid().
    let existing = conn
        .query_row(
            "SELECT id FROM room_messages
             WHERE room_id = ?1 AND sender_fingerprint = ?2 AND client_msg_id = ?3",
            params![room_id, sender_fingerprint, client_msg_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(existing.unwrap_or_else(|| conn.last_insert_rowid()))
}

/// LIKE-based message search within a room. Case-insensitive. The query
/// is treated as a literal substring — `%`, `_`, and `\` are escaped so
/// they cannot act as LIKE wildcards. huddle 2.0.0: this is also the graceful
/// fallback for [`search_room_messages_fts`] when FTS5 is unavailable or the
/// query isn't valid FTS5 syntax. Tombstoned messages (F10 deletes) are
/// excluded so a `[deleted]` row never surfaces in search results.
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
        "SELECT id, room_id, sender_fingerprint, direction, body, sent_at,
                client_msg_id, reply_to, edited_at, deleted_at
         FROM room_messages
         WHERE room_id = ?1 AND deleted_at IS NULL
           AND body LIKE ?2 ESCAPE '\\' COLLATE NOCASE
         ORDER BY sent_at DESC LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![room_id, pattern, limit], row_to_room_message)?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

/// huddle 2.0.0 (F8): ranked full-text search over a room's message bodies via
/// the `room_messages_fts` FTS5 index, ordered newest-first to match the LIKE
/// path it supersedes. The `query` is passed through as a raw FTS5 MATCH
/// expression, so the usual operators work: bare tokens AND together
/// (`hello world`), `*` does prefix matching (`hel*`), and `-` excludes
/// (`hello -world`). Tombstoned messages (F10 deletes) are filtered out.
///
/// Robustness: an empty/whitespace query — which is not a valid MATCH
/// expression — returns no results. Any FTS failure (an unavailable virtual
/// table on a SQLCipher build without FTS5, or an invalid FTS5 query
/// expression such as a stray quote) is caught and transparently retried via
/// the [`search_room_messages`] LIKE path, so search never hard-fails on user
/// input.
pub fn search_room_messages_fts(
    db: &Db,
    room_id: &str,
    query: &str,
    limit: i64,
) -> Result<Vec<StoredRoomMessage>> {
    if query.trim().is_empty() {
        return Ok(Vec::new());
    }

    let fts_result: rusqlite::Result<Vec<StoredRoomMessage>> = (|| {
        let conn = db.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT m.id, m.room_id, m.sender_fingerprint, m.direction, m.body, m.sent_at,
                    m.client_msg_id, m.reply_to, m.edited_at, m.deleted_at
             FROM room_messages_fts f
             JOIN room_messages m ON m.id = f.rowid
             WHERE m.room_id = ?1 AND m.deleted_at IS NULL AND f.body MATCH ?2
             ORDER BY m.sent_at DESC LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![room_id, query, limit], row_to_room_message)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
    })();

    match fts_result {
        Ok(msgs) => Ok(msgs),
        Err(e) => {
            warn!(error = %e, "FTS5 search failed; falling back to LIKE substring search");
            search_room_messages(db, room_id, query, limit)
        }
    }
}

pub fn get_room_messages(db: &Db, room_id: &str, limit: i64) -> Result<Vec<StoredRoomMessage>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, room_id, sender_fingerprint, direction, body, sent_at,
                client_msg_id, reply_to, edited_at, deleted_at
         FROM room_messages WHERE room_id = ?1 ORDER BY sent_at DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![room_id, limit], row_to_room_message)?;
    let mut msgs: Vec<StoredRoomMessage> = rows.collect::<std::result::Result<Vec<_>, _>>()?;
    msgs.reverse();
    Ok(msgs)
}

// =========================================================================
// huddle 2.0.0 (F9): disappearing messages — per-room TTL auto-deletion
// =========================================================================

/// The per-room disappearing-messages TTL in seconds, or `None` when the
/// feature is OFF for the room (stored as 0). When `Some(secs)`, a message
/// becomes eligible for [`delete_expired_messages`] once `sent_at + secs` has
/// passed. Defaults to `None` for unknown rooms and for any room that predates
/// the F9 migration (`disappearing_ttl_secs DEFAULT 0`).
pub fn get_room_disappearing_ttl(db: &Db, room_id: &str) -> Result<Option<u32>> {
    let conn = db.lock().unwrap();
    let secs: i64 = conn
        .query_row(
            "SELECT disappearing_ttl_secs FROM rooms WHERE id = ?1",
            params![room_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    Ok(if secs > 0 { Some(secs as u32) } else { None })
}

/// Set (or clear, with `None`) a room's disappearing-messages TTL. `None` maps
/// to 0 (OFF). Callers that learn the setting from a signed
/// `DisappearingMessagesUpdate` must verify the signer is a room owner first —
/// this repo function trusts its inputs.
pub fn set_room_disappearing_ttl(db: &Db, room_id: &str, ttl_secs: Option<u32>) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "UPDATE rooms SET disappearing_ttl_secs = ?1 WHERE id = ?2",
        params![ttl_secs.unwrap_or(0) as i64, room_id],
    )?;
    Ok(())
}

/// Physically delete every message that has outlived its room's
/// disappearing-messages TTL — i.e. `sent_at + rooms.disappearing_ttl_secs
/// <= now_ts` for rooms with the feature ON (`disappearing_ttl_secs > 0`).
/// Returns the number of rows removed (logged by the pruner). The FTS delete
/// trigger keeps the search index in lock-step. Reactions on a now-expired
/// message are harmlessly orphaned (their `target_client_msg_id` no longer
/// resolves) and age out with the room's FK cascade. Best-effort + local: each
/// peer prunes against its own clock.
pub fn delete_expired_messages(db: &Db, now_ts: i64) -> Result<usize> {
    let conn = db.lock().unwrap();
    let removed = conn.execute(
        "DELETE FROM room_messages
         WHERE id IN (
            SELECT m.id FROM room_messages m
            JOIN rooms r ON r.id = m.room_id
            WHERE r.disappearing_ttl_secs > 0
              AND m.sent_at + r.disappearing_ttl_secs <= ?1
         )",
        params![now_ts],
    )?;
    Ok(removed)
}

// =========================================================================
// huddle 2.0.0 (F10): reactions, replies, edits, deletes
// =========================================================================

/// A single reaction (one reactor, one emoji) on one message. Reactions are
/// stored one row per `(room, target message, reactor, emoji)`; the UI groups
/// them client-side by `target_client_msg_id` into per-emoji counts.
#[derive(Debug, Clone)]
pub struct StoredReaction {
    pub id: i64,
    pub room_id: String,
    /// The `client_msg_id` of the message being reacted to.
    pub target_client_msg_id: String,
    pub sender_fingerprint: String,
    pub emoji: String,
    pub reacted_at: i64,
}

/// Record a reaction. Idempotent on `(room, target message, reactor, emoji)`
/// via the UNIQUE constraint — a re-sent reaction (or a UI double-click) is a
/// no-op rather than an error or a duplicate badge. `reacted_at` is refreshed
/// on conflict so the freshest timestamp wins for any UI that sorts by it.
/// Callers verify the reaction's signed envelope (signer == sender) first.
pub fn add_reaction(
    db: &Db,
    room_id: &str,
    target_client_msg_id: &str,
    sender_fingerprint: &str,
    emoji: &str,
    reacted_at: i64,
) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO room_reactions
            (room_id, target_client_msg_id, sender_fingerprint, emoji, reacted_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(room_id, target_client_msg_id, sender_fingerprint, emoji)
            DO UPDATE SET reacted_at = excluded.reacted_at",
        params![
            room_id,
            target_client_msg_id,
            sender_fingerprint,
            emoji,
            reacted_at
        ],
    )?;
    Ok(())
}

/// Remove a single reaction (the toggle-off / change-emoji path). Exact match
/// on all four identity columns, so removing 👍 leaves a ❤️ from the same
/// reactor untouched. Idempotent: removing a reaction that isn't there affects
/// 0 rows and is not an error.
pub fn remove_reaction(
    db: &Db,
    room_id: &str,
    target_client_msg_id: &str,
    sender_fingerprint: &str,
    emoji: &str,
) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM room_reactions
         WHERE room_id = ?1 AND target_client_msg_id = ?2
           AND sender_fingerprint = ?3 AND emoji = ?4",
        params![room_id, target_client_msg_id, sender_fingerprint, emoji],
    )?;
    Ok(())
}

/// Every reaction in a room, oldest first. Cheap enough to load once when a
/// room opens and group client-side by `target_client_msg_id` (the
/// `idx_room_reactions_target` index keeps the per-message slice contiguous).
/// Returns an empty `Vec` for a room with no reactions.
pub fn list_room_reactions(db: &Db, room_id: &str) -> Result<Vec<StoredReaction>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, room_id, target_client_msg_id, sender_fingerprint, emoji, reacted_at
         FROM room_reactions WHERE room_id = ?1 ORDER BY reacted_at ASC, id ASC",
    )?;
    let rows = stmt.query_map(params![room_id], |row| {
        Ok(StoredReaction {
            id: row.get(0)?,
            room_id: row.get(1)?,
            target_client_msg_id: row.get(2)?,
            sender_fingerprint: row.get(3)?,
            emoji: row.get(4)?,
            reacted_at: row.get(5)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

/// Apply an edit to the message with this `client_msg_id`, last-write-wins on
/// `edited_at`: a stale edit (older-or-equal timestamp than one already applied)
/// is ignored. A delete is final — a tombstoned message (`deleted_at IS NOT
/// NULL`) can't be resurrected by a late edit. Returns `true` iff a row was
/// actually updated. The FTS index is kept current by the UPDATE trigger.
/// Callers enforce the edit policy (signer == original sender OR room owner)
/// before invoking.
pub fn apply_message_edit(
    db: &Db,
    room_id: &str,
    client_msg_id: &str,
    new_body: &str,
    edited_at: i64,
) -> Result<bool> {
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE room_messages
         SET body = ?3, edited_at = ?4
         WHERE room_id = ?1 AND client_msg_id = ?2
           AND deleted_at IS NULL
           AND (edited_at IS NULL OR edited_at < ?4)",
        params![room_id, client_msg_id, new_body, edited_at],
    )?;
    Ok(changed > 0)
}

/// Tombstone the message with this `client_msg_id`: blank the body (so the
/// deleted plaintext doesn't linger at rest, and the FTS index stops matching
/// it via the UPDATE trigger) and stamp `deleted_at`. Idempotent — a message
/// that's already deleted is left untouched. Returns `true` iff this call
/// tombstoned a row. Callers enforce the delete policy (signer == original
/// sender OR room owner) before invoking.
pub fn mark_message_deleted(
    db: &Db,
    room_id: &str,
    client_msg_id: &str,
    deleted_at: i64,
) -> Result<bool> {
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE room_messages
         SET body = '', deleted_at = ?3
         WHERE room_id = ?1 AND client_msg_id = ?2 AND deleted_at IS NULL",
        params![room_id, client_msg_id, deleted_at],
    )?;
    Ok(changed > 0)
}

/// Look up a stored message by its sender-minted `client_msg_id` within a room.
/// Used to resolve a reaction / edit / delete / reply target — e.g. to read the
/// original sender's fingerprint for the edit/delete authorization check, or to
/// confirm a reply target still exists. Returns `None` when no message in the
/// room carries that id (a pre-2.0 message has a NULL id and never matches).
pub fn find_message_by_client_id(
    db: &Db,
    room_id: &str,
    client_msg_id: &str,
) -> Result<Option<StoredRoomMessage>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, room_id, sender_fingerprint, direction, body, sent_at,
                client_msg_id, reply_to, edited_at, deleted_at
         FROM room_messages WHERE room_id = ?1 AND client_msg_id = ?2 LIMIT 1",
    )?;
    let mut rows = stmt.query_map(params![room_id, client_msg_id], row_to_room_message)?;
    match rows.next() {
        Some(r) => Ok(Some(r?)),
        None => Ok(None),
    }
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
    conn.execute(
        "DELETE FROM known_peers WHERE address = ?1",
        params![address],
    )?;
    Ok(())
}

/// Phase A: look up whether we've already trusted a peer by fingerprint.
/// Used by the network task when an inbound connection's Identify lands —
/// trusted fingerprints bypass the user-prompt modal.
pub fn is_fingerprint_trusted(db: &Db, fingerprint: &str) -> Result<bool> {
    let conn = db.lock().unwrap();
    let count: i64 = security_count(
        conn.query_row(
            "SELECT COUNT(*) FROM known_peers WHERE fingerprint = ?1 AND trusted = 1",
            params![fingerprint],
            |r| r.get(0),
        ),
        "is_fingerprint_trusted",
        0, // grant-check: assume NOT trusted on error
    );
    Ok(count > 0)
}

// =========================================================================
// huddle 1.0: Contacts — the durable, fingerprint-keyed address book
// =========================================================================

#[derive(Debug, Clone)]
pub struct Contact {
    pub fingerprint: String,
    pub alias: Option<String>,
    pub ed25519_pubkey: Option<String>,
    pub dm_room_id: Option<String>,
    pub source: String,
    pub note: Option<String>,
    pub added_at: i64,
    pub last_seen: Option<i64>,
}

fn row_to_contact(row: &rusqlite::Row) -> rusqlite::Result<Contact> {
    Ok(Contact {
        fingerprint: row.get(0)?,
        alias: row.get(1)?,
        ed25519_pubkey: row.get(2)?,
        dm_room_id: row.get(3)?,
        source: row.get(4)?,
        note: row.get(5)?,
        added_at: row.get(6)?,
        last_seen: row.get(7)?,
    })
}

/// Insert or fill-in a contact. Existing non-NULL fields are preserved
/// (COALESCE) so a later, sparser upsert never erases an alias / pubkey we
/// already learned; `last_seen` advances when provided and `source` is set
/// only on first insert. Use `set_contact_alias` to deliberately change an
/// alias.
pub fn upsert_contact(db: &Db, c: &Contact) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO contacts (fingerprint, alias, ed25519_pubkey, dm_room_id, source, note, added_at, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(fingerprint) DO UPDATE SET
           alias = COALESCE(excluded.alias, contacts.alias),
           ed25519_pubkey = COALESCE(excluded.ed25519_pubkey, contacts.ed25519_pubkey),
           dm_room_id = COALESCE(excluded.dm_room_id, contacts.dm_room_id),
           note = COALESCE(excluded.note, contacts.note),
           last_seen = COALESCE(excluded.last_seen, contacts.last_seen)",
        params![
            c.fingerprint,
            c.alias,
            c.ed25519_pubkey,
            c.dm_room_id,
            c.source,
            c.note,
            c.added_at,
            c.last_seen,
        ],
    )?;
    Ok(())
}

pub fn get_contact(db: &Db, fingerprint: &str) -> Result<Option<Contact>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT fingerprint, alias, ed25519_pubkey, dm_room_id, source, note, added_at, last_seen
         FROM contacts WHERE fingerprint = ?1",
    )?;
    let mut rows = stmt.query_map(params![fingerprint], row_to_contact)?;
    match rows.next() {
        Some(r) => Ok(Some(r?)),
        None => Ok(None),
    }
}

pub fn list_contacts(db: &Db) -> Result<Vec<Contact>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT fingerprint, alias, ed25519_pubkey, dm_room_id, source, note, added_at, last_seen
         FROM contacts ORDER BY COALESCE(last_seen, added_at) DESC",
    )?;
    let rows = stmt.query_map([], row_to_contact)?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub fn delete_contact(db: &Db, fingerprint: &str) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM contacts WHERE fingerprint = ?1",
        params![fingerprint],
    )?;
    Ok(())
}

pub fn is_contact(db: &Db, fingerprint: &str) -> Result<bool> {
    let conn = db.lock().unwrap();
    let count: i64 = security_count(
        conn.query_row(
            "SELECT COUNT(*) FROM contacts WHERE fingerprint = ?1",
            params![fingerprint],
            |r| r.get(0),
        ),
        "is_contact",
        0, // grant-check: assume NOT a contact on error
    );
    Ok(count > 0)
}

/// Deliberately set (or clear, with None) a contact's user-chosen alias.
/// Unlike `upsert_contact`, this overwrites — it's the explicit edit path.
pub fn set_contact_alias(db: &Db, fingerprint: &str, alias: Option<&str>) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "UPDATE contacts SET alias = ?2 WHERE fingerprint = ?1",
        params![fingerprint, alias],
    )?;
    Ok(())
}

// =========================================================================
// huddle 0.7.7: pending friend requests
// =========================================================================

/// Pending inbound dial that the user hasn't yet acted on. Persisted so a
/// brief absence (or app restart) doesn't lose the request. Auto-rejected
/// when older than [`PENDING_FRIEND_REQUEST_TTL_SECS`] (3 days).
#[derive(Debug, Clone)]
pub struct PendingFriendRequest {
    pub fingerprint: String,
    pub address: String,
    pub peer_id: String,
    pub received_at: i64,
}

/// 3 days, in seconds. Anything older is auto-rejected by the startup
/// sweep — long enough to cover a weekend away from the keyboard, short
/// enough that an actively-malicious peer's pending row doesn't linger
/// indefinitely.
pub const PENDING_FRIEND_REQUEST_TTL_SECS: i64 = 3 * 24 * 60 * 60;

pub fn upsert_pending_friend_request(db: &Db, req: &PendingFriendRequest) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO pending_friend_requests (fingerprint, address, peer_id, received_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(fingerprint, address) DO UPDATE SET
           peer_id = excluded.peer_id,
           received_at = excluded.received_at",
        params![req.fingerprint, req.address, req.peer_id, req.received_at],
    )?;
    Ok(())
}

pub fn list_pending_friend_requests(db: &Db) -> Result<Vec<PendingFriendRequest>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT fingerprint, address, peer_id, received_at
         FROM pending_friend_requests
         ORDER BY received_at DESC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(PendingFriendRequest {
            fingerprint: row.get(0)?,
            address: row.get(1)?,
            peer_id: row.get(2)?,
            received_at: row.get(3)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

/// Delete every row matching `fingerprint`. Both Accept and Reject paths
/// clear all of the peer's pending rows at once — accepting one address
/// implicitly accepts the peer, and we don't want a second row for the
/// same fp to re-prompt later.
pub fn delete_pending_friend_requests_for_fp(db: &Db, fingerprint: &str) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM pending_friend_requests WHERE fingerprint = ?1",
        params![fingerprint],
    )?;
    Ok(())
}

/// Drop rows older than the TTL. Called once on startup; returns the
/// number of rows pruned so callers can surface a status hint if any
/// pending requests aged out while the user was offline.
pub fn cleanup_expired_pending_friend_requests(db: &Db, now: i64) -> Result<usize> {
    // huddle 0.7.11: saturating_sub guards against `now < TTL` (occurs
    // in tests with hand-crafted timestamps and on freshly-reset clocks)
    // where a plain `now - TTL` would go negative and match every row.
    let cutoff = now.saturating_sub(PENDING_FRIEND_REQUEST_TTL_SECS);
    let conn = db.lock().unwrap();
    let removed = conn.execute(
        "DELETE FROM pending_friend_requests WHERE received_at < ?1",
        params![cutoff],
    )?;
    Ok(removed)
}

// =========================================================================
// huddle 1.0: pending contact requests (relay inbox — Phase 1)
// =========================================================================

/// An inbound contact/DM request that arrived over the relay inbox but
/// hasn't been accepted/declined yet. Keyed by fingerprint (relay requests
/// carry no dialable address — just the requester's signed identity). Shares
/// the 3-day [`PENDING_FRIEND_REQUEST_TTL_SECS`] sweep.
#[derive(Debug, Clone)]
pub struct PendingContactRequest {
    pub fingerprint: String,
    pub display_name: Option<String>,
    pub note: Option<String>,
    pub received_at: i64,
}

pub fn upsert_pending_contact_request(db: &Db, req: &PendingContactRequest) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO pending_contact_requests (fingerprint, display_name, note, received_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(fingerprint) DO UPDATE SET
           display_name = COALESCE(excluded.display_name, pending_contact_requests.display_name),
           note = COALESCE(excluded.note, pending_contact_requests.note),
           received_at = excluded.received_at",
        params![req.fingerprint, req.display_name, req.note, req.received_at],
    )?;
    Ok(())
}

pub fn list_pending_contact_requests(db: &Db) -> Result<Vec<PendingContactRequest>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT fingerprint, display_name, note, received_at
         FROM pending_contact_requests ORDER BY received_at DESC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(PendingContactRequest {
            fingerprint: row.get(0)?,
            display_name: row.get(1)?,
            note: row.get(2)?,
            received_at: row.get(3)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub fn delete_pending_contact_request(db: &Db, fingerprint: &str) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM pending_contact_requests WHERE fingerprint = ?1",
        params![fingerprint],
    )?;
    Ok(())
}

pub fn cleanup_expired_pending_contact_requests(db: &Db, now: i64) -> Result<usize> {
    let cutoff = now.saturating_sub(PENDING_FRIEND_REQUEST_TTL_SECS);
    let conn = db.lock().unwrap();
    let removed = conn.execute(
        "DELETE FROM pending_contact_requests WHERE received_at < ?1",
        params![cutoff],
    )?;
    Ok(removed)
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

/// Phase E: simple app-wide KV. Used for the global
/// 'verified_only_inbound' toggle and any other future flags.
pub fn get_setting(db: &Db, key: &str) -> Result<Option<String>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare("SELECT value FROM app_settings WHERE key = ?1")?;
    let row = stmt.query_row(params![key], |r| r.get::<_, String>(0)).ok();
    Ok(row)
}

pub fn set_setting(db: &Db, key: &str, value: &str) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO app_settings (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

/// Phase E: per-room "only verified members may join" toggle.
pub fn get_room_verified_only(db: &Db, room_id: &str) -> Result<bool> {
    let conn = db.lock().unwrap();
    let v: i64 = conn
        .query_row(
            "SELECT verified_only_join FROM rooms WHERE id = ?1",
            params![room_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    Ok(v != 0)
}

pub fn set_room_verified_only(db: &Db, room_id: &str, on: bool) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "UPDATE rooms SET verified_only_join = ?1 WHERE id = ?2",
        params![on as i64, room_id],
    )?;
    Ok(())
}

/// Phase G: mark a fingerprint as globally SAS-verified. Idempotent;
/// re-verifying just refreshes `verified_at`. Used by both sides of
/// an SAS exchange on receiving the partner's matching `SasConfirm`.
///
/// huddle 2.0.0 (F1): `pq_capable` records whether this SAS exchange bound the
/// partner's ML-KEM encapsulation key into the transcript (i.e. the peer
/// demonstrated post-quantum capability). It is **sticky-once-true**: a later
/// classical SAS verification (`pq_capable = false`) must NOT clear a
/// previously-observed PQ capability, exactly like the `known_peers.trusted`
/// sticky flag and the `room_members.mlkem_pubkey` COALESCE-preserve pin. This
/// is the durable anchor that lets `ensure_dm_key` refuse a classical-only DM
/// fallback for a peer who was verified PQ-capable, defeating a
/// post-verification relay downgrade.
pub fn add_verified_peer(
    db: &Db,
    fingerprint: &str,
    verified_at: i64,
    pq_capable: bool,
) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO verified_peers (fingerprint, verified_at, pq_capable) VALUES (?1, ?2, ?3)
         ON CONFLICT(fingerprint) DO UPDATE SET
            verified_at = excluded.verified_at,
            pq_capable = CASE
                WHEN excluded.pq_capable = 1 THEN 1
                ELSE verified_peers.pq_capable
            END",
        params![fingerprint, verified_at, pq_capable as i64],
    )?;
    Ok(())
}

/// huddle 2.0.0 (F1): did this fingerprint demonstrate post-quantum (ML-KEM)
/// capability during SAS verification? Returns `false` for unknown peers and
/// for peers verified before this column existed (`DEFAULT 0`). A `true` result
/// is a durable trust anchor: `ensure_dm_key` then refuses a classical-only DM
/// fallback for this peer, so a relay can't strip their ML-KEM pubkey from a
/// later `MemberAnnounce` to force a quantum-unsafe downgrade after they were
/// verified.
///
/// Fail-secure on a genuine DB error: "no row" is the legitimate
/// not-PQ-verified case and reads as `false`, but any *other* error refuses the
/// downgrade by reporting `true` — a loud, safe failed-DM beats a silent
/// downgrade, mirroring `security_count`'s deny-check default.
pub fn get_verified_peer_pq_capable(db: &Db, fingerprint: &str) -> Result<bool> {
    let conn = db.lock().unwrap();
    match conn.query_row(
        "SELECT pq_capable FROM verified_peers WHERE fingerprint = ?1",
        params![fingerprint],
        |r| r.get::<_, i64>(0),
    ) {
        Ok(v) => Ok(v != 0),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(e) => {
            warn!(
                error = %e,
                "get_verified_peer_pq_capable query failed; fail-secure: \
                 assuming PQ-capable to refuse a classical downgrade"
            );
            Ok(true)
        }
    }
}

/// Phase G + E: is this fingerprint globally SAS-verified? Used by
/// Phase E's global inbound filter and by the per-room "verified_only"
/// enforcement.
pub fn is_globally_verified(db: &Db, fingerprint: &str) -> Result<bool> {
    let conn = db.lock().unwrap();
    let count: i64 = security_count(
        conn.query_row(
            "SELECT COUNT(*) FROM verified_peers WHERE fingerprint = ?1",
            params![fingerprint],
            |r| r.get(0),
        ),
        "is_globally_verified",
        0, // grant-check: assume NOT verified on error
    );
    Ok(count > 0)
}

/// huddle 0.7: list every globally SAS-verified fingerprint. Used by
/// the People pane to render the "Verified" sub-list.
pub fn list_verified_peers(db: &Db) -> Result<Vec<String>> {
    let conn = db.lock().unwrap();
    let mut stmt =
        conn.prepare("SELECT fingerprint FROM verified_peers ORDER BY verified_at DESC")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

/// Phase H: has the first-launch onboarding card been dismissed?
pub fn is_onboarding_seen(db: &Db) -> Result<bool> {
    let conn = db.lock().unwrap();
    let v: i64 = conn
        .query_row(
            "SELECT onboarding_seen FROM identity WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    Ok(v != 0)
}

pub fn mark_onboarding_seen(db: &Db) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute("UPDATE identity SET onboarding_seen = 1 WHERE id = 1", [])?;
    Ok(())
}

/// huddle 0.6: the version string of huddle that this user last
/// finished onboarding for. Stored under the app_settings KV so
/// version bumps re-fire the "what's new" card without churning
/// the identity schema again. `None` means the user hasn't seen
/// any onboarding yet OR pre-existed the version-tracking change.
pub fn get_last_seen_onboarding_version(db: &Db) -> Result<Option<String>> {
    get_setting(db, "last_seen_onboarding_version")
}

pub fn set_last_seen_onboarding_version(db: &Db, version: &str) -> Result<()> {
    set_setting(db, "last_seen_onboarding_version", version)
}

/// huddle 0.6: opt-in flag for the crates.io update check. None means
/// the user hasn't been asked yet; `Some(true)` enables the background
/// poll; `Some(false)` disables it.
pub fn get_update_check_enabled(db: &Db) -> Result<Option<bool>> {
    Ok(
        get_setting(db, "update_check_enabled")?
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true")),
    )
}

pub fn set_update_check_enabled(db: &Db, enabled: bool) -> Result<()> {
    set_setting(db, "update_check_enabled", if enabled { "1" } else { "0" })
}

pub fn is_peer_blocked(db: &Db, fingerprint: &str) -> Result<bool> {
    let conn = db.lock().unwrap();
    let count: i64 = security_count(
        conn.query_row(
            "SELECT COUNT(*) FROM blocked_peers WHERE fingerprint = ?1",
            params![fingerprint],
            |r| r.get(0),
        ),
        "is_peer_blocked",
        1, // deny-check: assume blocked if the DB can't confirm otherwise
    );
    Ok(count > 0)
}

/// List every fingerprint we've blocked (across all rooms / global
/// rejection from the inbound-dial modal), newest first. Used by the
/// Settings modal's "blocked peers" pane to render the unblock action.
pub fn list_blocked_peers(db: &Db) -> Result<Vec<String>> {
    let conn = db.lock().unwrap();
    let mut stmt =
        conn.prepare("SELECT fingerprint FROM blocked_peers ORDER BY blocked_at DESC")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

/// Remove a fingerprint from the blocklist. Used by the Settings
/// modal's "unblock" action so a previously-rejected inbound dial can
/// reach us again. Counterpart of `block_peer`.
pub fn unblock_peer(db: &Db, fingerprint: &str) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM blocked_peers WHERE fingerprint = ?1",
        params![fingerprint],
    )?;
    Ok(())
}

// =========================================================================
// Peer profiles (huddle 0.5)
// =========================================================================

/// Upsert the cached username for a peer iff the incoming `updated_at` is
/// strictly newer than what we have stored — last-write-wins on the
/// sender's monotonic ms. A None username here means the peer cleared
/// their name; render as `[anonymous]`.
pub fn upsert_peer_profile(
    db: &Db,
    fingerprint: &str,
    username: Option<&str>,
    updated_at: i64,
) -> Result<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO peer_profiles (fingerprint, username, updated_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(fingerprint) DO UPDATE SET
            username   = excluded.username,
            updated_at = excluded.updated_at
         WHERE excluded.updated_at > peer_profiles.updated_at",
        params![fingerprint, username, updated_at],
    )?;
    Ok(())
}

/// Cached username for a peer if we've ever seen a signed ProfileUpdate
/// from them. Returns None for unknown peers and for peers who set
/// `username = None` (explicit anonymous) — caller renders `[anonymous]`.
pub fn get_peer_username(db: &Db, fingerprint: &str) -> Result<Option<String>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare("SELECT username FROM peer_profiles WHERE fingerprint = ?1")?;
    let mut rows = stmt.query(params![fingerprint])?;
    if let Some(row) = rows.next()? {
        Ok(row.get::<_, Option<String>>(0)?)
    } else {
        Ok(None)
    }
}

/// huddle 0.5.1: every fingerprint that has broadcast the given
/// username via a signed ProfileUpdate. Multiple matches are possible
/// — usernames aren't unique — so the "add by username" flow asks
/// the user to disambiguate via HD- ID when this returns > 1.
pub fn find_peers_by_username(db: &Db, username: &str) -> Result<Vec<String>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare("SELECT fingerprint FROM peer_profiles WHERE username = ?1")?;
    let rows = stmt.query_map(params![username], |row| row.get::<_, String>(0))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
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
    // huddle 1.3.4: bound the result set. With no LIMIT a single room member
    // could create tens of thousands of `FileOffer`s and OOM a peer that opens
    // the room (this loads every row into memory). Return the most recent
    // MAX_ATTACHMENTS_PER_ROOM, still in ascending (display) order.
    const MAX_ATTACHMENTS_PER_ROOM: i64 = 2000;
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, room_id, message_id, sender_fingerprint, file_id, name, mime,
                size_bytes, status, cache_path, saved_path, error,
                encrypted, wrapped_key, nonce, megolm_session_id, created_at,
                content_hash
         FROM (
             SELECT * FROM room_attachments WHERE room_id = ?1
             ORDER BY created_at DESC LIMIT ?2
         ) ORDER BY created_at ASC",
    )?;
    let rows = stmt.query_map(
        params![room_id, MAX_ATTACHMENTS_PER_ROOM],
        row_to_attachment,
    )?;
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
            kind: RoomKind::Group,
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
                role: "member".into(),
                mlkem_pubkey: None,
            },
        )
        .unwrap();
        let members = list_room_members(&db, &room.id).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].fingerprint, "fp-x");
        assert!(!members[0].verified);
    }

    #[test]
    fn mlkem_pin_persists_and_survives_a_null_reannounce() {
        // huddle 1.3.1: the post-quantum capability pin. Once we store a peer's
        // ML-KEM key, `lookup_peer_mlkem_pubkey` finds it, and a later announce
        // that omits the field (e.g. a relay replaying an old classical announce)
        // must NOT erase it (COALESCE-preserve, exactly like ed25519_pubkey).
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();
        assert!(lookup_peer_mlkem_pubkey(&db, "fp-pq").unwrap().is_none());

        upsert_room_member(
            &db,
            &StoredRoomMember {
                room_id: room.id.clone(),
                peer_id: String::new(),
                fingerprint: "fp-pq".into(),
                last_seen: Some(1),
                verified: false,
                ed25519_pubkey: Some("ed".into()),
                role: "member".into(),
                mlkem_pubkey: Some("EK-BASE64".into()),
            },
        )
        .unwrap();
        assert_eq!(
            lookup_peer_mlkem_pubkey(&db, "fp-pq").unwrap().as_deref(),
            Some("EK-BASE64")
        );

        // Replay of a classical (no-ek) announce must not clear the pin.
        upsert_room_member(
            &db,
            &StoredRoomMember {
                room_id: room.id.clone(),
                peer_id: String::new(),
                fingerprint: "fp-pq".into(),
                last_seen: Some(2),
                verified: false,
                ed25519_pubkey: Some("ed".into()),
                role: "member".into(),
                mlkem_pubkey: None,
            },
        )
        .unwrap();
        assert_eq!(
            lookup_peer_mlkem_pubkey(&db, "fp-pq").unwrap().as_deref(),
            Some("EK-BASE64"),
            "a later announce without the ML-KEM field must not erase the PQ pin"
        );
    }

    #[test]
    fn delete_outbound_megolm_removes_only_outbound() {
        // huddle 1.3.1: rotate_outbound deletes our outbound row(s) but leaves
        // every inbound session intact.
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();
        let save = |fp: &str, sid: &str, outbound: bool| {
            save_megolm_session(
                &db,
                &StoredMegolmSession {
                    room_id: room.id.clone(),
                    sender_fingerprint: fp.into(),
                    session_id: sid.into(),
                    session_data: b"x".to_vec(),
                    is_outbound: outbound,
                    created_at: 1,
                },
            )
            .unwrap();
        };
        save("me", "out-1", true);
        save("peer", "in-1", false);
        delete_outbound_megolm_sessions(&db, &room.id, "me").unwrap();
        let rows = load_megolm_sessions_for_room(&db, &room.id).unwrap();
        assert_eq!(rows.len(), 1, "only the inbound row should remain");
        assert!(!rows[0].is_outbound);
        assert_eq!(rows[0].session_id, "in-1");
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
                role: "member".into(),
                mlkem_pubkey: None,
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

        insert_room_message(&db, &room.id, "alice-fp", "in", "hi", 100, None, None).unwrap();
        insert_room_message(&db, &room.id, "me-fp", "out", "hello", 101, None, None).unwrap();
        insert_room_message(&db, &room.id, "alice-fp", "in", "bye", 102, None, None).unwrap();

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
        insert_room_message(
            &db,
            &room.id,
            "fp",
            "in",
            "literal percent: 50%",
            100,
            None,
            None,
        )
        .unwrap();
        insert_room_message(
            &db,
            &room.id,
            "fp",
            "in",
            "no special chars here",
            101,
            None,
            None,
        )
        .unwrap();

        // "%" must match a literal "%", not act as a wildcard-matches-all.
        let pct = search_room_messages(&db, &room.id, "%", 10).unwrap();
        assert_eq!(pct.len(), 1);
        assert!(pct[0].body.contains("50%"));

        // "_" likewise must not match an arbitrary single character.
        let underscore = search_room_messages(&db, &room.id, "_", 10).unwrap();
        assert!(underscore.is_empty());
    }

    // ---- F2: content-layer replay protection -------------------------------

    #[test]
    fn content_replay_seen_basic_record_and_check() {
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();

        // Empty table: nothing is seen.
        assert!(!check_content_replay_seen(&db, &room.id, "alice", "sess1", 0).unwrap());

        // After recording, the same tuple reads back as seen.
        record_content_seen(&db, &room.id, "alice", "sess1", 0, 1000).unwrap();
        assert!(check_content_replay_seen(&db, &room.id, "alice", "sess1", 0).unwrap());

        // A different message_index is NOT seen.
        assert!(!check_content_replay_seen(&db, &room.id, "alice", "sess1", 1).unwrap());
        // A different sender / session is NOT seen either.
        assert!(!check_content_replay_seen(&db, &room.id, "bob", "sess1", 0).unwrap());
        assert!(!check_content_replay_seen(&db, &room.id, "alice", "sess2", 0).unwrap());
    }

    #[test]
    fn content_replay_record_is_idempotent() {
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();

        // Recording the same tuple twice must not error (INSERT OR IGNORE on
        // the composite PK) and must leave exactly one row.
        record_content_seen(&db, &room.id, "alice", "s", 7, 1000).unwrap();
        record_content_seen(&db, &room.id, "alice", "s", 7, 2000).unwrap();
        assert!(check_content_replay_seen(&db, &room.id, "alice", "s", 7).unwrap());

        let conn = db.lock().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM content_replay_seen WHERE room_id = ?1",
                params![room.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "idempotent insert must not duplicate the row");
    }

    #[test]
    fn content_replay_is_per_room() {
        // Same (sender, session, index) in two different rooms are tracked
        // independently — the seen-set is keyed by room_id.
        let db = open_db_in_memory().unwrap();
        let room_a = make_room("a");
        let room_b = make_room("b");
        insert_room(&db, &room_a).unwrap();
        insert_room(&db, &room_b).unwrap();

        record_content_seen(&db, &room_a.id, "alice", "s", 0, 1000).unwrap();
        assert!(check_content_replay_seen(&db, &room_a.id, "alice", "s", 0).unwrap());
        // Identical tuple in room B is still fresh.
        assert!(!check_content_replay_seen(&db, &room_b.id, "alice", "s", 0).unwrap());
    }

    #[test]
    fn content_replay_gc_drops_only_old_rows() {
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();

        // 100 indices, created_at == index, across two sessions.
        for i in 0..100u32 {
            record_content_seen(&db, &room.id, "alice", "old", i, i as i64).unwrap();
            record_content_seen(&db, &room.id, "alice", "new", i, 1000 + i as i64).unwrap();
        }

        // Cut at 50: rows with created_at < 50 are deleted (only the "old"
        // session's indices 0..49). Everything >= 50 survives.
        let removed = gc_content_replay_seen(&db, 50).unwrap();
        assert_eq!(removed, 50);

        assert!(!check_content_replay_seen(&db, &room.id, "alice", "old", 0).unwrap());
        assert!(!check_content_replay_seen(&db, &room.id, "alice", "old", 49).unwrap());
        assert!(check_content_replay_seen(&db, &room.id, "alice", "old", 50).unwrap());
        assert!(check_content_replay_seen(&db, &room.id, "alice", "new", 0).unwrap());
    }

    #[test]
    fn content_replay_cascades_on_room_delete() {
        // The FK cascade clears a room's seen-set when the room is deleted, so
        // re-joining a room can't accidentally inherit a stale seen-set.
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();
        record_content_seen(&db, &room.id, "alice", "s", 0, 1000).unwrap();
        assert!(check_content_replay_seen(&db, &room.id, "alice", "s", 0).unwrap());

        {
            let conn = db.lock().unwrap();
            conn.execute("DELETE FROM rooms WHERE id = ?1", params![room.id])
                .unwrap();
        }
        let conn = db.lock().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM content_replay_seen WHERE room_id = ?1",
                params![room.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "FK cascade must clear the room's seen-set");
    }

    #[test]
    fn content_replay_index_bounds() {
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();

        // Empty session: no bounds.
        assert_eq!(
            content_seen_index_bounds(&db, &room.id, "alice", "s").unwrap(),
            None
        );

        record_content_seen(&db, &room.id, "alice", "s", 3, 1000).unwrap();
        record_content_seen(&db, &room.id, "alice", "s", 9, 1001).unwrap();
        record_content_seen(&db, &room.id, "alice", "s", 5, 1002).unwrap();
        assert_eq!(
            content_seen_index_bounds(&db, &room.id, "alice", "s").unwrap(),
            Some((3, 9))
        );
    }

    // ---- F1: PQ capability binding to the verified-peers trust anchor -------

    #[test]
    fn verified_peer_pq_capable_persists_and_is_sticky() {
        let db = open_db_in_memory().unwrap();
        // Unknown fingerprint: not PQ-capable.
        assert!(!get_verified_peer_pq_capable(&db, "fp").unwrap());

        // First verification without PQ binding: recorded, not PQ-capable.
        add_verified_peer(&db, "fp", 100, false).unwrap();
        assert!(is_globally_verified(&db, "fp").unwrap());
        assert!(!get_verified_peer_pq_capable(&db, "fp").unwrap());

        // A later verification WITH ML-KEM binding promotes the flag.
        add_verified_peer(&db, "fp", 200, true).unwrap();
        assert!(get_verified_peer_pq_capable(&db, "fp").unwrap());

        // Sticky-once-true: a subsequent classical (pq=false) verification must
        // NOT clear the pin (post-verification downgrade defense), though
        // verified_at still refreshes.
        add_verified_peer(&db, "fp", 300, false).unwrap();
        assert!(
            get_verified_peer_pq_capable(&db, "fp").unwrap(),
            "pq_capable must be sticky-once-true to defeat a forced downgrade"
        );
    }

    // ---- F8: FTS5 full-text search ----------------------------------------

    #[test]
    fn fts_search_basic_prefix_and_case() {
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();
        insert_room_message(&db, &room.id, "fp", "in", "hello world", 100, None, None).unwrap();
        insert_room_message(
            &db,
            &room.id,
            "fp",
            "in",
            "a helicopter flew",
            101,
            None,
            None,
        )
        .unwrap();
        insert_room_message(
            &db,
            &room.id,
            "fp",
            "in",
            "totally unrelated",
            102,
            None,
            None,
        )
        .unwrap();

        // Single token.
        let hits = search_room_messages_fts(&db, &room.id, "hello", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].body, "hello world");

        // Case-insensitive (unicode61 tokenizer).
        assert_eq!(
            search_room_messages_fts(&db, &room.id, "HELLO", 10)
                .unwrap()
                .len(),
            1
        );

        // Prefix query matches "hello" and "helicopter".
        assert_eq!(
            search_room_messages_fts(&db, &room.id, "hel*", 10)
                .unwrap()
                .len(),
            2
        );

        // Empty / whitespace query returns nothing.
        assert!(search_room_messages_fts(&db, &room.id, "   ", 10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn fts_index_tracks_inserts_edits_and_deletes() {
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();
        insert_room_message(
            &db,
            &room.id,
            "fp",
            "in",
            "original text",
            100,
            Some("m1"),
            None,
        )
        .unwrap();
        assert_eq!(
            search_room_messages_fts(&db, &room.id, "original", 10)
                .unwrap()
                .len(),
            1
        );

        // Edit re-indexes via the UPDATE trigger: old term gone, new searchable.
        apply_message_edit(&db, &room.id, "m1", "rewritten body", 200).unwrap();
        assert!(search_room_messages_fts(&db, &room.id, "original", 10)
            .unwrap()
            .is_empty());
        assert_eq!(
            search_room_messages_fts(&db, &room.id, "rewritten", 10)
                .unwrap()
                .len(),
            1
        );

        // Delete tombstones and drops the message from search.
        mark_message_deleted(&db, &room.id, "m1", 300).unwrap();
        assert!(search_room_messages_fts(&db, &room.id, "rewritten", 10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn fts_falls_back_to_like_when_table_missing() {
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();
        insert_room_message(
            &db,
            &room.id,
            "fp",
            "in",
            "needle in haystack",
            100,
            None,
            None,
        )
        .unwrap();

        // Drop the FTS table + triggers to simulate a SQLCipher build without
        // FTS5; the function must transparently fall back to the LIKE path.
        {
            let conn = db.lock().unwrap();
            conn.execute_batch(
                "DROP TRIGGER IF EXISTS room_messages_ai;
                 DROP TRIGGER IF EXISTS room_messages_ad;
                 DROP TRIGGER IF EXISTS room_messages_au;
                 DROP TABLE IF EXISTS room_messages_fts;",
            )
            .unwrap();
        }
        let hits = search_room_messages_fts(&db, &room.id, "needle", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].body, "needle in haystack");
    }

    // ---- F9: disappearing messages ----------------------------------------

    #[test]
    fn disappearing_ttl_get_set_roundtrip() {
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();
        // Off by default.
        assert_eq!(get_room_disappearing_ttl(&db, &room.id).unwrap(), None);
        set_room_disappearing_ttl(&db, &room.id, Some(3600)).unwrap();
        assert_eq!(
            get_room_disappearing_ttl(&db, &room.id).unwrap(),
            Some(3600)
        );
        // None clears back to off.
        set_room_disappearing_ttl(&db, &room.id, None).unwrap();
        assert_eq!(get_room_disappearing_ttl(&db, &room.id).unwrap(), None);
    }

    #[test]
    fn delete_expired_messages_respects_per_room_ttl() {
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();
        insert_room_message(&db, &room.id, "fp", "in", "old", 100, None, None).unwrap();
        insert_room_message(&db, &room.id, "fp", "in", "new", 950, None, None).unwrap();

        // Feature OFF: nothing expires regardless of age.
        assert_eq!(delete_expired_messages(&db, 10_000).unwrap(), 0);

        // Turn on a 100s TTL. At now=1000, "old" (100+100=200 <= 1000) expires
        // but "new" (950+100=1050 > 1000) survives.
        set_room_disappearing_ttl(&db, &room.id, Some(100)).unwrap();
        assert_eq!(delete_expired_messages(&db, 1000).unwrap(), 1);
        let remaining = get_room_messages(&db, &room.id, 10).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].body, "new");
    }

    // ---- F10: reactions, replies, edits, deletes --------------------------

    #[test]
    fn insert_message_persists_client_id_and_reply() {
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();
        insert_room_message(&db, &room.id, "fp", "out", "hi", 100, Some("uuid-1"), None).unwrap();
        insert_room_message(
            &db,
            &room.id,
            "fp2",
            "in",
            "re: hi",
            101,
            Some("uuid-2"),
            Some("uuid-1"),
        )
        .unwrap();

        let found = find_message_by_client_id(&db, &room.id, "uuid-2")
            .unwrap()
            .unwrap();
        assert_eq!(found.body, "re: hi");
        assert_eq!(found.client_msg_id.as_deref(), Some("uuid-2"));
        assert_eq!(found.reply_to.as_deref(), Some("uuid-1"));

        // A pre-2.0 message (NULL client_msg_id) is never found by id.
        insert_room_message(&db, &room.id, "fp", "in", "legacy", 102, None, None).unwrap();
        assert!(find_message_by_client_id(&db, &room.id, "uuid-missing")
            .unwrap()
            .is_none());
    }

    // F2 dedup: count rows in room_messages for a (room, sender, client_msg_id).
    fn count_msgs_with_client_id(db: &Db, room_id: &str, sender: &str, cid: &str) -> i64 {
        db.lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM room_messages
                 WHERE room_id = ?1 AND sender_fingerprint = ?2 AND client_msg_id = ?3",
                params![room_id, sender, cid],
                |r| r.get(0),
            )
            .unwrap()
    }

    #[test]
    fn duplicate_client_id_insert_is_idempotent() {
        // huddle 2.0.0 (F2 dedup): two concurrent identical deliveries (same
        // room + sender + client_msg_id) must collapse to one row via the partial
        // UNIQUE index + INSERT OR IGNORE — and the second call must return the
        // first row's id, not a stale last_insert_rowid().
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();

        let id1 = insert_room_message(&db, &room.id, "fp", "in", "hello", 100, Some("dup-1"), None)
            .unwrap();
        // A re-delivery with the same id (even a different body) is a no-op.
        let id2 = insert_room_message(
            &db,
            &room.id,
            "fp",
            "in",
            "hello-replayed",
            101,
            Some("dup-1"),
            None,
        )
        .unwrap();
        assert_eq!(
            id1, id2,
            "deduped insert must return the surviving row's id"
        );
        assert_eq!(
            count_msgs_with_client_id(&db, &room.id, "fp", "dup-1"),
            1,
            "the replay must not create a second row"
        );
        // The first write wins; the ignored replay can't overwrite the body.
        let m = find_message_by_client_id(&db, &room.id, "dup-1")
            .unwrap()
            .unwrap();
        assert_eq!(m.body, "hello");

        // The partial index is keyed by sender, so a *different* sender reusing
        // the same client_msg_id is a distinct row (not deduped).
        insert_room_message(
            &db,
            &room.id,
            "fp2",
            "in",
            "mine too",
            102,
            Some("dup-1"),
            None,
        )
        .unwrap();
        assert_eq!(count_msgs_with_client_id(&db, &room.id, "fp2", "dup-1"), 1);

        // NULL client_msg_id rows are exempt from the partial index: two such
        // inserts stay distinct (pre-2.0 messages must never be deduped).
        let n1 =
            insert_room_message(&db, &room.id, "fp", "in", "legacy a", 103, None, None).unwrap();
        let n2 =
            insert_room_message(&db, &room.id, "fp", "in", "legacy b", 104, None, None).unwrap();
        assert_ne!(n1, n2, "NULL-id messages must each get their own row");
    }

    #[test]
    fn reactions_add_remove_list() {
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();

        add_reaction(&db, &room.id, "m1", "alice", "👍", 10).unwrap();
        add_reaction(&db, &room.id, "m1", "bob", "👍", 11).unwrap();
        add_reaction(&db, &room.id, "m1", "alice", "❤️", 12).unwrap();
        // Idempotent: re-adding the same (msg, reactor, emoji) doesn't duplicate.
        add_reaction(&db, &room.id, "m1", "alice", "👍", 13).unwrap();
        assert_eq!(list_room_reactions(&db, &room.id).unwrap().len(), 3);

        // Remove alice's 👍 only; her ❤️ and bob's 👍 survive.
        remove_reaction(&db, &room.id, "m1", "alice", "👍").unwrap();
        let all = list_room_reactions(&db, &room.id).unwrap();
        assert_eq!(all.len(), 2);
        assert!(all
            .iter()
            .any(|r| r.sender_fingerprint == "bob" && r.emoji == "👍"));
        assert!(all
            .iter()
            .any(|r| r.sender_fingerprint == "alice" && r.emoji == "❤️"));

        // Removing a reaction that isn't there is a no-op.
        remove_reaction(&db, &room.id, "m1", "carol", "🔥").unwrap();
        assert_eq!(list_room_reactions(&db, &room.id).unwrap().len(), 2);
    }

    #[test]
    fn message_edit_is_last_write_wins() {
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();
        insert_room_message(&db, &room.id, "fp", "out", "v0", 100, Some("m1"), None).unwrap();

        assert!(apply_message_edit(&db, &room.id, "m1", "v2", 200).unwrap());
        let m = find_message_by_client_id(&db, &room.id, "m1")
            .unwrap()
            .unwrap();
        assert_eq!(m.body, "v2");
        assert_eq!(m.edited_at, Some(200));

        // A stale edit (older timestamp) is ignored.
        assert!(!apply_message_edit(&db, &room.id, "m1", "v1-late", 150).unwrap());
        assert_eq!(
            find_message_by_client_id(&db, &room.id, "m1")
                .unwrap()
                .unwrap()
                .body,
            "v2"
        );

        // A newer edit wins.
        assert!(apply_message_edit(&db, &room.id, "m1", "v3", 300).unwrap());
        assert_eq!(
            find_message_by_client_id(&db, &room.id, "m1")
                .unwrap()
                .unwrap()
                .body,
            "v3"
        );
    }

    #[test]
    fn message_delete_tombstones_and_blocks_edit() {
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();
        insert_room_message(&db, &room.id, "fp", "out", "secret", 100, Some("m1"), None).unwrap();

        assert!(mark_message_deleted(&db, &room.id, "m1", 200).unwrap());
        let m = find_message_by_client_id(&db, &room.id, "m1")
            .unwrap()
            .unwrap();
        assert_eq!(
            m.body, "",
            "delete must blank the body so plaintext is gone"
        );
        assert_eq!(m.deleted_at, Some(200));

        // Idempotent: re-deleting is a no-op.
        assert!(!mark_message_deleted(&db, &room.id, "m1", 300).unwrap());

        // A late edit can't resurrect a tombstoned message.
        assert!(!apply_message_edit(&db, &room.id, "m1", "back", 400).unwrap());
        assert_eq!(
            find_message_by_client_id(&db, &room.id, "m1")
                .unwrap()
                .unwrap()
                .body,
            ""
        );

        // Deleted messages don't surface in search.
        assert!(search_room_messages(&db, &room.id, "secret", 10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn megolm_rotation_state_round_trips_and_upserts() {
        // huddle 2.0.0 (F4): the durable epoch bookkeeping survives a restart.
        // Missing → None (caller keeps the in-memory 0/now baseline); a save
        // round-trips exactly; a second save for the same (room, fingerprint)
        // overwrites rather than duplicating; a different fingerprint is its
        // own row.
        let db = open_db_in_memory().unwrap();
        let room = make_room("r");
        insert_room(&db, &room).unwrap();

        assert_eq!(
            get_megolm_rotation_state(&db, &room.id, "me-fp").unwrap(),
            None
        );

        set_megolm_rotation_state(&db, &room.id, "me-fp", 7, 1000).unwrap();
        assert_eq!(
            get_megolm_rotation_state(&db, &room.id, "me-fp").unwrap(),
            Some((7, 1000))
        );

        // Upsert: a fresh save for the same key overwrites (e.g. after a
        // rotation resets the counter to 0/now).
        set_megolm_rotation_state(&db, &room.id, "me-fp", 0, 2000).unwrap();
        assert_eq!(
            get_megolm_rotation_state(&db, &room.id, "me-fp").unwrap(),
            Some((0, 2000))
        );

        // A different fingerprint is an independent row.
        set_megolm_rotation_state(&db, &room.id, "other-fp", 42, 3000).unwrap();
        assert_eq!(
            get_megolm_rotation_state(&db, &room.id, "other-fp").unwrap(),
            Some((42, 3000))
        );
        assert_eq!(
            get_megolm_rotation_state(&db, &room.id, "me-fp").unwrap(),
            Some((0, 2000))
        );
    }
}
