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
    /// huddle 2.0.0 (F4): in-memory epoch bookkeeping for scheduled
    /// forward-only outbound rotation. `messages_since_rotation` counts
    /// `encrypt` calls on the *current* outbound session; `last_rotation_at`
    /// is the unix time (seconds) the current epoch began. Both reset in
    /// `rotate_outbound`. They are advisory inputs the app feeds to a
    /// `RotationPolicy` to decide when to mint a fresh epoch — they do NOT
    /// affect encrypt/decrypt/replay behavior. The durable copy lives in the
    /// app's `room_megolm_rotation_state` table; call `restore_rotation_state`
    /// after `load` to rehydrate it.
    messages_since_rotation: u32,
    last_rotation_at: i64,
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
            // Fresh epoch: nothing sent yet, clock starts now.
            messages_since_rotation: 0,
            last_rotation_at: now_unix(),
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
                // huddle 2.0.0 (F4): the durable epoch bookkeeping lives in the
                // app's `room_megolm_rotation_state` table, not in the session
                // pickles, so it starts at zero/now here. The app rehydrates it
                // via `restore_rotation_state` right after this returns.
                messages_since_rotation: 0,
                last_rotation_at: now_unix(),
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
        // huddle 2.0.0 (F4): advance the epoch message counter so the app can
        // decide (via `RotationPolicy`) when to rotate. Saturating so a
        // pathologically long-lived session can never wrap the counter.
        self.messages_since_rotation = self.messages_since_rotation.saturating_add(1);
        Ok((session_id, msg.to_bytes()))
    }

    /// Decrypt a message from a specific sender. Returns `(plaintext,
    /// message_index)`.
    ///
    /// huddle 2.0.0 (F2): the Megolm `message_index` is surfaced alongside the
    /// plaintext so the app layer can dedup replayed *content* against the
    /// durable `content_replay_seen` set. It is a monotonic ratchet position
    /// within the session whose KDF output never repeats for a given (session,
    /// index) pair, so the tuple (room, sender, session, index) uniquely names
    /// one ciphertext — see `app::mod::handle_room_message`'s `Encrypted` arm.
    pub fn decrypt(
        &mut self,
        sender_fingerprint: &str,
        session_id: &str,
        ciphertext: &[u8],
    ) -> Result<(Vec<u8>, u32)> {
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

        Ok((decrypted.plaintext, decrypted.message_index))
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
    ///
    /// huddle 2.0.0 (F4): this is also the engine for *scheduled* forward-only
    /// epoch rotation — the app calls it when a `RotationPolicy` trips (after N
    /// messages or T seconds) to bound key-compromise exposure. Rotation resets
    /// the epoch bookkeeping (`messages_since_rotation` → 0, `last_rotation_at`
    /// → now) so the next epoch starts counting fresh. The membership-change and
    /// classical→hybrid callers benefit from the reset too — every fresh
    /// outbound session is, correctly, a brand-new epoch.
    pub fn rotate_outbound(&mut self) -> Result<()> {
        repo::delete_outbound_megolm_sessions(&self.db, &self.room_id, &self.our_fingerprint)?;
        self.outbound = GroupSession::new(SessionConfig::version_1());
        self.persist_outbound()?;
        // A fresh epoch starts now with zero messages sent.
        self.messages_since_rotation = 0;
        self.last_rotation_at = now_unix();
        Ok(())
    }

    /// huddle 2.0.0 (F4): number of messages encrypted on the *current*
    /// outbound epoch — since `new_for_room`, the last `rotate_outbound`, or the
    /// value restored via `restore_rotation_state`. The app compares this with a
    /// `RotationPolicy` to schedule forward-only rotation.
    pub fn messages_since_rotation(&self) -> u32 {
        self.messages_since_rotation
    }

    /// huddle 2.0.0 (F4): unix time (seconds) the current outbound epoch began.
    pub fn last_rotation_at(&self) -> i64 {
        self.last_rotation_at
    }

    /// huddle 2.0.0 (F4): seconds elapsed since the current epoch began, clamped
    /// at 0 so a backwards-stepping wall clock never yields a negative age
    /// (which would otherwise wrongly trip a time-based rotation). Only forward
    /// time can trigger rotation.
    pub fn seconds_since_rotation(&self) -> i64 {
        (now_unix() - self.last_rotation_at).max(0)
    }

    /// huddle 2.0.0 (F4): convenience — does the current epoch's live
    /// bookkeeping trip `policy`? Equivalent to
    /// `policy.should_rotate(self.messages_since_rotation(), self.seconds_since_rotation())`.
    pub fn should_rotate(&self, policy: &RotationPolicy) -> bool {
        policy.should_rotate(self.messages_since_rotation, self.seconds_since_rotation())
    }

    /// huddle 2.0.0 (F4): rehydrate the epoch bookkeeping from the app's durable
    /// `room_megolm_rotation_state` row after a `load`. `load` only restores the
    /// Megolm ratchet (the session pickles); the message counter and epoch start
    /// time live in a separate table the app owns, so the app calls this once
    /// after constructing the `RoomCrypto` to continue counting from where it
    /// left off rather than from zero.
    pub fn restore_rotation_state(&mut self, messages_since_rotation: u32, last_rotation_at: i64) {
        self.messages_since_rotation = messages_since_rotation;
        self.last_rotation_at = last_rotation_at;
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

/// huddle 2.0.0 (F4): scheduled forward-only Megolm epoch rotation policy.
///
/// Bounds key-compromise exposure: an attacker who harvests a wrapped outbound
/// session key and later breaks the wrap (e.g. a post-quantum break of a
/// classical key) can only read back to the most recent rotation. The window is
/// `min(max_messages, max_age_secs)` — whichever trigger trips first.
///
/// A `0` threshold disables *that* trigger; setting both to `0` disables
/// scheduled rotation entirely (matching pre-2.0.0 behavior). Membership-change
/// rotation is unconditional and lives in the app layer — this policy only
/// governs the *scheduled* path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationPolicy {
    /// Rotate once this many messages have been sent on the current epoch.
    /// `0` disables the message-count trigger.
    pub max_messages: u32,
    /// Rotate once this many seconds have elapsed since the epoch began.
    /// `0` disables the time trigger.
    pub max_age_secs: i64,
}

impl RotationPolicy {
    /// Blueprint default: rotate after 1000 messages.
    pub const DEFAULT_MAX_MESSAGES: u32 = 1000;
    /// Blueprint default: rotate after 24 hours.
    pub const DEFAULT_MAX_HOURS: i64 = 24;

    /// Build a policy from a message cap and an age cap in seconds.
    pub fn new(max_messages: u32, max_age_secs: i64) -> Self {
        Self {
            max_messages,
            max_age_secs,
        }
    }

    /// Build a policy from the app's stored config: a message cap and an age cap
    /// expressed in *hours* (the unit surfaced in Settings → Encryption). A
    /// non-positive hour count disables the time trigger.
    pub fn from_messages_and_hours(max_messages: u32, max_hours: i64) -> Self {
        let max_age_secs = max_hours.max(0).saturating_mul(3600);
        Self {
            max_messages,
            max_age_secs,
        }
    }

    /// A policy that never rotates on a schedule (pre-2.0.0 behavior).
    pub fn disabled() -> Self {
        Self {
            max_messages: 0,
            max_age_secs: 0,
        }
    }

    /// Whether either trigger is armed. When `false`, `should_rotate` is always
    /// `false`.
    pub fn is_enabled(&self) -> bool {
        self.max_messages > 0 || self.max_age_secs > 0
    }

    /// Decide whether the current epoch should rotate given how many messages it
    /// has sent and how long it has been open. Either armed trigger reaching its
    /// threshold fires; a `0` threshold is disarmed and never fires.
    pub fn should_rotate(&self, messages_since_rotation: u32, seconds_since_rotation: i64) -> bool {
        let by_count = self.max_messages > 0 && messages_since_rotation >= self.max_messages;
        let by_age = self.max_age_secs > 0 && seconds_since_rotation >= self.max_age_secs;
        by_count || by_age
    }
}

impl Default for RotationPolicy {
    /// The blueprint's seeded defaults: 1000 messages or 24 hours.
    fn default() -> Self {
        Self::from_messages_and_hours(Self::DEFAULT_MAX_MESSAGES, Self::DEFAULT_MAX_HOURS)
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

        let mut alice = RoomCrypto::new_for_room(
            db_alice.clone(),
            room_id.clone(),
            "alice-fp".into(),
            [0u8; 32],
        )
        .unwrap();
        let mut bob =
            RoomCrypto::new_for_room(db_bob.clone(), room_id.clone(), "bob-fp".into(), [0u8; 32])
                .unwrap();

        bob.add_inbound_session("alice-fp", &alice.our_session_key_b64())
            .unwrap();

        let (session_id, ciphertext) = alice.encrypt(b"hello group").unwrap();
        let (plaintext, index) = bob.decrypt("alice-fp", &session_id, &ciphertext).unwrap();
        assert_eq!(plaintext, b"hello group");
        // First message on a fresh outbound session is message_index 0.
        assert_eq!(index, 0);
    }

    #[test]
    fn bidirectional_round_trip() {
        let db_a = open_db_in_memory().unwrap();
        let db_b = open_db_in_memory().unwrap();
        let room_id = setup_room(&db_a, "r", "a-fp");
        setup_room(&db_b, "r", "a-fp");

        let mut alice =
            RoomCrypto::new_for_room(db_a.clone(), room_id.clone(), "a-fp".into(), [0u8; 32])
                .unwrap();
        let mut bob =
            RoomCrypto::new_for_room(db_b.clone(), room_id.clone(), "b-fp".into(), [0u8; 32])
                .unwrap();

        alice
            .add_inbound_session("b-fp", &bob.our_session_key_b64())
            .unwrap();
        bob.add_inbound_session("a-fp", &alice.our_session_key_b64())
            .unwrap();

        let (sid_a, ct_a) = alice.encrypt(b"from alice").unwrap();
        assert_eq!(bob.decrypt("a-fp", &sid_a, &ct_a).unwrap().0, b"from alice");

        let (sid_b, ct_b) = bob.encrypt(b"from bob").unwrap();
        assert_eq!(alice.decrypt("b-fp", &sid_b, &ct_b).unwrap().0, b"from bob");
    }

    #[test]
    fn outbound_persists_and_reloads() {
        let db = open_db_in_memory().unwrap();
        let room_id = setup_room(&db, "r", "me-fp");

        let mut crypto =
            RoomCrypto::new_for_room(db.clone(), room_id.clone(), "me-fp".into(), [0u8; 32])
                .unwrap();
        let original_session_id = crypto.our_session_id();
        let (_, _) = crypto.encrypt(b"advance the ratchet").unwrap();
        drop(crypto);

        let reloaded = RoomCrypto::load(db.clone(), room_id.clone(), "me-fp".into(), [0u8; 32])
            .unwrap()
            .expect("should have outbound session");
        assert_eq!(reloaded.our_session_id(), original_session_id);
    }

    #[test]
    fn decrypt_surfaces_monotonic_message_index() {
        // huddle 2.0.0 (F2): the message_index returned by decrypt is the
        // Megolm ratchet position. It starts at 0 and increments per encrypt,
        // and — because the inbound ratchet state is persisted on every
        // decrypt — continues from where it left off after a reload. The app
        // layer relies on (session_id, message_index) uniquely naming one
        // ciphertext to dedup replays.
        let db_alice = open_db_in_memory().unwrap();
        let db_bob = open_db_in_memory().unwrap();
        let room_id = setup_room(&db_alice, "test", "alice-fp");
        setup_room(&db_bob, "test", "alice-fp");

        let mut alice = RoomCrypto::new_for_room(
            db_alice.clone(),
            room_id.clone(),
            "alice-fp".into(),
            [0u8; 32],
        )
        .unwrap();
        let mut bob =
            RoomCrypto::new_for_room(db_bob.clone(), room_id.clone(), "bob-fp".into(), [0u8; 32])
                .unwrap();
        bob.add_inbound_session("alice-fp", &alice.our_session_key_b64())
            .unwrap();

        let (sid, ct0) = alice.encrypt(b"zero").unwrap();
        assert_eq!(bob.decrypt("alice-fp", &sid, &ct0).unwrap().1, 0);
        let (_, ct1) = alice.encrypt(b"one").unwrap();
        assert_eq!(bob.decrypt("alice-fp", &sid, &ct1).unwrap().1, 1);

        // Reload Bob's inbound session and decrypt the next message — the
        // ratchet (and thus message_index) continues from the persisted state.
        drop(bob);
        let mut bob = RoomCrypto::load(db_bob.clone(), room_id.clone(), "bob-fp".into(), [0u8; 32])
            .unwrap()
            .expect("bob has a persisted outbound session");
        let (_, ct2) = alice.encrypt(b"two").unwrap();
        assert_eq!(bob.decrypt("alice-fp", &sid, &ct2).unwrap().1, 2);
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

        let mut alice = RoomCrypto::new_for_room(
            db_alice.clone(),
            room_id.clone(),
            "alice-fp".into(),
            [0u8; 32],
        )
        .unwrap();
        let mut bob =
            RoomCrypto::new_for_room(db_bob.clone(), room_id.clone(), "bob-fp".into(), [0u8; 32])
                .unwrap();

        // Alice holds an inbound session from Bob and can decrypt his messages.
        alice
            .add_inbound_session("bob-fp", &bob.our_session_key_b64())
            .unwrap();
        let (sid1, ct1) = bob.encrypt(b"before rotate").unwrap();
        assert_eq!(
            alice.decrypt("bob-fp", &sid1, &ct1).unwrap().0,
            b"before rotate"
        );

        let old_outbound = alice.our_session_id();

        // Rotate Alice's outbound session.
        alice.rotate_outbound().unwrap();
        let new_outbound = alice.our_session_id();
        assert_ne!(
            old_outbound, new_outbound,
            "rotate must mint a fresh outbound session"
        );

        // Inbound from Bob is preserved — Alice still decrypts his next message.
        let (sid2, ct2) = bob.encrypt(b"after rotate").unwrap();
        assert_eq!(
            alice.decrypt("bob-fp", &sid2, &ct2).unwrap().0,
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
        let reloaded = RoomCrypto::load(
            db_alice.clone(),
            room_id.clone(),
            "alice-fp".into(),
            [0u8; 32],
        )
        .unwrap()
        .expect("outbound session present");
        assert_eq!(reloaded.our_session_id(), new_outbound);
    }

    #[test]
    fn message_count_increments_on_encrypt() {
        // huddle 2.0.0 (F4): each encrypt advances the epoch message counter
        // the app reads to schedule rotation. Fresh session starts at 0.
        let db = open_db_in_memory().unwrap();
        let room_id = setup_room(&db, "r", "me-fp");
        let mut crypto =
            RoomCrypto::new_for_room(db.clone(), room_id.clone(), "me-fp".into(), [0u8; 32])
                .unwrap();
        assert_eq!(crypto.messages_since_rotation(), 0);
        for _ in 0..3 {
            crypto.encrypt(b"msg").unwrap();
        }
        assert_eq!(crypto.messages_since_rotation(), 3);
    }

    #[test]
    fn rotate_outbound_resets_message_count() {
        // huddle 2.0.0 (F4): rotating mints a fresh outbound session AND resets
        // the epoch bookkeeping so the next epoch counts from zero.
        let db = open_db_in_memory().unwrap();
        let room_id = setup_room(&db, "r", "me-fp");
        let mut crypto =
            RoomCrypto::new_for_room(db.clone(), room_id.clone(), "me-fp".into(), [0u8; 32])
                .unwrap();
        for _ in 0..5 {
            crypto.encrypt(b"msg").unwrap();
        }
        assert_eq!(crypto.messages_since_rotation(), 5);
        let old_session = crypto.our_session_id();

        crypto.rotate_outbound().unwrap();
        assert_ne!(
            crypto.our_session_id(),
            old_session,
            "rotate mints a new session"
        );
        assert_eq!(
            crypto.messages_since_rotation(),
            0,
            "rotate resets the epoch counter"
        );
    }

    #[test]
    fn restore_rotation_state_rehydrates_after_load() {
        // huddle 2.0.0 (F4): the durable counter lives in the app's
        // room_megolm_rotation_state table, not the session pickles, so a fresh
        // `load` starts at zero and the app rehydrates via restore_rotation_state.
        let db = open_db_in_memory().unwrap();
        let room_id = setup_room(&db, "r", "me-fp");
        let mut crypto =
            RoomCrypto::new_for_room(db.clone(), room_id.clone(), "me-fp".into(), [0u8; 32])
                .unwrap();
        crypto.encrypt(b"one").unwrap();
        crypto.encrypt(b"two").unwrap();
        crypto.encrypt(b"three").unwrap();
        assert_eq!(crypto.messages_since_rotation(), 3);
        drop(crypto);

        let mut reloaded = RoomCrypto::load(db.clone(), room_id.clone(), "me-fp".into(), [0u8; 32])
            .unwrap()
            .expect("outbound session present");
        assert_eq!(
            reloaded.messages_since_rotation(),
            0,
            "load starts the counter at zero"
        );

        reloaded.restore_rotation_state(3, 1000);
        assert_eq!(reloaded.messages_since_rotation(), 3);
        assert_eq!(reloaded.last_rotation_at(), 1000);

        // Counting continues from the rehydrated value.
        reloaded.encrypt(b"four").unwrap();
        reloaded.encrypt(b"five").unwrap();
        assert_eq!(reloaded.messages_since_rotation(), 5);
    }

    #[test]
    fn rotation_policy_triggers_and_disables() {
        // Message-count trigger fires at/after the threshold.
        let by_count = RotationPolicy::new(5, 0);
        assert!(by_count.is_enabled());
        assert!(!by_count.should_rotate(4, 0));
        assert!(by_count.should_rotate(5, 0));
        assert!(by_count.should_rotate(6, 0));

        // Age trigger: hours convert to seconds, fires at/after the threshold.
        let by_age = RotationPolicy::from_messages_and_hours(0, 1);
        assert_eq!(by_age.max_age_secs, 3600);
        assert!(!by_age.should_rotate(10_000, 3599));
        assert!(by_age.should_rotate(0, 3600));

        // Disabled: neither trigger ever fires, regardless of bookkeeping.
        let off = RotationPolicy::disabled();
        assert!(!off.is_enabled());
        assert!(!off.should_rotate(u32::MAX, i64::MAX));

        // Blueprint defaults: 1000 messages or 24 hours.
        let dflt = RotationPolicy::default();
        assert_eq!(dflt.max_messages, 1000);
        assert_eq!(dflt.max_age_secs, 24 * 3600);
    }

    #[test]
    fn should_rotate_reads_live_bookkeeping() {
        // huddle 2.0.0 (F4): the RoomCrypto convenience wires the live epoch
        // counter into a policy and clears after a rotation.
        let db = open_db_in_memory().unwrap();
        let room_id = setup_room(&db, "r", "me-fp");
        let mut crypto =
            RoomCrypto::new_for_room(db.clone(), room_id.clone(), "me-fp".into(), [0u8; 32])
                .unwrap();
        let policy = RotationPolicy::new(3, 0);

        crypto.encrypt(b"a").unwrap();
        crypto.encrypt(b"b").unwrap();
        assert!(!crypto.should_rotate(&policy));
        crypto.encrypt(b"c").unwrap();
        assert!(crypto.should_rotate(&policy));

        // After rotating, the epoch is fresh and no longer trips the policy.
        crypto.rotate_outbound().unwrap();
        assert!(!crypto.should_rotate(&policy));
    }

    #[test]
    fn decrypt_unknown_sender_errors() {
        let db = open_db_in_memory().unwrap();
        let room_id = setup_room(&db, "r", "me-fp");
        let mut crypto =
            RoomCrypto::new_for_room(db.clone(), room_id.clone(), "me-fp".into(), [0u8; 32])
                .unwrap();
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
