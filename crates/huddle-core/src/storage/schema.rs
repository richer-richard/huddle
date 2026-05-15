pub const MIGRATIONS: &[&str] = &[
    // Our Ed25519 secret. olm_account_data left for forward compat but unused.
    "CREATE TABLE IF NOT EXISTS identity (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        ed25519_secret BLOB NOT NULL,
        olm_account_data BLOB,
        created_at INTEGER NOT NULL
    );",
    // Rooms we've created or joined
    "CREATE TABLE IF NOT EXISTS rooms (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        creator_fingerprint TEXT NOT NULL,
        encrypted INTEGER NOT NULL,
        passphrase_salt BLOB,
        created_at INTEGER NOT NULL,
        last_active INTEGER
    );",
    // Per-room Megolm sessions: ours (outbound) and others' (inbound)
    "CREATE TABLE IF NOT EXISTS room_megolm_sessions (
        room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
        sender_fingerprint TEXT NOT NULL,
        session_id TEXT NOT NULL,
        session_data BLOB NOT NULL,
        is_outbound INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (room_id, sender_fingerprint, session_id)
    );",
    // Known members of each room, keyed by their fingerprint (the stable
    // cryptographic identity). peer_id is informational and often unknown
    // at the app layer, so it is not part of the primary key.
    "CREATE TABLE IF NOT EXISTS room_members (
        room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
        peer_id TEXT NOT NULL DEFAULT '',
        fingerprint TEXT NOT NULL,
        last_seen INTEGER,
        PRIMARY KEY (room_id, fingerprint)
    );",
    "CREATE TABLE IF NOT EXISTS room_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
        sender_fingerprint TEXT NOT NULL,
        direction TEXT NOT NULL CHECK (direction IN ('in', 'out')),
        body TEXT NOT NULL,
        sent_at INTEGER NOT NULL
    );",
    "CREATE INDEX IF NOT EXISTS idx_room_messages_room ON room_messages(room_id, sent_at);",
    "CREATE INDEX IF NOT EXISTS idx_room_members_room ON room_members(room_id);",
    // Peers we've manually dialed. We auto-reconnect on the next launch so
    // the user doesn't have to retype an address to rejoin a room.
    "CREATE TABLE IF NOT EXISTS known_peers (
        address TEXT PRIMARY KEY,
        label TEXT,
        last_connected_at INTEGER,
        last_attempt_at INTEGER,
        created_at INTEGER NOT NULL
    );",
    // File attachments offered / received in a room. A row is created
    // the moment we see a FileOffer; status moves through the lifecycle
    // as chunks arrive and the user activates the card.
    "CREATE TABLE IF NOT EXISTS room_attachments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
        message_id INTEGER,
        sender_fingerprint TEXT NOT NULL,
        file_id TEXT NOT NULL,
        name TEXT NOT NULL,
        mime TEXT,
        size_bytes INTEGER NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('offered','downloading','ready','saved','failed','cancelled')),
        cache_path TEXT,
        saved_path TEXT,
        error TEXT,
        encrypted INTEGER NOT NULL DEFAULT 0,
        wrapped_key TEXT,
        nonce TEXT,
        megolm_session_id TEXT,
        content_hash TEXT,
        created_at INTEGER NOT NULL,
        UNIQUE(room_id, file_id)
    );",
    "CREATE INDEX IF NOT EXISTS idx_room_attachments_room ON room_attachments(room_id);",
    // Phase 5: contact verification — user marks a member's fingerprint
    // as verified after comparing it out-of-band. Default 0 (unverified).
    "ALTER TABLE room_members ADD COLUMN verified INTEGER NOT NULL DEFAULT 0;",
    // Phase 6 QoL: per-room mute flag.
    "ALTER TABLE rooms ADD COLUMN muted INTEGER NOT NULL DEFAULT 0;",
    // Phase 6: display names — our own, plus per-room remembered names
    // of other members.
    "ALTER TABLE identity ADD COLUMN display_name TEXT;",
    "ALTER TABLE room_members ADD COLUMN display_name TEXT;",
    // Phase 0 (v0.3.0): app-level signed message envelopes. Members learn
    // each others' pubkeys from `MemberAnnounce.sender_ed25519_pubkey`
    // and persist them here so `SignedRoomMessage` envelopes can be
    // verified without re-asking the network on every message.
    "ALTER TABLE room_members ADD COLUMN ed25519_pubkey TEXT;",
    // Phase A (v0.3.0): inbound-dial accept. Trusted=1 means an inbound
    // connection from a peer with this fingerprint bypasses the prompt.
    // Fingerprint is learned from Identify after the dial completes, so
    // it's nullable on pre-Phase-A rows.
    "ALTER TABLE known_peers ADD COLUMN fingerprint TEXT;",
    "ALTER TABLE known_peers ADD COLUMN trusted INTEGER NOT NULL DEFAULT 0;",
    // Phase A: a fingerprint the user has explicitly rejected. Inbound
    // connections from a blocked fingerprint are auto-disconnected on
    // every restart (the in-memory blocklist on its own would reset).
    "CREATE TABLE IF NOT EXISTS blocked_peers (
        fingerprint TEXT PRIMARY KEY,
        blocked_at INTEGER NOT NULL
    );",
];
