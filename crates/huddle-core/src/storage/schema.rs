pub const MIGRATIONS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS identity (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        ed25519_secret BLOB NOT NULL,
        olm_account_data BLOB NOT NULL,
        created_at INTEGER NOT NULL
    );",
    "CREATE TABLE IF NOT EXISTS peers (
        peer_id TEXT PRIMARY KEY,
        fingerprint TEXT NOT NULL,
        display_name TEXT,
        olm_session_data BLOB,
        last_seen INTEGER
    );",
    "CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        peer_id TEXT NOT NULL REFERENCES peers(peer_id),
        direction TEXT NOT NULL CHECK (direction IN ('in', 'out')),
        body TEXT NOT NULL,
        sent_at INTEGER NOT NULL,
        delivered_at INTEGER
    );",
    "CREATE INDEX IF NOT EXISTS idx_messages_peer ON messages(peer_id, sent_at);",
];
