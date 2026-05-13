pub mod keychain;
pub mod repo;
pub mod schema;

use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::error::Result;

pub type Db = Arc<Mutex<Connection>>;

/// Open the DB. If `master_key` is `Some`, SQLCipher is unlocked with
/// `PRAGMA key`; otherwise the DB is opened unencrypted (the Phase 1
/// path, kept for tests and `--no-master-passphrase` runs).
pub fn open_db(path: &Path, master_key: Option<&[u8; 32]>) -> Result<Db> {
    let conn = Connection::open(path)?;
    if let Some(key) = master_key {
        let pragma = format!("PRAGMA key = \"x'{}'\";", hex::encode(key));
        conn.execute_batch(&pragma)?;
    }
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
    run_migrations(&conn)?;
    Ok(Arc::new(Mutex::new(conn)))
}

pub fn open_db_in_memory() -> Result<Db> {
    let conn = Connection::open_in_memory()?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;
    run_migrations(&conn)?;
    Ok(Arc::new(Mutex::new(conn)))
}

fn run_migrations(conn: &Connection) -> Result<()> {
    for migration in schema::MIGRATIONS {
        if let Err(e) = conn.execute_batch(migration) {
            let msg = e.to_string().to_lowercase();
            // Tolerate idempotent additive migrations on existing DBs
            // (ALTER TABLE ... ADD COLUMN runs every launch but errors
            // on the second run; CREATE INDEX IF NOT EXISTS already
            // handles itself).
            if msg.contains("duplicate column")
                || msg.contains("already exists")
                || msg.contains("duplicate column name")
            {
                continue;
            }
            return Err(e.into());
        }
    }
    Ok(())
}
