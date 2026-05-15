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

/// Apply pending schema migrations, tracked by `PRAGMA user_version`.
/// Each entry in `schema::MIGRATIONS` runs exactly once, in order; the
/// version cursor advances after each so a real SQL error aborts startup
/// instead of being silently swallowed. Migrations are therefore
/// append-only — never reorder or delete an existing entry.
fn run_migrations(conn: &Connection) -> Result<()> {
    let applied: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    for (idx, migration) in schema::MIGRATIONS.iter().enumerate() {
        if (idx as i64) < applied {
            continue;
        }
        conn.execute_batch(migration)?;
        // `PRAGMA user_version` does not accept bound parameters.
        conn.execute_batch(&format!("PRAGMA user_version = {};", idx + 1))?;
    }
    Ok(())
}
