pub mod keychain;
pub mod repo;
pub mod schema;

use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::error::{HuddleError, Result};

pub type Db = Arc<Mutex<Connection>>;

/// Open the DB. If `master_key` is `Some`, SQLCipher is unlocked with
/// `PRAGMA key`; otherwise the DB is opened unencrypted (the Phase 1
/// path, kept for tests and `--no-master-passphrase` runs).
///
/// huddle 0.7.11: after `PRAGMA key` we run a sentinel query that
/// forces SQLCipher to actually try to decrypt a page. A wrong master
/// key (typo on the prompt) used to surface as a cryptic "file is not
/// a database" error from a downstream `CREATE TABLE`; we now catch
/// it here and return a clean "wrong master passphrase" message.
pub fn open_db(path: &Path, master_key: Option<&[u8; 32]>) -> Result<Db> {
    let conn = Connection::open(path)?;
    if let Some(key) = master_key {
        let pragma = format!("PRAGMA key = \"x'{}'\";", hex::encode(key));
        conn.execute_batch(&pragma)?;
        // Sentinel query: forces decryption of page 1. If the key is
        // wrong, SQLCipher returns an error here with a recognizable
        // shape — turn it into a domain-specific error so the TUI can
        // re-prompt rather than crashing with a generic message.
        if let Err(e) = conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        }) {
            return Err(HuddleError::Session(format!(
                "wrong master passphrase, or DB file corrupt: {e}"
            )));
        }
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
///
/// huddle 0.7.11: each migration runs inside a transaction that ALSO
/// bumps `user_version`. Pre-0.7.11 a partial-batch failure (e.g. the
/// second statement in a multi-statement migration errored) left the
/// schema in a half-applied state with `user_version` un-bumped, so
/// the next launch retried the first statement (now a duplicate) and
/// wedged startup forever. Wrapping in a tx means a failure rolls back
/// cleanly.
fn run_migrations(conn: &Connection) -> Result<()> {
    let applied: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    for (idx, migration) in schema::MIGRATIONS.iter().enumerate() {
        if (idx as i64) < applied {
            continue;
        }
        // Atomic apply: migration + version bump in one transaction.
        let target = (idx + 1) as i64;
        let batch = format!(
            "BEGIN; {migration}; PRAGMA user_version = {target}; COMMIT;",
            migration = migration,
            target = target
        );
        if let Err(e) = conn.execute_batch(&batch) {
            // Best-effort rollback (no-op if not in a tx).
            let _ = conn.execute_batch("ROLLBACK;");
            return Err(HuddleError::Other(format!(
                "migration {idx} failed: {e}"
            )));
        }
    }
    Ok(())
}
