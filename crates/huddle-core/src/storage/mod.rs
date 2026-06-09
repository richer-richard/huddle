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

/// Re-encrypt the open SQLCipher database in place under `new_key` for the
/// huddle 2.0.0 master-passphrase change (F5).
///
/// `PRAGMA rekey` rewrites every page with the new key as one atomic
/// SQLCipher operation; we then run the same sentinel query as `open_db` to
/// prove the connection now decrypts under the new key before the caller
/// commits the rest of the rotation (re-persisting the Megolm subkey and
/// writing the new salt via `keychain::rotate_salt`). A botched rekey thus
/// surfaces here as a clean domain error rather than as a cryptic failure on
/// the next unrelated statement.
///
/// Rollback safety: SQLCipher's rekey is all-or-nothing, so a failure here
/// leaves the database readable under the *old* key. Because the caller only
/// rotates `keychain.salt` after this returns `Ok`, an aborted change always
/// recovers to the previous passphrase on the next launch.
pub fn rekey_db(conn: &Connection, new_key: &[u8; 32]) -> Result<()> {
    let pragma = format!("PRAGMA rekey = \"x'{}'\";", hex::encode(new_key));
    conn.execute_batch(&pragma)?;
    // Sentinel: force a page decryption under the freshly-installed key.
    if let Err(e) = conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    }) {
        return Err(HuddleError::Session(format!(
            "database rekey did not verify under the new master key: {e}"
        )));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    // huddle 2.0.0 (F5): rekey must atomically swap the master key — the old
    // key can no longer open the DB, the new key can, and no rows are lost.
    #[test]
    fn rekey_swaps_the_master_key_without_data_loss() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rekey.db");
        let old_key = [0x11u8; 32];
        let new_key = [0x22u8; 32];

        // Create an encrypted DB under the old key, write a row, then rekey.
        {
            let db = open_db(&path, Some(&old_key)).unwrap();
            let conn = db.lock().unwrap();
            conn.execute_batch("CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('hi');")
                .unwrap();
            rekey_db(&conn, &new_key).unwrap();
        }

        // The old key must no longer open it — a clean error, not a panic.
        assert!(open_db(&path, Some(&old_key)).is_err());

        // The new key opens it and the data survived the rekey intact.
        let db = open_db(&path, Some(&new_key)).unwrap();
        let conn = db.lock().unwrap();
        let v: String = conn.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(v, "hi");
    }
}
