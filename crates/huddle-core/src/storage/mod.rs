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
/// prove the connection now decrypts under the new key. The caller re-encrypts
/// the Megolm session pickles under the new persist subkey *before* this call,
/// so once the rekey commits the whole rotation is durable. A botched rekey
/// surfaces here as a clean domain error rather than as a cryptic failure on
/// the next unrelated statement.
///
/// Rollback safety: SQLCipher's rekey is all-or-nothing, so a failure here
/// leaves the database readable under the *old* key. The F5 change flow keeps
/// `keychain.salt` fixed (it never rotates the salt), so the new master key is
/// re-derived purely from the new passphrase — this `PRAGMA rekey` is the sole
/// commit point, and an aborted change always recovers to the previous
/// passphrase on the next launch with no salt-write window to brick the DB.
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
            return Err(HuddleError::Other(format!("migration {idx} failed: {e}")));
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

    // huddle 2.0.0 (F5 CRITICAL): a passphrase change re-derives the new master
    // key from the new passphrase against the SAME salt, then rekeys — it must
    // NOT rotate the salt. This proves the salt-free rotation round-trips end to
    // end: the new passphrase opens the DB, the old no longer does, and the row
    // survives. Because no salt is written, there is no post-rekey salt-write
    // failure window that could leave the on-disk salt deriving the old key while
    // the DB is encrypted under the new one (the bug this fix removes).
    #[test]
    fn passphrase_change_rekeys_without_rotating_the_salt() {
        use keychain::{derive_master_key, derive_subkey};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rekey-fixed-salt.db");
        // One fixed salt for both derivations — exactly what the change flow does.
        let salt = [0x5au8; keychain::KEYCHAIN_SALT_LEN];

        let old_master = derive_master_key("old-pass", &salt).unwrap();
        let new_master = derive_master_key("new-pass", &salt).unwrap();
        // Same salt + a different passphrase already yields a different key — the
        // whole premise for never needing to rotate the salt.
        assert_ne!(old_master, new_master);
        // ...and a different Megolm persist subkey, so the pickles genuinely must
        // be re-encrypted across the change (the work the held lock protects).
        assert_ne!(
            derive_subkey(&old_master, b"megolm-persist"),
            derive_subkey(&new_master, b"megolm-persist")
        );

        {
            let db = open_db(&path, Some(&old_master)).unwrap();
            let conn = db.lock().unwrap();
            conn.execute_batch("CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('keep');")
                .unwrap();
            rekey_db(&conn, &new_master).unwrap();
        }

        // The old passphrase's key can no longer open it; the new one can and the
        // row survived — all without ever touching the salt on disk.
        assert!(open_db(&path, Some(&old_master)).is_err());
        let db = open_db(&path, Some(&new_master)).unwrap();
        let conn = db.lock().unwrap();
        let v: String = conn.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(v, "keep");
    }
}
