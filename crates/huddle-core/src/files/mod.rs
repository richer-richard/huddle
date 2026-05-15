//! File transfer: chunking, reassembly, hash verification, cache, save.
//!
//! Cache layout:
//!   <data_dir>/files/cache/<file_id>          // verified, complete
//!   <data_dir>/files/cache/<file_id>.part     // in-progress reassembly
//!
//! File-IDs are the SHA-256 hash of the wire bytes (plaintext for
//! non-encrypted offers, ciphertext for encrypted offers — the
//! encryption layer is a separate concern). Receivers verify each
//! completed transfer's bytes match the announced file_id before
//! exposing the file to the caller.

pub mod encryption;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sha2::{Digest, Sha256};

use crate::error::{HuddleError, Result};

/// Bytes per chunk on the wire. A `FileChunk` is base64-encoded inside a
/// JSON envelope, so the raw chunk must leave room for ~34% base64
/// expansion plus the envelope and still fit under gossipsub's transmit
/// limit. 40 KiB raw → ~55 KiB on the wire, comfortably under even the
/// 64 KiB gossipsub default (and well under the 256 KiB ceiling huddle
/// sets explicitly — see `network::start_network_with`).
pub const CHUNK_SIZE: usize = 40 * 1024;

/// Hard cap on a single offer for Phase 2. Larger files defer to a
/// dedicated libp2p stream protocol (see plan.md Phase 3 notes).
pub const MAX_FILE_SIZE: u64 = 1024 * 1024;

/// What `prepare_outgoing` hands back: enough to drive a sequence of
/// FileOffer + N FileChunk gossipsub messages.
#[derive(Debug, Clone)]
pub struct OutgoingPlan {
    pub file_id: String,
    pub name: String,
    pub mime: Option<String>,
    pub size_bytes: u64,
    pub chunks: Vec<Vec<u8>>,
}

/// What `accept_chunk` returns on the chunk that completes the transfer.
#[derive(Debug, Clone)]
pub struct CompletedFile {
    pub file_id: String,
    pub cache_path: PathBuf,
    pub size_bytes: u64,
}

struct IncomingTransfer {
    expected_total: u32,
    /// Announced total file size. Seeded from the caller's best guess
    /// (the offer's `size_bytes`, or `MAX_FILE_SIZE` when chunks arrive
    /// before the offer) and corrected by `set_expected_size` once the
    /// offer lands. Drives the progress bar's denominator.
    expected_size: u64,
    chunks: HashMap<u32, Vec<u8>>,
    bytes_received: u64,
}

pub struct FileManager {
    cache_dir: PathBuf,
    incoming: Mutex<HashMap<String, IncomingTransfer>>,
}

impl FileManager {
    /// `data_dir` is huddle's per-user data directory; the cache lives
    /// underneath at `<data_dir>/files/cache`.
    pub fn new(data_dir: &Path) -> Result<Self> {
        let cache_dir = data_dir.join("files").join("cache");
        fs::create_dir_all(&cache_dir)?;
        Ok(Self {
            cache_dir,
            incoming: Mutex::new(HashMap::new()),
        })
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    pub fn cache_path(&self, file_id: &str) -> PathBuf {
        self.cache_dir.join(file_id)
    }

    /// Read a previously-completed transfer's bytes from cache.
    pub fn read_cache(&self, file_id: &str) -> Result<Vec<u8>> {
        let path = self.cache_path(file_id);
        Ok(fs::read(&path)?)
    }

    /// Build a transfer plan from an on-disk file.
    pub fn prepare_outgoing_from_path(&self, path: &Path) -> Result<OutgoingPlan> {
        let bytes = fs::read(path)?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "untitled".into());
        let mime = guess_mime(&name);
        self.prepare_outgoing_from_bytes(&name, mime, bytes)
    }

    /// Build a transfer plan from an in-memory blob (useful for the
    /// encrypted path, where the caller pre-encrypts a file).
    pub fn prepare_outgoing_from_bytes(
        &self,
        name: &str,
        mime: Option<String>,
        bytes: Vec<u8>,
    ) -> Result<OutgoingPlan> {
        let size = bytes.len() as u64;
        if size > MAX_FILE_SIZE {
            return Err(HuddleError::Other(format!(
                "file is {} bytes — Phase 2 cap is {} (~1 MiB)",
                size, MAX_FILE_SIZE
            )));
        }
        let file_id = sha256_hex(&bytes);
        let chunks: Vec<Vec<u8>> = bytes.chunks(CHUNK_SIZE).map(|c| c.to_vec()).collect();
        let chunks = if chunks.is_empty() {
            vec![Vec::new()]
        } else {
            chunks
        };

        // Stash the outgoing file into our own cache too — that way the
        // sender's UI can show the same "ready" card and re-save it
        // later without a round-trip.
        let cache_path = self.cache_path(&file_id);
        if !cache_path.exists() {
            fs::write(&cache_path, &bytes)?;
        }

        Ok(OutgoingPlan {
            file_id,
            name: name.to_string(),
            mime,
            size_bytes: size,
            chunks,
        })
    }

    /// Accept one chunk of an incoming transfer. Returns `Some` only on
    /// the last chunk that completes the file (after SHA-256 verification).
    pub fn accept_chunk(
        &self,
        file_id: &str,
        chunk_index: u32,
        total_chunks: u32,
        data: Vec<u8>,
        expected_size: u64,
    ) -> Result<Option<CompletedFile>> {
        if expected_size > MAX_FILE_SIZE {
            return Err(HuddleError::Other(format!(
                "incoming size {} exceeds Phase 2 cap",
                expected_size
            )));
        }
        // Fast-skip if already complete.
        let cache_path = self.cache_path(file_id);
        if cache_path.exists() {
            let bytes = fs::read(&cache_path)?;
            if sha256_hex(&bytes) == file_id {
                return Ok(Some(CompletedFile {
                    file_id: file_id.into(),
                    cache_path,
                    size_bytes: bytes.len() as u64,
                }));
            }
        }

        let mut map = self.incoming.lock().unwrap();
        let entry = map.entry(file_id.to_string()).or_insert(IncomingTransfer {
            expected_total: total_chunks,
            expected_size,
            chunks: HashMap::new(),
            bytes_received: 0,
        });
        if entry.expected_total != total_chunks {
            return Err(HuddleError::Other(
                "chunk total disagrees with prior chunks".into(),
            ));
        }
        if !entry.chunks.contains_key(&chunk_index) {
            entry.bytes_received += data.len() as u64;
            entry.chunks.insert(chunk_index, data);
        }

        if entry.chunks.len() as u32 != entry.expected_total {
            return Ok(None);
        }

        // All chunks arrived — assemble and verify.
        let total = entry.expected_total;
        let mut assembled: Vec<u8> = Vec::with_capacity(entry.bytes_received as usize);
        for idx in 0..total {
            let part = entry
                .chunks
                .get(&idx)
                .ok_or_else(|| HuddleError::Other(format!("missing chunk {idx}")))?;
            assembled.extend_from_slice(part);
        }
        map.remove(file_id);
        drop(map);

        let computed = sha256_hex(&assembled);
        if computed != file_id {
            return Err(HuddleError::Other(format!(
                "hash mismatch — expected {}, got {}",
                file_id, computed
            )));
        }
        // Write to a `.part` then atomically rename — never expose a
        // partial file under the final name.
        let part = self.cache_dir.join(format!("{}.part", file_id));
        fs::write(&part, &assembled)?;
        fs::rename(&part, &cache_path)?;

        Ok(Some(CompletedFile {
            file_id: file_id.into(),
            cache_path,
            size_bytes: assembled.len() as u64,
        }))
    }

    /// Drop any partial state for an incoming transfer.
    pub fn cancel_incoming(&self, file_id: &str) {
        self.incoming.lock().unwrap().remove(file_id);
    }

    /// Record the authoritative total size for an in-progress transfer —
    /// called when a FileOffer arrives after chunks have already started,
    /// so the progress denominator stops being a guess. No-op when there
    /// is no active transfer for `file_id`.
    pub fn set_expected_size(&self, file_id: &str, size: u64) {
        if let Some(e) = self.incoming.lock().unwrap().get_mut(file_id) {
            e.expected_size = size;
        }
    }

    /// Bytes received so far and the expected total, for an in-progress
    /// transfer.
    pub fn progress(&self, file_id: &str) -> Option<(u64, u64)> {
        let map = self.incoming.lock().unwrap();
        let e = map.get(file_id)?;
        Some((e.bytes_received, e.expected_size))
    }

    /// Copy `bytes` into the platform's Downloads folder under
    /// `target_name` (with `-N` suffix on collision). Returns the
    /// absolute path of the saved file.
    pub fn write_to_downloads(&self, target_name: &str, bytes: &[u8]) -> Result<PathBuf> {
        let dir = dirs::download_dir()
            .or_else(dirs::home_dir)
            .ok_or_else(|| HuddleError::Other("no Downloads / home directory".into()))?;
        fs::create_dir_all(&dir)?;
        let sanitized = sanitize_filename(target_name);
        let path = pick_non_colliding(&dir, &sanitized);
        fs::write(&path, bytes)?;
        Ok(path)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    hex::encode(hash)
}

fn sanitize_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches(|c: char| c == ' ' || c == '.');
    if trimmed.is_empty() {
        "untitled".into()
    } else {
        trimmed.to_string()
    }
}

fn pick_non_colliding(dir: &Path, name: &str) -> PathBuf {
    let base = dir.join(name);
    if !base.exists() {
        return base;
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) => (s.to_string(), format!(".{e}")),
        None => (name.to_string(), String::new()),
    };
    for n in 1..1000 {
        let candidate = dir.join(format!("{stem}-{n}{ext}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    dir.join(format!("{stem}-collision{ext}"))
}

/// Best-effort MIME guess from a filename. Returns None for unknown
/// extensions — receivers should not depend on this being present.
pub fn guess_mime(name: &str) -> Option<String> {
    let lower = name.to_lowercase();
    let ext = lower.rsplit('.').next()?;
    let m = match ext {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "pdf" => "application/pdf",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "txt" => "text/plain",
        "md" => "text/markdown",
        "json" => "application/json",
        "zip" => "application/zip",
        "tar" => "application/x-tar",
        "gz" => "application/gzip",
        "rs" => "text/x-rust",
        "py" => "text/x-python",
        _ => return None,
    };
    Some(m.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_manager() -> (FileManager, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let m = FileManager::new(dir.path()).expect("new");
        (m, dir)
    }

    #[test]
    fn sanitize_strips_slashes_and_control_chars() {
        // Leading `..` is stripped (no hidden traversal); inner is fine
        // because slashes are already replaced with `_`.
        assert_eq!(sanitize_filename("../../etc/passwd"), "_.._etc_passwd");
        assert_eq!(sanitize_filename("file/with\\path"), "file_with_path");
        assert_eq!(sanitize_filename(""), "untitled");
        assert_eq!(sanitize_filename("..."), "untitled");
    }

    #[test]
    fn collision_picks_dash_suffix() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path();
        let first = pick_non_colliding(p, "a.txt");
        std::fs::write(&first, b"x").unwrap();
        let second = pick_non_colliding(p, "a.txt");
        assert_eq!(second.file_name().unwrap().to_str().unwrap(), "a-1.txt");
        std::fs::write(&second, b"x").unwrap();
        let third = pick_non_colliding(p, "a.txt");
        assert_eq!(third.file_name().unwrap().to_str().unwrap(), "a-2.txt");
    }

    #[test]
    fn mime_lookup() {
        assert_eq!(guess_mime("photo.png").as_deref(), Some("image/png"));
        assert_eq!(guess_mime("notes.md").as_deref(), Some("text/markdown"));
        assert!(guess_mime("unknown.xyz").is_none());
    }

    #[test]
    fn outgoing_plan_round_trip_with_chunking() {
        let (mgr, _t) = fresh_manager();
        let bytes: Vec<u8> = (0..200_000u32).map(|i| (i & 0xFF) as u8).collect();
        let plan = mgr
            .prepare_outgoing_from_bytes("file.bin", None, bytes.clone())
            .unwrap();
        let expected_chunks = (bytes.len() + CHUNK_SIZE - 1) / CHUNK_SIZE;
        assert_eq!(plan.chunks.len(), expected_chunks);
        assert_eq!(plan.size_bytes, bytes.len() as u64);

        // Reassemble via accept_chunk into a fresh manager — should hit
        // hash-verification path and produce a cache file.
        let (mgr2, _t2) = fresh_manager();
        let total = plan.chunks.len() as u32;
        let mut completion: Option<CompletedFile> = None;
        for (i, chunk) in plan.chunks.iter().enumerate() {
            let c = mgr2
                .accept_chunk(&plan.file_id, i as u32, total, chunk.clone(), plan.size_bytes)
                .unwrap();
            if c.is_some() {
                completion = c;
            }
        }
        let done = completion.expect("completion on last chunk");
        assert_eq!(done.file_id, plan.file_id);
        assert!(done.cache_path.exists());
        let back = std::fs::read(&done.cache_path).unwrap();
        assert_eq!(back, bytes);
    }

    #[test]
    fn duplicate_chunks_are_ignored_no_double_count() {
        let (mgr, _t) = fresh_manager();
        let plan = mgr
            .prepare_outgoing_from_bytes("x.bin", None, vec![7u8; 200_000])
            .unwrap();
        let total = plan.chunks.len() as u32;
        let (mgr2, _t2) = fresh_manager();
        // Send chunk 0 twice — should not corrupt accounting.
        mgr2.accept_chunk(
            &plan.file_id,
            0,
            total,
            plan.chunks[0].clone(),
            plan.size_bytes,
        )
        .unwrap();
        mgr2.accept_chunk(
            &plan.file_id,
            0,
            total,
            plan.chunks[0].clone(),
            plan.size_bytes,
        )
        .unwrap();
        // Send remaining chunks.
        for i in 1..total {
            let r = mgr2
                .accept_chunk(
                    &plan.file_id,
                    i,
                    total,
                    plan.chunks[i as usize].clone(),
                    plan.size_bytes,
                )
                .unwrap();
            if i + 1 == total {
                assert!(r.is_some(), "completion should fire on last chunk");
            }
        }
    }

    #[test]
    fn hash_mismatch_is_rejected() {
        let (mgr, _t) = fresh_manager();
        let bytes = vec![1u8; 100];
        let plan = mgr
            .prepare_outgoing_from_bytes("x.bin", None, bytes)
            .unwrap();
        // Tamper with chunk 0.
        let (mgr2, _t2) = fresh_manager();
        let mut bad = plan.chunks[0].clone();
        bad[0] = bad[0].wrapping_add(1);
        let total = plan.chunks.len() as u32;
        let err = mgr2
            .accept_chunk(&plan.file_id, 0, total, bad, plan.size_bytes)
            .err();
        // Single-chunk file: completion attempted on the only chunk →
        // hash mismatch surfaces immediately.
        if total == 1 {
            assert!(err.is_some(), "expected hash mismatch error");
        }
    }

    #[test]
    fn write_to_downloads_collision_suffixes() {
        let tmp = tempfile::tempdir().unwrap();
        let dl = tmp.path().to_path_buf();
        // Manually call sanitize / pick to avoid touching real ~/Downloads.
        let a = pick_non_colliding(&dl, "doc.txt");
        std::fs::write(&a, b"a").unwrap();
        let b = pick_non_colliding(&dl, "doc.txt");
        assert!(b.file_name().unwrap().to_str().unwrap().contains("doc-1"));
    }
}
