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
use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::error::{HuddleError, Result};

/// Bytes per chunk on the wire. A `FileChunk` is base64-encoded inside a
/// JSON envelope, and on the relay path that envelope is itself base64'd
/// again (the relay's `payload_b64`), so a raw chunk inflates ~1.78× before
/// the relay's 256 KiB `MAX_PAYLOAD_B64` cap. huddle 1.2.5: 128 KiB raw →
/// ~175 KiB JSON (under the 256 KiB gossipsub `max_transmit_size`) → ~233 KiB
/// after the relay's second base64 — both safely under 256 KiB. Bigger chunks
/// mean far fewer messages per file (a 50 MiB file is ~400 chunks, not ~1280),
/// which keeps a whole file under the relay's 500-per-recipient mailbox cap so
/// it still delivers to an OFFLINE peer.
pub const CHUNK_SIZE: usize = 128 * 1024;

/// Hard cap on a single file. huddle 1.2.5: raised from 1 MiB to 50 MiB. The
/// transfer holds the whole file in memory on both ends (sender reads it all;
/// receiver reassembles chunks in a map), and at 128 KiB/chunk a 50 MiB file is
/// ~400 chunks — under the relay's 500-per-recipient mailbox cap, so even an
/// offline recipient receives the complete file. Truly large (GB) files want a
/// streaming/resumable transport (see the future-functionality brainstorm).
/// NOTE: the RECEIVER enforces its own cap, so a >1 MiB file only lands if both
/// peers are ≥1.2.5.
pub const MAX_FILE_SIZE: u64 = 50 * 1024 * 1024;

/// huddle 1.3.4: cap on concurrent *incomplete* inbound transfers. Each
/// distinct `file_id` an attacker streams a partial transfer for would
/// otherwise pin an `IncomingTransfer` in the reassembly map forever (no TTL,
/// no GC). Beyond this many, the least-recently-active transfer is evicted to
/// make room, so the map size is bounded regardless of how many file_ids a
/// hostile peer invents.
const MAX_CONCURRENT_INCOMING: usize = 32;

/// huddle 1.3.4: hard ceiling on the total bytes buffered across ALL
/// incomplete transfers. The per-transfer cap is `MAX_FILE_SIZE` (50 MiB), so
/// without this a full `MAX_CONCURRENT_INCOMING` of near-complete transfers
/// could pin 32 × 50 MiB = 1.6 GiB. A chunk that would push the global total
/// past this drops its (over-budget) transfer instead, keeping
/// `sum(bytes_received) <= MAX_TOTAL_INCOMING_BYTES` as a hard invariant.
const MAX_TOTAL_INCOMING_BYTES: u64 = 256 * 1024 * 1024;

/// huddle 1.3.4: a `file_id` is the lowercase-hex SHA-256 of the file bytes —
/// exactly 64 hex characters. Anything else (path separators, `..`, NUL, wrong
/// length) is malicious or corrupt and must NEVER be joined onto the cache dir,
/// or it escapes into an arbitrary filesystem path (read-amplification /
/// traversal via an unauthenticated `FileChunk`/offer). Reject up front.
fn is_valid_file_id(file_id: &str) -> bool {
    file_id.len() == 64 && file_id.bytes().all(|b| b.is_ascii_hexdigit())
}

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
    /// huddle 1.3.4: last time a chunk was accepted for this transfer. Drives
    /// least-recently-active eviction so the reassembly map stays bounded.
    last_activity: Instant,
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
        if !is_valid_file_id(file_id) {
            return Err(HuddleError::Other(
                "read_cache: file_id is not a 64-char hex digest (rejected to \
                 prevent path traversal)"
                    .into(),
            ));
        }
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
                "file is {} bytes — the cap is {} bytes (~{} MiB)",
                size,
                MAX_FILE_SIZE,
                MAX_FILE_SIZE / (1024 * 1024)
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
        // huddle 1.3.4: validate the (attacker-controlled) file_id BEFORE it is
        // ever turned into a filesystem path below, so `../../…` can't escape
        // the cache dir into an arbitrary-file read.
        if !is_valid_file_id(file_id) {
            return Err(HuddleError::Other(
                "FileChunk: file_id is not a 64-char hex digest (rejected to \
                 prevent path traversal)"
                    .into(),
            ));
        }
        if expected_size > MAX_FILE_SIZE {
            return Err(HuddleError::Other(format!(
                "incoming size {} exceeds Phase 2 cap",
                expected_size
            )));
        }
        // huddle 0.7.11: pre-0.7.11 only `expected_size` was capped,
        // not the per-chunk `data.len()`, `chunk_index`, or the running
        // `bytes_received`. A hostile peer could advertise expected_size
        // = 1 MiB and stream chunks summing to far more (DoS via heap
        // exhaustion). Now we enforce all four invariants up front and
        // drop the transfer if any is violated.
        if total_chunks == 0 {
            return Err(HuddleError::Other(
                "FileChunk: total_chunks must be ≥ 1".into(),
            ));
        }
        // huddle 2.0.2 (audit M-8): bound the chunk COUNT, not just total bytes.
        // The byte budget below doesn't limit the number of entries in the
        // per-transfer `chunks` map — an attacker advertising total_chunks ≈
        // u32::MAX and streaming empty/tiny chunks at distinct indices would grow
        // that map (and its allocator overhead) without tripping the byte cap.
        // A legitimate MAX_FILE_SIZE (50 MiB) transfer needs ≤ a few hundred
        // 256-KiB chunks; this ceiling allows ~3 KiB chunks and still bounds the
        // map to MAX_CHUNKS_PER_FILE * MAX_CONCURRENT_INCOMING entries. Empty
        // chunks (which carry no bytes and so evade the byte budget) are rejected.
        const MAX_CHUNKS_PER_FILE: u32 = 16_384;
        if total_chunks > MAX_CHUNKS_PER_FILE {
            return Err(HuddleError::Other(format!(
                "FileChunk: total_chunks {} exceeds cap of {}",
                total_chunks, MAX_CHUNKS_PER_FILE
            )));
        }
        // Reject empty chunks (they carry no bytes and so evade the byte budget),
        // EXCEPT the one legitimate case: a genuine zero-byte file, which
        // `prepare_outgoing_from_bytes` encodes as a single empty chunk.
        if data.is_empty() && !(total_chunks == 1 && expected_size == 0) {
            return Err(HuddleError::Other("FileChunk: empty chunk rejected".into()));
        }
        if chunk_index >= total_chunks {
            return Err(HuddleError::Other(format!(
                "FileChunk: chunk_index {} >= total_chunks {}",
                chunk_index, total_chunks
            )));
        }
        // Each chunk is bounded by gossipsub's 256 KiB max_transmit_size
        // anyway, but enforce here too so we don't accept oversize
        // chunks that snuck past a misbehaving forwarder.
        const MAX_CHUNK_BYTES: usize = 256 * 1024;
        if data.len() > MAX_CHUNK_BYTES {
            return Err(HuddleError::Other(format!(
                "FileChunk: data {} bytes exceeds per-chunk cap of {}",
                data.len(),
                MAX_CHUNK_BYTES
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

        // huddle 1.3.4: bound the number of concurrent *incomplete* transfers.
        // A hostile peer can stream one chunk each for thousands of distinct
        // file_ids; without this each would pin an entry forever. When a new
        // file_id arrives at the cap, evict the least-recently-active transfer.
        if !map.contains_key(file_id) {
            while map.len() >= MAX_CONCURRENT_INCOMING {
                match lru_incoming_key(&map) {
                    Some(victim) => {
                        map.remove(&victim);
                    }
                    None => break,
                }
            }
            map.insert(
                file_id.to_string(),
                IncomingTransfer {
                    expected_total: total_chunks,
                    expected_size,
                    chunks: HashMap::new(),
                    bytes_received: 0,
                    last_activity: Instant::now(),
                },
            );
        }

        if map.get(file_id).map(|e| e.expected_total) != Some(total_chunks) {
            return Err(HuddleError::Other(
                "chunk total disagrees with prior chunks".into(),
            ));
        }

        let already_have = map
            .get(file_id)
            .map(|e| e.chunks.contains_key(&chunk_index))
            .unwrap_or(false);
        if !already_have {
            let (new_total, advertised) = {
                let e = map.get(file_id).expect("entry present");
                (
                    e.bytes_received.saturating_add(data.len() as u64),
                    e.expected_size,
                )
            };
            // expected_size acts as the running ceiling. Some senders'
            // expected_size may be slightly off because of encryption overhead
            // (Megolm ciphertext > plaintext); allow a 1 KiB grace before
            // dropping the whole transfer (malicious peer or file changed
            // mid-stream).
            if new_total > advertised.saturating_add(1024) {
                map.remove(file_id);
                return Err(HuddleError::Other(format!(
                    "FileChunk: bytes_received {} would exceed expected_size {}",
                    new_total, advertised
                )));
            }
            // huddle 1.3.4: global memory budget across ALL incomplete
            // transfers. Sum every OTHER transfer's buffered bytes; if adding
            // this chunk would breach the ceiling, drop this (over-budget)
            // transfer rather than grow past it, keeping the global sum bounded.
            let others: u64 = map
                .iter()
                .filter(|(k, _)| k.as_str() != file_id)
                .map(|(_, t)| t.bytes_received)
                .sum();
            if others.saturating_add(new_total) > MAX_TOTAL_INCOMING_BYTES {
                map.remove(file_id);
                return Err(HuddleError::Other(format!(
                    "FileChunk: total buffered {} would exceed global cap {}",
                    others.saturating_add(new_total),
                    MAX_TOTAL_INCOMING_BYTES
                )));
            }
            let e = map.get_mut(file_id).expect("entry present");
            e.bytes_received = new_total;
            e.chunks.insert(chunk_index, data);
            e.last_activity = Instant::now();
        }

        if map.get(file_id).map(|e| e.chunks.len() as u32) != Some(total_chunks) {
            return Ok(None);
        }

        // All chunks arrived — assemble and verify.
        let transfer = map.get(file_id).expect("entry present and complete");
        let total = transfer.expected_total;
        let mut assembled: Vec<u8> = Vec::with_capacity(transfer.bytes_received as usize);
        for idx in 0..total {
            let part = transfer
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

/// huddle 1.3.4: the key of the least-recently-active incomplete transfer, used
/// to evict when the reassembly map is at capacity. `None` only if the map is
/// empty (in which case there's nothing to evict).
fn lru_incoming_key(map: &HashMap<String, IncomingTransfer>) -> Option<String> {
    map.iter()
        .min_by_key(|(_, t)| t.last_activity)
        .map(|(k, _)| k.clone())
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
                .accept_chunk(
                    &plan.file_id,
                    i as u32,
                    total,
                    chunk.clone(),
                    plan.size_bytes,
                )
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

    // huddle 1.3.4: a file_id with path-traversal must be rejected before it is
    // turned into a filesystem path, in both accept_chunk and read_cache.
    #[test]
    fn file_id_path_traversal_is_rejected() {
        assert!(is_valid_file_id(&"a".repeat(64)));
        assert!(is_valid_file_id(&"0123456789abcdef".repeat(4)));
        assert!(!is_valid_file_id("../../../../etc/passwd"));
        assert!(!is_valid_file_id("..")); // too short + dots
        assert!(!is_valid_file_id(&"a".repeat(63))); // wrong length
        assert!(!is_valid_file_id(&"a".repeat(65)));
        assert!(!is_valid_file_id(&format!("{}/", "a".repeat(63)))); // slash
        assert!(!is_valid_file_id(&"g".repeat(64))); // non-hex

        let (mgr, _t) = fresh_manager();
        let err = mgr
            .accept_chunk("../../../../etc/passwd", 0, 1, vec![1], 1)
            .unwrap_err();
        assert!(format!("{err}").contains("path traversal"));
        assert!(mgr.read_cache("../../secret").is_err());
    }

    // huddle 1.3.4: the reassembly map must not grow without bound when a peer
    // streams partial transfers for many distinct file_ids.
    #[test]
    fn incomplete_transfers_are_bounded() {
        let (mgr, _t) = fresh_manager();
        // Start far more incomplete transfers than the cap, each with a valid
        // (but never-completed) 2-chunk file_id. Only one chunk each → none
        // complete, so all would persist without eviction.
        for i in 0..(MAX_CONCURRENT_INCOMING * 4) {
            // Build a valid 64-hex id that varies per i.
            let id = format!("{:064x}", i);
            let _ = mgr.accept_chunk(&id, 0, 2, vec![0u8; 16], 1024);
        }
        let live = mgr.incoming.lock().unwrap().len();
        assert!(
            live <= MAX_CONCURRENT_INCOMING,
            "incomplete-transfer map grew to {live}, cap is {MAX_CONCURRENT_INCOMING}"
        );
    }
}
