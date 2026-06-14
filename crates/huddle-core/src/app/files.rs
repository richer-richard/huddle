//! `AppHandle` file-transfer methods — send/save/cancel/open/list attachments.
//! Split out of the `app/mod.rs` god file (huddle 2.1.x maintainability refactor)
//! as an additional inherent `impl AppHandle` block. The chunk-receive handlers
//! (`handle_file_offer`/`handle_file_chunk`) ride with the inbound dispatch in
//! `app/mod.rs`; the struct + shared helpers stay there too.

use super::*;

impl AppHandle {
    /// Send a local file to a room. Reads the file, optionally encrypts
    /// it for encrypted rooms, chunks it, broadcasts a FileOffer then
    /// each FileChunk. Returns the file_id once all chunks are queued.
    pub async fn send_file(&self, room_id: &str, path: &Path) -> Result<String> {
        let bytes = std::fs::read(path)?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "untitled".into());
        let mime = crate::files::guess_mime(&name);
        let original_path = path.to_path_buf();

        let (room_encrypted, mut maybe_session_id, encrypted_meta_opt, wire_bytes) = {
            let mut rooms = self.active_rooms.lock();
            let room = rooms
                .get_mut(room_id)
                .ok_or_else(|| HuddleError::Other(format!("not in room {room_id}")))?;
            // huddle 0.7.11: read-only joiners (code-joined peers) cannot
            // send files. Mirrors the check in send_room_message; without
            // it, code-joined peers could broadcast FileOffer/FileChunk
            // even though existing members ignore their chat messages.
            if room.read_only {
                return Err(HuddleError::Other(
                    "this room is read-only — you can't send files".into(),
                ));
            }
            if room.info.encrypted {
                let crypto = room
                    .crypto
                    .as_mut()
                    .ok_or_else(|| HuddleError::Session("missing room crypto".into()))?;
                let (ciphertext, meta) = file_encryption::encrypt_file(&bytes, crypto)?;
                (
                    true,
                    Some(meta.megolm_session_id.clone()),
                    Some(meta),
                    ciphertext,
                )
            } else {
                (false, None, None, bytes)
            }
        };
        let _ = &mut maybe_session_id; // silence unused warning when non-encrypted

        let plan =
            self.file_manager
                .prepare_outgoing_from_bytes(&name, mime.clone(), wire_bytes)?;
        let file_id = plan.file_id.clone();
        let total = plan.chunks.len() as u32;
        let our_fp = self.identity.fingerprint().to_string();

        let attachment = StoredAttachment {
            id: 0,
            room_id: room_id.to_string(),
            message_id: None,
            sender_fingerprint: our_fp.clone(),
            file_id: file_id.clone(),
            name: name.clone(),
            mime: mime.clone(),
            size_bytes: plan.size_bytes as i64,
            status: AttachmentStatus::Ready,
            cache_path: Some(
                self.file_manager
                    .cache_path(&file_id)
                    .to_string_lossy()
                    .into(),
            ),
            saved_path: Some(original_path.to_string_lossy().into()),
            error: None,
            encrypted: room_encrypted,
            wrapped_key: encrypted_meta_opt
                .as_ref()
                .map(|m| m.wrapped_key_b64.clone()),
            nonce: encrypted_meta_opt.as_ref().map(|m| m.nonce_b64.clone()),
            megolm_session_id: encrypted_meta_opt
                .as_ref()
                .map(|m| m.megolm_session_id.clone()),
            content_hash: encrypted_meta_opt.as_ref().map(|m| m.content_hash.clone()),
            created_at: now_unix(),
        };
        repo::upsert_attachment(&self.db, &attachment)?;
        let _ = self.app_event_tx.send(AppEvent::FileOffered {
            room_id: room_id.to_string(),
            file_id: file_id.clone(),
            name: name.clone(),
            size_bytes: plan.size_bytes,
            sender_fingerprint: our_fp.clone(),
        });

        // Publish the offer. huddle 0.7.11: FileOffer is now signed so
        // peers can't announce a file in someone else's name (attribution
        // spoof). FileChunks themselves stay plain — the receiver
        // assembles by chunk-index and verifies SHA-256 against
        // `file_id`, so spoofed chunks waste bandwidth but can't smuggle
        // mismatched bytes through the hash gate.
        let offer = RoomMessage::FileOffer {
            sender_fingerprint: our_fp.clone(),
            file_id: file_id.clone(),
            name,
            size_bytes: plan.size_bytes,
            mime,
            chunk_count: total,
            encrypted_meta: encrypted_meta_opt,
        };
        if let Ok(env) = crate::crypto::sign_message(&self.identity, &offer) {
            if let Ok(bytes) = crate::network::protocol::encode_wire_signed(&env) {
                self.network
                    .publish_room_message(room_id.to_string(), bytes)
                    .await;
            }
        }

        // Stream chunks. Brief pacing so gossipsub doesn't see a thundering
        // herd from a single peer.
        let net = self.network.clone();
        let room = room_id.to_string();
        let our = our_fp.clone();
        let fid = file_id.clone();
        let chunks = plan.chunks.clone();
        tokio::spawn(async move {
            for (i, data) in chunks.iter().enumerate() {
                let msg = RoomMessage::FileChunk {
                    sender_fingerprint: our.clone(),
                    file_id: fid.clone(),
                    chunk_index: i as u32,
                    total_chunks: total,
                    data_b64: B64.encode(data),
                };
                if let Ok(bytes) = encode_wire(&msg) {
                    net.publish_room_message(room.clone(), bytes).await;
                }
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
        });

        Ok(file_id)
    }

    /// Save a completed/ready attachment to the user's Downloads folder.
    /// Decrypts encrypted attachments on the way out.
    pub async fn save_to_downloads(&self, room_id: &str, file_id: &str) -> Result<PathBuf> {
        let attachment = repo::get_attachment(&self.db, room_id, file_id)?
            .ok_or_else(|| HuddleError::Other("attachment not found".into()))?;
        if !matches!(
            attachment.status,
            AttachmentStatus::Ready | AttachmentStatus::Saved
        ) {
            return Err(HuddleError::Other(format!(
                "attachment is not ready (status={})",
                attachment.status.as_str()
            )));
        }
        // Our own encrypted attachment: the file_manager cache holds the
        // ciphertext and we have no inbound Megolm session keyed by
        // ourselves, so it can't be decrypted back. But `saved_path` still
        // points at the original plaintext we sent — copy from there.
        let plaintext = if attachment.encrypted
            && attachment.sender_fingerprint == self.identity.fingerprint()
        {
            match attachment
                .saved_path
                .as_deref()
                .filter(|p| Path::new(p).exists())
            {
                Some(src) => std::fs::read(src)?,
                None => {
                    return Err(HuddleError::Other(
                        "your original file has moved or been deleted — it can't be \
                         recovered from the encrypted cache"
                            .into(),
                    ));
                }
            }
        } else {
            let cached = self.file_manager.read_cache(file_id)?;
            if attachment.encrypted {
                let meta = EncryptedFileMeta {
                    megolm_session_id: attachment
                        .megolm_session_id
                        .clone()
                        .ok_or_else(|| HuddleError::Other("missing megolm_session_id".into()))?,
                    wrapped_key_b64: attachment
                        .wrapped_key
                        .clone()
                        .ok_or_else(|| HuddleError::Other("missing wrapped_key".into()))?,
                    nonce_b64: attachment
                        .nonce
                        .clone()
                        .ok_or_else(|| HuddleError::Other("missing nonce".into()))?,
                    content_hash: attachment
                        .content_hash
                        .clone()
                        .ok_or_else(|| HuddleError::Other("missing content_hash".into()))?,
                };
                self.decrypt_attachment(room_id, &attachment.sender_fingerprint, &cached, &meta)?
            } else {
                cached
            }
        };
        let saved = self
            .file_manager
            .write_to_downloads(&attachment.name, &plaintext)?;
        repo::update_attachment_paths(
            &self.db,
            room_id,
            file_id,
            None,
            Some(&saved.to_string_lossy()),
        )?;
        repo::update_attachment_status(&self.db, room_id, file_id, AttachmentStatus::Saved, None)?;
        let _ = self.app_event_tx.send(AppEvent::FileSaved {
            file_id: file_id.into(),
            path: saved.to_string_lossy().into(),
        });
        Ok(saved)
    }

    /// Drop any in-flight chunks and remove the attachment row.
    pub async fn cancel_transfer(&self, room_id: &str, file_id: &str) -> Result<()> {
        self.file_manager.cancel_incoming(file_id);
        repo::update_attachment_status(
            &self.db,
            room_id,
            file_id,
            AttachmentStatus::Cancelled,
            None,
        )?;
        Ok(())
    }

    /// Launch the system's default opener on a saved file.
    pub fn open_saved(&self, room_id: &str, file_id: &str) -> Result<()> {
        let attachment = repo::get_attachment(&self.db, room_id, file_id)?
            .ok_or_else(|| HuddleError::Other("attachment not found".into()))?;
        let path = attachment.saved_path.ok_or_else(|| {
            HuddleError::Other("not saved yet — press Enter to save first".into())
        })?;
        open_with_system(&path)
    }

    pub fn list_room_attachments(&self, room_id: &str) -> Result<Vec<StoredAttachment>> {
        repo::list_room_attachments(&self.db, room_id)
    }
}
