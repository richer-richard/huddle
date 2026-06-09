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
    // Phase B: soft owner role. 'owner' = can grant other owners and
    // ban members; 'member' = vanilla participant. The creator of a
    // room is auto-promoted at start_room time; subsequent grants
    // come from `RoomMessage::OwnerGrant` (signed envelopes).
    "ALTER TABLE room_members ADD COLUMN role TEXT NOT NULL DEFAULT 'member';",
    // Phase B: per-room ban list. A banned fingerprint is ignored by
    // honest clients — their MemberAnnounce is dropped, their messages
    // skipped. The cryptographic enforcement is the immediate
    // RotateRoomKey that follows a ban: the banned peer can't unwrap
    // the new session key without the new passphrase.
    "CREATE TABLE IF NOT EXISTS room_bans (
        room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
        banned_fingerprint TEXT NOT NULL,
        banned_by_fingerprint TEXT NOT NULL,
        signature_b64 TEXT NOT NULL,
        banned_at INTEGER NOT NULL,
        PRIMARY KEY (room_id, banned_fingerprint)
    );",
    "CREATE INDEX IF NOT EXISTS idx_room_bans_room ON room_bans(room_id);",
    // Phase G: global per-fingerprint verification — populated when an
    // SAS verification succeeds. Distinct from `room_members.verified`
    // (which is per-room) so Phase E's global inbound filter can
    // answer "is this fingerprint SAS-verified at all?" in one query.
    "CREATE TABLE IF NOT EXISTS verified_peers (
        fingerprint TEXT PRIMARY KEY,
        verified_at INTEGER NOT NULL
    );",
    // Phase E: simple app-wide settings KV. First use: a global
    // 'verified_only_inbound' flag that auto-rejects inbound dials
    // from unverified fingerprints without prompting.
    "CREATE TABLE IF NOT EXISTS app_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );",
    // Phase E: per-room verified-only join. When 1, existing members
    // refuse to wrap their session key for an unverified joiner's
    // MemberAnnounce, and the lowest-fp owner sends a signed
    // `JoinRefused` so the joiner sees an explanation instead of a
    // silent hang.
    "ALTER TABLE rooms ADD COLUMN verified_only_join INTEGER NOT NULL DEFAULT 0;",
    // Phase H: a flag for "we've shown the welcome-and-key-concepts
    // onboarding card to this user". Persisted on identity (single
    // row) so it doesn't reappear next launch.
    "ALTER TABLE identity ADD COLUMN onboarding_seen INTEGER NOT NULL DEFAULT 0;",
    // huddle 0.5: per-peer profile cache populated by signed
    // ProfileUpdate broadcasts. `username = NULL` means the peer has
    // explicitly cleared their username and should render as
    // `[anonymous]`. `updated_at` is the sender's claimed monotonic ms;
    // last-write-wins so an out-of-order replay can't downgrade a
    // newer name.
    "CREATE TABLE IF NOT EXISTS peer_profiles (
        fingerprint TEXT PRIMARY KEY,
        username TEXT,
        updated_at INTEGER NOT NULL
    );",
    // huddle 0.7: explicit room kind ('direct' = 1-1 DM, 'group' = N-way
    // room). Existing rooms back-fill to 'group' via the column default —
    // they were created via the named `start_room` flow with group
    // ergonomics from the start, so the back-fill is loss-free.
    // RoomKind drives the sidebar split: DMs go in the Direct messages
    // section, groups in Group rooms. Direct rooms also reject any
    // MemberAnnounce that would push them past 2 members (honest-client
    // enforcement) and are filtered out of third parties' discovery
    // caches.
    "ALTER TABLE rooms ADD COLUMN kind TEXT NOT NULL DEFAULT 'group';",
    // huddle 0.7.7: pending inbound friend requests. When an `InboundDial`
    // modal isn't acted on within the 15s in-memory window, we spill the
    // request here instead of just rejecting — the user gets up to 3 days
    // to review and accept (or reject) later from the People pane.
    //
    // Primary key is (fingerprint, address) so a peer who dials from
    // multiple addresses (LAN + relay-circuit) gets one row per address.
    // On Accept we re-dial the stored address and run the same trust
    // upsert as `trust_inbound`. A startup sweep drops rows older than
    // 3 days (`PENDING_FRIEND_REQUEST_TTL_SECS`), so the table size
    // stays bounded without an extra background task.
    "CREATE TABLE IF NOT EXISTS pending_friend_requests (
        fingerprint TEXT NOT NULL,
        address TEXT NOT NULL,
        peer_id TEXT NOT NULL,
        received_at INTEGER NOT NULL,
        PRIMARY KEY (fingerprint, address)
    );",
    "CREATE INDEX IF NOT EXISTS idx_pending_friend_requests_received
       ON pending_friend_requests(received_at);",
    // huddle 1.0: a unified, fingerprint-keyed address book. Unlike
    // `known_peers` (keyed by an ephemeral libp2p multiaddr, useless once a
    // peer leaves the LAN), a contact is keyed by the stable cryptographic
    // identity, so it survives network changes — the durable link that lets
    // two people keep chatting over the relay after the LAN is gone.
    // `username`/`verified`/`trusted` are NOT denormalized here — they're
    // derived at read time from `peer_profiles` / `verified_peers` /
    // `known_peers` so they can't go stale. `ed25519_pubkey` is cached so a
    // DM key can be re-derived offline. `dm_room_id` is the canonical DM
    // room. `source` records how the contact entered the book
    // (dm/request/dial/lan/invite).
    "CREATE TABLE IF NOT EXISTS contacts (
        fingerprint     TEXT PRIMARY KEY,
        alias           TEXT,
        ed25519_pubkey  TEXT,
        dm_room_id      TEXT,
        source          TEXT NOT NULL DEFAULT 'unknown',
        note            TEXT,
        added_at        INTEGER NOT NULL,
        last_seen       INTEGER
    );",
    // huddle 1.0: inbound contact/DM requests that arrived over the relay
    // inbox (Phase 1) but haven't been accepted/declined yet. Mirrors the
    // `pending_friend_requests` shape (a 3-day TTL sweep keeps it bounded)
    // but is keyed purely by fingerprint — relay requests carry no dialable
    // address, just the requester's signed identity.
    "CREATE TABLE IF NOT EXISTS pending_contact_requests (
        fingerprint   TEXT PRIMARY KEY,
        display_name  TEXT,
        note          TEXT,
        received_at   INTEGER NOT NULL
    );",
    "CREATE INDEX IF NOT EXISTS idx_pending_contact_requests_received
       ON pending_contact_requests(received_at);",
    // huddle 1.3.1: cache a member's ML-KEM-768 encapsulation (public) key,
    // learned from `MemberAnnounce.sender_mlkem_pubkey` (Direct rooms only).
    // This is the durable, cross-restart anchor for **post-quantum capability
    // pinning**: once we have ever seen a peer's ML-KEM key in a signed
    // announce, we refuse to fall back to a classical-only DM wrap key for
    // them — so a malicious relay can't replay a captured pre-1.3 (classical)
    // announce to force a quantum-unsafe downgrade. COALESCE-preserved on
    // re-announce exactly like `ed25519_pubkey`, so a later announce that omits
    // the field can't erase the pin. NULL for pre-1.3 peers and group members.
    "ALTER TABLE room_members ADD COLUMN mlkem_pubkey TEXT;",
    // huddle 2.0.0 (F2): content-layer replay protection. A durable seen-set of
    // (room_id, sender_fingerprint, session_id, message_index) lets us silently
    // drop a wire-level replay of an already-processed *content* message — even
    // across restarts or a cross-transport re-broadcast. Megolm's message_index
    // is a monotonic ratchet position whose KDF output never repeats for a given
    // (session, index) pair, so the tuple uniquely names one ciphertext for the
    // lifetime of the session. ONLY content (RoomMessage::Encrypted) is recorded
    // here — control messages (MemberAnnounce, RotateRoomKey, SasInit, …) are
    // deliberately excluded so legitimate recurring control-plane re-broadcasts
    // keep working. created_at is the local receive time, used by the bounded GC
    // sweep (idx_content_replay_by_time). FK cascade clears rows when a room is
    // left/deleted. Additive only; zero wire-format change — old peers never see
    // this table and keep accepting replays as before.
    "CREATE TABLE IF NOT EXISTS content_replay_seen (
        room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
        sender_fingerprint TEXT NOT NULL,
        session_id TEXT NOT NULL,
        message_index INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (room_id, sender_fingerprint, session_id, message_index)
    );
    CREATE INDEX IF NOT EXISTS idx_content_replay_by_time
        ON content_replay_seen(created_at);",
    // huddle 2.0.0 (F1): persist whether a verified peer demonstrated
    // post-quantum (ML-KEM) capability at SAS-verification time. Once set,
    // `get_verified_peer_pq_capable` is a durable trust anchor that lets
    // `ensure_dm_key` refuse a classical-only DM fallback for this peer — so a
    // relay can't strip their ML-KEM pubkey from a later MemberAnnounce to force
    // a quantum-unsafe downgrade *after* they were verified. Conservative
    // back-fill: existing rows default to 0 (assume not PQ-capable until a fresh
    // SAS verification with ML-KEM binding sets the flag). Sticky-once-true is
    // enforced in `add_verified_peer`, not by the column.
    "ALTER TABLE verified_peers ADD COLUMN pq_capable INTEGER NOT NULL DEFAULT 0;",
    // huddle 2.0.0 (F8): a SQLite FTS5 full-text index over room_messages.body,
    // kept in lock-step by triggers. An *external-content* table
    // (content=room_messages, content_rowid=id) stores only the inverted index —
    // the body text itself still lives once, in room_messages — so the index
    // roughly doubles only the tokenized body size, not the full plaintext. The
    // whole index lives inside the same SQLCipher file under `PRAGMA key`, so it
    // adds no new at-rest exposure. The bundled SQLCipher is built with
    // SQLITE_ENABLE_FTS5; `search_room_messages_fts` still falls back to the LIKE
    // path (`search_room_messages`) if a query or the table is ever unavailable.
    // The backfill seeds the index from existing history; the ai/ad/au triggers
    // mirror INSERT/DELETE/UPDATE — the UPDATE trigger keeps the index correct
    // when `apply_message_edit` / `mark_message_deleted` (F10) rewrite a body.
    // Additive + local-only: pre-2.0 peers never run this and keep LIKE-searching,
    // with zero wire-format impact.
    "CREATE VIRTUAL TABLE room_messages_fts USING fts5(
        body,
        content='room_messages',
        content_rowid='id'
    );
    INSERT INTO room_messages_fts(rowid, body) SELECT id, body FROM room_messages;
    CREATE TRIGGER room_messages_ai AFTER INSERT ON room_messages BEGIN
        INSERT INTO room_messages_fts(rowid, body) VALUES (new.id, new.body);
    END;
    CREATE TRIGGER room_messages_ad AFTER DELETE ON room_messages BEGIN
        INSERT INTO room_messages_fts(room_messages_fts, rowid, body)
            VALUES('delete', old.id, old.body);
    END;
    CREATE TRIGGER room_messages_au AFTER UPDATE ON room_messages BEGIN
        INSERT INTO room_messages_fts(room_messages_fts, rowid, body)
            VALUES('delete', old.id, old.body);
        INSERT INTO room_messages_fts(rowid, body) VALUES (new.id, new.body);
    END;",
    // huddle 2.0.0 (F9): per-room disappearing-messages TTL, in seconds. 0 (the
    // back-fill default) means OFF — no message ever expires, so every pre-2.0
    // room keeps its current keep-forever behavior. When > 0,
    // `delete_expired_messages` physically removes any message whose
    // `sent_at + disappearing_ttl_secs <= now`, and the FTS delete trigger above
    // drops it from the search index in the same step. Local-only and best-effort
    // (each peer prunes against its own clock); the setting itself is propagated
    // out-of-band via a signed control message at the app layer.
    "ALTER TABLE rooms ADD COLUMN disappearing_ttl_secs INTEGER NOT NULL DEFAULT 0;",
    // huddle 2.0.0 (F10): content-layer conversation affordances — a stable
    // per-message client id (so reactions/replies/edits/deletes can target a
    // message across peers), reply threading, and edit/delete tombstones.
    //
    //  * client_msg_id — a sender-minted stable id (UUID v4) echoed on the wire so
    //    every peer names the same logical message. NULL for pre-2.0 messages,
    //    which therefore can't be reacted-to / edited / replied-to (no target
    //    handle) — their content still flows, only the affordances are unavailable.
    //  * reply_to — the client_msg_id this message replies to, or NULL.
    //  * edited_at / deleted_at — last-edit and tombstone timestamps.
    //    `apply_message_edit` is last-write-wins on edited_at; `mark_message_deleted`
    //    blanks the body and stamps deleted_at (a real delete, so the plaintext
    //    doesn't linger at rest and FTS stops matching it via the UPDATE trigger).
    //
    // room_reactions is one row per (room, target message, reactor, emoji); the
    // UNIQUE key makes a repeated reaction idempotent and `remove_reaction` an
    // exact-match delete. FK cascade clears a room's reactions when the room is
    // left/deleted. All additive: old peers ignore the new columns/variants and
    // old DBs back-fill NULL.
    "ALTER TABLE room_messages ADD COLUMN client_msg_id TEXT;
    ALTER TABLE room_messages ADD COLUMN reply_to TEXT;
    ALTER TABLE room_messages ADD COLUMN edited_at INTEGER;
    ALTER TABLE room_messages ADD COLUMN deleted_at INTEGER;
    CREATE INDEX IF NOT EXISTS idx_room_messages_client_msg_id
        ON room_messages(room_id, client_msg_id);
    CREATE TABLE IF NOT EXISTS room_reactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
        target_client_msg_id TEXT NOT NULL,
        sender_fingerprint TEXT NOT NULL,
        emoji TEXT NOT NULL,
        reacted_at INTEGER NOT NULL,
        UNIQUE(room_id, target_client_msg_id, sender_fingerprint, emoji)
    );
    CREATE INDEX IF NOT EXISTS idx_room_reactions_target
        ON room_reactions(room_id, target_client_msg_id);",
    // huddle 2.0.0 (F2 dedup): make duplicate content inserts idempotent at the
    // storage layer. Two concurrent copies of the same RoomMessage::Encrypted
    // (same room + sender + client_msg_id) can each pass check_content_replay_seen
    // *before* either records the seen-set entry, then both reach
    // insert_room_message — and with no constraint that produced two duplicate
    // rows with an identical client_msg_id. A PARTIAL UNIQUE index lets
    // `INSERT OR IGNORE` collapse the second write into a silent no-op, closing
    // the check→record→insert race. It is PARTIAL (WHERE client_msg_id IS NOT
    // NULL) so the many legitimate NULL rows — every pre-2.0 message and any 2.0
    // message a sender minted no id for — are exempt and never collide with each
    // other. Keyed by (room, sender, client_msg_id): the same logical message
    // from one sender is one row, while two senders that happen to mint the same
    // UUID stay distinct. Additive + local-only; old NULL rows can't violate it.
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_room_messages_dedup
        ON room_messages(room_id, sender_fingerprint, client_msg_id)
        WHERE client_msg_id IS NOT NULL;",
];
