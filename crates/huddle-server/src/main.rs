//! huddle-server — a centralized relay + offline mailbox for huddle.
//!
//! Designed to run on a single host behind a **Tor v3 onion service**.
//! Clients open a WebSocket, announce their identity + room memberships,
//! and publish messages addressed to a room. The server fans each message
//! out to the room's other members that are currently connected, and
//! queues it in a per-recipient mailbox for those who are offline.
//!
//! The server treats huddle's wire bytes as an **opaque base64 blob** — it
//! routes by the cleartext `room` id and never decrypts. End-to-end
//! encryption (Megolm / X25519) and authenticity (signed envelopes) are
//! entirely the clients' concern, exactly as on huddle's libp2p path.
//!
//! What the operator can still see is metadata: room ids, member
//! fingerprints, and timing. The onion service hides client IPs; blinding
//! the room/recipient identifiers is deferred anonymity-hardening work.
//!
//! Config via env:
//!   HUDDLE_SERVER_BIND  (default 127.0.0.1:8787)
//!   HUDDLE_SERVER_DB    (default huddle-server.db)
//!   RUST_LOG            (default info)

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex, Semaphore};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, info, warn};

// huddle 2.0.4 (WS1.1): the relay now shares the wire protocol + the identity
// helpers (fingerprint derivation, the `RELAY_AUTH_DOMAIN || nonce` builder)
// with the client via the lean, runtime-free `huddle-protocol` crate — instead
// of the hand-duplicated copies the relay used to carry.
use huddle_protocol::identity::{compute_fingerprint, relay_auth_msg};
use huddle_protocol::relay::{ClientMsg, ServerMsg};
/// huddle 1.1.4: drop queued mailbox ciphertext older than this so an offline
/// recipient's queue can't grow without bound over time (count is already
/// capped by `MAX_MAILBOX_PER_FP`; this adds an age bound).
const MAILBOX_TTL_SECS: i64 = 30 * 24 * 60 * 60;
/// huddle 1.1.4: bound each connection's outbound queue. A stalled reader can
/// no longer make the server buffer unboundedly — fan-out past this is dropped
/// to the recipient's mailbox instead (memory-amplification DoS defense).
const OUTBOUND_CAP: usize = 256;
/// huddle 1.1.4: drop a connection that connects but never completes the auth
/// handshake within this many seconds (idle pre-auth DoS defense).
const PRE_AUTH_TIMEOUT_SECS: u64 = 20;
/// huddle 1.2.1: short-lived "connect code" registry. A client can mint a code
/// that maps to its (authenticated) identity so a peer adds/DMs it by typing
/// the code instead of the full 24-hex HD-ID. Codes expire after this many
/// seconds. They grant NO authority — redeeming one only resolves the owner's
/// fingerprint+pubkey so the redeemer can send a contact request the owner
/// still has to accept — so the only abuse is spammy contact requests, bounded
/// by the TTL and the 40-bit code space.
const CONNECT_TOKEN_TTL_SECS: i64 = 5 * 60;
/// Crockford base32 (no I/L/O/U) — unambiguous to read aloud / retype.
const CONNECT_TOKEN_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// 8 chars × 5 bits = 40 bits (~1.1e12), short to type yet infeasible to
/// brute-force within the 5-minute window.
const CONNECT_TOKEN_LEN: usize = 8;
/// Global cap on live codes (memory bound; far above any real concurrency).
const MAX_CONNECT_TOKENS: usize = 50_000;

/// Reject base64 payloads larger than this (≈256 KiB encoded).
const MAX_PAYLOAD_B64: usize = 256 * 1024;
const MAX_ID_LEN: usize = 128;
const MAX_MSG_ID_LEN: usize = 256;
/// Keep at most this many queued messages per offline recipient.
const MAX_MAILBOX_PER_FP: usize = 500;
/// huddle 2.0.2 (audit H-2): global ceiling on total queued mailbox rows across
/// ALL recipients. The per-fp cap alone doesn't bound disk because a client can
/// mint unlimited Ed25519 identities and `SendDirect` to unlimited fabricated
/// recipients (500 rows × N fake fps). At ≤256 KiB/row this bounds worst-case
/// mailbox disk; operators with more storage can raise it. We SHED (refuse new
/// rows) when full rather than evict, so a flooder can't push out other
/// recipients' legitimately-queued messages.
const MAX_MAILBOX_TOTAL_ROWS: usize = 100_000;
const MAX_ROOMS_PER_HELLO: usize = 1000;
/// huddle 2.0.2 (audit L-17): cap distinct rooms a single identity may join, so
/// the `memberships` table can't be grown without bound by re-Hello'ing fresh
/// room ids. Far above any real user's room count.
const MAX_ROOMS_PER_FP: usize = 10_000;
/// huddle 2.1.2 (audit NSR-4): GLOBAL ceiling on total membership rows across ALL
/// identities. The per-fp cap (L-17) bounds rooms-per-identity but not the table
/// globally — auth mints free Ed25519 identities and membership rows persist past
/// disconnect (only Unsubscribe deletes), so identity churn grows the table
/// monotonically. Mirrors the H-2 mailbox ceiling: shed new memberships when full.
/// Far above any real relay's membership count; operators with more storage may
/// raise it.
const MAX_MEMBERSHIPS_TOTAL: usize = 10_000_000;
/// huddle 1.3.4: cap concurrent sockets a single authenticated fingerprint may
/// register. Each registered connection is a target in the per-room publish
/// fan-out (one `ServerMsg` clone + `try_send` apiece), so an identity opening
/// thousands of sockets turns every message into O(N) work + N×payload
/// allocations. A handful of devices is plenty; reject beyond this.
const MAX_CONNECTIONS_PER_FP: usize = 16;
/// huddle 1.3.4: global ceiling on concurrent accepted connections. The accept
/// loop previously spawned a handler per socket with no bound, so an attacker
/// could exhaust memory/FDs with idle connections (and the per-fingerprint cap
/// above only limits *registered* sockets, not pre-auth ones). A permit is held
/// for each connection's lifetime; new connections beyond this are dropped.
const MAX_TOTAL_CONNECTIONS: usize = 4096;
/// huddle 2.0.3 (audit N-H1): cap the rows a single SENDER may have outstanding
/// in the mailbox. The H-2 global ceiling alone let one identity squat the whole
/// 100k pool with rows for fabricated, never-draining recipients; bounding
/// per-sender outstanding rows (idx_mailbox_sender) makes squatting cost many
/// identities, and the per-connection rate limit slows each. Generous enough for
/// a heavy poster in a large mostly-offline group (rows drain as members ACK).
const MAX_MAILBOX_PER_SENDER: usize = 10_000;
/// huddle 2.0.3 (audit N-H1): per-connection token bucket for the mailbox-writing
/// ops (Publish/SendDirect) — burst capacity then a sustained refill, well above
/// any human or file-transfer cadence yet far below a flood.
const RATE_BUCKET_CAPACITY: f64 = 300.0;
const RATE_BUCKET_REFILL_PER_SEC: f64 = 100.0;
/// huddle 2.0.3 (audit N-M7): drop an authenticated socket that sends no frame
/// for this long. Healthy clients send an application keepalive every
/// ~60 s, so this only reaps idle/dead sockets — closing the "authenticate then
/// hold the socket forever" connection-pool exhaustion. Must exceed the client
/// keepalive period with margin.
const RELAY_IDLE_TIMEOUT_SECS: u64 = 150;

/// huddle 2.0.3 (audit N-H1): minimal per-connection token-bucket rate limiter.
struct RateLimiter {
    tokens: f64,
    last: std::time::Instant,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            tokens: RATE_BUCKET_CAPACITY,
            last: std::time::Instant::now(),
        }
    }

    /// Refill by elapsed time and try to consume one token. Returns `false` when
    /// the bucket is empty (the caller should shed the op).
    fn allow(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens =
            (self.tokens + elapsed * RATE_BUCKET_REFILL_PER_SEC).min(RATE_BUCKET_CAPACITY);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// huddle 2.0 (F7): what the per-connection writer pump consumes. Almost every
/// event is a protocol `Msg` to serialize and write to the socket. `Flush` is a
/// write barrier used only by the legacy (acks=false) mailbox drain: the writer
/// signals it AFTER it has flushed every preceding `Msg` to the socket, so the
/// drain can delete those mailbox rows only once they've truly reached the wire
/// — not merely the bounded outbound channel. This closes the pre-2.0
/// OUTBOUND_CAP loss window where a row accepted into the buffer but not yet
/// written was deleted, then lost if the socket died mid-drain.
enum OutEvent {
    Msg(ServerMsg),
    Flush(oneshot::Sender<()>),
}

type Tx = mpsc::Sender<OutEvent>;

/// huddle 1.2.1: one minted connect code and what it resolves to.
struct ConnectTokenEntry {
    fingerprint: String,
    pubkey_b64: String,
    expires_at: i64,
}

/// huddle 1.2.1: the in-memory connect-code registry. Ephemeral (never
/// persisted — codes live ≤5 min). Indexed both ways so minting a fresh code
/// can evict the owner's previous one.
#[derive(Default)]
struct ConnectTokens {
    by_token: HashMap<String, ConnectTokenEntry>,
    by_fp: HashMap<String, String>,
}

impl ConnectTokens {
    /// Drop every expired entry from both indexes.
    fn gc(&mut self, now: i64) {
        let expired: Vec<String> = self
            .by_token
            .iter()
            .filter(|(_, e)| e.expires_at <= now)
            .map(|(t, _)| t.clone())
            .collect();
        for t in expired {
            if let Some(e) = self.by_token.remove(&t) {
                if self.by_fp.get(&e.fingerprint) == Some(&t) {
                    self.by_fp.remove(&e.fingerprint);
                }
            }
        }
    }
}

/// huddle 2.0 (F13): lock-free operational counters exposed at `GET /metrics`
/// in the Prometheus text exposition format. All updates are `Relaxed` — these
/// are coarse operability gauges/counters, not synchronization primitives, so
/// no ordering guarantees are needed across them.
#[derive(Default)]
struct Metrics {
    /// Gauge: accepted sockets currently inside a connection handler (bounded by
    /// `MAX_TOTAL_CONNECTIONS`). Includes brief HTTP probes such as the scrape
    /// that reads this very counter.
    active_connections: AtomicU64,
    /// Counter: room/direct messages fanned out live to a connected recipient.
    publish_delivered: AtomicU64,
    /// Counter: messages queued to an offline recipient's on-disk mailbox.
    publish_queued: AtomicU64,
    /// Counter: fan-out sends dropped because a live recipient's bounded
    /// outbound queue (`OUTBOUND_CAP`) was full; the message is mailboxed
    /// instead (memory-amplification DoS defense, see `OUTBOUND_CAP`).
    outbound_cap_drops: AtomicU64,
    /// Counter: connections dropped for not completing the auth handshake before
    /// the `PRE_AUTH_TIMEOUT_SECS` deadline (idle pre-auth DoS defense).
    pre_auth_timeouts: AtomicU64,
}

struct Shared {
    db: Mutex<Connection>,
    /// fingerprint → the live socket senders for that identity (a user may
    /// be connected from more than one client at once).
    conns: Mutex<HashMap<String, Vec<Tx>>>,
    /// huddle 1.2.1: short-lived connect codes (the DM "add by code" feature).
    tokens: Mutex<ConnectTokens>,
    /// huddle 2.0 (F13): operational counters rendered at `GET /metrics`.
    metrics: Metrics,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let bind = std::env::var("HUDDLE_SERVER_BIND").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
    let db_path =
        std::env::var("HUDDLE_SERVER_DB").unwrap_or_else(|_| "huddle-server.db".to_string());

    let conn = Connection::open(&db_path)?;
    migrate(&conn)?;
    let shared = Arc::new(Shared {
        db: Mutex::new(conn),
        conns: Mutex::new(HashMap::new()),
        tokens: Mutex::new(ConnectTokens::default()),
        metrics: Metrics::default(),
    });

    // huddle 1.1.4: periodic mailbox GC. Every hour drop queued ciphertext
    // older than MAILBOX_TTL_SECS so an offline recipient's queue is bounded
    // in age as well as count (MAX_MAILBOX_PER_FP). The first tick fires
    // immediately, so an expired backlog is also swept on startup.
    {
        let shared = shared.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                tick.tick().await;
                let cutoff = now_unix() - MAILBOX_TTL_SECS;
                let db = shared.db.lock().await;
                match db.execute("DELETE FROM mailbox WHERE created_at < ?1", params![cutoff]) {
                    Ok(n) if n > 0 => {
                        debug!(removed = n, "mailbox GC: dropped expired ciphertext")
                    }
                    Ok(_) => {}
                    Err(e) => debug!(error = %e, "mailbox GC failed"),
                }
                // huddle 2.1.2 (audit NSR-4): GC orphaned per-room sequence rows.
                // `room_seq` gains one undeleted row per distinct room ever published
                // to; drop those whose room no longer has any member so the table
                // can't grow without bound under room-id churn. Safe: a room with no
                // members has no delivery order to preserve (and `seq` isn't consumed
                // client-side yet), so if it re-forms its sequence simply restarts.
                match db.execute(
                    "DELETE FROM room_seq WHERE room NOT IN (SELECT room FROM memberships)",
                    [],
                ) {
                    Ok(n) if n > 0 => debug!(removed = n, "room_seq GC: dropped orphaned rows"),
                    Ok(_) => {}
                    Err(e) => debug!(error = %e, "room_seq GC failed"),
                }
            }
        });
    }

    let listener = TcpListener::bind(&bind).await?;
    info!(%bind, db = %db_path, "huddle-server listening (WebSocket + /health + /metrics)");

    // huddle 1.3.4: bound the number of concurrent connections. A permit is
    // acquired per accepted socket and released when its handler returns.
    let conn_limit = Arc::new(Semaphore::new(MAX_TOTAL_CONNECTIONS));
    loop {
        let (stream, _peer) = listener.accept().await?;
        let permit = match conn_limit.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!(
                    cap = MAX_TOTAL_CONNECTIONS,
                    "connection limit reached — dropping new connection"
                );
                drop(stream);
                continue;
            }
        };
        let shared = shared.clone();
        tokio::spawn(async move {
            // Hold the permit for the whole connection lifetime.
            let _permit = permit;
            // huddle 2.0 (F13): count this accepted socket as an active
            // connection for the lifetime of its handler so `/metrics` can
            // report live concurrency against `MAX_TOTAL_CONNECTIONS`.
            shared
                .metrics
                .active_connections
                .fetch_add(1, Ordering::Relaxed);
            if let Err(e) = handle_conn(stream, shared.clone()).await {
                debug!(error = %e, "connection ended");
            }
            shared
                .metrics
                .active_connections
                .fetch_sub(1, Ordering::Relaxed);
        });
    }
}

/// Distinguish a plain `GET /health` probe from a WebSocket upgrade by
/// peeking (not consuming) the first bytes of the request.
async fn handle_conn(stream: TcpStream, shared: Arc<Shared>) -> Result<()> {
    let mut buf = [0u8; 1024];
    // huddle 1.3.1: bound the pre-WebSocket phase with the same PRE_AUTH_TIMEOUT
    // that guards the post-upgrade auth handshake, so the documented idle-pre-auth
    // DoS defense actually covers the earliest phase. Without this, a client that
    // opens TCP and sends nothing parks forever in `peek`, and one that dribbles a
    // partial upgrade parks forever in `accept_async` — a slowloris that holds a
    // task + FD entirely outside the auth-deadline window.
    //
    // huddle 1.3.3: peek and accept share ONE deadline (`timeout_at`) instead of
    // each getting a fresh PRE_AUTH_TIMEOUT, so the whole pre-WS phase is a single
    // ~PRE_AUTH_TIMEOUT window — not 2x — before serve_ws's own auth deadline takes
    // over. A slowloris can no longer chain per-phase timers to pin a connection
    // for a multiple of the documented budget.
    let dur = std::time::Duration::from_secs(PRE_AUTH_TIMEOUT_SECS);
    let pre_ws_deadline = tokio::time::Instant::now() + dur;
    // huddle 2.0 (F13): a slowloris that opens TCP and dribbles (or sends
    // nothing) trips this deadline; count it as a pre-auth timeout, alongside
    // the post-upgrade auth-handshake timeout in `serve_ws`.
    let n = match tokio::time::timeout_at(pre_ws_deadline, stream.peek(&mut buf)).await {
        Ok(r) => r?,
        Err(_) => {
            shared
                .metrics
                .pre_auth_timeouts
                .fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    };
    let head = String::from_utf8_lossy(&buf[..n]);
    if head.to_ascii_lowercase().contains("upgrade: websocket") {
        // huddle 1.3.1: cap the inbound message/frame size at the WS layer so an
        // oversized frame is rejected before it is buffered, copied, and parsed.
        // tungstenite's default ceiling is 64 MiB, ~256x the MAX_PAYLOAD_B64 guard
        // (which only runs post-parse, per-variant), so it was not a real memory
        // bound. 512 KiB leaves headroom over MAX_PAYLOAD_B64 (256 KiB) + the JSON
        // envelope while making the WS layer the actual per-connection ceiling.
        let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
            max_message_size: Some(512 * 1024),
            max_frame_size: Some(512 * 1024),
            ..Default::default()
        };
        let ws = match tokio::time::timeout_at(
            pre_ws_deadline,
            tokio_tungstenite::accept_async_with_config(stream, Some(config)),
        )
        .await
        {
            Ok(r) => r?,
            Err(_) => {
                // A partial WebSocket upgrade that never completes is the same
                // idle-pre-auth abuse; count it too (huddle 2.0, F13).
                shared
                    .metrics
                    .pre_auth_timeouts
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        };
        serve_ws(ws, shared).await
    } else {
        // Plain HTTP. `/health` keeps the JSON probe contract; `/metrics`
        // exposes the Prometheus-format operational counters (huddle 2.0, F13);
        // every other path (notably `/`) serves the static landing page so a
        // browser visiting the onion sees something intentional instead of raw
        // bytes. The relay protocol lives on the WebSocket upgrade above —
        // clients (the CLI, and any future frontend) hit `/ws`.
        match request_target(&head) {
            "/health" => serve_health(stream).await,
            "/metrics" => serve_metrics(stream, &head, &shared).await,
            _ => serve_landing(stream).await,
        }
    }
}

async fn serve_health(mut stream: TcpStream) -> Result<()> {
    let body = r#"{"ok":true,"service":"huddle-server"}"#;
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// huddle 2.0 (F13): serve the operational counters at `GET /metrics` in the
/// Prometheus text exposition format (v0.0.4). Hand-rendered from the
/// `AtomicU64` gauges/counters plus a live `COUNT(*)` of the mailbox table — no
/// extra dependency. Like `/health`, this is a one-shot HTTP response on the
/// same port the WebSocket relay rides; an operator points Prometheus (or
/// `curl`) at it directly, or via the onion. It exposes only aggregate counts,
/// never room ids, fingerprints, or ciphertext.
async fn serve_metrics(mut stream: TcpStream, head: &str, shared: &Arc<Shared>) -> Result<()> {
    // huddle 2.0.2 (audit L-16): /metrics exposes live activity metadata (online
    // users, message volume, mailbox backlog). It is now DISABLED by default and,
    // when enabled via HUDDLE_METRICS_TOKEN, requires a matching bearer token.
    let want = std::env::var("HUDDLE_METRICS_TOKEN")
        .ok()
        .filter(|t| !t.is_empty());
    let provided = head.lines().find_map(|l| {
        let (name, val) = l.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("authorization") {
            Some(val.trim().to_string())
        } else {
            None
        }
    });
    // huddle 2.0.3 (audit N-L7): compare fixed-length SHA-256 digests rather than
    // the raw token strings, so neither the token length nor a byte-prefix match
    // leaks through comparison timing.
    let authorized = match (&want, &provided) {
        (Some(tok), Some(p)) => {
            Sha256::digest(format!("Bearer {tok}").as_bytes()) == Sha256::digest(p.as_bytes())
        }
        _ => false,
    };
    if !authorized {
        let code = if want.is_none() {
            "404 Not Found"
        } else {
            "401 Unauthorized"
        };
        let resp = format!("HTTP/1.1 {code}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        stream.write_all(resp.as_bytes()).await?;
        stream.flush().await?;
        return Ok(());
    }
    let m = &shared.metrics;
    let active = m.active_connections.load(Ordering::Relaxed);
    let delivered = m.publish_delivered.load(Ordering::Relaxed);
    let queued = m.publish_queued.load(Ordering::Relaxed);
    let cap_drops = m.outbound_cap_drops.load(Ordering::Relaxed);
    let pre_auth = m.pre_auth_timeouts.load(Ordering::Relaxed);
    // Total queued rows across every recipient. A read-only aggregate; on any
    // error we report 0 rather than failing the scrape.
    let mailbox_rows: i64 = {
        let db = shared.db.lock().await;
        db.query_row("SELECT COUNT(*) FROM mailbox", [], |r| r.get(0))
            .unwrap_or(0)
    };
    let body = format!(
        "# HELP huddle_active_connections Accepted sockets currently being handled.\n\
         # TYPE huddle_active_connections gauge\n\
         huddle_active_connections {active}\n\
         # HELP huddle_max_connections Configured ceiling on concurrent connections.\n\
         # TYPE huddle_max_connections gauge\n\
         huddle_max_connections {max_conns}\n\
         # HELP huddle_mailbox_rows Queued mailbox rows across all recipients.\n\
         # TYPE huddle_mailbox_rows gauge\n\
         huddle_mailbox_rows {mailbox_rows}\n\
         # HELP huddle_publish_delivered_total Messages fanned out live to a connected recipient.\n\
         # TYPE huddle_publish_delivered_total counter\n\
         huddle_publish_delivered_total {delivered}\n\
         # HELP huddle_publish_queued_total Messages queued to an offline recipient's mailbox.\n\
         # TYPE huddle_publish_queued_total counter\n\
         huddle_publish_queued_total {queued}\n\
         # HELP huddle_outbound_cap_drops_total Fan-out sends dropped because a recipient's outbound queue was full.\n\
         # TYPE huddle_outbound_cap_drops_total counter\n\
         huddle_outbound_cap_drops_total {cap_drops}\n\
         # HELP huddle_pre_auth_timeouts_total Connections dropped for not authenticating before the deadline.\n\
         # TYPE huddle_pre_auth_timeouts_total counter\n\
         huddle_pre_auth_timeouts_total {pre_auth}\n",
        max_conns = MAX_TOTAL_CONNECTIONS,
    );
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// The static landing page served at the onion root. Compiled into the
/// binary (`include_str!`) so the server has no runtime file dependency.
const LANDING_HTML: &str = include_str!("landing.html");

/// Extract the request target (path) from an HTTP request's head, e.g.
/// `GET /health HTTP/1.1` → `/health`. The query string is stripped.
/// Falls back to `/` when the request line can't be parsed.
fn request_target(head: &str) -> &str {
    head.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .map(|target| target.split('?').next().unwrap_or("/"))
        .unwrap_or("/")
}

/// Serve the landing page as `text/html` with privacy-hardening headers:
/// a strict CSP that blocks scripts and every external resource (the page
/// is fully self-contained), plus no-referrer and no content sniffing.
/// The page is built to render with JavaScript disabled, so the CSP can
/// forbid scripts outright.
async fn serve_landing(mut stream: TcpStream) -> Result<()> {
    let resp = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Referrer-Policy: no-referrer\r\n\
         Connection: close\r\n\
         \r\n{}",
        LANDING_HTML.len(),
        LANDING_HTML
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

async fn serve_ws(ws: WebSocketStream<TcpStream>, shared: Arc<Shared>) -> Result<()> {
    let (mut sink, mut stream) = ws.split();
    let (tx, mut rx) = mpsc::channel::<OutEvent>(OUTBOUND_CAP);

    // Pump outgoing messages from the channel to the socket. Other
    // connections push into `tx` to deliver fan-out messages here.
    let writer = tokio::spawn(async move {
        while let Some(evt) = rx.recv().await {
            match evt {
                OutEvent::Msg(msg) => {
                    let json = match serde_json::to_string(&msg) {
                        Ok(j) => j,
                        Err(_) => continue,
                    };
                    // `SinkExt::send` feeds AND flushes, so once it returns Ok the
                    // bytes have reached the socket — that's what lets the `Flush`
                    // barrier below stand for "everything ahead of me is on the wire".
                    if sink.send(WsMessage::Text(json.into())).await.is_err() {
                        break;
                    }
                }
                // huddle 2.0 (F7): a write barrier. Because the channel is FIFO and
                // we got here, every `Msg` queued before this barrier has been
                // flushed to the socket. Signal the waiter so it can safely delete
                // the corresponding legacy mailbox rows. If the waiter is gone we
                // just drop the signal.
                OutEvent::Flush(done) => {
                    let _ = done.send(());
                }
            }
        }
    });

    // huddle 1.1.4: enforced client auth. Greet with a random 32-byte nonce;
    // the client must answer with a `Hello` carrying its pubkey + an Ed25519
    // signature over `RELAY_AUTH_DOMAIN || nonce`. Until that verifies we
    // accept nothing else and drop the connection on failure (a hard break —
    // pre-1.1.3 clients that send no proof are rejected). The proven
    // fingerprint is then PINNED to the connection: a later Hello may
    // re-assert rooms but can never re-key the socket to an identity it
    // didn't prove (which would otherwise let it steal that identity's
    // mailbox / fan-out).
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    if tx
        .send(OutEvent::Msg(ServerMsg::Challenge {
            nonce_b64: B64.encode(nonce),
        }))
        .await
        .is_err()
    {
        writer.abort();
        return Ok(());
    }

    let mut fingerprint: Option<String> = None;
    // huddle 1.2.1: the pubkey proven at auth, retained so `CreateConnectToken`
    // can bind it into the code (lets a redeemer TOFU-pin the owner's key).
    let mut proven_pubkey: Option<String> = None;
    let mut authenticated = false;
    // huddle 2.0 (F7): whether this connection's client advertised ACK support in
    // its `Hello` (the `acks` capability bit). When true the relay uses
    // at-least-once mailbox delivery (tag each row with its id, delete only on
    // `Ack`); when false it keeps the classical delete-on-deliver behavior.
    let mut acks_enabled = false;
    // Drop a connection that never finishes the handshake within the deadline
    // (idle pre-auth DoS defense). Disabled once authenticated.
    let auth_deadline = tokio::time::sleep(std::time::Duration::from_secs(PRE_AUTH_TIMEOUT_SECS));
    tokio::pin!(auth_deadline);
    // huddle 2.0.3 (audit N-M7): once authenticated, reap a socket that sends no
    // frame for RELAY_IDLE_TIMEOUT_SECS. Healthy clients send an application
    // keepalive well within that window, so this only drops idle/dead sockets —
    // closing the "authenticate then hold 4096 sockets forever" pool exhaustion.
    let idle_deadline = tokio::time::sleep(std::time::Duration::from_secs(RELAY_IDLE_TIMEOUT_SECS));
    tokio::pin!(idle_deadline);
    // huddle 2.0.3 (audit N-H1): per-connection token bucket for mailbox writes.
    let mut limiter = RateLimiter::new();

    loop {
        let frame = tokio::select! {
            _ = &mut auth_deadline, if !authenticated => {
                debug!("client did not authenticate within the timeout; dropping");
                shared.metrics.pre_auth_timeouts.fetch_add(1, Ordering::Relaxed);
                break;
            }
            _ = &mut idle_deadline, if authenticated => {
                debug!("authenticated client idle past timeout; dropping");
                break;
            }
            f = stream.next() => match f {
                Some(Ok(fr)) => fr,
                Some(Err(_)) | None => break,
            },
        };
        // Any received frame counts as liveness; push the idle deadline out.
        idle_deadline.as_mut().reset(
            tokio::time::Instant::now() + std::time::Duration::from_secs(RELAY_IDLE_TIMEOUT_SECS),
        );
        let text = match frame {
            WsMessage::Text(t) => t.as_str().to_string(),
            WsMessage::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
            WsMessage::Close(_) => break,
            WsMessage::Ping(_) | WsMessage::Pong(_) | WsMessage::Frame(_) => continue,
        };
        let msg: ClientMsg = match serde_json::from_str(&text) {
            Ok(m) => m,
            Err(e) => {
                let _ = tx
                    .send(OutEvent::Msg(ServerMsg::Error {
                        message: format!("bad message: {e}"),
                    }))
                    .await;
                continue;
            }
        };
        // Gate: nothing happens until the client proves its fingerprint. On
        // success we BIND the server-derived fingerprint (from the verified
        // pubkey) to this connection — never the client-claimed string.
        if !authenticated {
            match &msg {
                ClientMsg::Hello {
                    fingerprint: claimed,
                    pubkey_b64,
                    signature_b64,
                    ..
                } => match verify_client_auth(claimed, pubkey_b64, signature_b64, &nonce) {
                    Ok(proven_fp) => {
                        fingerprint = Some(proven_fp);
                        proven_pubkey = Some(pubkey_b64.clone());
                        authenticated = true;
                    }
                    Err(e) => {
                        debug!(error = %e, "client auth failed; dropping connection");
                        let _ = tx
                            .send(OutEvent::Msg(ServerMsg::Error {
                                message: format!("auth failed: {e}"),
                            }))
                            .await;
                        break;
                    }
                },
                _ => {
                    let _ = tx
                        .send(OutEvent::Msg(ServerMsg::Error {
                            message: "authenticate with hello first".into(),
                        }))
                        .await;
                    break;
                }
            }
        }
        if let Err(e) = handle_client_msg(
            msg,
            &mut fingerprint,
            &proven_pubkey,
            &mut acks_enabled,
            &tx,
            &shared,
            &mut limiter,
        )
        .await
        {
            let _ = tx
                .send(OutEvent::Msg(ServerMsg::Error {
                    message: e.to_string(),
                }))
                .await;
        }
    }

    // Deregister this socket so fan-out stops targeting it.
    if let Some(fp) = &fingerprint {
        let mut conns = shared.conns.lock().await;
        if let Some(v) = conns.get_mut(fp) {
            v.retain(|s| !s.same_channel(&tx));
            if v.is_empty() {
                conns.remove(fp);
            }
        }
    }
    writer.abort();
    Ok(())
}

async fn handle_client_msg(
    msg: ClientMsg,
    fingerprint: &mut Option<String>,
    proven_pubkey: &Option<String>,
    acks_enabled: &mut bool,
    tx: &Tx,
    shared: &Arc<Shared>,
    limiter: &mut RateLimiter,
) -> Result<()> {
    match msg {
        ClientMsg::Hello { rooms, acks, .. } => {
            // huddle 1.1.4: the routing fingerprint is the one PROVEN during
            // the auth handshake (bound by serve_ws from the verified pubkey),
            // NOT the client-claimed `fingerprint` field — which we ignore here
            // so a second Hello can't re-key this socket to an identity it never
            // proved (and drain that identity's mailbox). A re-Hello may only
            // re-assert room memberships.
            let fp = require_fp(fingerprint)?;
            // huddle 1.3.4: enforce a per-identity connection cap so one
            // fingerprint can't register thousands of sockets and turn every
            // room publish into an O(N)-clone fan-out amplification.
            let registered = {
                let mut conns = shared.conns.lock().await;
                let entry = conns.entry(fp.clone()).or_default();
                if entry.iter().any(|s| s.same_channel(tx)) {
                    // Repeat Hello on an already-registered socket — fine.
                    true
                } else if entry.len() >= MAX_CONNECTIONS_PER_FP {
                    false
                } else {
                    entry.push(tx.clone());
                    true
                }
            };
            if !registered {
                let _ = tx
                    .send(OutEvent::Msg(ServerMsg::Error {
                        message: "too many concurrent connections for this identity".into(),
                    }))
                    .await;
                bail!("per-fingerprint connection limit ({MAX_CONNECTIONS_PER_FP}) exceeded");
            }
            {
                let db = shared.db.lock().await;
                for room in rooms.iter().take(MAX_ROOMS_PER_HELLO) {
                    if let Some(room) = clean_id(room) {
                        add_membership(&db, &fp, &room)?;
                    }
                }
            }
            // huddle 2.0 (F7): pin this connection's at-least-once capability from
            // the Hello bit. A re-Hello may flip it (e.g. a client that upgraded
            // mid-session), but in practice it's constant for a socket's life.
            *acks_enabled = acks;
            let _ = tx
                .send(OutEvent::Msg(ServerMsg::Ready {
                    fingerprint: fp.clone(),
                }))
                .await;
            flush_mailbox(&fp, tx, shared, acks).await?;
        }
        ClientMsg::Subscribe { room } => {
            let fp = require_fp(fingerprint)?;
            let room = clean_id(&room).ok_or_else(|| anyhow!("invalid room"))?;
            let db = shared.db.lock().await;
            add_membership(&db, &fp, &room)?;
        }
        ClientMsg::Unsubscribe { room } => {
            let fp = require_fp(fingerprint)?;
            let room = clean_id(&room).ok_or_else(|| anyhow!("invalid room"))?;
            let db = shared.db.lock().await;
            db.execute(
                "DELETE FROM memberships WHERE fingerprint = ?1 AND room = ?2",
                params![fp, room],
            )?;
        }
        ClientMsg::Publish {
            room,
            id,
            payload_b64,
        } => {
            let fp = require_fp(fingerprint)?;
            let room = clean_id(&room).ok_or_else(|| anyhow!("invalid room"))?;
            if id.is_empty() || id.len() > MAX_MSG_ID_LEN {
                bail!("invalid message id");
            }
            if payload_b64.len() > MAX_PAYLOAD_B64 {
                bail!("payload too large");
            }
            // huddle 2.0.3 (audit N-H1): rate-limit the mailbox-writing op. Shed
            // (report as not-delivered, preserving the Sent contract) rather than
            // disconnect, so a legit burst degrades gracefully and a flooder is
            // throttled instead of being able to fill the global pool in a burst.
            if !limiter.allow() {
                let _ = tx
                    .send(OutEvent::Msg(ServerMsg::Sent {
                        id,
                        delivered: 0,
                        queued: 0,
                    }))
                    .await;
                return Ok(());
            }
            // The sender is, by definition, a member of the room.
            let (members, seq) = {
                let db = shared.db.lock().await;
                add_membership(&db, &fp, &room)?;
                // huddle 2.0.8 (WS2 #5): one per-room sequence number for this
                // publish, delivered to every live member for total ordering.
                let seq = next_room_seq(&db, &room)?;
                (room_members(&db, &room)?, seq)
            };
            let mut delivered = 0usize;
            let mut queued = 0usize;
            for member in members {
                if member == fp {
                    continue;
                }
                let online = {
                    let conns = shared.conns.lock().await;
                    match conns.get(&member) {
                        // huddle 1.1.4: `try_send` on the bounded outbound queue —
                        // a slow/stalled recipient (Full) or a gone one (Closed)
                        // counts as not-live, so we mailbox it instead of blocking
                        // the publisher or buffering unboundedly. huddle 2.0 (F13):
                        // a Full drop is the OUTBOUND_CAP back-pressure metric.
                        Some(senders) => {
                            let out = ServerMsg::Message {
                                room: room.clone(),
                                id: id.clone(),
                                payload_b64: payload_b64.clone(),
                                // Live fan-out is never mailboxed, so no row id.
                                mailbox_id: None,
                                seq: Some(seq),
                            };
                            fan_out(senders, &out, &shared.metrics)
                        }
                        None => false,
                    }
                };
                if online {
                    delivered += 1;
                    shared
                        .metrics
                        .publish_delivered
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    let db = shared.db.lock().await;
                    if enqueue(&db, &fp, &member, &room, &id, &payload_b64)? {
                        queued += 1;
                        shared
                            .metrics
                            .publish_queued
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            let _ = tx
                .send(OutEvent::Msg(ServerMsg::Sent {
                    id,
                    delivered,
                    queued,
                }))
                .await;
        }
        ClientMsg::SendDirect {
            to,
            room,
            id,
            payload_b64,
        } => {
            // huddle 1.2: must be authenticated (the proven fingerprint gates
            // every op), but the SENDER need not share any room with `to`.
            // We deliver straight to the recipient fingerprint's connections,
            // or queue it in their mailbox when they're offline — exactly the
            // same per-fingerprint mailbox group fan-out uses for offline
            // members. This makes 1:1 DMs and friend requests work without the
            // both-sides-subscribed-the-same-room dance.
            let from = require_fp(fingerprint)?;
            let to = clean_id(&to).ok_or_else(|| anyhow!("invalid recipient"))?;
            let room = clean_id(&room).ok_or_else(|| anyhow!("invalid room"))?;
            if id.is_empty() || id.len() > MAX_MSG_ID_LEN {
                bail!("invalid message id");
            }
            if payload_b64.len() > MAX_PAYLOAD_B64 {
                bail!("payload too large");
            }
            // huddle 2.0.3 (audit N-H1): rate-limit the mailbox-writing op.
            if !limiter.allow() {
                let _ = tx
                    .send(OutEvent::Msg(ServerMsg::Sent {
                        id,
                        delivered: 0,
                        queued: 0,
                    }))
                    .await;
                return Ok(());
            }
            let online = {
                let conns = shared.conns.lock().await;
                match conns.get(&to) {
                    Some(senders) => {
                        let out = ServerMsg::Message {
                            room: room.clone(),
                            id: id.clone(),
                            payload_b64: payload_b64.clone(),
                            // Live direct delivery is never mailboxed.
                            mailbox_id: None,
                            // SendDirect is 1:1 (DMs / friend requests), not a
                            // room broadcast, so it carries no per-room sequence.
                            seq: None,
                        };
                        fan_out(senders, &out, &shared.metrics)
                    }
                    None => false,
                }
            };
            let (delivered, queued) = if online {
                shared
                    .metrics
                    .publish_delivered
                    .fetch_add(1, Ordering::Relaxed);
                (1usize, 0usize)
            } else {
                let db = shared.db.lock().await;
                if enqueue(&db, &from, &to, &room, &id, &payload_b64)? {
                    shared
                        .metrics
                        .publish_queued
                        .fetch_add(1, Ordering::Relaxed);
                    (0usize, 1usize)
                } else {
                    // Mailbox full (global cap): shed without disconnecting.
                    (0usize, 0usize)
                }
            };
            let _ = tx
                .send(OutEvent::Msg(ServerMsg::Sent {
                    id,
                    delivered,
                    queued,
                }))
                .await;
        }
        ClientMsg::CreateConnectToken => {
            // huddle 1.2.1: mint a short-lived code bound to the proven identity.
            let fp = require_fp(fingerprint)?;
            let pubkey = proven_pubkey.clone().unwrap_or_default();
            let now = now_unix();
            let token = {
                let mut t = shared.tokens.lock().await;
                t.gc(now);
                // Evict this fp's previous code so only one is live at a time.
                if let Some(old) = t.by_fp.remove(&fp) {
                    t.by_token.remove(&old);
                }
                if t.by_token.len() >= MAX_CONNECT_TOKENS {
                    bail!("connect-code registry full; try again shortly");
                }
                // Generate a code not currently in use.
                let mut tok = gen_connect_token();
                let mut tries = 0;
                while t.by_token.contains_key(&tok) && tries < 8 {
                    tok = gen_connect_token();
                    tries += 1;
                }
                t.by_token.insert(
                    tok.clone(),
                    ConnectTokenEntry {
                        fingerprint: fp.clone(),
                        pubkey_b64: pubkey,
                        expires_at: now + CONNECT_TOKEN_TTL_SECS,
                    },
                );
                t.by_fp.insert(fp.clone(), tok.clone());
                tok
            };
            let _ = tx
                .send(OutEvent::Msg(ServerMsg::ConnectToken {
                    token,
                    ttl_secs: CONNECT_TOKEN_TTL_SECS as u64,
                }))
                .await;
        }
        ClientMsg::RedeemConnectToken { token } => {
            // huddle 1.2.1: resolve a code → owner fingerprint+pubkey. Must be
            // authenticated (so redemptions are traceable), but the resolution
            // grants nothing beyond the identity to send a contact request to.
            let _fp = require_fp(fingerprint)?;
            let now = now_unix();
            let resolved = {
                let mut t = shared.tokens.lock().await;
                t.gc(now);
                normalize_connect_token(&token)
                    .and_then(|norm| t.by_token.get(&norm))
                    .filter(|e| e.expires_at > now)
                    .map(|e| (e.fingerprint.clone(), e.pubkey_b64.clone()))
            };
            let (fingerprint, pubkey_b64) = match resolved {
                Some((fp, pk)) => (Some(fp), Some(pk)),
                None => (None, None),
            };
            let _ = tx
                .send(OutEvent::Msg(ServerMsg::ConnectTokenResolved {
                    token: normalize_connect_token(&token).unwrap_or_default(),
                    fingerprint,
                    pubkey_b64,
                }))
                .await;
        }
        ClientMsg::Fetch => {
            let fp = require_fp(fingerprint)?;
            flush_mailbox(&fp, tx, shared, *acks_enabled).await?;
        }
        ClientMsg::Ack { mailbox_id } => {
            // huddle 2.0 (F7): the client durably handled a mailbox-delivered
            // message; delete exactly that row. Scoped to the authenticated
            // fingerprint so an identity can only drop its OWN queued rows — a
            // bare `id` is not capability enough to delete a stranger's mailbox.
            // A no-op when the row is already gone (duplicate/late ACK, or it was
            // swept by the TTL GC) — safe and idempotent.
            let fp = require_fp(fingerprint)?;
            let db = shared.db.lock().await;
            db.execute(
                "DELETE FROM mailbox WHERE id = ?1 AND fingerprint = ?2",
                params![mailbox_id, fp],
            )?;
        }
        ClientMsg::Ping => {
            let _ = tx.send(OutEvent::Msg(ServerMsg::Pong)).await;
        }
    }
    Ok(())
}

/// huddle 2.0 (F13): deliver `out` to one recipient's live sockets, counting any
/// `OUTBOUND_CAP`-full drop. Returns `true` when at least one socket accepted
/// it; a `false` return means the caller should mailbox the message. A `Closed`
/// send (gone socket) is silent — it's just a not-live connection.
fn fan_out(senders: &[Tx], out: &ServerMsg, metrics: &Metrics) -> bool {
    let mut any_ok = false;
    for s in senders {
        match s.try_send(OutEvent::Msg(out.clone())) {
            Ok(()) => any_ok = true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                metrics.outbound_cap_drops.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }
    any_ok
}

/// Drain a recipient's offline mailbox onto its live socket.
///
/// huddle 1.1.4: peek (do NOT delete) the queue and deliver into the bounded
/// outbound channel. If the socket is gone, `tx.send` errors and we stop — the
/// rest stay in the DB with their original `created_at` for the next
/// connection, so there's no silent loss and no TTL reset.
///
/// huddle 2.0 (F7): `acks` selects the delivery discipline:
/// - `false` (pre-2.0 clients): tag each row with no `mailbox_id` and delete it
///   only AFTER the writer confirms it reached the socket. We push the batch,
///   then enqueue an `OutEvent::Flush` write barrier; because the outbound
///   channel is FIFO, the writer signals that barrier only once every preceding
///   message has been flushed to the wire (`SinkExt::send` flushes). So a socket
///   that dies mid-drain leaves ALL the batch's rows in the DB for the next
///   connection instead of losing messages that were buffered but never written
///   — the safe 1.1.4 delete-after-the-socket-send behavior. The cost is that a
///   socket death after a partial write redelivers the already-written prefix
///   next time; old clients dedup that by `msg_id`. The queue can never wedge:
///   an old client that drains successfully has its rows deleted and never
///   re-sends an `Ack`.
/// - `true` (2.0+ clients): at-least-once — tag each row with its `id` and keep
///   it on disk. The client `Ack`s after durably persisting, and only then does
///   the relay delete the row (see the `Ack` handler). A lost ACK simply means
///   the row is redelivered on the next drain (an accepted, rare duplicate),
///   bounded by the existing TTL GC.
async fn flush_mailbox(fp: &str, tx: &Tx, shared: &Arc<Shared>, acks: bool) -> Result<()> {
    let items = {
        let db = shared.db.lock().await;
        peek_mailbox(&db, fp)?
    };
    // Rows pushed toward the socket on the legacy (acks=false) path this drain.
    // They're deleted only once the write barrier below confirms they reached
    // the wire. The at-least-once path never collects ids here (deletes on `Ack`).
    let mut legacy_ids: Vec<i64> = Vec::new();
    let mut socket_alive = true;
    for (row_id, room, msg_id, payload_b64) in items {
        // At-least-once clients get the row id to ACK; legacy clients get `None`
        // and the barrier-confirmed delete path below.
        let mailbox_id = if acks { Some(row_id) } else { None };
        if tx
            .send(OutEvent::Msg(ServerMsg::Message {
                room,
                id: msg_id,
                payload_b64,
                mailbox_id,
                // huddle 2.0.8 (WS2 #5): offline-mailbox replays don't carry the
                // per-room sequence in this first slice (the documented
                // follow-up persists it alongside the queued row).
                seq: None,
            }))
            .await
            .is_err()
        {
            socket_alive = false;
            break; // socket gone — keep the remaining rows for next time
        }
        if !acks {
            legacy_ids.push(row_id);
        }
    }
    // huddle 2.0 (F7): for legacy clients, delete the drained rows ONLY once the
    // writer confirms they hit the socket. We enqueue a `Flush` barrier after the
    // batch and await its signal; the writer signals it only after flushing every
    // message ahead of it (FIFO). If the barrier can't be sent or the writer
    // drops it (socket died before writing the batch), we delete nothing and the
    // rows survive for the next drain — no loss, at worst a deduped redelivery.
    if !acks && socket_alive && !legacy_ids.is_empty() {
        let (done_tx, done_rx) = oneshot::channel();
        if tx.send(OutEvent::Flush(done_tx)).await.is_ok() && done_rx.await.is_ok() {
            let db = shared.db.lock().await;
            delete_mailbox_ids(&db, &legacy_ids)?;
        }
    }
    Ok(())
}

fn require_fp(fp: &Option<String>) -> Result<String> {
    fp.clone().ok_or_else(|| anyhow!("send hello first"))
}

// huddle 2.0.4 (WS1.1): `compute_fingerprint` now comes from `huddle-protocol`
// (imported above) — the relay no longer open-codes it.

/// huddle 1.1.4: verify a client's auth proof. The claimed fingerprint must
/// equal `compute_fingerprint(pubkey)`, and the signature must verify (strict,
/// rejecting low/mixed-order keys) over `RELAY_AUTH_DOMAIN || nonce`. Any
/// mismatch is an auth failure and the caller drops the connection.
/// Returns the server-derived fingerprint (`compute_fingerprint(pubkey)`) on
/// success — the caller PINS this to the connection so the client-claimed
/// `fingerprint` string is never trusted for routing.
fn verify_client_auth(
    claimed_fp: &str,
    pubkey_b64: &str,
    signature_b64: &str,
    nonce: &[u8; 32],
) -> Result<String> {
    let pk_bytes = B64
        .decode(pubkey_b64)
        .map_err(|e| anyhow!("bad pubkey base64: {e}"))?;
    let pk: [u8; 32] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("pubkey must be 32 bytes"))?;
    let sig_bytes = B64
        .decode(signature_b64)
        .map_err(|e| anyhow!("bad signature base64: {e}"))?;
    let sig: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("signature must be 64 bytes"))?;
    let proven_fp = compute_fingerprint(&pk);
    if proven_fp != claimed_fp {
        bail!("fingerprint does not match pubkey");
    }
    let vk = VerifyingKey::from_bytes(&pk).map_err(|e| anyhow!("bad ed25519 pubkey: {e}"))?;
    // huddle 2.0.4 (WS1.1): the `RELAY_AUTH_DOMAIN || nonce` bytes come from the
    // shared `huddle_protocol::identity::relay_auth_msg`, byte-identical to the
    // client's signer by construction.
    vk.verify_strict(&relay_auth_msg(nonce), &Signature::from_bytes(&sig))
        .map_err(|e| anyhow!("signature verification failed: {e}"))?;
    Ok(proven_fp)
}

/// Validate a fingerprint / room id used purely for routing. Length-capped
/// and restricted to a safe character set; passed through unchanged so the
/// identity matches exactly on both ends.
fn clean_id(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() || t.len() > MAX_ID_LEN {
        return None;
    }
    if t.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ':' | '.'))
    {
        Some(t.to_string())
    } else {
        None
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// huddle 1.2.1: generate a fresh connect code — `CONNECT_TOKEN_LEN` chars from
/// the Crockford base32 alphabet. The alphabet length (32) divides 2^32, so
/// `next_u32() % 32` is unbiased.
fn gen_connect_token() -> String {
    let mut rng = rand::rngs::OsRng;
    (0..CONNECT_TOKEN_LEN)
        .map(|_| {
            let i = (rng.next_u32() as usize) % CONNECT_TOKEN_ALPHABET.len();
            CONNECT_TOKEN_ALPHABET[i] as char
        })
        .collect()
}

/// huddle 1.2.1: canonicalize a typed connect code — uppercase, strip spaces /
/// dashes — and validate it's exactly `CONNECT_TOKEN_LEN` Crockford-base32
/// chars. Returns `None` for anything that isn't a well-formed code (so a
/// stray HD-ID or username can't accidentally match a stored token).
fn normalize_connect_token(s: &str) -> Option<String> {
    let up: String = s
        .trim()
        .to_ascii_uppercase()
        .chars()
        .filter(|c| *c != '-' && *c != ' ')
        .collect();
    if up.len() == CONNECT_TOKEN_LEN && up.bytes().all(|b| CONNECT_TOKEN_ALPHABET.contains(&b)) {
        Some(up)
    } else {
        None
    }
}

// ---- storage ----

fn migrate(c: &Connection) -> Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS memberships (
            fingerprint TEXT NOT NULL,
            room        TEXT NOT NULL,
            PRIMARY KEY (fingerprint, room)
        );
        CREATE TABLE IF NOT EXISTS mailbox (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL,
            room        TEXT NOT NULL,
            msg_id      TEXT NOT NULL,
            payload_b64 TEXT NOT NULL,
            created_at  INTEGER NOT NULL,
            sender      TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_mailbox_fp ON mailbox(fingerprint);
        -- huddle 2.0.3 (audit N-H1): index the sender so the per-sender
        -- outstanding-rows cap in `enqueue` stays cheap on the hot path.
        CREATE INDEX IF NOT EXISTS idx_mailbox_sender ON mailbox(sender);
        -- huddle 2.0.3 (audit N-L5): index memberships by room so the
        -- per-Publish fan-out lookup isn't a full table scan.
        CREATE INDEX IF NOT EXISTS idx_memberships_room ON memberships(room);
        -- huddle 2.0.8 (WS2 foundations #5): durable per-room monotonic sequence
        -- for total-ordered delivery (the foundation MLS commit ordering needs).
        CREATE TABLE IF NOT EXISTS room_seq (
            room TEXT PRIMARY KEY,
            next INTEGER NOT NULL
        );",
    )?;
    // huddle 2.0.3 (audit N-H1): add the `sender` column to a pre-2.0.3 mailbox
    // table. SQLite has no "ADD COLUMN IF NOT EXISTS", so guard on table_info.
    let has_sender: i64 = c.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('mailbox') WHERE name = 'sender'",
        [],
        |r| r.get(0),
    )?;
    if has_sender == 0 {
        c.execute_batch("ALTER TABLE mailbox ADD COLUMN sender TEXT;")?;
    }
    Ok(())
}

fn add_membership(c: &Connection, fp: &str, room: &str) -> Result<()> {
    // Fast path: re-asserting an existing (fp,room) is always allowed (idempotent)
    // and costs only a primary-key-indexed lookup — the common case on the hot
    // publish path, where the sender's own membership already exists. Doing this
    // first keeps the heavier cap COUNTs off that path entirely.
    let exists: i64 = c.query_row(
        "SELECT COUNT(*) FROM memberships WHERE fingerprint = ?1 AND room = ?2",
        params![fp, room],
        |r| r.get(0),
    )?;
    if exists > 0 {
        return Ok(());
    }
    // huddle 2.0.2 (audit L-17): bound distinct rooms per identity. Uses the
    // memberships(fingerprint, …) primary-key index.
    let per_fp: i64 = c.query_row(
        "SELECT COUNT(*) FROM memberships WHERE fingerprint = ?1",
        params![fp],
        |r| r.get(0),
    )?;
    if per_fp as usize >= MAX_ROOMS_PER_FP {
        return Ok(()); // at per-identity cap; shed the new membership silently
    }
    // huddle 2.1.2 (audit NSR-4): GLOBAL membership ceiling so identity churn can't
    // grow the table without bound (the per-fp cap above doesn't bound it globally).
    // The full-table COUNT runs ONLY here, on a genuinely-new insert — never on the
    // hot path's existing-membership re-assert, which already returned above.
    let total: i64 = c.query_row("SELECT COUNT(*) FROM memberships", [], |r| r.get(0))?;
    if total as usize >= MAX_MEMBERSHIPS_TOTAL {
        return Ok(()); // relay membership table full; shed silently
    }
    c.execute(
        "INSERT OR IGNORE INTO memberships(fingerprint, room) VALUES(?1, ?2)",
        params![fp, room],
    )?;
    Ok(())
}

fn room_members(c: &Connection, room: &str) -> Result<Vec<String>> {
    let mut stmt = c.prepare("SELECT fingerprint FROM memberships WHERE room = ?1")?;
    let rows = stmt.query_map(params![room], |r| r.get::<_, String>(0))?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

/// huddle 2.0.8 (WS2 foundations #5): atomically assign the next per-room
/// monotonic sequence number. Durable across relay restarts (a table, not an
/// in-memory counter), so the total order MLS commits need survives a reboot.
fn next_room_seq(c: &Connection, room: &str) -> Result<i64> {
    let seq: i64 = c.query_row(
        "INSERT INTO room_seq(room, next) VALUES(?1, 1)
         ON CONFLICT(room) DO UPDATE SET next = next + 1
         RETURNING next",
        params![room],
        |r| r.get(0),
    )?;
    Ok(seq)
}

/// Returns `Ok(true)` if the message was queued, `Ok(false)` if it was shed
/// because the global mailbox ceiling is reached (the caller should NOT count it
/// as queued, but must not disconnect the client — the relay is simply full).
fn enqueue(
    c: &Connection,
    sender: &str,
    fp: &str,
    room: &str,
    id: &str,
    payload_b64: &str,
) -> Result<bool> {
    // huddle 2.0.2 (audit H-2): global mailbox ceiling — shed rather than evict.
    let total: i64 = c.query_row("SELECT COUNT(*) FROM mailbox", [], |r| r.get(0))?;
    if total as usize >= MAX_MAILBOX_TOTAL_ROWS {
        return Ok(false);
    }
    // huddle 2.0.3 (audit N-H1): per-sender outstanding-rows cap. Without it the
    // global ceiling above is squattable by one identity (the H-2 residual):
    // ~200 fabricated, never-connecting recipients × 500 rows fills the pool and
    // sheds every honest user's offline message for 30 days. Bounding the rows a
    // single sender can hold outstanding (cheap via idx_mailbox_sender) means
    // squatting now costs many identities; legit rows drain as recipients ACK.
    let by_sender: i64 = c.query_row(
        "SELECT COUNT(*) FROM mailbox WHERE sender = ?1",
        params![sender],
        |r| r.get(0),
    )?;
    if by_sender as usize >= MAX_MAILBOX_PER_SENDER {
        return Ok(false);
    }
    // huddle 2.1.2 (audit NSR-1): the per-RECIPIENT cap is enforced by SHEDDING the
    // new row when the recipient is already at MAX_MAILBOX_PER_FP — NOT by the old
    // trim that kept the NEWEST rows (`DELETE ... ORDER BY id DESC LIMIT 500`). That
    // newest-wins trim let a peer flood ~500 junk `SendDirect` to an offline
    // recipient and silently EVICT that recipient's older, legitimately-queued
    // messages from honest senders (who had already been told `queued:1`), defeating
    // even at-least-once delivery. Sheicng instead — exactly like the H-2 global
    // ceiling and the N-H1 per-sender cap above — means a flooder can fill a victim's
    // mailbox but can no longer push out messages already queued for them; the victim
    // drains and frees slots on reconnect. Cheap on the hot path via idx_mailbox_fp.
    let by_fp: i64 = c.query_row(
        "SELECT COUNT(*) FROM mailbox WHERE fingerprint = ?1",
        params![fp],
        |r| r.get(0),
    )?;
    if by_fp as usize >= MAX_MAILBOX_PER_FP {
        return Ok(false);
    }
    c.execute(
        "INSERT INTO mailbox(fingerprint, room, msg_id, payload_b64, created_at, sender)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        params![fp, room, id, payload_b64, now_unix(), sender],
    )?;
    Ok(true)
}

/// huddle 1.1.4: read a recipient's queued ciphertext WITHOUT deleting it, so
/// the caller (`flush_mailbox`) can delete only what it actually delivered —
/// closing the delete-then-lose window. Returns `(row_id, room, msg_id,
/// payload_b64)` oldest-first. All DB access shares one `Mutex<Connection>`, so
/// peek and the matching delete can't interleave with another drain.
fn peek_mailbox(c: &Connection, fp: &str) -> Result<Vec<(i64, String, String, String)>> {
    let mut stmt = c.prepare(
        "SELECT id, room, msg_id, payload_b64 FROM mailbox WHERE fingerprint = ?1 ORDER BY id ASC",
    )?;
    let rows = stmt.query_map(params![fp], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Delete the specific mailbox rows that were confirmed delivered.
fn delete_mailbox_ids(c: &Connection, ids: &[i64]) -> Result<()> {
    for id in ids {
        c.execute("DELETE FROM mailbox WHERE id = ?1", params![id])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        enqueue, flush_mailbox, migrate, next_room_seq, peek_mailbox, request_target, ClientMsg,
        ConnectTokens, Connection, Metrics, OutEvent, ServerMsg, Shared, OUTBOUND_CAP,
    };
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};

    /// A `Shared` backed by a fresh in-memory mailbox DB — enough state to drive
    /// `flush_mailbox` without a live socket (huddle 2.0, F7).
    fn test_shared() -> Arc<Shared> {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        Arc::new(Shared {
            db: Mutex::new(conn),
            conns: Mutex::new(HashMap::new()),
            tokens: Mutex::new(ConnectTokens::default()),
            metrics: Metrics::default(),
        })
    }

    /// How many rows are still queued for `fp`.
    async fn mailbox_count(shared: &Arc<Shared>, fp: &str) -> usize {
        let db = shared.db.lock().await;
        peek_mailbox(&db, fp).unwrap().len()
    }

    #[test]
    fn message_serializes_mailbox_id_only_when_present() {
        // huddle 2.0 (F7): a live message carries no `mailbox_id` on the wire, so
        // a pre-2.0 client decodes exactly the fields it expects (backward-compat
        // via skip_serializing_if).
        let live = ServerMsg::Message {
            room: "r".into(),
            id: "i".into(),
            payload_b64: "p".into(),
            mailbox_id: None,
            seq: None,
        };
        let s = serde_json::to_string(&live).unwrap();
        assert!(
            !s.contains("mailbox_id"),
            "live message must omit mailbox_id for old-client compat: {s}"
        );
        // A queued (at-least-once) delivery carries the row id to ACK.
        let queued = ServerMsg::Message {
            room: "r".into(),
            id: "i".into(),
            payload_b64: "p".into(),
            mailbox_id: Some(42),
            seq: None,
        };
        let s = serde_json::to_string(&queued).unwrap();
        assert!(
            s.contains("\"mailbox_id\":42"),
            "queued message must carry its mailbox_id: {s}"
        );
    }

    #[test]
    fn room_seq_is_per_room_and_monotonic() {
        // huddle 2.0.8 (WS2 #5): each room gets its own durable monotonic
        // sequence — the total order MLS commit delivery needs.
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        assert_eq!(next_room_seq(&conn, "room-a").unwrap(), 1);
        assert_eq!(next_room_seq(&conn, "room-a").unwrap(), 2);
        assert_eq!(next_room_seq(&conn, "room-a").unwrap(), 3);
        // A different room sequences independently.
        assert_eq!(next_room_seq(&conn, "room-b").unwrap(), 1);
        assert_eq!(next_room_seq(&conn, "room-a").unwrap(), 4);
    }

    #[test]
    fn parses_ack() {
        // huddle 2.0 (F7): the relay must accept the new ACK variant.
        let m: ClientMsg = serde_json::from_str(r#"{"type":"ack","mailbox_id":7}"#).unwrap();
        match m {
            ClientMsg::Ack { mailbox_id } => assert_eq!(mailbox_id, 7),
            other => panic!("expected ack, got {other:?}"),
        }
    }

    #[test]
    fn hello_acks_capability_defaults_false() {
        // A pre-2.0 Hello (no `acks` field) must decode with the bit off, so the
        // relay keeps the classical delete-on-deliver behavior for old clients.
        let m: ClientMsg = serde_json::from_str(r#"{"type":"hello","fingerprint":"fp"}"#).unwrap();
        match m {
            ClientMsg::Hello { acks, .. } => assert!(!acks),
            other => panic!("expected hello, got {other:?}"),
        }
        // A 2.0 client opts in explicitly.
        let m: ClientMsg =
            serde_json::from_str(r#"{"type":"hello","fingerprint":"fp","acks":true}"#).unwrap();
        match m {
            ClientMsg::Hello { acks, .. } => assert!(acks),
            other => panic!("expected hello, got {other:?}"),
        }
    }

    #[test]
    fn parses_plain_paths() {
        assert_eq!(
            request_target("GET / HTTP/1.1\r\nHost: x.onion\r\n\r\n"),
            "/"
        );
        assert_eq!(request_target("GET /health HTTP/1.1\r\n\r\n"), "/health");
        assert_eq!(request_target("GET /ws HTTP/1.1\r\n"), "/ws");
    }

    #[test]
    fn strips_query_string() {
        assert_eq!(
            request_target("GET /health?probe=1 HTTP/1.1\r\n"),
            "/health"
        );
        assert_eq!(request_target("GET /?x HTTP/1.1\r\n"), "/");
    }

    #[test]
    fn other_methods_keep_their_target() {
        // The router only special-cases the WebSocket upgrade and /health;
        // every other method/path falls through to the landing page, so we
        // just need the target parsed faithfully here.
        assert_eq!(request_target("HEAD /health HTTP/1.1\r\n"), "/health");
        assert_eq!(request_target("POST /anything HTTP/1.1\r\n"), "/anything");
    }

    #[test]
    fn malformed_requests_fall_back_to_root() {
        assert_eq!(request_target(""), "/"); // empty
        assert_eq!(request_target("GET"), "/"); // no target token
        assert_eq!(request_target("garbage\r\n"), "/"); // single token
    }

    #[tokio::test]
    async fn legacy_flush_deletes_only_after_writer_confirms() {
        // huddle 2.0 (F7): for acks=false clients the rows must be deleted only
        // once the writer flushes the batch to the socket and signals the `Flush`
        // barrier — the safe 1.1.4 deliver-then-delete behavior.
        let shared = test_shared();
        let fp = "fp-legacy";
        {
            let db = shared.db.lock().await;
            for i in 0..3 {
                enqueue(&db, "sender", fp, "room", &format!("m{i}"), "p").unwrap();
            }
        }
        let (tx, mut rx) = mpsc::channel::<OutEvent>(OUTBOUND_CAP);
        // A faithful writer: it drains every message and signals each barrier,
        // standing in for a socket that stays up for the whole drain.
        let writer = tokio::spawn(async move {
            let mut written = 0usize;
            while let Some(evt) = rx.recv().await {
                match evt {
                    OutEvent::Msg(_) => written += 1,
                    OutEvent::Flush(done) => {
                        let _ = done.send(());
                    }
                }
            }
            written
        });
        flush_mailbox(fp, &tx, &shared, false).await.unwrap();
        drop(tx); // let the writer observe the channel close and finish
        let written = writer.await.unwrap();
        assert_eq!(written, 3, "all three legacy messages reached the writer");
        assert_eq!(
            mailbox_count(&shared, fp).await,
            0,
            "rows deleted only after the write barrier confirmed delivery"
        );
    }

    #[tokio::test]
    async fn legacy_flush_keeps_rows_when_socket_dies_before_barrier() {
        // huddle 2.0 (F7): if the socket dies mid-drain — the writer drops its
        // receiver before handling the `Flush` barrier — the legacy path must
        // delete NOTHING, so a buffered-but-unwritten message is never lost. It
        // is redelivered on the next connection (deduped by msg_id) instead.
        let shared = test_shared();
        let fp = "fp-legacy-drop";
        {
            let db = shared.db.lock().await;
            for i in 0..3 {
                enqueue(&db, "sender", fp, "room", &format!("m{i}"), "p").unwrap();
            }
        }
        let (tx, mut rx) = mpsc::channel::<OutEvent>(OUTBOUND_CAP);
        // The writer takes the three messages but returns (dropping `rx`) before
        // it ever signals the trailing barrier — exactly a socket that drops
        // after the buffer was accepted but before the bytes hit the wire.
        let writer = tokio::spawn(async move {
            for _ in 0..3 {
                let _ = rx.recv().await;
            }
            // `rx` dropped here: the `Flush` barrier's signal is discarded.
        });
        flush_mailbox(fp, &tx, &shared, false).await.unwrap();
        writer.await.unwrap();
        assert_eq!(
            mailbox_count(&shared, fp).await,
            3,
            "no rows deleted: the messages may never have reached the socket"
        );
    }

    #[tokio::test]
    async fn at_least_once_tags_rows_and_keeps_them_until_ack() {
        // huddle 2.0 (F7): for acks=true clients flush tags each delivery with its
        // mailbox_id and deletes nothing — the row lives until the client `Ack`s.
        let shared = test_shared();
        let fp = "fp-ack";
        {
            let db = shared.db.lock().await;
            enqueue(&db, "sender", fp, "room", "m0", "p").unwrap();
            enqueue(&db, "sender", fp, "room", "m1", "p").unwrap();
        }
        let (tx, mut rx) = mpsc::channel::<OutEvent>(OUTBOUND_CAP);
        let collector = tokio::spawn(async move {
            let mut ids = Vec::new();
            while let Some(evt) = rx.recv().await {
                if let OutEvent::Msg(ServerMsg::Message { mailbox_id, .. }) = evt {
                    ids.push(mailbox_id);
                }
            }
            ids
        });
        flush_mailbox(fp, &tx, &shared, true).await.unwrap();
        drop(tx);
        let ids = collector.await.unwrap();
        assert_eq!(ids.len(), 2, "both queued messages were delivered");
        assert!(
            ids.iter().all(|m| m.is_some()),
            "acks=true tags every delivery with its mailbox_id to ACK"
        );
        assert_eq!(
            mailbox_count(&shared, fp).await,
            2,
            "acks=true never deletes in flush; it waits for the client's Ack"
        );
    }
}
