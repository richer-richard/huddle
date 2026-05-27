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
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Result};
use futures_util::{SinkExt, StreamExt};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, info};

/// Reject base64 payloads larger than this (≈256 KiB encoded).
const MAX_PAYLOAD_B64: usize = 256 * 1024;
const MAX_ID_LEN: usize = 128;
const MAX_MSG_ID_LEN: usize = 256;
/// Keep at most this many queued messages per offline recipient.
const MAX_MAILBOX_PER_FP: usize = 500;
const MAX_ROOMS_PER_HELLO: usize = 1000;

// ---- wire protocol (server level — cleartext routing only) ----

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMsg {
    /// Announce identity and (re)assert room memberships, then drain the
    /// mailbox. Must be the first message.
    Hello {
        fingerprint: String,
        #[serde(default)]
        rooms: Vec<String>,
    },
    Subscribe {
        room: String,
    },
    Unsubscribe {
        room: String,
    },
    /// Send an opaque payload to every other member of `room`.
    Publish {
        room: String,
        id: String,
        payload_b64: String,
    },
    /// Re-drain the mailbox on demand.
    Fetch,
    Ping,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMsg {
    Ready { fingerprint: String },
    Message { room: String, id: String, payload_b64: String },
    Sent { id: String, delivered: usize, queued: usize },
    Pong,
    Error { message: String },
}

type Tx = mpsc::UnboundedSender<ServerMsg>;

struct Shared {
    db: Mutex<Connection>,
    /// fingerprint → the live socket senders for that identity (a user may
    /// be connected from more than one client at once).
    conns: Mutex<HashMap<String, Vec<Tx>>>,
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
    let db_path = std::env::var("HUDDLE_SERVER_DB").unwrap_or_else(|_| "huddle-server.db".to_string());

    let conn = Connection::open(&db_path)?;
    migrate(&conn)?;
    let shared = Arc::new(Shared {
        db: Mutex::new(conn),
        conns: Mutex::new(HashMap::new()),
    });

    let listener = TcpListener::bind(&bind).await?;
    info!(%bind, db = %db_path, "huddle-server listening (WebSocket + /health)");

    loop {
        let (stream, _peer) = listener.accept().await?;
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, shared).await {
                debug!(error = %e, "connection ended");
            }
        });
    }
}

/// Distinguish a plain `GET /health` probe from a WebSocket upgrade by
/// peeking (not consuming) the first bytes of the request.
async fn handle_conn(stream: TcpStream, shared: Arc<Shared>) -> Result<()> {
    let mut buf = [0u8; 1024];
    let n = stream.peek(&mut buf).await?;
    let head = String::from_utf8_lossy(&buf[..n]);
    if head.to_ascii_lowercase().contains("upgrade: websocket") {
        let ws = tokio_tungstenite::accept_async(stream).await?;
        serve_ws(ws, shared).await
    } else {
        // Plain HTTP. `/health` keeps the JSON probe contract; every other
        // path (notably `/`) serves the static landing page so a browser
        // visiting the onion sees something intentional instead of raw
        // bytes. The relay protocol lives on the WebSocket upgrade above —
        // clients (the CLI, and any future frontend) hit `/ws`.
        match request_target(&head) {
            "/health" => serve_health(stream).await,
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
    let (tx, mut rx) = mpsc::unbounded_channel::<ServerMsg>();

    // Pump outgoing messages from the channel to the socket. Other
    // connections push into `tx` to deliver fan-out messages here.
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let json = match serde_json::to_string(&msg) {
                Ok(j) => j,
                Err(_) => continue,
            };
            if sink.send(WsMessage::Text(json.into())).await.is_err() {
                break;
            }
        }
    });

    let mut fingerprint: Option<String> = None;

    while let Some(frame) = stream.next().await {
        let frame = match frame {
            Ok(f) => f,
            Err(_) => break,
        };
        let text = match frame {
            WsMessage::Text(t) => t.as_str().to_string(),
            WsMessage::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
            WsMessage::Close(_) => break,
            WsMessage::Ping(_) | WsMessage::Pong(_) | WsMessage::Frame(_) => continue,
        };
        let msg: ClientMsg = match serde_json::from_str(&text) {
            Ok(m) => m,
            Err(e) => {
                let _ = tx.send(ServerMsg::Error {
                    message: format!("bad message: {e}"),
                });
                continue;
            }
        };
        if let Err(e) = handle_client_msg(msg, &mut fingerprint, &tx, &shared).await {
            let _ = tx.send(ServerMsg::Error {
                message: e.to_string(),
            });
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
    tx: &Tx,
    shared: &Arc<Shared>,
) -> Result<()> {
    match msg {
        ClientMsg::Hello { fingerprint: fp, rooms } => {
            let fp = clean_id(&fp).ok_or_else(|| anyhow!("invalid fingerprint"))?;
            *fingerprint = Some(fp.clone());
            shared
                .conns
                .lock()
                .await
                .entry(fp.clone())
                .or_default()
                .push(tx.clone());
            {
                let db = shared.db.lock().await;
                for room in rooms.iter().take(MAX_ROOMS_PER_HELLO) {
                    if let Some(room) = clean_id(room) {
                        add_membership(&db, &fp, &room)?;
                    }
                }
            }
            let _ = tx.send(ServerMsg::Ready { fingerprint: fp.clone() });
            flush_mailbox(&fp, tx, shared).await?;
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
        ClientMsg::Publish { room, id, payload_b64 } => {
            let fp = require_fp(fingerprint)?;
            let room = clean_id(&room).ok_or_else(|| anyhow!("invalid room"))?;
            if id.is_empty() || id.len() > MAX_MSG_ID_LEN {
                bail!("invalid message id");
            }
            if payload_b64.len() > MAX_PAYLOAD_B64 {
                bail!("payload too large");
            }
            // The sender is, by definition, a member of the room.
            let members = {
                let db = shared.db.lock().await;
                add_membership(&db, &fp, &room)?;
                room_members(&db, &room)?
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
                        Some(senders) => {
                            let out = ServerMsg::Message {
                                room: room.clone(),
                                id: id.clone(),
                                payload_b64: payload_b64.clone(),
                            };
                            senders.iter().fold(false, |acc, s| acc | s.send(out.clone()).is_ok())
                        }
                        None => false,
                    }
                };
                if online {
                    delivered += 1;
                } else {
                    let db = shared.db.lock().await;
                    enqueue(&db, &member, &room, &id, &payload_b64)?;
                    queued += 1;
                }
            }
            let _ = tx.send(ServerMsg::Sent { id, delivered, queued });
        }
        ClientMsg::Fetch => {
            let fp = require_fp(fingerprint)?;
            flush_mailbox(&fp, tx, shared).await?;
        }
        ClientMsg::Ping => {
            let _ = tx.send(ServerMsg::Pong);
        }
    }
    Ok(())
}

async fn flush_mailbox(fp: &str, tx: &Tx, shared: &Arc<Shared>) -> Result<()> {
    let items = {
        let db = shared.db.lock().await;
        take_mailbox(&db, fp)?
    };
    for (room, id, payload_b64) in items {
        let _ = tx.send(ServerMsg::Message { room, id, payload_b64 });
    }
    Ok(())
}

fn require_fp(fp: &Option<String>) -> Result<String> {
    fp.clone().ok_or_else(|| anyhow!("send hello first"))
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
            created_at  INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_mailbox_fp ON mailbox(fingerprint);",
    )?;
    Ok(())
}

fn add_membership(c: &Connection, fp: &str, room: &str) -> Result<()> {
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

fn enqueue(c: &Connection, fp: &str, room: &str, id: &str, payload_b64: &str) -> Result<()> {
    c.execute(
        "INSERT INTO mailbox(fingerprint, room, msg_id, payload_b64, created_at)
         VALUES(?1, ?2, ?3, ?4, ?5)",
        params![fp, room, id, payload_b64, now_unix()],
    )?;
    // Trim to the newest MAX_MAILBOX_PER_FP entries for this recipient.
    c.execute(
        "DELETE FROM mailbox WHERE fingerprint = ?1 AND id NOT IN (
            SELECT id FROM mailbox WHERE fingerprint = ?1 ORDER BY id DESC LIMIT ?2
        )",
        params![fp, MAX_MAILBOX_PER_FP as i64],
    )?;
    Ok(())
}

fn take_mailbox(c: &Connection, fp: &str) -> Result<Vec<(String, String, String)>> {
    let mut out = Vec::new();
    {
        let mut stmt = c.prepare(
            "SELECT room, msg_id, payload_b64 FROM mailbox WHERE fingerprint = ?1 ORDER BY id ASC",
        )?;
        let rows = stmt.query_map(params![fp], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            out.push(row?);
        }
    }
    c.execute("DELETE FROM mailbox WHERE fingerprint = ?1", params![fp])?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::request_target;

    #[test]
    fn parses_plain_paths() {
        assert_eq!(request_target("GET / HTTP/1.1\r\nHost: x.onion\r\n\r\n"), "/");
        assert_eq!(request_target("GET /health HTTP/1.1\r\n\r\n"), "/health");
        assert_eq!(request_target("GET /ws HTTP/1.1\r\n"), "/ws");
    }

    #[test]
    fn strips_query_string() {
        assert_eq!(request_target("GET /health?probe=1 HTTP/1.1\r\n"), "/health");
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
}
