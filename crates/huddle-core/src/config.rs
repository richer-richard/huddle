use std::path::PathBuf;

pub fn data_dir() -> PathBuf {
    let base = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("huddle")
}

/// Phase D: location of the user's optional config file. We use
/// `dirs::config_dir()` rather than `data_dir()` so this lives in the
/// platform-appropriate "preferences" directory (macOS
/// `~/Library/Application Support`, Linux `~/.config`, Windows
/// `%APPDATA%`). Doesn't have to exist — `load_relays` returns an
/// empty list if absent.
pub fn config_path() -> PathBuf {
    let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("huddle").join("config.toml")
}

/// Phase D: parse the relay multiaddr list from the config file. The
/// documented form (README + MANUAL_TESTING §14) is a top-level array:
///
/// ```toml
/// relays = [
///   "/dns4/relay.example.com/tcp/4001/p2p/12D3Koo...",
/// ]
/// ```
///
/// huddle 0.7.12: the parser now honors exactly that. Pre-0.7.12 it
/// required an undocumented `[network]` section header AND only parsed a
/// single-line array, so the documented header-less, multi-line form
/// silently produced zero relays — the `config.toml` path to cross-
/// internet reach was a no-op. Now no header is required (a `relays`
/// entry is accepted whether or not it sits under a section), the array
/// may span multiple lines, a single-line `relays = ["a", "b"]` and a
/// bare scalar `relays = "a"` both work, and trailing `# comments` are
/// stripped. Returns an empty Vec if the file doesn't exist or has no
/// relays entry.
pub fn load_relays() -> Option<Vec<String>> {
    let path = config_path();
    let body = std::fs::read_to_string(&path).ok()?;
    Some(parse_relays(&body))
}

/// Pure relay-list extraction, split out from `load_relays` so it can be
/// unit-tested without touching the filesystem.
fn parse_relays(body: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut in_array = false;
    for raw in body.lines() {
        let line = strip_inline_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if in_array {
            // Inside a multi-line `relays = [ ... ]`. Collect quoted
            // entries until the closing `]`.
            let (segment, closed) = match line.find(']') {
                Some(idx) => (&line[..idx], true),
                None => (line, false),
            };
            collect_relay_items(segment, &mut out);
            if closed {
                in_array = false;
            }
            continue;
        }
        // Outside an array the only key we care about is `relays`.
        // Section headers (`[network]`) and unrelated keys fall through
        // — we accept a `relays` entry whether or not it sits under a
        // section, matching the header-less documented form.
        let rest = match line.strip_prefix("relays") {
            Some(r) => r.trim_start(),
            None => continue,
        };
        let rest = match rest.strip_prefix('=') {
            Some(r) => r.trim(),
            None => continue, // a key like `relays_enabled` — not ours
        };
        match rest.strip_prefix('[') {
            // Array form, single- or multi-line.
            Some(after_open) => match after_open.find(']') {
                Some(idx) => collect_relay_items(&after_open[..idx], &mut out),
                None => {
                    collect_relay_items(after_open, &mut out);
                    in_array = true;
                }
            },
            // Bare scalar form: `relays = "addr"`.
            None => {
                let item = rest.trim_matches('"').trim_matches('\'');
                if !item.is_empty() {
                    out.push(item.to_string());
                }
            }
        }
    }
    out
}

/// Strip a `#` comment from a config line. Multiaddrs never contain `#`,
/// so cutting at the first one is safe for the relays value space and
/// matches TOML comment semantics.
fn strip_inline_comment(line: &str) -> &str {
    match line.find('#') {
        Some(idx) => &line[..idx],
        None => line,
    }
}

/// Split a comma-separated array segment into trimmed, unquoted relay
/// entries, dropping empties.
fn collect_relay_items(segment: &str, out: &mut Vec<String>) {
    for item in segment.split(',') {
        let item = item.trim().trim_matches('"').trim_matches('\'');
        if !item.is_empty() {
            out.push(item.to_string());
        }
    }
}

/// huddle 0.8: optional override for the centralized server (a Tor-onion
/// relay) WebSocket URL, read from `config.toml`:
///
/// ```toml
/// server_url = "ws://<your-onion>.onion:80/ws"
/// ```
///
/// Precedence is resolved by the caller (`main.rs`): the `--server` CLI
/// flag wins, then this config value, then the baked-in default onion.
/// So you can repoint the client at a different relay without recompiling
/// or retyping a flag every launch. Returns `None` if absent.
pub fn server_url() -> Option<String> {
    parse_scalar(&std::fs::read_to_string(config_path()).ok()?, "server_url")
}

/// huddle 0.8: optional override for the local Tor SOCKS5 proxy address
/// used to reach `.onion` server URLs (default `127.0.0.1:9050`). Set in
/// `config.toml` as `tor_socks = "127.0.0.1:9150"` — e.g. to use the Tor
/// Browser bundle's port. `--tor-socks` overrides this. `None` if absent.
pub fn tor_socks() -> Option<String> {
    parse_scalar(&std::fs::read_to_string(config_path()).ok()?, "tor_socks")
}

/// huddle 1.0: optional clearnet relay URL — a `ws://<ip>:<port>/ws` or
/// `wss://host/ws` door onto the SAME relay backend as the onion. Lets users
/// behind a VPN (or where Tor is blocked) reach the relay directly and fast.
/// The scheme decides which clearnet door (plain / TLS) is used.
///
/// ```toml
/// clearnet_url = "ws://203.0.113.7:8787/ws"
/// ```
/// `--clearnet-server` overrides this. `None` if absent.
pub fn clearnet_url() -> Option<String> {
    parse_scalar(
        &std::fs::read_to_string(config_path()).ok()?,
        "clearnet_url",
    )
}

/// huddle 1.0: optional Tor bridge line for the bridge door (to reach Tor
/// where it's blocked). With the `arti` build this is passed to the embedded
/// Tor; otherwise it documents that your system Tor should carry this bridge.
///
/// ```toml
/// tor_bridge = "obfs4 1.2.3.4:443 <FINGERPRINT> cert=... iat-mode=0"
/// ```
/// `--tor-bridge` overrides this. `None` if absent.
pub fn tor_bridge() -> Option<String> {
    parse_scalar(&std::fs::read_to_string(config_path()).ok()?, "tor_bridge")
}

/// Extract a top-level `key = "value"` string from a config body. Honors
/// the same header-less, inline-comment-stripping conventions as
/// `parse_relays`. Section headers and unrelated keys fall through.
/// Returns the first match's unquoted value, or `None`.
fn parse_scalar(body: &str, key: &str) -> Option<String> {
    for raw in body.lines() {
        let line = strip_inline_comment(raw).trim();
        let rest = match line.strip_prefix(key) {
            Some(r) => r.trim_start(),
            None => continue,
        };
        // Guard against prefix collisions (`server_url_backup`): the next
        // char after the key must begin an assignment.
        let rest = match rest.strip_prefix('=') {
            Some(r) => r.trim(),
            None => continue,
        };
        let val = rest.trim_matches('"').trim_matches('\'').trim();
        if !val.is_empty() {
            return Some(val.to_string());
        }
    }
    None
}

pub fn db_path() -> PathBuf {
    data_dir().join("huddle.db")
}

pub fn log_path() -> PathBuf {
    data_dir().join("huddle.log")
}

pub fn ensure_data_dir() -> std::io::Result<()> {
    let dir = data_dir();
    std::fs::create_dir_all(&dir)?;
    // huddle 2.0.2 (audit L-11): the data dir holds the SQLCipher DB (+ WAL/SHM),
    // the keychain salt, and logs. Restrict it to the owner (0700) on Unix so
    // other local users can't traverse in to read the encrypted DB or salt. This
    // also protects files created inside with a default umask. Best-effort.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dir_is_inside_huddle_directory() {
        let dir = data_dir();
        assert!(dir.ends_with("huddle") || dir.to_string_lossy().contains("huddle"));
    }

    #[test]
    fn db_path_ends_with_huddle_db() {
        let path = db_path();
        assert_eq!(path.file_name().unwrap(), "huddle.db");
    }

    // huddle 0.7.12 — relay-parsing regression tests. The form below is
    // verbatim what README.md (line 283) and MANUAL_TESTING.md §14 tell
    // users to put in config.toml; pre-0.7.12 it parsed to zero relays.
    #[test]
    fn parse_relays_documented_multiline_no_header() {
        let body = "relays = [\n  \"/dns4/relay.example.com/tcp/4001/p2p/12D3Koo\",\n]\n";
        assert_eq!(
            parse_relays(body),
            vec!["/dns4/relay.example.com/tcp/4001/p2p/12D3Koo".to_string()]
        );
    }

    #[test]
    fn parse_relays_multiline_with_network_header() {
        let body = "[network]\nrelays = [\n  \"/ip4/1.2.3.4/tcp/4001/p2p/A\",\n  \"/ip4/5.6.7.8/tcp/4001/p2p/B\",\n]\n";
        assert_eq!(
            parse_relays(body),
            vec![
                "/ip4/1.2.3.4/tcp/4001/p2p/A".to_string(),
                "/ip4/5.6.7.8/tcp/4001/p2p/B".to_string(),
            ]
        );
    }

    #[test]
    fn parse_relays_single_line_array() {
        let body = "relays = [\"/ip4/1.2.3.4/tcp/1/p2p/A\", \"/ip4/5.6.7.8/tcp/2/p2p/B\"]";
        assert_eq!(parse_relays(body).len(), 2);
    }

    #[test]
    fn parse_relays_scalar_form() {
        let body = "relays = \"/ip4/1.2.3.4/tcp/1/p2p/A\"";
        assert_eq!(
            parse_relays(body),
            vec!["/ip4/1.2.3.4/tcp/1/p2p/A".to_string()]
        );
    }

    #[test]
    fn parse_relays_strips_comments_and_blanks() {
        let body = "# a comment\n\nrelays = [\n  \"/ip4/1.2.3.4/tcp/1/p2p/A\",  # inline note\n]\n";
        assert_eq!(
            parse_relays(body),
            vec!["/ip4/1.2.3.4/tcp/1/p2p/A".to_string()]
        );
    }

    #[test]
    fn parse_relays_empty_when_absent() {
        assert!(parse_relays("[network]\nfoo = 1\n").is_empty());
        assert!(parse_relays("").is_empty());
    }

    #[test]
    fn parse_relays_ignores_similar_key() {
        // `relays_enabled` must not be mistaken for the `relays` array.
        assert!(parse_relays("relays_enabled = true\n").is_empty());
    }

    // huddle 0.8 — scalar overrides for the onion relay + SOCKS proxy.
    #[test]
    fn parse_scalar_reads_quoted_value() {
        let body = "server_url = \"ws://abc.onion:80/ws\"\n";
        assert_eq!(
            parse_scalar(body, "server_url").as_deref(),
            Some("ws://abc.onion:80/ws")
        );
    }

    #[test]
    fn parse_scalar_strips_comment_and_header() {
        let body = "[network]\ntor_socks = \"127.0.0.1:9150\"  # tor browser\n";
        assert_eq!(
            parse_scalar(body, "tor_socks").as_deref(),
            Some("127.0.0.1:9150")
        );
    }

    #[test]
    fn parse_scalar_none_when_absent_or_similar_key() {
        assert!(parse_scalar("foo = 1\n", "server_url").is_none());
        // prefix collision must not match
        assert!(parse_scalar("server_url_backup = \"x\"\n", "server_url").is_none());
    }
}
