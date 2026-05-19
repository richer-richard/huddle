//! huddle 0.7.4: desktop notifications when the terminal isn't focused,
//! plus a one-shot catch-up summary when the app reopens.
//!
//! Cross-platform without an extra crate: shells out to `osascript` on
//! macOS, `notify-send` on Linux, and PowerShell BalloonTip on Windows.
//! Failures are logged and dropped — a missing notifier should never
//! crash the TUI.
//!
//! Focus tracking uses crossterm's `EnableFocusChange` ANSI sequence
//! (`\x1b[?1004h`). Modern terminals (iTerm2, Terminal.app, Alacritty,
//! Kitty, wezterm, Windows Terminal, GNOME Terminal) all emit the
//! companion `FocusGained` / `FocusLost` events; on terminals that
//! don't, we keep the default `focused = true` and simply never fire
//! the unfocused-only notifications.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// 0.7.5: minimum time between fired desktop notifications. Within
/// this window, additional `notify()` calls are coalesced into one
/// summary notification ("N more new messages") fired after the
/// window closes. Prevents process / thread spam for busy rooms.
const RATE_LIMIT: Duration = Duration::from_millis(2000);

struct RateState {
    /// When the most recent notification was actually dispatched.
    last_fired_at: Instant,
    /// Calls suppressed during the active cooldown window.
    pending_count: u32,
    /// Set while a delayed summary thread is sleeping out the window.
    timer_running: bool,
}

fn rate_state() -> &'static Mutex<RateState> {
    static STATE: OnceLock<Mutex<RateState>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(RateState {
            // Initialize far enough in the past that the first call
            // always fires immediately.
            last_fired_at: Instant::now() - RATE_LIMIT * 2,
            pending_count: 0,
            timer_running: false,
        })
    })
}

static WINDOW_FOCUSED: AtomicBool = AtomicBool::new(true);
/// Becomes `true` after the terminal has emitted at least one
/// FocusGained or FocusLost event.
static FOCUS_OBSERVED: AtomicBool = AtomicBool::new(false);

fn startup_instant() -> Instant {
    static START: OnceLock<Instant> = OnceLock::new();
    *START.get_or_init(Instant::now)
}

/// huddle 0.7.12: time after which a terminal that has NEVER emitted a
/// FocusChange event is assumed to lack focus tracking entirely. Until
/// then `is_focused()` returns `true` (don't spam during a launch
/// window). After the grace period elapses with no signal, we flip to
/// `false` so users on tmux-without-focus-events / basic SSH still get
/// notifications.
///
/// The trade-off: 0.7.10 defaulted false (spam), 0.7.11 defaulted true
/// (silence on legacy terminals). 0.7.12 splits the difference — calm
/// during startup, then assume focus tracking is broken and notify.
const FOCUS_DETECTION_GRACE: Duration = Duration::from_secs(5);

pub fn set_focused(focused: bool) {
    WINDOW_FOCUSED.store(focused, Ordering::Relaxed);
    FOCUS_OBSERVED.store(true, Ordering::Relaxed);
}

pub fn is_focused() -> bool {
    if !FOCUS_OBSERVED.load(Ordering::Relaxed) {
        // If we're still inside the grace window, assume focused
        // (suppresses startup-burst notifications on slow-to-signal
        // terminals). After the grace window, assume the terminal
        // doesn't speak focus events and fall back to "always notify"
        // so the user isn't silently missing every message.
        return Instant::now().duration_since(startup_instant()) < FOCUS_DETECTION_GRACE;
    }
    WINDOW_FOCUSED.load(Ordering::Relaxed)
}

/// Fire a desktop notification on a background thread. Non-blocking;
/// errors are swallowed. Rate-limited (see `RATE_LIMIT`): within a
/// hot window, subsequent calls are coalesced and a single "N more
/// new messages" summary fires once the window closes.
pub fn notify(title: &str, body: &str) {
    let now = Instant::now();
    let action = {
        let mut s = rate_state().lock().expect("rate state poisoned");
        if now.duration_since(s.last_fired_at) >= RATE_LIMIT && !s.timer_running {
            s.last_fired_at = now;
            NotifyAction::FireNow
        } else {
            s.pending_count = s.pending_count.saturating_add(1);
            if !s.timer_running {
                s.timer_running = true;
                NotifyAction::ScheduleSummary
            } else {
                NotifyAction::Coalesce
            }
        }
    };
    match action {
        NotifyAction::FireNow => fire(title.to_string(), body.to_string()),
        NotifyAction::ScheduleSummary => {
            let last_fired = rate_state()
                .lock()
                .map(|s| s.last_fired_at)
                .unwrap_or(now);
            let sleep = RATE_LIMIT.saturating_sub(now.duration_since(last_fired));
            std::thread::spawn(move || {
                std::thread::sleep(sleep);
                let (n, fire_at) = {
                    let mut s = rate_state().lock().expect("rate state poisoned");
                    let n = s.pending_count;
                    s.pending_count = 0;
                    s.timer_running = false;
                    let fire_at = Instant::now();
                    if n > 0 {
                        s.last_fired_at = fire_at;
                    }
                    (n, fire_at)
                };
                let _ = fire_at;
                if n > 0 {
                    let body = if n == 1 {
                        "1 more new message".to_string()
                    } else {
                        format!("{} more new messages", n)
                    };
                    fire("huddle".to_string(), body);
                }
            });
        }
        NotifyAction::Coalesce => {}
    }
}

enum NotifyAction {
    FireNow,
    ScheduleSummary,
    Coalesce,
}

fn fire(title: String, body: String) {
    std::thread::spawn(move || {
        if let Err(e) = send_notification(&title, &body) {
            tracing::debug!(error = %e, "desktop notification failed");
        }
    });
}

/// Trim a message body to a single line of at most ~120 chars for
/// the notification preview. Real terminals will wrap long previews
/// awkwardly and some notification daemons truncate silently.
pub fn preview(body: &str) -> String {
    let single: String = body.chars().map(|c| if c == '\n' { ' ' } else { c }).collect();
    let trimmed = single.trim();
    if trimmed.chars().count() > 120 {
        let head: String = trimmed.chars().take(117).collect();
        format!("{}…", head)
    } else {
        trimmed.to_string()
    }
}

#[cfg(target_os = "macos")]
fn send_notification(title: &str, body: &str) -> std::io::Result<()> {
    // huddle 0.7.11: AppleScript strings can't contain literal CR / LF,
    // and treat both `\` and `"` as special. Pre-0.7.11 only the
    // backslash and double-quote were escaped, so a room name or
    // username containing a CR (a peer-controlled value!) silently
    // broke the osascript invocation. Now we strip every control char
    // before passing to osascript.
    let sanitize = |s: &str| -> String {
        s.chars()
            .filter(|c| !c.is_control())
            .collect::<String>()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    };
    let script = format!(
        r#"display notification "{}" with title "{}""#,
        sanitize(body),
        sanitize(title)
    );
    std::process::Command::new("osascript")
        .args(["-e", &script])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn send_notification(title: &str, body: &str) -> std::io::Result<()> {
    // huddle 0.7.11: strip control chars from title/body so a peer-
    // controlled username with embedded CR can't confuse the daemon.
    // Also pass --category=im.received which most notification daemons
    // (GNOME Shell, KDE) use to group desktop messaging notifications.
    let sanitize = |s: &str| -> String { s.chars().filter(|c| !c.is_control()).collect() };
    std::process::Command::new("notify-send")
        .arg("--app-name=huddle")
        .arg("--category=im.received")
        .arg("--expire-time=5000")
        .arg(sanitize(title))
        .arg(sanitize(body))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn send_notification(title: &str, body: &str) -> std::io::Result<()> {
    // huddle 0.7.11: strip control chars + PowerShell single-quote
    // escape. A literal LF / CR in a peer-controlled username used to
    // smuggle a multi-line PowerShell statement (low-impact since the
    // surrounding context constrains what can be injected, but worth
    // closing). PowerShell single-quoted strings: `'` → `''`.
    let esc = |s: &str| -> String {
        s.chars()
            .filter(|c| !c.is_control())
            .collect::<String>()
            .replace('\'', "''")
    };
    let script = format!(
        "[reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null; \
         [reflection.assembly]::loadwithpartialname('System.Drawing') | Out-Null; \
         $n = New-Object System.Windows.Forms.NotifyIcon; \
         $n.Icon = [System.Drawing.SystemIcons]::Information; \
         $n.BalloonTipTitle = '{}'; \
         $n.BalloonTipText = '{}'; \
         $n.Visible = $true; \
         $n.ShowBalloonTip(5000); \
         Start-Sleep -Seconds 5; \
         $n.Dispose()",
        esc(title),
        esc(body)
    );
    std::process::Command::new("powershell")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &script])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn send_notification(_title: &str, _body: &str) -> std::io::Result<()> {
    Ok(())
}
