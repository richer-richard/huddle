//! Desktop notifications, ported from the TUI's `crates/huddle/src/notifier.rs`.
//! Shells out to `osascript` (macOS), `notify-send` (Linux), or PowerShell
//! (Windows). Focus is handled by egui (`InputState::focused`), so the ANSI
//! focus-tracking from the TUI version is dropped here. Rate-limited so a hot
//! room can't spawn a process per message.

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const RATE_LIMIT: Duration = Duration::from_millis(2000);

struct RateState {
    last_fired_at: Instant,
    pending_count: u32,
    timer_running: bool,
}

fn rate_state() -> &'static Mutex<RateState> {
    static STATE: OnceLock<Mutex<RateState>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(RateState {
            last_fired_at: Instant::now() - RATE_LIMIT * 2,
            pending_count: 0,
            timer_running: false,
        })
    })
}

enum NotifyAction {
    FireNow,
    ScheduleSummary,
    Coalesce,
}

/// Fire a desktop notification (non-blocking; errors swallowed). Within a hot
/// window, extra calls coalesce into one "N more new messages" summary.
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
            let last_fired = rate_state().lock().map(|s| s.last_fired_at).unwrap_or(now);
            let sleep = RATE_LIMIT.saturating_sub(now.duration_since(last_fired));
            std::thread::spawn(move || {
                std::thread::sleep(sleep);
                let n = {
                    let mut s = rate_state().lock().expect("rate state poisoned");
                    let n = s.pending_count;
                    s.pending_count = 0;
                    s.timer_running = false;
                    if n > 0 {
                        s.last_fired_at = Instant::now();
                    }
                    n
                };
                if n > 0 {
                    let body = if n == 1 {
                        "1 more new message".to_string()
                    } else {
                        format!("{n} more new messages")
                    };
                    fire("huddle".to_string(), body);
                }
            });
        }
        NotifyAction::Coalesce => {}
    }
}

fn fire(title: String, body: String) {
    std::thread::spawn(move || {
        if let Err(e) = send_notification(&title, &body) {
            tracing::debug!(error = %e, "desktop notification failed");
        }
    });
}

/// Trim a message body to a single short line for the notification preview.
pub fn preview(body: &str) -> String {
    let single: String = body.chars().map(|c| if c == '\n' { ' ' } else { c }).collect();
    let trimmed = single.trim();
    if trimmed.chars().count() > 120 {
        format!("{}…", trimmed.chars().take(117).collect::<String>())
    } else {
        trimmed.to_string()
    }
}

#[cfg(target_os = "macos")]
fn send_notification(title: &str, body: &str) -> std::io::Result<()> {
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
