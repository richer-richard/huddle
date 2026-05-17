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

static WINDOW_FOCUSED: AtomicBool = AtomicBool::new(true);

pub fn set_focused(focused: bool) {
    WINDOW_FOCUSED.store(focused, Ordering::Relaxed);
}

pub fn is_focused() -> bool {
    WINDOW_FOCUSED.load(Ordering::Relaxed)
}

/// Fire a desktop notification on a background thread. Non-blocking;
/// errors are swallowed.
pub fn notify(title: &str, body: &str) {
    let title = title.to_string();
    let body = body.to_string();
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
    // AppleScript string escaping: `\` → `\\`, `"` → `\"`.
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!(
        r#"display notification "{}" with title "{}""#,
        esc(body),
        esc(title)
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
    std::process::Command::new("notify-send")
        .arg("--app-name=huddle")
        .arg("--expire-time=5000")
        .arg(title)
        .arg(body)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn send_notification(title: &str, body: &str) -> std::io::Result<()> {
    // PowerShell single-quoted strings: `'` → `''`.
    let esc = |s: &str| s.replace('\'', "''");
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
