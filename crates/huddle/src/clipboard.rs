//! huddle 0.7.8: copy strings to the OS clipboard via platform-native
//! shell tools. No new crate dependency — we shell out the same way
//! `notifier.rs` does. Failures are non-fatal: a missing tool returns
//! a short error string the caller can surface as a status message
//! ("clipboard tool not found"), and the app keeps running.
//!
//! macOS uses `pbcopy`. Linux tries `wl-copy` first (Wayland), falls
//! back to `xclip -selection clipboard` (X11). Windows pipes into
//! `clip.exe`. Unknown platforms return Err.
//!
//! huddle 0.7.11: clipboard tools can hang indefinitely (xclip with no
//! DISPLAY, wl-copy with no Wayland compositor responding). The
//! synchronous `copy` now runs on its own OS thread with a 2 s hard
//! timeout so the TUI never freezes on a yank.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const COPY_TIMEOUT: Duration = Duration::from_secs(2);

/// Copy `text` to the OS clipboard. Runs the platform tool on a
/// dedicated thread bounded by `COPY_TIMEOUT` so a hung clipboard
/// daemon can't freeze the calling task. The hung thread is leaked
/// (it stays parked on the blocking child wait until the tool either
/// finishes or the process exits); this is acceptable because we only
/// spawn one per yank and the rate-limited.
pub fn copy(text: &str) -> Result<(), String> {
    let owned = text.to_string();
    let (tx, rx) = mpsc::channel::<Result<(), String>>();
    std::thread::Builder::new()
        .name("huddle-clipboard".into())
        .spawn(move || {
            let _ = tx.send(copy_blocking(&owned));
        })
        .map_err(|e| format!("clipboard thread spawn failed: {e}"))?;
    match rx.recv_timeout(COPY_TIMEOUT) {
        Ok(r) => r,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(format!(
            "clipboard tool didn't respond within {}s — is the clipboard service running?",
            COPY_TIMEOUT.as_secs()
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err("clipboard thread crashed".to_string())
        }
    }
}

fn copy_blocking(text: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        run_with_stdin("pbcopy", &[], text)
    }
    #[cfg(target_os = "linux")]
    {
        match run_with_stdin("wl-copy", &[], text) {
            Ok(()) => Ok(()),
            Err(_) => run_with_stdin("xclip", &["-selection", "clipboard"], text),
        }
    }
    #[cfg(target_os = "windows")]
    {
        run_with_stdin("clip", &[], text)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = text;
        Err("clipboard not supported on this platform".to_string())
    }
}

fn run_with_stdin(program: &str, args: &[&str], text: &str) -> Result<(), String> {
    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(error = %e, program, "clipboard tool not found");
            return Err(format!("clipboard tool not found ({program})"));
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        if let Err(e) = stdin.write_all(text.as_bytes()) {
            tracing::debug!(error = %e, program, "clipboard write failed");
            return Err(format!("clipboard write failed: {e}"));
        }
    }
    match child.wait() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!("clipboard tool exited {status}")),
        Err(e) => Err(format!("clipboard wait failed: {e}")),
    }
}
