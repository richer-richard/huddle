//! huddle 0.7.8: copy strings to the OS clipboard via platform-native
//! shell tools. No new crate dependency — we shell out the same way
//! `notifier.rs` does. Failures are non-fatal: a missing tool returns
//! a short error string the caller can surface as a status message
//! ("clipboard tool not found"), and the app keeps running.
//!
//! macOS uses `pbcopy`. Linux tries `wl-copy` first (Wayland), falls
//! back to `xclip -selection clipboard` (X11). Windows pipes into
//! `clip.exe`. Unknown platforms return Err.

use std::io::Write;
use std::process::{Command, Stdio};

/// Copy `text` to the OS clipboard. Synchronous on the calling thread —
/// the underlying tools are fast and the text is small (identity fields,
/// not arbitrary message bodies), so blocking the TUI for a few ms is
/// acceptable and lets the caller surface the result in the status bar
/// immediately.
pub fn copy(text: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        run_with_stdin("pbcopy", &[], text)
    }
    #[cfg(target_os = "linux")]
    {
        // Wayland first; fall back to X11. `wl-copy` writes the body
        // to stdin like pbcopy. `xclip -selection clipboard` likewise.
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
