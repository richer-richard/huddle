//! TUI lifecycle & terminal I/O — the panic hook, the `run_tui` entry point and
//! its `main_loop` event loop, the master-passphrase / seed-import / welcome
//! prompts, and paste handling. Split out of the `app/mod.rs` TUI god file
//! (huddle 2.1.x maintainability refactor). Free functions reaching `TuiApp` +
//! `handle_action` via `use super::*`.

use super::*;

/// Install a panic hook that restores the terminal *before* the default
/// hook prints the panic message. Without this, a panic inside the TUI
/// prints into the alternate screen, which is then torn down — losing the
/// message. Call once at startup.
pub fn install_panic_hook() {
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(
            io::stdout(),
            LeaveAlternateScreen,
            DisableMouseCapture,
            DisableFocusChange,
            DisableBracketedPaste
        );
        original(info);
    }));
}

pub async fn run_tui(handle: AppHandle) -> Result<()> {
    enable_raw_mode()?;
    // From here on, every exit path restores the terminal.
    let _guard = TerminalGuard;
    let mut stdout = io::stdout();
    execute!(
        stdout,
        EnterAlternateScreen,
        EnableMouseCapture,
        EnableFocusChange,
        // Bracketed paste lets us tell a single drag-and-dropped file path
        // (one Paste event) apart from the user typing — see `handle_paste`.
        EnableBracketedPaste
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = TuiApp::new(handle);
    // huddle 0.6: if the user already opted in to update checks
    // (Some(true) on a prior launch), kick the once-per-24h poll.
    if matches!(app.handle.update_check_enabled(), Some(true)) {
        spawn_update_check(&app);
    }
    let mut event_rx = app.handle.subscribe();

    let result = main_loop(&mut terminal, &mut app, &mut event_rx).await;

    app.handle.shutdown().await;
    result
}

/// What `prompt_master_passphrase` hands back. An empty `passphrase`
/// means the user pressed Esc / Ctrl-C — caller should exit cleanly.
pub struct AuthPrompt {
    pub passphrase: String,
    /// Only populated on first-launch (sign-up) flow.
    pub username: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthField {
    Username,
    Passphrase,
    Confirm,
}

/// Prompt for the master passphrase before bringing up `AppHandle`.
/// First-launch (`is_new=true`) collects username + passphrase + confirm;
/// returning users only enter their passphrase. Tab cycles between
/// fields; Enter advances or submits.
pub fn prompt_master_passphrase(is_new: bool) -> Result<AuthPrompt> {
    use crossterm::event::{KeyCode, KeyModifiers};
    use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph};

    enable_raw_mode()?;
    let _guard = TerminalGuard;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut username = String::new();
    let mut passphrase = String::new();
    let mut confirm = String::new();
    let mut field = if is_new {
        AuthField::Username
    } else {
        AuthField::Passphrase
    };
    let mut error: Option<String> = None;
    let mut outcome: Option<AuthPrompt> = None;

    while outcome.is_none() {
        terminal.draw(|f| {
            let height: u16 = if is_new { 18 } else { 12 };
            let area = crate::ui::centered_rect(64, height, f.area());
            f.render_widget(Clear, area);
            let block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .padding(Padding::uniform(1))
                .title(Span::styled(
                    if is_new {
                        " welcome to huddle — sign up "
                    } else {
                        " unlock huddle "
                    },
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ));

            let masked = |s: &str| -> String { s.chars().map(|_| '•').collect() };
            let label_style = |is_focused: bool| {
                if is_focused {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::DarkGray)
                }
            };
            let value_style = Style::default().fg(Color::White);
            let cursor = Span::styled("_", Style::default().fg(Color::DarkGray));

            let mut lines: Vec<Line> = Vec::new();
            lines.push(Line::from(""));
            if is_new {
                lines.push(Line::from(Span::styled(
                    "  pick a username (display name in chat — you can change it later)",
                    Style::default().fg(Color::DarkGray),
                )));
                lines.push(Line::from(Span::styled(
                    "  and a passphrase that encrypts your local database.",
                    Style::default().fg(Color::DarkGray),
                )));
                lines.push(Line::from(Span::styled(
                    "  forget the passphrase and your data is unrecoverable.",
                    Style::default().fg(Color::DarkGray),
                )));
                lines.push(Line::from(""));

                let u_focused = field == AuthField::Username;
                lines.push(Line::from(vec![
                    Span::styled("  username:    ", label_style(u_focused)),
                    Span::styled(username.clone(), value_style),
                    if u_focused {
                        cursor.clone()
                    } else {
                        Span::raw("")
                    },
                ]));
                let p_focused = field == AuthField::Passphrase;
                lines.push(Line::from(vec![
                    Span::styled("  passphrase:  ", label_style(p_focused)),
                    Span::styled(masked(&passphrase), value_style),
                    if p_focused {
                        cursor.clone()
                    } else {
                        Span::raw("")
                    },
                ]));
                let c_focused = field == AuthField::Confirm;
                lines.push(Line::from(vec![
                    Span::styled("  confirm:     ", label_style(c_focused)),
                    Span::styled(masked(&confirm), value_style),
                    if c_focused {
                        cursor.clone()
                    } else {
                        Span::raw("")
                    },
                ]));
            } else {
                lines.push(Line::from(Span::styled(
                    "  enter your passphrase to unlock the database.",
                    Style::default().fg(Color::DarkGray),
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("  passphrase: ", label_style(true)),
                    Span::styled(masked(&passphrase), value_style),
                    cursor.clone(),
                ]));
            }

            if let Some(err) = &error {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    format!("  ! {}", err),
                    Style::default().fg(Color::Red),
                )));
            }
            lines.push(Line::from(""));
            let hint_label = if is_new {
                if field == AuthField::Confirm {
                    " sign up   "
                } else {
                    " next field   "
                }
            } else {
                " unlock   "
            };
            lines.push(Line::from(vec![
                Span::styled(" Enter", Style::default().fg(Color::Yellow)),
                Span::styled(hint_label, Style::default().fg(Color::DarkGray)),
                Span::styled("Tab", Style::default().fg(Color::Yellow)),
                Span::styled(" cycle fields   ", Style::default().fg(Color::DarkGray)),
                Span::styled("Esc", Style::default().fg(Color::Yellow)),
                Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
            ]));
            f.render_widget(Paragraph::new(lines).block(block), area);
        })?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && matches!(key.code, KeyCode::Char('c'))
                {
                    outcome = Some(AuthPrompt {
                        passphrase: String::new(),
                        username: None,
                    });
                    break;
                }
                match key.code {
                    KeyCode::Esc => {
                        outcome = Some(AuthPrompt {
                            passphrase: String::new(),
                            username: None,
                        });
                    }
                    KeyCode::Tab if is_new => {
                        field = match field {
                            AuthField::Username => AuthField::Passphrase,
                            AuthField::Passphrase => AuthField::Confirm,
                            AuthField::Confirm => AuthField::Username,
                        };
                    }
                    KeyCode::Backspace => match field {
                        AuthField::Username => {
                            username.pop();
                        }
                        AuthField::Passphrase => {
                            passphrase.pop();
                        }
                        AuthField::Confirm => {
                            confirm.pop();
                        }
                    },
                    KeyCode::Enter => {
                        if is_new {
                            match field {
                                AuthField::Username => {
                                    if username.trim().is_empty() {
                                        error = Some("username can't be empty".into());
                                    } else {
                                        error = None;
                                        field = AuthField::Passphrase;
                                    }
                                }
                                AuthField::Passphrase => {
                                    if passphrase.is_empty() {
                                        error = Some("passphrase can't be empty".into());
                                    } else {
                                        error = None;
                                        field = AuthField::Confirm;
                                    }
                                }
                                AuthField::Confirm => {
                                    if confirm != passphrase {
                                        error = Some("passphrases don't match — try again".into());
                                        confirm.clear();
                                    } else {
                                        outcome = Some(AuthPrompt {
                                            passphrase: passphrase.clone(),
                                            username: Some(username.trim().to_string()),
                                        });
                                    }
                                }
                            }
                        } else if passphrase.is_empty() {
                            error = Some("passphrase can't be empty".into());
                        } else {
                            outcome = Some(AuthPrompt {
                                passphrase: passphrase.clone(),
                                username: None,
                            });
                        }
                    }
                    KeyCode::Char(c) => match field {
                        AuthField::Username => username.push(c),
                        AuthField::Passphrase => passphrase.push(c),
                        AuthField::Confirm => confirm.push(c),
                    },
                    _ => {}
                }
            }
        }
    }

    Ok(outcome.unwrap_or(AuthPrompt {
        passphrase: String::new(),
        username: None,
    }))
}

/// huddle 2.0.0 (F6): on a fresh launch, offer to recover an existing identity
/// from a 24-word BIP39 seed phrase before a random one is generated. Returns
/// `Ok(Some(phrase))` with a checksum-valid phrase to import, or `Ok(None)`
/// when the user skips (generate fresh). Esc / Ctrl-C also skip.
///
/// Validation is local: the phrase is decoded + checksum-checked via
/// [`huddle_core::app::fingerprint_from_phrase`]; the derived HD-ID is previewed
/// live so the user can confirm they pasted the right backup before committing.
pub fn prompt_import_seed() -> Result<Option<Zeroizing<String>>> {
    use crossterm::event::{KeyCode, KeyModifiers};
    use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph, Wrap};

    enable_raw_mode()?;
    let _guard = TerminalGuard;
    let mut stdout = io::stdout();
    // Bracketed paste so a copied 24-word phrase lands as one Paste event.
    execute!(stdout, EnterAlternateScreen, EnableBracketedPaste)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // F6: the typed/pasted phrase IS the crown-jewel root secret. Hold it in a
    // `Zeroizing<String>` so the backing bytes are scrubbed when this modal
    // closes (or unwinds), not just length-reset, however long the user lingers.
    let mut input = Zeroizing::new(String::new());
    let mut error: Option<String> = None;
    // Outer Option: None = still prompting. Inner Option: the resolved choice
    // (Some(phrase) = import, None = skip). The imported phrase stays wrapped in
    // `Zeroizing` all the way back to the caller.
    let mut outcome: Option<Option<Zeroizing<String>>> = None;

    while outcome.is_none() {
        // Live preview: does the current input decode to a valid identity?
        let preview = if input.trim().is_empty() {
            None
        } else {
            huddle_core::app::fingerprint_from_phrase(input.trim()).ok()
        };
        terminal.draw(|f| {
            let area = crate::ui::centered_rect(72, 18, f.area());
            f.render_widget(Clear, area);
            let block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .padding(Padding::uniform(1))
                .title(Span::styled(
                    " recover identity from seed phrase ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ));
            let mut lines: Vec<Line> = vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  fresh install — recover an existing huddle identity?",
                    Style::default().fg(Color::White),
                )),
                Line::from(Span::styled(
                    "  paste your 24-word BIP39 seed phrase, or press Esc to",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(Span::styled(
                    "  start fresh with a brand-new identity.",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(""),
                Line::from(vec![
                    Span::styled("  > ", Style::default().fg(Color::Cyan).bold()),
                    Span::styled(
                        if input.is_empty() {
                            "word1 word2 … word24".to_string()
                        } else {
                            input.to_string()
                        },
                        if input.is_empty() {
                            Style::default().fg(Color::DarkGray)
                        } else {
                            Style::default().fg(Color::White)
                        },
                    ),
                ]),
            ];
            if let Some(fp) = &preview {
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("  ✓ valid → ", Style::default().fg(Color::Green)),
                    Span::styled(
                        crate::ui::display_id(fp),
                        Style::default().fg(Color::Yellow).bold(),
                    ),
                ]));
            }
            if let Some(err) = &error {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    format!("  ✗ {}", err),
                    Style::default().fg(Color::Red).bold(),
                )));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled(" Enter", Style::default().fg(Color::Yellow)),
                Span::styled(" import   ", Style::default().fg(Color::DarkGray)),
                Span::styled("Esc", Style::default().fg(Color::Yellow)),
                Span::styled(" skip (new identity)", Style::default().fg(Color::DarkGray)),
            ]));
            let para = Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(block);
            f.render_widget(para, area);
        })?;

        if event::poll(Duration::from_millis(200))? {
            // Bracketed paste lets a multi-word phrase arrive in one event.
            match event::read()? {
                Event::Paste(text) => {
                    input.push_str(text.trim());
                }
                Event::Key(key) => {
                    if key.modifiers.contains(KeyModifiers::CONTROL)
                        && matches!(key.code, KeyCode::Char('c'))
                    {
                        outcome = Some(None);
                        break;
                    }
                    match key.code {
                        KeyCode::Esc => outcome = Some(None),
                        KeyCode::Backspace => {
                            input.pop();
                        }
                        KeyCode::Enter => {
                            if input.trim().is_empty() {
                                outcome = Some(None);
                            } else if huddle_core::app::fingerprint_from_phrase(input.trim())
                                .is_ok()
                            {
                                // Keep the returned phrase wrapped so the caller's
                                // copy is scrubbed once it's been consumed.
                                outcome = Some(Some(Zeroizing::new(input.trim().to_string())));
                            } else {
                                error = Some(
                                    "that's not a valid 24-word phrase (checksum failed)".into(),
                                );
                            }
                        }
                        KeyCode::Char(c) => input.push(c),
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }

    Ok(outcome.flatten())
}

/// Show the welcome card before bringing up `AppHandle`. Returns `Ok(true)`
/// when the user is ready to continue or `Ok(false)` if they pressed
/// Ctrl-C / q (caller exits without starting the app).
pub fn show_welcome() -> Result<bool> {
    use crossterm::event::{KeyCode, KeyModifiers};

    enable_raw_mode()?;
    let _guard = TerminalGuard;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let outcome = loop {
        terminal.draw(crate::ui::picker::render_welcome)?;
        if poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && matches!(key.code, KeyCode::Char('c'))
                {
                    break false;
                }
                match key.code {
                    KeyCode::Char('q') => break false,
                    _ => break true,
                }
            }
        }
    };
    Ok(outcome)
}

async fn main_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut TuiApp,
    event_rx: &mut tokio::sync::broadcast::Receiver<AppEvent>,
) -> Result<()> {
    let mut should_quit = false;
    let mut last_refresh = std::time::Instant::now();

    while !should_quit {
        terminal.draw(|f| crate::ui::render(f, app))?;

        // Drain any pending app events.
        while let Ok(ev) = event_rx.try_recv() {
            app.handle_app_event(ev);
        }

        // Refresh discovered rooms every second (covers TTL pruning).
        if last_refresh.elapsed() > Duration::from_secs(1) {
            app.refresh_discovered();
            app.refresh_attachments();
            last_refresh = std::time::Instant::now();
        }

        // Drop expired status-bar messages.
        app.tick_status();

        // huddle 0.7.4: end of the startup catch-up window. Drain the
        // accumulated counter into one summary desktop notification
        // ("N new messages while you were away") and disarm the gate
        // so future messages route through the per-message path.
        if let Some(deadline) = app.startup_grace_until {
            if Instant::now() >= deadline {
                let n = app.startup_catchup_count;
                app.startup_catchup_count = 0;
                app.startup_grace_until = None;
                if n > 0 && app.handle.notifications_enabled() {
                    let body = if n == 1 {
                        "1 new message while you were away".to_string()
                    } else {
                        format!("{} new messages while you were away", n)
                    };
                    crate::notifier::notify("huddle", &body);
                }
            }
        }

        // huddle 0.6: drain the update-check slot. The poll task
        // writes here when a newer version is detected; we copy
        // into `update_banner` once so the lobby renders the banner.
        if app.update_banner.is_none() {
            if let Ok(mut slot) = app.update_check_slot.lock() {
                if let Some(v) = slot.take() {
                    app.update_banner = Some(v);
                }
            }
        }

        // huddle 0.5: if go_dark fired, hold the goodbye modal on
        // screen for `GO_DARK_FAREWELL`, then quit. The data dir is
        // already wiped at this point; the network task is down.
        if let Some(t) = app.went_dark_at {
            if t.elapsed() >= GO_DARK_FAREWELL {
                should_quit = true;
                continue;
            }
        }

        // Phase A: an inbound-dial modal that's been ignored for 15s
        // gets spilled to the persistent `pending_friend_requests`
        // table (huddle 0.7.7). The live libp2p connection is closed
        // so we don't leave an unknown peer attached — but the
        // *request* lives on for up to 3 days, viewable + acceptable
        // from the People pane. A startup sweep removes rows older
        // than the TTL so the table stays bounded.
        let auto_reject_state: Option<InboundDialState> = if let Modal::InboundDial(s) = &app.modal
        {
            if s.opened_at.elapsed() >= Duration::from_secs(15) {
                Some(s.clone())
            } else {
                None
            }
        } else {
            None
        };
        if let Some(s) = auto_reject_state {
            // Persist first so a failed reject_inbound doesn't drop
            // the request on the floor.
            if let Err(e) =
                app.handle
                    .spill_pending_friend_request(s.peer_id, &s.fingerprint, &s.address)
            {
                tracing::warn!(%e, "failed to spill pending friend request");
            }
            // Disconnect-only — do NOT block_peer. The user hasn't
            // decided yet; reject_inbound's block was appropriate for
            // a transient 15s timeout but blocks a peer permanently,
            // which contradicts "remember the request for 3 days".
            app.handle.disconnect_peer(s.peer_id).await;
            app.set_status(format!(
                "saved request from {} — review in People → Pending",
                short_fp(&s.fingerprint)
            ));
            app.modal = Modal::None;
            app.refresh_pending_requests();
        }

        if poll(Duration::from_millis(33))? {
            match event::read()? {
                Event::Key(key) => {
                    let action = input::map_key(key, app);
                    should_quit = handle_action(action, app).await?;
                }
                Event::Mouse(m) => {
                    if matches!(m.kind, MouseEventKind::Down(MouseButton::Left))
                        && app.current_pane_room_id().is_some()
                    {
                        // Click-to-toggle: clicking anywhere inside the
                        // chat area while we're in a room enters card
                        // focus mode if there are cards. Precise hit-
                        // testing per-card requires Rect tracking from
                        // render — left as a follow-up.
                        if let Some(r) = app.active_room() {
                            if !r.attachments.is_empty() && !r.card_focus {
                                handle_action(input::Action::ToggleCardFocus, app).await?;
                            }
                        }
                    }
                }
                Event::Paste(text) => {
                    should_quit = handle_paste(text, app).await?;
                }
                Event::FocusGained => crate::notifier::set_focused(true),
                Event::FocusLost => crate::notifier::set_focused(false),
                _ => {}
            }
        }

        // An async-event modal queued while the user was mid-interaction
        // (see `replace_modal_if_idle`) surfaces once the foreground modal
        // is dismissed — by any path, not just `Action::CloseModal`. The
        // queue is FIFO (huddle 0.6); we drain one per tick so the user
        // sees them in arrival order.
        if matches!(app.modal, Modal::None) {
            if let Some(m) = app.pending_modals.pop_front() {
                app.modal = m;
            }
        }
    }

    Ok(())
}

/// Handle a bracketed-paste event. A file dragged onto the terminal
/// arrives as one paste of its (shell-escaped) path; if the paste
/// resolves to one or more existing files and we're in a room, attach
/// them. Otherwise the text is replayed as ordinary keystrokes so normal
/// pasting into the composer and modal text fields keeps working.
async fn handle_paste(text: String, app: &mut TuiApp) -> Result<bool> {
    let files = parse_dropped_paths(&text);
    if !files.is_empty() {
        let room_id = match app.active_room() {
            Some(r) => r.room_id.clone(),
            None => {
                app.set_status("open a room to attach a dropped file");
                return Ok(false);
            }
        };
        // Don't let a dropped path also land in whatever modal is open.
        app.modal = Modal::None;
        let mut sent = 0usize;
        for path in &files {
            match app.handle.send_file(&room_id, path).await {
                Ok(_) => sent += 1,
                Err(e) => app.set_status(format!("attach failed for {}: {e}", path.display())),
            }
        }
        if sent == 1 {
            app.set_status(format!("sending {}", files[0].display()));
        } else if sent > 1 {
            app.set_status(format!("sending {sent} files"));
        }
        return Ok(false);
    }

    // Not a file drop — replay the pasted text as keystrokes so it lands
    // in the active text field (composer or modal) via the normal path.
    for c in text.chars() {
        if c == '\n' || c == '\r' || c.is_control() {
            continue;
        }
        let key = KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE);
        let action = input::map_key(key, app);
        if handle_action(action, app).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Parse a dragged-and-dropped paste into existing file paths. Handles the
/// shell-style escaping terminals apply: `\ ` for spaces, single/double
/// quotes around a path, and multiple space-separated paths. Only paths
/// that exist as regular files are returned, so ordinary pasted text (no
/// real file behind it) yields an empty list and falls through to text.
fn parse_dropped_paths(text: &str) -> Vec<std::path::PathBuf> {
    tokenize_paste(text)
        .into_iter()
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_file())
        .collect()
}

/// Split a paste into candidate path tokens, honoring the shell-style
/// escaping terminals apply on drag-and-drop: backslash escapes outside
/// single quotes, and single/double quoted spans. Pure (no filesystem) so
/// it can be unit-tested directly.
fn tokenize_paste(text: &str) -> Vec<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut tokens: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = trimmed.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' if !in_single => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            c if c.is_whitespace() && !in_single && !in_double => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

#[cfg(test)]
mod paste_tests {
    use super::tokenize_paste;

    #[test]
    fn unescapes_backslash_spaces() {
        assert_eq!(
            tokenize_paste("/Users/me/My\\ File.txt"),
            vec!["/Users/me/My File.txt"]
        );
    }

    #[test]
    fn strips_surrounding_quotes() {
        assert_eq!(
            tokenize_paste("'/path/with space.txt'"),
            vec!["/path/with space.txt"]
        );
        assert_eq!(
            tokenize_paste("\"/path/two words.png\""),
            vec!["/path/two words.png"]
        );
    }

    #[test]
    fn splits_multiple_unquoted_paths() {
        assert_eq!(
            tokenize_paste("/a/one.txt /b/two.txt"),
            vec!["/a/one.txt", "/b/two.txt"]
        );
    }

    #[test]
    fn plain_text_tokenizes_but_wont_be_files() {
        // The words tokenize; parse_dropped_paths' is_file() filter then
        // drops them, so ordinary pasted prose falls through to typing.
        assert_eq!(tokenize_paste("hello world"), vec!["hello", "world"]);
    }
}
