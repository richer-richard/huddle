use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph, Wrap};

use crate::app::{
    AcceptRotationState, AttachPathState, AttachPickerState, ChangePassphraseState,
    ConfirmDeleteState, ConfirmInviteState, DialPeerState, EmojiPickerState, ExportSeedState,
    ExportStep, InboundDialState, JoinRoomState, JoinWithCodeState, MemberActionKind,
    MemberActionState, PassField, PasteInviteState, RotateRoomState, SafetyNumberChangedState,
    SasStage, SasState, SearchState, ShowInviteState, ShowJoinCodeState, StartField,
    StartRoomState, VerifyState, ATTACH_VISIBLE_ROWS, REACTION_EMOJIS,
};
use crate::ui::centered_rect;

pub fn render_start_room(f: &mut Frame, s: &StartRoomState) {
    let area = centered_rect(50, 13, f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Span::styled(
            " start a new room ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .padding(Padding::uniform(1));

    let lines = vec![
        Line::from(""),
        field_line("name", &s.name, matches!(s.focus, StartField::Name), false),
        Line::from(""),
        encrypted_line(s),
        Line::from(""),
        passphrase_line(s),
        Line::from(""),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Tab", Style::default().fg(Color::Yellow)),
            Span::styled(" next  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Enter", Style::default().fg(Color::Yellow)),
            Span::styled(" start  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

fn field_line(label: &str, value: &str, focused: bool, mask: bool) -> Line<'static> {
    let display = if mask {
        "*".repeat(value.chars().count())
    } else {
        value.to_string()
    };
    let cursor = if focused { "_" } else { "" };
    let value_str = format!("[ {}{} ]", display, cursor);
    let value_style = if focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::White)
    };
    Line::from(vec![
        Span::styled(
            format!(" {:<11}", label),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(value_str, value_style),
    ])
}

fn encrypted_line(s: &StartRoomState) -> Line<'static> {
    let check = if s.encrypted { "[x]" } else { "[ ]" };
    let label = if s.encrypted { "yes" } else { "no" };
    let focused = matches!(s.focus, StartField::Encrypted);
    let style = if focused {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };
    Line::from(vec![
        Span::styled(" encrypted   ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{} {}", check, label), style),
        Span::styled(
            if focused {
                "   (Enter/Space toggle)"
            } else {
                ""
            },
            Style::default().fg(Color::DarkGray),
        ),
    ])
}

fn passphrase_line(s: &StartRoomState) -> Line<'static> {
    if !s.encrypted {
        return Line::from(Span::styled(
            " passphrase  (encryption disabled)",
            Style::default().fg(Color::DarkGray),
        ));
    }
    field_line(
        "passphrase",
        &s.passphrase,
        matches!(s.focus, StartField::Passphrase),
        true,
    )
}

pub fn render_join_room(f: &mut Frame, j: &JoinRoomState) {
    let area = centered_rect(54, 9, f.area());
    f.render_widget(Clear, area);

    // "[enc]" only appears when the announcement marked this room
    // encrypted — a visual confirmation before they type a passphrase.
    let lock = if j.encrypted { "[enc] " } else { "" };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta))
        .title(Span::styled(
            format!(" {lock}join #{} ", j.room_name),
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ))
        .padding(Padding::uniform(1));

    let masked = "*".repeat(j.passphrase.chars().count());
    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(" passphrase  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("[ {}_ ]", masked),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(""),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Enter", Style::default().fg(Color::Yellow)),
            Span::styled(" join  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

pub fn render_quit_confirm(f: &mut Frame) {
    let area = centered_rect(40, 6, f.area());
    f.render_widget(Clear, area);
    let para = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            " quit huddle?",
            Style::default().fg(Color::White),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" [y]", Style::default().fg(Color::Yellow)),
            Span::styled(" yes  ", Style::default().fg(Color::DarkGray)),
            Span::styled("[Esc/n]", Style::default().fg(Color::Yellow)),
            Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
        ]),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red))
            .padding(Padding::uniform(1)),
    );
    f.render_widget(para, area);
}

/// huddle 0.7.11: confirmation before wiping the entire blocklist.
pub fn render_clear_blocked_confirm(f: &mut Frame, blocked_count: usize) {
    let area = centered_rect(56, 7, f.area());
    f.render_widget(Clear, area);
    let para = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            format!(" unblock all {blocked_count} blocked peers?"),
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            " (they'll be able to dial you again on next contact)",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" [y/Enter]", Style::default().fg(Color::Yellow)),
            Span::styled(" clear all  ", Style::default().fg(Color::DarkGray)),
            Span::styled("[Esc/n]", Style::default().fg(Color::Yellow)),
            Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
        ]),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red))
            .padding(Padding::uniform(1)),
    );
    f.render_widget(para, area);
}

pub fn render_help(f: &mut Frame, scroll: u16) {
    use crate::keybindings::{Context, BINDINGS};
    let area = centered_rect(76, 28, f.area());
    f.render_widget(Clear, area);

    // Group bindings by Context, preserving the source order so help
    // lays out the same way every time and never drifts away from the
    // input.rs match arms.
    let sections: &[(Context, &str)] = &[
        (Context::Global, "Global"),
        (Context::Lobby, "Lobby"),
        (Context::LobbyRooms, "Lobby — rooms focus"),
        (Context::LobbyPeers, "Lobby — known peers focus"),
        (Context::RoomChat, "In a room"),
        (Context::RoomInputActive, "While typing"),
        (Context::RoomCardFocus, "Card focus mode"),
    ];

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("  huddle {} — keybindings", env!("CARGO_PKG_VERSION")),
        Style::default().fg(Color::DarkGray),
    )));
    lines.push(Line::from(""));
    let key_w: usize = 18;
    for (ctx, label) in sections {
        let mut count = 0usize;
        for b in BINDINGS.iter().filter(|b| b.context == *ctx) {
            if count == 0 {
                lines.push(Line::from(Span::styled(
                    format!(" {}", label),
                    Style::default().fg(Color::Cyan).bold(),
                )));
                lines.push(Line::from(""));
            }
            count += 1;
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  {:<width$}", b.keys, width = key_w),
                    Style::default().fg(Color::Yellow),
                ),
                Span::styled(b.description.to_string(), Style::default().fg(Color::White)),
            ]));
        }
        if count > 0 {
            lines.push(Line::from(""));
        }
    }
    lines.push(Line::from(Span::styled(
        "  press j/k or PgUp/PgDn to scroll · any other key to close",
        Style::default().fg(Color::DarkGray),
    )));
    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .padding(Padding::uniform(1))
                .title(Span::styled(
                    " help ",
                    Style::default().fg(Color::Cyan).bold(),
                )),
        );
    f.render_widget(para, area);
}

pub fn render_dial_peer(f: &mut Frame, s: &DialPeerState) {
    let area = centered_rect(64, 11, f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .padding(Padding::uniform(1))
        .title(Span::styled(
            " dial a peer ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));

    let status = s
        .status
        .clone()
        .unwrap_or_else(|| "ip:port  ·  [ipv6]:port  ·  /ip4/.../tcp/...".into());

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(" address  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("[ {}_ ]", s.address),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            format!(" {}", status),
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Enter", Style::default().fg(Color::Yellow)),
            Span::styled(" dial  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(block);
    f.render_widget(para, area);
}

pub fn render_attach_path(f: &mut Frame, s: &AttachPathState) {
    let area = centered_rect(64, 11, f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .padding(Padding::uniform(1))
        .title(Span::styled(
            " attach a file by path ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(" path  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("[ {}_ ]", s.input),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            " type an absolute path  ·  ~ expands to $HOME",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        if let Some(err) = &s.error {
            Line::from(Span::styled(
                format!(" ! {err}"),
                Style::default().fg(Color::Red),
            ))
        } else {
            Line::from("")
        },
        Line::from(vec![
            Span::styled(" Enter", Style::default().fg(Color::Yellow)),
            Span::styled(" send  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(block);
    f.render_widget(para, area);
}

pub fn render_rotate_room(f: &mut Frame, s: &RotateRoomState) {
    let area = centered_rect(60, 10, f.area());
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta))
        .padding(Padding::uniform(1))
        .title(Span::styled(
            " rotate room key ",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ));
    let masked: String = s.passphrase.chars().map(|_| '•').collect();
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  enter a NEW passphrase. share it with the others",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "  out-of-band (chat, voice). they'll get a prompt.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" new passphrase: ", Style::default().fg(Color::Yellow)),
            Span::styled(masked, Style::default().fg(Color::White)),
            Span::styled("_", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Enter", Style::default().fg(Color::Yellow)),
            Span::styled(" confirm  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
        ]),
    ];
    f.render_widget(Paragraph::new(lines).block(block), area);
}

pub fn render_accept_rotation(f: &mut Frame, s: &AcceptRotationState) {
    let area = centered_rect(64, 11, f.area());
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta))
        .padding(Padding::uniform(1))
        .title(Span::styled(
            " key rotation requested ",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ));
    let masked: String = s.passphrase.chars().map(|_| '•').collect();
    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(
                &s.rotator_fingerprint[..s.rotator_fingerprint.len().min(9)],
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(
                " rotated this room's key.",
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(Span::styled(
            "  enter the new passphrase to keep receiving messages.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" new passphrase: ", Style::default().fg(Color::Yellow)),
            Span::styled(masked, Style::default().fg(Color::White)),
            Span::styled("_", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Enter", Style::default().fg(Color::Yellow)),
            Span::styled(" accept  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::styled(
                " ignore (you'll stop seeing messages)",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    ];
    f.render_widget(Paragraph::new(lines).block(block), area);
}

pub fn render_qr_identity(f: &mut Frame, app: &crate::app::TuiApp) {
    let fingerprint = app.handle.fingerprint().to_string();
    let rendered = render_fingerprint_qr(&fingerprint);

    let height = (rendered.len() as u16) + 8;
    let width = rendered
        .iter()
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(20) as u16
        + 6;
    let area = centered_rect(width.max(40), height.max(12), f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .padding(Padding::uniform(1))
        .title(Span::styled(
            " your identity ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(Span::styled(
        "  your id:",
        Style::default().fg(Color::DarkGray),
    )));
    lines.push(Line::from(Span::styled(
        format!("  {}", super::display_id(&fingerprint)),
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));
    for row in rendered {
        lines.push(Line::from(Span::styled(
            format!("  {}", row),
            Style::default().fg(Color::White),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(" Esc", Style::default().fg(Color::Yellow)),
        Span::styled(" close", Style::default().fg(Color::DarkGray)),
    ]));
    f.render_widget(Paragraph::new(lines).block(block), area);
}

/// Render a fingerprint as a QR code using two-row Unicode half-blocks.
/// Returns one terminal row per pair of QR modules.
fn render_fingerprint_qr(fingerprint: &str) -> Vec<String> {
    let code = match qrcode::QrCode::new(fingerprint.as_bytes()) {
        Ok(c) => c,
        Err(_) => return vec!["(could not render QR)".into()],
    };
    let colors = code.to_colors();
    let width = code.width();
    let height = colors.len() / width;
    let mut rows = Vec::new();
    let on = |x: usize, y: usize| -> bool {
        if y >= height || x >= width {
            return false;
        }
        colors[y * width + x] == qrcode::Color::Dark
    };
    // Pad with a one-module quiet zone.
    let pad_w = width + 2;
    let pad_h = height + 2;
    let dark_in_padded = |x: usize, y: usize| -> bool {
        if x == 0 || x == pad_w - 1 || y == 0 || y == pad_h - 1 {
            false
        } else {
            on(x - 1, y - 1)
        }
    };
    let mut y = 0;
    while y < pad_h {
        let mut row = String::new();
        for x in 0..pad_w {
            let top = dark_in_padded(x, y);
            let bottom = if y + 1 < pad_h {
                dark_in_padded(x, y + 1)
            } else {
                false
            };
            let ch = match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            };
            // Double-wide so the QR is square-ish in cells with ~2:1 aspect.
            row.push(ch);
            row.push(ch);
        }
        rows.push(row);
        y += 2;
    }
    rows
}

pub fn render_search(f: &mut Frame, s: &SearchState) {
    let area = centered_rect(80, 20, f.area());
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .padding(Padding::uniform(1))
        .title(Span::styled(
            " search messages ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled(" query: ", Style::default().fg(Color::Yellow)),
        Span::styled(s.query.clone(), Style::default().fg(Color::White)),
        Span::styled("_", Style::default().fg(Color::DarkGray)),
    ]));
    lines.push(Line::from(""));
    if !s.searched {
        lines.push(Line::from(Span::styled(
            "  press Enter to search",
            Style::default().fg(Color::DarkGray),
        )));
    } else if s.results.is_empty() {
        lines.push(Line::from(Span::styled(
            "  no matches",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            format!("  {} match(es) — newest first:", s.results.len()),
            Style::default().fg(Color::DarkGray),
        )));
        lines.push(Line::from(""));
        let visible = 10usize;
        let offset = if s.selected >= visible {
            s.selected.saturating_sub(visible - 1)
        } else {
            0
        };
        for (i, m) in s.results.iter().enumerate().skip(offset).take(visible) {
            let is_focused = i == s.selected;
            let marker = if is_focused { "› " } else { "  " };
            let time = {
                let secs_today = (m.sent_at % 86_400) as u32;
                let hh = (secs_today / 3600) % 24;
                let mm = (secs_today / 60) % 60;
                format!("{:02}:{:02}", hh, mm)
            };
            let snippet: String = m.body.chars().take(60).collect();
            let style = if is_focused {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            lines.push(Line::from(vec![
                Span::styled(format!("  {}", marker), Style::default().fg(Color::Yellow)),
                Span::styled(format!("{}  ", time), Style::default().fg(Color::DarkGray)),
                Span::styled(snippet, style),
            ]));
        }
    }
    while lines.len() < 14 {
        lines.push(Line::from(""));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(" Enter", Style::default().fg(Color::Yellow)),
        Span::styled(" search   ", Style::default().fg(Color::DarkGray)),
        Span::styled("↑/↓", Style::default().fg(Color::Yellow)),
        Span::styled(" results   ", Style::default().fg(Color::DarkGray)),
        Span::styled("Esc", Style::default().fg(Color::Yellow)),
        Span::styled(" close", Style::default().fg(Color::DarkGray)),
    ]));
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

pub fn render_verify(f: &mut Frame, s: &VerifyState) {
    let area = centered_rect(72, 16, f.area());
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .padding(Padding::uniform(1))
        .title(Span::styled(
            " verify members ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled("  your id: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            super::display_id(&s.our_fingerprint),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::from(Span::styled(
        "  compare each peer's id with them out-of-band",
        Style::default().fg(Color::DarkGray),
    )));
    lines.push(Line::from(Span::styled(
        "  (read aloud, call, etc.) before marking verified.",
        Style::default().fg(Color::DarkGray),
    )));
    lines.push(Line::from(""));
    for (i, (fp, verified)) in s.members.iter().enumerate() {
        let marker = if i == s.selected { "› " } else { "  " };
        let check = if *verified { "[✓] " } else { "[ ] " };
        let check_style = if *verified {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let name_style = if i == s.selected {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(vec![
            Span::styled(format!("  {}", marker), Style::default().fg(Color::Yellow)),
            Span::styled(check, check_style),
            Span::styled(super::display_id(fp), name_style),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(" j/k", Style::default().fg(Color::Yellow)),
        Span::styled(" navigate  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Enter/Space", Style::default().fg(Color::Yellow)),
        Span::styled(" toggle verified  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Esc", Style::default().fg(Color::Yellow)),
        Span::styled(" close", Style::default().fg(Color::DarkGray)),
    ]));
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// Maximum indentation depth we render literally; deeper nodes keep this
/// indent so the fixed-width modal never wraps.
const ATTACH_MAX_INDENT: usize = 8;

pub fn render_attach_picker(f: &mut Frame, s: &AttachPickerState) {
    let area = centered_rect(80, 22, f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Span::styled(
            " attach a file ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .padding(Padding::uniform(1));

    // Width available for a row's name after the modal border + padding,
    // the focus marker and the caret. Used to truncate long names.
    let inner_w = area.width.saturating_sub(4) as usize; // 2 borders + 2 padding
    let name_budget = inner_w.saturating_sub(6); // marker + caret + breathing room

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled("  in ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{}", s.root.display()),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::from(""));

    if let Some(err) = &s.error {
        lines.push(Line::from(Span::styled(
            format!("  ! {}", err),
            Style::default().fg(Color::Red),
        )));
    }

    let visible = ATTACH_VISIBLE_ROWS;
    let end = (s.scroll + visible).min(s.flat.len());

    if s.flat.is_empty() && s.error.is_none() {
        lines.push(Line::from(Span::styled(
            "  (empty)",
            Style::default().fg(Color::DarkGray),
        )));
    }

    for (i, row) in s.flat.iter().enumerate().take(end).skip(s.scroll) {
        let is_focused = i == s.selected;
        let marker = if is_focused { "›" } else { " " };
        let indent = "  ".repeat(row.depth.min(ATTACH_MAX_INDENT));
        let caret = if row.is_dir {
            if row.expanded {
                "▾ "
            } else {
                "▸ "
            }
        } else {
            "· "
        };
        let suffix = if row.is_dir { "/" } else { "" };
        let name = truncate_middle(
            &row.name,
            name_budget.saturating_sub(row.depth.min(ATTACH_MAX_INDENT) * 2),
        );
        let annotation = if row.has_error {
            "  (no access)"
        } else if row.is_empty_dir {
            "  (empty)"
        } else {
            ""
        };

        let name_style = if is_focused {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else if row.has_error {
            Style::default().fg(Color::Red)
        } else if row.is_dir {
            Style::default().fg(Color::Blue)
        } else {
            Style::default().fg(Color::White)
        };

        lines.push(Line::from(vec![
            Span::styled(format!(" {} ", marker), Style::default().fg(Color::Yellow)),
            Span::raw(indent),
            Span::styled(caret, Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{}{}", name, suffix), name_style),
            Span::styled(annotation, Style::default().fg(Color::DarkGray)),
        ]));
    }
    // Pad to a stable height (header rows + visible rows).
    while lines.len() < visible + 4 {
        lines.push(Line::from(""));
    }

    // Scroll position hint.
    let more_above = s.scroll > 0;
    let more_below = end < s.flat.len();
    let scroll_hint = match (more_above, more_below) {
        (true, true) => "  ▲▼ more",
        (true, false) => "  ▲ more above",
        (false, true) => "  ▼ more below",
        (false, false) => "",
    };
    lines.push(Line::from(Span::styled(
        scroll_hint,
        Style::default().fg(Color::DarkGray),
    )));

    let hint = |k: &'static str, d: &'static str| {
        vec![
            Span::styled(k, Style::default().fg(Color::Yellow)),
            Span::styled(d, Style::default().fg(Color::DarkGray)),
        ]
    };
    let mut footer: Vec<Span> = Vec::new();
    footer.extend(hint(" ↑/↓", " move  "));
    footer.extend(hint("Space", " expand/collapse  "));
    footer.extend(hint("Enter", " pick  "));
    footer.extend(hint("←/→", " out/in  "));
    footer.extend(hint(".", " hidden  "));
    footer.extend(hint("p", " type path  "));
    footer.extend(hint("Esc", " cancel"));
    lines.push(Line::from(footer));

    let para = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    f.render_widget(para, area);
}

/// Shorten `name` to fit `budget` columns, keeping the start and the
/// extension-bearing tail with an ellipsis in the middle.
fn truncate_middle(name: &str, budget: usize) -> String {
    let chars: Vec<char> = name.chars().collect();
    if budget < 4 || chars.len() <= budget {
        return name.to_string();
    }
    let keep = budget - 1; // room for the ellipsis
    let head = keep / 2;
    let tail = keep - head;
    let head_str: String = chars[..head].iter().collect();
    let tail_str: String = chars[chars.len() - tail..].iter().collect();
    format!("{head_str}…{tail_str}")
}

pub fn render_info(f: &mut Frame, msg: &str) {
    let area = centered_rect(56, 8, f.area());
    f.render_widget(Clear, area);
    let para = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(msg, Style::default().fg(Color::White))),
        Line::from(""),
        Line::from(""),
        Line::from(Span::styled(
            "  press any key to dismiss",
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .wrap(Wrap { trim: false })
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .padding(Padding::uniform(1)),
    );
    f.render_widget(para, area);
}

/// Phase A: an unknown peer dialed us. Show their fingerprint and let
/// the user pick accept (this session only), reject (block forever), or
/// trust+accept (remember for next time). The 15s countdown is informa-
/// tional — the `main_loop` auto-rejects on expiry.
pub fn render_inbound_dial(f: &mut Frame, s: &InboundDialState) {
    let area = centered_rect(64, 14, f.area());
    f.render_widget(Clear, area);

    let elapsed = s.opened_at.elapsed();
    let remaining = 15_u64.saturating_sub(elapsed.as_secs());

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  an unknown peer wants to connect.",
            Style::default().fg(Color::White),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  id:      ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                super::display_id(&s.fingerprint),
                Style::default().fg(Color::Yellow).bold(),
            ),
        ]),
        Line::from(vec![
            Span::styled("  address: ", Style::default().fg(Color::DarkGray)),
            Span::styled(s.address.clone(), Style::default().fg(Color::White)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" [a]", Style::default().fg(Color::Green).bold()),
            Span::styled(" accept    ", Style::default().fg(Color::DarkGray)),
            Span::styled(" [r]", Style::default().fg(Color::Red).bold()),
            Span::styled(" reject    ", Style::default().fg(Color::DarkGray)),
            Span::styled(" [t]", Style::default().fg(Color::Cyan).bold()),
            Span::styled(" trust+accept", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            format!("  auto-reject in {}s", remaining),
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow))
            .padding(Padding::uniform(1))
            .title(Span::styled(
                " inbound connection ",
                Style::default().fg(Color::Yellow).bold(),
            )),
    );
    f.render_widget(para, area);
}

/// Phase B: kick / grant member picker. Owner-only — the action handler
/// gates the open via `owner_action_members`. List of (fingerprint,
/// is_owner) so the picker can badge existing owners (for the Kick
/// flavor — Grant filters them out at open time).
pub fn render_member_action(f: &mut Frame, s: &MemberActionState) {
    let title = match s.kind {
        MemberActionKind::Kick => " kick member ",
        MemberActionKind::Grant => " grant owner ",
    };
    let border_color = match s.kind {
        MemberActionKind::Kick => Color::Red,
        MemberActionKind::Grant => Color::Cyan,
    };
    let action_word = match s.kind {
        MemberActionKind::Kick => "kick",
        MemberActionKind::Grant => "grant owner to",
    };

    let height = 8 + s.members.len() as u16;
    let area = centered_rect(64, height.min(20), f.area());
    f.render_widget(Clear, area);

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("  pick a member to {}:", action_word),
        Style::default().fg(Color::White),
    )));
    lines.push(Line::from(""));
    for (idx, (fp, is_owner)) in s.members.iter().enumerate() {
        let selected = idx == s.selected;
        let marker = if selected { "▶" } else { " " };
        let badge = if *is_owner { " (owner)" } else { "" };
        let style = if selected {
            Style::default().fg(Color::Yellow).bold()
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(vec![
            Span::styled(format!(" {} ", marker), style),
            Span::styled(super::display_id(fp), style),
            Span::styled(badge, Style::default().fg(Color::DarkGray)),
        ]));
    }
    if s.kind == MemberActionKind::Kick {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  kick = ban + rotate room key. you'll get the new",
            Style::default().fg(Color::DarkGray),
        )));
        lines.push(Line::from(Span::styled(
            "  passphrase to share with remaining members.",
            Style::default().fg(Color::DarkGray),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(" j/k", Style::default().fg(Color::Yellow)),
        Span::styled(" move  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Enter", Style::default().fg(Color::Yellow)),
        Span::styled(" confirm  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Esc", Style::default().fg(Color::Yellow)),
        Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
    ]));

    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .padding(Padding::uniform(1))
            .title(Span::styled(
                title,
                Style::default().fg(border_color).bold(),
            )),
    );
    f.render_widget(para, area);
}

/// Phase G: SAS verification modal. Two stages:
/// - Waiting: just sent SasInit, partner hasn't responded yet
/// - Comparing: both sides have the code; user reads it aloud / shows
///   the other side, both press Match if they agree
pub fn render_sas(f: &mut Frame, s: &SasState) {
    let area = centered_rect(72, 18, f.area());
    f.render_widget(Clear, area);

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(""));
    // Title row carries the partner fp + a short room-id tag so the
    // user knows which conversation they're verifying when several
    // rooms are open in parallel.
    let short_room: String = s.room_id.chars().take(8).collect();
    lines.push(Line::from(vec![
        Span::styled("  verifying  ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            super::display_id(&s.partner_fingerprint),
            Style::default().fg(Color::Yellow).bold(),
        ),
        Span::styled(
            format!("  · room {}", short_room),
            Style::default().fg(Color::DarkGray),
        ),
    ]));
    lines.push(Line::from(""));

    match &s.stage {
        SasStage::Waiting => {
            lines.push(Line::from(Span::styled(
                "  waiting for partner to accept…",
                Style::default().fg(Color::White),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  Esc cancels.",
                Style::default().fg(Color::DarkGray),
            )));
        }
        SasStage::Comparing {
            // huddle 0.9: the SAS is shown as its word list + decimal
            // (emoji-free). Both peers still derive identical indices, so
            // the word/decimal comparison is exactly as strong.
            emoji_labels,
            decimal,
            our_matched,
        } => {
            lines.push(Line::from(Span::styled(
                "  read this code aloud / show to your partner:",
                Style::default().fg(Color::White),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::raw("   "),
                Span::styled(
                    emoji_labels.clone(),
                    Style::default().fg(Color::Yellow).bold(),
                ),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled(
                    "  or compare decimal: ",
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(decimal.clone(), Style::default().fg(Color::Cyan).bold()),
            ]));
            lines.push(Line::from(""));
            if *our_matched {
                lines.push(Line::from(Span::styled(
                    "  ✓ you confirmed. waiting for partner…",
                    Style::default().fg(Color::Green),
                )));
            } else {
                lines.push(Line::from(vec![
                    Span::styled(" [m]", Style::default().fg(Color::Green).bold()),
                    Span::styled("atch  ", Style::default().fg(Color::DarkGray)),
                    Span::styled(" [c]", Style::default().fg(Color::Red).bold()),
                    Span::styled("ancel  ", Style::default().fg(Color::DarkGray)),
                    Span::styled(" Esc", Style::default().fg(Color::Red)),
                    Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
                ]));
            }
        }
    }

    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Magenta))
            .padding(Padding::uniform(1))
            .title(Span::styled(
                " SAS verify ",
                Style::default().fg(Color::Magenta).bold(),
            )),
    );
    f.render_widget(para, area);
}

pub fn render_go_dark(f: &mut Frame, s: &crate::app::GoDarkState) {
    use crate::app::GO_DARK_CONFIRM_PHRASE;
    let area = centered_rect(70, 20, f.area());
    f.render_widget(Clear, area);
    // Passphrase is masked; the typed phrase is shown verbatim so the
    // user can see the case match live.
    let displayed_input: String = if s.requires_passphrase {
        "•".repeat(s.input.chars().count())
    } else {
        s.input.clone()
    };
    let (prompt_label, hint_below): (&str, String) = if s.requires_passphrase {
        (
            "master passphrase: ",
            "Enter your master passphrase to wipe everything.".into(),
        )
    } else {
        (
            "type to confirm: ",
            format!(
                "Type `{}` (case sensitive) to wipe everything.",
                GO_DARK_CONFIRM_PHRASE
            ),
        )
    };
    let mut lines: Vec<Line> = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  THIS WILL:",
            Style::default().fg(Color::Red).bold(),
        )),
        Line::from(Span::styled(
            "   • leave every room you've joined",
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            "   • permanently delete your identity",
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            "   • delete all messages, files, peers",
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            "   • wipe the database and keychain",
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            "   • exit huddle",
            Style::default().fg(Color::White),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  This CANNOT be undone.",
            Style::default().fg(Color::Red).bold(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("  {}", hint_below),
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("› ", Style::default().fg(Color::Yellow)),
            Span::styled(prompt_label, Style::default().fg(Color::DarkGray)),
            Span::styled(displayed_input, Style::default().fg(Color::Cyan).bold()),
        ]),
    ];
    // huddle 0.7.6: error renders prominently above the hint bar so the
    // user can't miss a bad attempt — the previous flow buried it at
    // the bottom of an already-tall modal.
    if let Some(err) = &s.last_error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  ✗ {}", err),
            Style::default().fg(Color::Red).bold(),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(" Enter", Style::default().fg(Color::Red).bold()),
        Span::styled(" delete  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Esc", Style::default().fg(Color::Yellow)),
        Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
    ]));
    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red))
            .padding(Padding::uniform(1))
            .title(Span::styled(
                " delete account (go dark) ",
                Style::default().fg(Color::Red).bold(),
            )),
    );
    f.render_widget(para, area);
}

/// huddle 0.7: Compose-DM modal. Single-field input with inline
/// suggestions pulled from `known_peers` + `peer_profiles`. On confirm
/// the action handler calls `start_direct(fp)`; on unresolvable input
/// it morphs into `AddFriend` semantics (same modal recycled).
pub fn render_compose_dm(f: &mut Frame, s: &crate::app::ComposeDmState, app: &crate::app::TuiApp) {
    let area = centered_rect(64, 16, f.area());
    f.render_widget(Clear, area);
    let displayed = if s.input.is_empty() {
        Span::styled(
            "type a username or HD-ID...",
            Style::default().fg(Color::DarkGray),
        )
    } else {
        Span::styled(s.input.clone(), Style::default().fg(Color::White).bold())
    };
    // Inline autocomplete: filter known_peers by label prefix.
    let mut suggestions: Vec<String> = Vec::new();
    if !s.input.is_empty() {
        let q = s.input.to_ascii_lowercase();
        for p in app.known_peers.iter().take(20) {
            if let Some(label) = &p.label {
                if let Some(name) = app.handle.lookup_username(label) {
                    if name.to_ascii_lowercase().starts_with(&q) {
                        suggestions.push(format!("{} ({})", name, crate::ui::short_fp(label)));
                        continue;
                    }
                }
                if label.to_ascii_lowercase().starts_with(&q) {
                    suggestions.push(format!("HD-{}", &label.to_uppercase()));
                }
            }
            if suggestions.len() >= 4 {
                break;
            }
        }
    }

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  message who?",
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            "  pick from your contacts, or paste an HD-ID.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  > ", Style::default().fg(Color::Cyan).bold()),
            displayed,
        ]),
    ];
    if !suggestions.is_empty() {
        lines.push(Line::from(""));
        for s in &suggestions {
            lines.push(Line::from(vec![
                Span::styled("    · ", Style::default().fg(Color::DarkGray)),
                Span::styled(s.clone(), Style::default().fg(Color::White)),
            ]));
        }
    } else if !s.input.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "    (no match — Enter morphs into add-friend)",
            Style::default().fg(Color::DarkGray),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(" Enter", Style::default().fg(Color::Yellow)),
        Span::styled(" start DM  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Esc", Style::default().fg(Color::Yellow)),
        Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
    ]));
    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .padding(Padding::uniform(1))
            .title(Span::styled(
                " compose DM ",
                Style::default().fg(Color::Cyan).bold(),
            )),
    );
    f.render_widget(para, area);
}

pub fn render_add_friend(f: &mut Frame, s: &crate::app::AddFriendState) {
    let area = centered_rect(64, 14, f.area());
    f.render_widget(Clear, area);
    let displayed = if s.input.is_empty() {
        Span::styled(
            "HD-XXXX-…   ·   a connect code (K7M9Q2X4)   ·   alice",
            Style::default().fg(Color::DarkGray),
        )
    } else {
        Span::styled(s.input.clone(), Style::default().fg(Color::White).bold())
    };
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  enter a friend's HD ID, a connect code, or username.",
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            "  a connect code is the short code a friend generated",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "  with G; paste an invite link with v for a cold start.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  > ", Style::default().fg(Color::Cyan).bold()),
            displayed,
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Enter", Style::default().fg(Color::Yellow)),
            Span::styled(" dial  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
        ]),
    ];
    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .padding(Padding::uniform(1))
            .title(Span::styled(
                " add friend ",
                Style::default().fg(Color::Cyan).bold(),
            )),
    );
    f.render_widget(para, area);
}

/// huddle 1.2.1: show a freshly minted connect code for the user to share. A
/// peer types it into their "add friend" field to add us — short-lived, so it
/// can't be reused later to enumerate us.
pub fn render_connect_code(f: &mut Frame, s: &crate::app::ConnectCodeState) {
    let area = centered_rect(60, 13, f.area());
    f.render_widget(Clear, area);
    // Pretty-print as two groups of four for readability (K7M9-Q2X4).
    let pretty = if s.code.len() == 8 {
        format!("{}-{}", &s.code[..4], &s.code[4..])
    } else {
        s.code.clone()
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let remaining = (s.expires_at - now).max(0);
    let mins = remaining / 60;
    let secs = remaining % 60;
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  share this code — a friend adds you by typing it",
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            "  into their \"add friend\" box (a, or A on the GUI).",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("        {pretty}"),
            Style::default().fg(Color::Cyan).bold(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("  expires in {mins}m {secs:02}s"),
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" c", Style::default().fg(Color::Yellow)),
            Span::styled(" copy   ", Style::default().fg(Color::DarkGray)),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::styled(" close", Style::default().fg(Color::DarkGray)),
        ]),
    ];
    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .padding(Padding::uniform(1))
            .title(Span::styled(
                " your connect code ",
                Style::default().fg(Color::Cyan).bold(),
            )),
    );
    f.render_widget(para, area);
}

pub fn render_edit_username(f: &mut Frame, s: &crate::app::EditUsernameState) {
    let area = centered_rect(60, 10, f.area());
    f.render_widget(Clear, area);
    let displayed = if s.input.is_empty() {
        Span::styled(
            " (empty — submit to clear → [anonymous])",
            Style::default().fg(Color::DarkGray),
        )
    } else {
        Span::styled(s.input.clone(), Style::default().fg(Color::White).bold())
    };
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  pick a self-declared username (32 chars max).",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "  signed and broadcast to every joined room.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  > ", Style::default().fg(Color::Cyan).bold()),
            displayed,
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Enter", Style::default().fg(Color::Yellow)),
            Span::styled(" save  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
        ]),
    ];
    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .padding(Padding::uniform(1))
            .title(Span::styled(
                " edit username ",
                Style::default().fg(Color::Cyan).bold(),
            )),
    );
    f.render_widget(para, area);
}

/// Phase F: an owner-side modal showing the freshly-generated 8-char
/// join code (with a single `-` separator for readability). 10-minute
/// expiry, single-use; once a joiner consumes it the slot opens again.
pub fn render_show_join_code(f: &mut Frame, s: &ShowJoinCodeState) {
    let area = centered_rect(64, 13, f.area());
    f.render_widget(Clear, area);
    // Short hash disambiguates when two rooms share a name (e.g.
    // multiple "general"s discovered across networks).
    let short_id: String = s.room_id.chars().take(8).collect();
    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  room: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                s.room_name.clone(),
                Style::default().fg(Color::White).bold(),
            ),
            Span::styled(
                format!("  ({})", short_id),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("    "),
            Span::styled(s.code.clone(), Style::default().fg(Color::Yellow).bold()),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  share this OOB with the prospective joiner.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "  valid for 10 minutes, single use.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  press any key to dismiss",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .padding(Padding::uniform(1))
            .title(Span::styled(
                " join code ",
                Style::default().fg(Color::Cyan).bold(),
            )),
    );
    f.render_widget(para, area);
}

/// Phase F: joiner-side modal — paste / type the code shared OOB by an
/// owner of the encrypted room they're joining.
pub fn render_join_with_code(f: &mut Frame, s: &JoinWithCodeState) {
    let area = centered_rect(64, 12, f.area());
    f.render_widget(Clear, area);
    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  joining: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                s.room_name.clone(),
                Style::default().fg(Color::White).bold(),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" code:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("[ {}_ ]", s.code),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  read-only: you'll be able to read messages but not",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "  send until an owner shares the room passphrase.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Enter", Style::default().fg(Color::Yellow)),
            Span::styled(" submit  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
        ]),
    ];
    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .padding(Padding::uniform(1))
            .title(Span::styled(
                " join with code ",
                Style::default().fg(Color::Cyan).bold(),
            )),
    );
    f.render_widget(para, area);
}

/// Phase C: show a freshly-built invite URL to copy + share.
pub fn render_show_invite(f: &mut Frame, s: &ShowInviteState) {
    let area = centered_rect(80, 14, f.area());
    f.render_widget(Clear, area);
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(""));
    let scope_line = match &s.includes_room {
        Some(name) => format!("  invite to: {} (room scoped)", name),
        None => "  peer-only invite (no room attached)".to_string(),
    };
    lines.push(Line::from(Span::styled(
        scope_line,
        Style::default().fg(Color::White),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        s.url.clone(),
        Style::default().fg(Color::Yellow),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  copy + share with the joiner. passphrase (if any) must be",
        Style::default().fg(Color::DarkGray),
    )));
    lines.push(Line::from(Span::styled(
        "  shared separately — it's never in the link.",
        Style::default().fg(Color::DarkGray),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  press any key to dismiss",
        Style::default().fg(Color::DarkGray),
    )));
    let para = Paragraph::new(lines).wrap(Wrap { trim: true }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .padding(Padding::uniform(1))
            .title(Span::styled(
                " invite link ",
                Style::default().fg(Color::Cyan).bold(),
            )),
    );
    f.render_widget(para, area);
}

/// Phase C: paste-an-invite text field. On Enter, decodes to a
/// ConfirmInvite modal showing what we'll dial.
pub fn render_paste_invite(f: &mut Frame, s: &PasteInviteState) {
    let area = centered_rect(80, 11, f.area());
    f.render_widget(Clear, area);
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  paste a huddle://invite#... link:",
            Style::default().fg(Color::White),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!(" {}_", s.url),
            Style::default().fg(Color::Yellow),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Enter", Style::default().fg(Color::Yellow)),
            Span::styled(" parse  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
        ]),
    ];
    let para = Paragraph::new(lines).wrap(Wrap { trim: true }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .padding(Padding::uniform(1))
            .title(Span::styled(
                " paste invite ",
                Style::default().fg(Color::Cyan).bold(),
            )),
    );
    f.render_widget(para, area);
}

/// Phase C: parsed invite — confirm before dialing.
pub fn render_confirm_invite(f: &mut Frame, s: &ConfirmInviteState) {
    let area = centered_rect(72, 14, f.area());
    f.render_widget(Clear, area);
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  id:   ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            super::display_id(&s.invite.fingerprint),
            Style::default().fg(Color::Yellow).bold(),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  dial: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            s.invite.host_multiaddr.clone(),
            Style::default().fg(Color::White),
        ),
    ]));
    if let Some(room) = &s.invite.room {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("  room:        ", Style::default().fg(Color::DarkGray)),
            Span::styled(room.name.clone(), Style::default().fg(Color::White).bold()),
            Span::styled(
                if room.encrypted {
                    "  (encrypted)"
                } else {
                    "  (public)"
                },
                Style::default().fg(Color::DarkGray),
            ),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(" [d]", Style::default().fg(Color::Green).bold()),
        Span::styled("ial  ", Style::default().fg(Color::DarkGray)),
        Span::styled(" [c]", Style::default().fg(Color::Red).bold()),
        Span::styled("ancel  ", Style::default().fg(Color::DarkGray)),
        Span::styled(" Esc", Style::default().fg(Color::Red)),
        Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
    ]));
    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .padding(Padding::uniform(1))
            .title(Span::styled(
                " accept invite? ",
                Style::default().fg(Color::Cyan).bold(),
            )),
    );
    f.render_widget(para, area);
}

/// Phase H + huddle 0.6: paginated onboarding. `pages` is a filtered
/// index list into `ONBOARDING_PAGES` so a version bump shows only
/// the new "what's new" cards. `cursor` is the position within
/// that filtered list (not the global index).
pub fn render_onboarding(f: &mut Frame, page_indices: &[usize], cursor: usize) {
    let all = crate::app::ONBOARDING_PAGES;
    if page_indices.is_empty() {
        return;
    }
    let cursor = cursor.min(page_indices.len() - 1);
    let global_idx = page_indices[cursor].min(all.len() - 1);
    let page = &all[global_idx];
    let total = page_indices.len();

    // Chrome around the body: title + 4 blank spacers + dots + nav hint
    // (7) plus the border (2) and uniform padding (2) = 11 lines. Sizing
    // the card to exactly fit means a normal-size terminal shows the whole
    // page WITHOUT scrolling (the pages are written to fit ~24 rows).
    let height = (page.body.len() as u16) + 11;
    // huddle 0.7.11: clamp to the terminal's available space rather
    // than the hard 76×24 the original code requested. On a narrow
    // window (mid-flow resize, ssh from a tablet), `centered_rect`
    // used to return a zero-rect when width < 76 or height < 24 and
    // the onboarding modal silently disappeared. Now we shrink to fit
    // and render a "(resize for full view)" hint when truncated.
    // huddle 0.8: dropped the hard `.min(24)` cap — it clipped longer
    // pages on tall terminals and forced the user to (try to) scroll a
    // non-scrollable modal. We now grow to fit, bounded only by the
    // terminal height.
    let avail = f.area();
    let target_w = 76u16.min(avail.width.saturating_sub(2));
    let target_h = height.min(avail.height.saturating_sub(2));
    if target_w < 20 || target_h < 6 {
        // Truly tiny terminal — render a single-line hint instead of
        // a sub-pixel rect. Better degradation than silent dismissal.
        let hint = Paragraph::new(Line::from(Span::styled(
            " huddle: resize terminal to ≥ 30×8 to read onboarding ",
            Style::default().fg(Color::Yellow),
        )));
        f.render_widget(Clear, avail);
        f.render_widget(hint, avail);
        return;
    }
    let area = centered_rect(target_w, target_h, avail);
    f.render_widget(Clear, area);

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("  {}", page.title),
        Style::default().fg(Color::Yellow).bold(),
    )));
    lines.push(Line::from(""));
    for body in page.body.iter() {
        lines.push(Line::from(Span::styled(
            format!("  {}", body),
            Style::default().fg(Color::White),
        )));
    }
    lines.push(Line::from(""));
    let dots: String = (0..total)
        .map(|i| if i == cursor { "●" } else { "○" })
        .collect::<Vec<_>>()
        .join(" ");
    lines.push(Line::from(Span::styled(
        format!("  {} ({}/{})", dots, cursor + 1, total),
        Style::default().fg(Color::DarkGray),
    )));
    lines.push(Line::from(""));
    let nav_hint = if cursor + 1 == total {
        " Enter dismiss   ← back   Esc skip"
    } else if cursor == 0 {
        " Enter / → next   Esc skip"
    } else {
        " Enter / → next   ← back   Esc skip"
    };
    lines.push(Line::from(Span::styled(
        nav_hint,
        Style::default().fg(Color::DarkGray),
    )));

    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .padding(Padding::uniform(1))
            .title(Span::styled(
                " welcome to huddle ",
                Style::default().fg(Color::Cyan).bold(),
            )),
    );
    f.render_widget(para, area);
}

/// huddle 0.6: scrollable notification history overlay (Ctrl+H).
/// Shows the last `STATUS_HISTORY_CAP` status-bar entries, newest
/// first, with absolute timestamps.
pub fn render_status_history(f: &mut Frame, app: &crate::app::TuiApp, scroll: u16) {
    let area = centered_rect(80, 24, f.area());
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .padding(Padding::uniform(1))
        .title(Span::styled(
            format!(" notification history ({}) ", app.status_history.len()),
            Style::default().fg(Color::Cyan).bold(),
        ));
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(""));
    if app.status_history.is_empty() {
        lines.push(Line::from(Span::styled(
            "  no notifications yet.",
            Style::default().fg(Color::DarkGray),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  everything huddle would say in the status bar will land here",
            Style::default().fg(Color::DarkGray),
        )));
        lines.push(Line::from(Span::styled(
            "  for replay. give it a few minutes.",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        // Render newest-first so the most recent is always visible at
        // the top of the modal without scrolling.
        for entry in app.status_history.iter().rev() {
            let t = format_clock_time(entry.timestamp);
            lines.push(Line::from(vec![
                Span::styled(format!("  {}  ", t), Style::default().fg(Color::DarkGray)),
                Span::styled(entry.message.clone(), Style::default().fg(Color::White)),
            ]));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  j/k scroll · PgUp/PgDn page · c clear · Esc / q close",
        Style::default().fg(Color::DarkGray),
    )));
    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0))
        .block(block);
    f.render_widget(para, area);
}

fn format_clock_time(unix_secs: i64) -> String {
    let secs_today = (unix_secs % 86_400) as u32;
    let hh = (secs_today / 3600) % 24;
    let mm = (secs_today / 60) % 60;
    let ss = secs_today % 60;
    format!("{:02}:{:02}:{:02}", hh, mm, ss)
}

/// huddle 0.6: command palette (Ctrl+P / `:`). Fuzzy-search every
/// palette-eligible action plus a few "extras" (toggles & dismiss
/// banner). Enter executes; Esc cancels.
pub fn render_command_palette(f: &mut Frame, s: &crate::app::CommandPaletteState) {
    let area = centered_rect(80, 22, f.area());
    f.render_widget(Clear, area);
    let entries = crate::app::palette_filtered(&s.query);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .padding(Padding::uniform(1))
        .title(Span::styled(
            " command palette ",
            Style::default().fg(Color::Cyan).bold(),
        ));
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled(" › ", Style::default().fg(Color::Cyan).bold()),
        Span::styled(s.query.clone(), Style::default().fg(Color::White)),
        Span::styled("_", Style::default().fg(Color::DarkGray)),
    ]));
    lines.push(Line::from(""));
    if entries.is_empty() {
        lines.push(Line::from(Span::styled(
            "  no matching commands.",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        // Show up to 14 entries; window around the selected one so
        // scrolling with ↓ works even past the visible cap.
        const VISIBLE: usize = 14;
        let offset = if s.selected >= VISIBLE {
            s.selected.saturating_sub(VISIBLE - 1)
        } else {
            0
        };
        for (i, e) in entries.iter().enumerate().skip(offset).take(VISIBLE) {
            let focused = i == s.selected;
            let marker = if focused { "› " } else { "  " };
            let label_style = if focused {
                Style::default().fg(Color::Cyan).bold()
            } else {
                Style::default().fg(Color::White)
            };
            let keys_pretty = if e.keys.is_empty() {
                "".to_string()
            } else {
                format!("    [{}]", e.keys)
            };
            lines.push(Line::from(vec![
                Span::styled(format!("  {}", marker), Style::default().fg(Color::Yellow)),
                Span::styled(e.label.to_string(), label_style),
                Span::styled(keys_pretty, Style::default().fg(Color::DarkGray)),
            ]));
        }
    }
    while lines.len() < 18 {
        lines.push(Line::from(""));
    }
    lines.push(Line::from(Span::styled(
        " Enter run · ↑/↓ navigate · type to filter · Esc cancel",
        Style::default().fg(Color::DarkGray),
    )));
    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(block);
    f.render_widget(para, area);
}

/// huddle 0.6: first-launch opt-in for the crates.io update check.
/// Shown to users who haven't been asked yet (after onboarding).
pub fn render_update_opt_in(f: &mut Frame) {
    let area = centered_rect(72, 14, f.area());
    f.render_widget(Clear, area);
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  check crates.io for updates?",
            Style::default().fg(Color::White).bold(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  huddle would HTTPS GET https://crates.io once per 24 h",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "  to see if there's a newer version available. A banner",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "  shows in the lobby header when one is. No telemetry.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  privacy note: crates.io's CDN sees your IP + User-Agent.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "  default OFF for that reason. you can toggle from settings.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" [y]", Style::default().fg(Color::Green).bold()),
            Span::styled(" enable    ", Style::default().fg(Color::DarkGray)),
            Span::styled(" [n / Esc]", Style::default().fg(Color::Red).bold()),
            Span::styled(" no thanks", Style::default().fg(Color::DarkGray)),
        ]),
    ];
    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow))
            .padding(Padding::uniform(1))
            .title(Span::styled(
                " update check ",
                Style::default().fg(Color::Yellow).bold(),
            )),
    );
    f.render_widget(para, area);
}

pub fn render_error(f: &mut Frame, msg: &str) {
    let area = centered_rect(56, 8, f.area());
    f.render_widget(Clear, area);
    let para = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(msg, Style::default().fg(Color::White))),
        Line::from(""),
        Line::from(""),
        Line::from(Span::styled(
            "  press any key to dismiss",
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .wrap(Wrap { trim: false })
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red))
            .padding(Padding::uniform(1))
            .title(Span::styled(
                " error ",
                Style::default().fg(Color::Red).bold(),
            )),
    );
    f.render_widget(para, area);
}

/// huddle 0.7.7: InvitePicker — pick peers to auto-DM a room invite.
/// Tiered (Verified → DM partners → Known peers), Space to toggle, `/`-
/// free filter (literal typing narrows live), Enter to send.
pub fn render_invite_picker(f: &mut Frame, s: &crate::app::InvitePickerState) {
    use crate::app::{filtered_invite_candidates, InviteTier, INVITE_PICKER_SOFT_CAP};

    let area = centered_rect(76, 24, f.area());
    f.render_widget(Clear, area);

    let visible = filtered_invite_candidates(s);
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled("  invite to ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("#{}", s.room_name),
            Style::default().fg(Color::White).bold(),
        ),
        Span::styled(
            format!("  ·  {} selected ", s.selected.len()),
            Style::default().fg(if s.selected.is_empty() {
                Color::DarkGray
            } else {
                Color::Cyan
            }),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  filter: ", Style::default().fg(Color::DarkGray)),
        if s.filter.is_empty() {
            Span::styled(
                "(type to narrow by username or HD-prefix)",
                Style::default().fg(Color::DarkGray),
            )
        } else {
            Span::styled(s.filter.clone(), Style::default().fg(Color::White))
        },
    ]));
    lines.push(Line::from(""));

    if visible.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (no matches — Backspace to clear filter, Esc to cancel)",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        // Group with section headers as we walk in tier order. The
        // `gather_invite_candidates` helper pre-sorts so every Verified
        // appears before every DmPartner appears before every Known.
        let mut current_tier: Option<InviteTier> = None;
        for (i, c) in visible.iter().enumerate() {
            if current_tier != Some(c.tier) {
                let (label, color) = match c.tier {
                    InviteTier::Verified => ("Verified", Color::Green),
                    InviteTier::DmPartner => ("DM partners", Color::Cyan),
                    InviteTier::Known => ("Known peers", Color::DarkGray),
                };
                lines.push(Line::from(Span::styled(
                    format!("  {}", label),
                    Style::default().fg(color).bold(),
                )));
                current_tier = Some(c.tier);
            }
            let checked = s.selected.contains(&c.fingerprint);
            let box_glyph = if checked { "[x]" } else { "[ ]" };
            let cursor = if i == s.cursor { "▸" } else { " " };
            let username = c
                .username
                .clone()
                .unwrap_or_else(|| "[anonymous]".to_string());
            let hd = format!("HD-{}", crate::ui::short_fp(&c.fingerprint).to_uppercase());
            let mut spans = vec![
                Span::styled(cursor, Style::default().fg(Color::Yellow)),
                Span::raw(" "),
                Span::styled(
                    box_glyph,
                    if checked {
                        Style::default().fg(Color::Cyan).bold()
                    } else {
                        Style::default().fg(Color::DarkGray)
                    },
                ),
                Span::raw(" "),
                Span::styled(username, Style::default().fg(Color::White)),
                Span::raw("  "),
                Span::styled(hd, Style::default().fg(Color::DarkGray)),
            ];
            if c.tier == InviteTier::Verified {
                spans.push(Span::styled("  ✓", Style::default().fg(Color::Green)));
            }
            lines.push(Line::from(spans));
        }
    }

    if let Some(msg) = &s.status_line {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {}", msg),
            Style::default().fg(Color::Yellow),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(" Space", Style::default().fg(Color::Yellow)),
        Span::styled(" toggle  ", Style::default().fg(Color::DarkGray)),
        Span::styled("↑↓", Style::default().fg(Color::Yellow)),
        Span::styled(" move  ", Style::default().fg(Color::DarkGray)),
        Span::styled("type", Style::default().fg(Color::Yellow)),
        Span::styled(" filter  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Enter", Style::default().fg(Color::Yellow)),
        Span::styled(" send  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Esc", Style::default().fg(Color::Yellow)),
        Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
    ]));
    lines.push(Line::from(Span::styled(
        format!(
            "  (soft cap: {} selections per send)",
            INVITE_PICKER_SOFT_CAP
        ),
        Style::default().fg(Color::DarkGray),
    )));

    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .padding(Padding::uniform(1))
            .title(Span::styled(
                " invite peers ",
                Style::default().fg(Color::Cyan).bold(),
            )),
    );
    f.render_widget(para, area);
}

// =========================================================================
// huddle 2.0.0 (F3): safety-number-change alarm
// =========================================================================

/// Render the TOFU-drift alarm. The offending message was already dropped by
/// the core; this surfaces the change loudly and offers the two cryptographically
/// safe responses — re-verify out-of-band (SAS) or block. Dismiss (Esc) leaves
/// the pinned key unchanged, so the user stays protected by default.
pub fn render_safety_number_changed(f: &mut Frame, s: &SafetyNumberChangedState) {
    let area = centered_rect(70, 18, f.area());
    f.render_widget(Clear, area);

    let who = s
        .display_name
        .clone()
        .unwrap_or_else(|| super::display_id(&s.fingerprint));

    let opt = |label: &str, key: &str, focused: bool, color: Color| -> Line<'static> {
        let marker = if focused { "▶" } else { " " };
        let style = if focused {
            Style::default().fg(color).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        Line::from(vec![
            Span::styled(format!("  {} ", marker), style),
            Span::styled(format!("[{}] {}", key, label), style),
        ])
    };

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  the identity key for {} CHANGED.", who),
            Style::default().fg(Color::Red).bold(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  someone may be impersonating them, or they reinstalled /",
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            "  recovered onto a new device. their last message was DROPPED.",
            Style::default().fg(Color::White),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  old key  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                short_key(&s.old_pubkey_b64),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            Span::styled("  new key  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                short_key(&s.new_pubkey_b64),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(""),
        opt(
            "re-verify out-of-band (SAS)",
            "v",
            s.focus == 0,
            Color::Cyan,
        ),
        opt("block this peer", "b", s.focus == 1, Color::Red),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Tab/↑↓", Style::default().fg(Color::Yellow)),
            Span::styled(" move  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Enter", Style::default().fg(Color::Yellow)),
            Span::styled(" choose  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::styled(" dismiss (stay safe)", Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow))
            .padding(Padding::uniform(1))
            .title(Span::styled(
                format!(" ⚠ safety number changed: {} ", who),
                Style::default().fg(Color::Yellow).bold(),
            )),
    );
    f.render_widget(para, area);
}

/// First two base64 groups of a pubkey — enough to read the change at a glance
/// without dumping 44 characters into the modal.
fn short_key(b64: &str) -> String {
    let head: String = b64.chars().take(12).collect();
    format!("{}…", head)
}

// =========================================================================
// huddle 2.0.0 (F5): change master passphrase
// =========================================================================

pub fn render_change_passphrase(f: &mut Frame, s: &ChangePassphraseState) {
    let area = centered_rect(64, 16, f.area());
    f.render_widget(Clear, area);

    let pass_field = |label: &str, value: &str, focused: bool| -> Line<'static> {
        let masked = "•".repeat(value.chars().count());
        let cursor = if focused { "_" } else { "" };
        let value_style = if focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::White)
        };
        Line::from(vec![
            Span::styled(
                format!("  {:<14}", label),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(format!("[ {}{} ]", masked, cursor), value_style),
        ])
    };

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  re-encrypts the local database under a new key.",
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            "  there is NO recovery if you forget the new passphrase.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        pass_field("current", &s.current, s.focus == PassField::Current),
        pass_field("new", &s.new_pass, s.focus == PassField::New),
        pass_field("confirm new", &s.confirm, s.focus == PassField::Confirm),
    ];
    if let Some(err) = &s.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  ✗ {}", err),
            Style::default().fg(Color::Red).bold(),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(" Tab", Style::default().fg(Color::Yellow)),
        Span::styled(" next field  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Enter", Style::default().fg(Color::Yellow)),
        Span::styled(" change  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Esc", Style::default().fg(Color::Yellow)),
        Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
    ]));

    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .padding(Padding::uniform(1))
            .title(Span::styled(
                " change master passphrase ",
                Style::default().fg(Color::Cyan).bold(),
            )),
    );
    f.render_widget(para, area);
}

// =========================================================================
// huddle 2.0.0 (F6): export identity seed phrase
// =========================================================================

pub fn render_export_seed(f: &mut Frame, s: &ExportSeedState) {
    let area = centered_rect(72, 22, f.area());
    f.render_widget(Clear, area);

    let mut lines: Vec<Line> = Vec::new();
    match s.step {
        ExportStep::Reveal => {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  these 24 words ARE your identity. anyone who reads them",
                Style::default().fg(Color::Red).bold(),
            )));
            lines.push(Line::from(Span::styled(
                "  can impersonate you. write them down offline — never type",
                Style::default().fg(Color::White),
            )));
            lines.push(Line::from(Span::styled(
                "  them into a website or share a photo.",
                Style::default().fg(Color::White),
            )));
            lines.push(Line::from(""));
            if s.revealed {
                for line in numbered_phrase(&s.phrase) {
                    lines.push(line);
                }
            } else {
                lines.push(Line::from(Span::styled(
                    "  •••  hidden — press Space to reveal  •••",
                    Style::default().fg(Color::DarkGray),
                )));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled(" Space", Style::default().fg(Color::Yellow)),
                Span::styled(" reveal/hide  ", Style::default().fg(Color::DarkGray)),
                Span::styled("Enter", Style::default().fg(Color::Yellow)),
                Span::styled(" I've saved it →  ", Style::default().fg(Color::DarkGray)),
                Span::styled("Esc", Style::default().fg(Color::Yellow)),
                Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
            ]));
        }
        ExportStep::Reentry => {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  type the 24 words back to confirm you saved them correctly:",
                Style::default().fg(Color::White),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("  > ", Style::default().fg(Color::Cyan).bold()),
                Span::styled(
                    if s.reentry.is_empty() {
                        "word1 word2 … word24".to_string()
                    } else {
                        s.reentry.clone()
                    },
                    if s.reentry.is_empty() {
                        Style::default().fg(Color::DarkGray)
                    } else {
                        Style::default().fg(Color::White)
                    },
                ),
            ]));
            if let Some(err) = &s.error {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    format!("  ✗ {}", err),
                    Style::default().fg(Color::Red).bold(),
                )));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled(" Enter", Style::default().fg(Color::Yellow)),
                Span::styled(" verify  ", Style::default().fg(Color::DarkGray)),
                Span::styled("Esc", Style::default().fg(Color::Yellow)),
                Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
            ]));
        }
        ExportStep::Done => {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  ✓ verified — your backup matches your identity.",
                Style::default().fg(Color::Green).bold(),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  store the words somewhere safe and offline. import them on",
                Style::default().fg(Color::White),
            )));
            lines.push(Line::from(Span::styled(
                "  a fresh install to recover this identity.",
                Style::default().fg(Color::White),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled(" Enter", Style::default().fg(Color::Yellow)),
                Span::styled(" close", Style::default().fg(Color::DarkGray)),
            ]));
        }
    }

    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Magenta))
            .padding(Padding::uniform(1))
            .title(Span::styled(
                " export seed phrase ",
                Style::default().fg(Color::Magenta).bold(),
            )),
    );
    f.render_widget(para, area);
}

/// Render a space-separated phrase as numbered words, two per line, so the
/// user can read the 24 words off without ambiguity.
fn numbered_phrase(phrase: &str) -> Vec<Line<'static>> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    let mut out: Vec<Line> = Vec::new();
    for pair in words.chunks(3) {
        let mut spans: Vec<Span> = vec![Span::raw("   ")];
        for (i, w) in pair.iter().enumerate() {
            let n = out.len() * 3 + i + 1;
            spans.push(Span::styled(
                format!("{:>2}. ", n),
                Style::default().fg(Color::DarkGray),
            ));
            spans.push(Span::styled(
                format!("{:<12}", w),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        out.push(Line::from(spans));
    }
    out
}

// =========================================================================
// huddle 2.0.0 (F10): emoji picker + delete confirmation
// =========================================================================

pub fn render_emoji_picker(f: &mut Frame, s: &EmojiPickerState) {
    let area = centered_rect(52, 8, f.area());
    f.render_widget(Clear, area);

    let mut spans: Vec<Span> = vec![Span::raw("  ")];
    for (i, e) in REACTION_EMOJIS.iter().enumerate() {
        let selected = i == s.selected;
        let style = if selected {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD | Modifier::REVERSED)
        } else {
            Style::default().fg(Color::White)
        };
        spans.push(Span::styled(format!(" {} ", e), style));
    }

    let lines = vec![
        Line::from(""),
        Line::from(spans),
        Line::from(""),
        Line::from(vec![
            Span::styled(" ←/→", Style::default().fg(Color::Yellow)),
            Span::styled(" pick  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Enter", Style::default().fg(Color::Yellow)),
            Span::styled(" react  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .padding(Padding::uniform(1))
            .title(Span::styled(
                " react ",
                Style::default().fg(Color::Cyan).bold(),
            )),
    );
    f.render_widget(para, area);
}

pub fn render_confirm_delete(f: &mut Frame, _s: &ConfirmDeleteState) {
    let area = centered_rect(58, 9, f.area());
    f.render_widget(Clear, area);
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  delete this message?",
            Style::default().fg(Color::White).bold(),
        )),
        Line::from(Span::styled(
            "  it's tombstoned everywhere (best effort) and shows as [deleted].",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" y / Enter", Style::default().fg(Color::Red).bold()),
            Span::styled(" delete   ", Style::default().fg(Color::DarkGray)),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
        ]),
    ];
    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red))
            .padding(Padding::uniform(1))
            .title(Span::styled(
                " delete message ",
                Style::default().fg(Color::Red).bold(),
            )),
    );
    f.render_widget(para, area);
}
