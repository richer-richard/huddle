use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph, Wrap};

use crate::app::{
    AcceptRotationState, AttachPickerState, ConfirmInviteState, DialPeerState, InboundDialState,
    JoinRoomState, JoinWithCodeState, MemberActionKind, MemberActionState, PasteInviteState,
    RotateRoomState, SasStage, SasState, SearchState, SettingsState, ShowInviteState,
    ShowJoinCodeState, StartField, StartRoomState, VerifyState,
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
        Span::styled(format!(" {:<11}", label), Style::default().fg(Color::DarkGray)),
        Span::styled(value_str, value_style),
    ])
}

fn encrypted_line(s: &StartRoomState) -> Line<'static> {
    let check = if s.encrypted { "[x]" } else { "[ ]" };
    let label = if s.encrypted { "yes" } else { "no" };
    let focused = matches!(s.focus, StartField::Encrypted);
    let style = if focused {
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };
    Line::from(vec![
        Span::styled(" encrypted   ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{} {}", check, label), style),
        Span::styled(
            if focused { "   (Enter/Space toggle)" } else { "" },
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

    // 🔒 only appears when the announcement marked this room encrypted
    // — gives users a visual confirmation before they type a passphrase.
    let lock = if j.encrypted { "🔒 " } else { "" };
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
                Span::styled(
                    b.description.to_string(),
                    Style::default().fg(Color::White),
                ),
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

    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(block);
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
            Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
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
            Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
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
            Span::styled(" ignore (you'll stop seeing messages)", Style::default().fg(Color::DarkGray)),
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
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
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
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
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
        for (i, m) in s
            .results
            .iter()
            .enumerate()
            .skip(offset)
            .take(visible)
        {
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
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            lines.push(Line::from(vec![
                Span::styled(format!("  {}", marker), Style::default().fg(Color::Yellow)),
                Span::styled(
                    format!("{}  ", time),
                    Style::default().fg(Color::DarkGray),
                ),
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
    f.render_widget(Paragraph::new(lines).block(block).wrap(Wrap { trim: false }), area);
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
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled("  your id: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            super::display_id(&s.our_fingerprint),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
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
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let name_style = if i == s.selected {
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
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
    f.render_widget(Paragraph::new(lines).block(block).wrap(Wrap { trim: false }), area);
}

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

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled("  in ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{}", s.cwd.display()),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::from(""));

    if let Some(err) = &s.error {
        lines.push(Line::from(Span::styled(
            format!("  ! {}", err),
            Style::default().fg(Color::Red),
        )));
    }

    // Reserve about 14 visible rows for entries.
    let visible = 14usize;
    let offset = if s.selected >= visible {
        s.selected.saturating_sub(visible - 1)
    } else {
        0
    };
    let take = visible.min(s.entries.len().saturating_sub(offset));
    if s.entries.is_empty() && s.error.is_none() {
        lines.push(Line::from(Span::styled(
            "  (empty directory)",
            Style::default().fg(Color::DarkGray),
        )));
    }
    for (i, entry) in s.entries.iter().enumerate().skip(offset).take(take) {
        let is_focused = i == s.selected;
        let marker = if is_focused { "› " } else { "  " };
        let icon = if entry.is_dir { "[dir] " } else { "      " };
        let suffix = if entry.is_dir { "/" } else { "" };
        let style = if is_focused {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else if entry.is_dir {
            Style::default().fg(Color::Blue)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(vec![
            Span::styled(format!("  {}", marker), Style::default().fg(Color::Yellow)),
            Span::styled(icon, Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{}{}", entry.name, suffix), style),
        ]));
    }
    // Pad to visible rows to keep layout stable.
    while lines.len() < visible + 4 {
        lines.push(Line::from(""));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(" j/k", Style::default().fg(Color::Yellow)),
        Span::styled(" navigate  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Enter", Style::default().fg(Color::Yellow)),
        Span::styled(" descend/pick  ", Style::default().fg(Color::DarkGray)),
        Span::styled("h/Backspace", Style::default().fg(Color::Yellow)),
        Span::styled(" up  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Esc", Style::default().fg(Color::Yellow)),
        Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
    ]));

    let para = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    f.render_widget(para, area);
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

    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(
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

    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(
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
            emoji_string,
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
                    emoji_string.clone(),
                    Style::default().fg(Color::Yellow).bold(),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::raw("   "),
                Span::styled(emoji_labels.clone(), Style::default().fg(Color::DarkGray)),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("  fallback decimal: ", Style::default().fg(Color::DarkGray)),
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

    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(
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

/// Phase E + huddle 0.6: settings modal. The TuiApp is passed in so
/// we can render contextual info (update-check status, pending modal
/// count) without bloating SettingsState.
pub fn render_settings(f: &mut Frame, s: &SettingsState, app: &crate::app::TuiApp) {
    let area = centered_rect(72, 26, f.area());
    f.render_widget(Clear, area);
    let check = if s.verified_only_inbound { "[x]" } else { "[ ]" };
    let blocked = s.blocked_peer_count;
    let clear_hint = if blocked == 0 {
        Line::from(Span::styled(
            "  no blocked peers.",
            Style::default().fg(Color::DarkGray),
        ))
    } else {
        Line::from(vec![
            Span::styled("  press ", Style::default().fg(Color::DarkGray)),
            Span::styled("c", Style::default().fg(Color::Yellow).bold()),
            Span::styled(" to clear all.", Style::default().fg(Color::DarkGray)),
        ])
    };
    let username_label = match &s.username {
        Some(n) if !n.is_empty() => n.clone(),
        _ => "[anonymous]".into(),
    };
    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(" username: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                username_label,
                Style::default().fg(Color::Cyan).bold(),
            ),
        ]),
        Line::from(vec![
            Span::styled("  press ", Style::default().fg(Color::DarkGray)),
            Span::styled("u", Style::default().fg(Color::Yellow).bold()),
            Span::styled(
                " to edit (empty input clears).",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" ", Style::default()),
            Span::styled(check, Style::default().fg(Color::Yellow).bold()),
            Span::styled(
                " reject inbound dials from unverified fingerprints",
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(Span::styled(
            "  press v / Space / Enter to toggle.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" blocked peers: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}", blocked),
                Style::default().fg(Color::White).bold(),
            ),
        ]),
        clear_hint,
        Line::from(""),
        Line::from(vec![
            Span::styled(" update check (crates.io): ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                match app.handle.update_check_enabled() {
                    Some(true) => "ON",
                    Some(false) => "OFF",
                    None => "(not asked yet)",
                },
                Style::default().fg(Color::Cyan).bold(),
            ),
        ]),
        Line::from(vec![
            Span::styled("  press ", Style::default().fg(Color::DarkGray)),
            Span::styled("U", Style::default().fg(Color::Yellow).bold()),
            Span::styled(" to toggle", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" press ", Style::default().fg(Color::DarkGray)),
            Span::styled("W", Style::default().fg(Color::Yellow).bold()),
            Span::styled(" to replay onboarding / what's new", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" [⌥⇧1]", Style::default().fg(Color::Red).bold()),
            Span::styled(
                " delete account (go dark) — press ",
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled("⌥⇧1", Style::default().fg(Color::Red).bold()),
            Span::styled(
                " (Option+Shift+1)",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Esc / q", Style::default().fg(Color::Yellow)),
            Span::styled(" close", Style::default().fg(Color::DarkGray)),
        ]),
    ];
    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .padding(Padding::uniform(1))
                .title(Span::styled(
                    " settings ",
                    Style::default().fg(Color::Cyan).bold(),
                )),
        );
    f.render_widget(para, area);
}

pub fn render_go_dark(f: &mut Frame, s: &crate::app::GoDarkState) {
    use crate::app::{GoDarkField, GO_DARK_CONFIRM_PHRASE};
    let area = centered_rect(70, 22, f.area());
    f.render_widget(Clear, area);
    let mask = |v: &str| -> String { "•".repeat(v.chars().count()) };
    let pp_focused = matches!(s.focus, GoDarkField::Passphrase);
    let cf_focused = matches!(s.focus, GoDarkField::Confirm);
    let cf_ok = s.confirm == GO_DARK_CONFIRM_PHRASE;
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
        Line::from(vec![
            Span::styled(
                if pp_focused { "› " } else { "  " },
                Style::default().fg(Color::Yellow),
            ),
            Span::styled("master passphrase: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                mask(&s.passphrase),
                if pp_focused {
                    Style::default().fg(Color::Cyan).bold()
                } else {
                    Style::default().fg(Color::White)
                },
            ),
        ]),
        Line::from(vec![
            Span::styled(
                if cf_focused { "› " } else { "  " },
                Style::default().fg(Color::Yellow),
            ),
            Span::styled(
                format!("type '{}': ", GO_DARK_CONFIRM_PHRASE),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                s.confirm.clone(),
                if cf_focused {
                    Style::default().fg(Color::Cyan).bold()
                } else if cf_ok {
                    Style::default().fg(Color::Red).bold()
                } else {
                    Style::default().fg(Color::White)
                },
            ),
        ]),
        Line::from(""),
    ];
    if let Some(err) = &s.last_error {
        lines.push(Line::from(Span::styled(
            format!("  {}", err),
            Style::default().fg(Color::Red),
        )));
    }
    let enabled_hint = if cf_ok {
        Span::styled(
            " Enter ",
            Style::default().fg(Color::Red).bold(),
        )
    } else {
        Span::styled(" Enter ", Style::default().fg(Color::DarkGray))
    };
    lines.push(Line::from(vec![
        Span::styled(" Tab", Style::default().fg(Color::Yellow)),
        Span::styled(" switch  ", Style::default().fg(Color::DarkGray)),
        enabled_hint,
        Span::styled(
            if cf_ok { "delete  " } else { "(confirm phrase to enable)  " },
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled("Esc", Style::default().fg(Color::Yellow)),
        Span::styled(" cancel", Style::default().fg(Color::DarkGray)),
    ]));
    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red))
                .padding(Padding::uniform(1))
                .title(Span::styled(
                    " ⚠ delete account (go dark) ",
                    Style::default().fg(Color::Red).bold(),
                )),
        );
    f.render_widget(para, area);
}

/// huddle 0.7: Compose-DM modal. Single-field input with inline
/// suggestions pulled from `known_peers` + `peer_profiles`. On confirm
/// the action handler calls `start_direct(fp)`; on unresolvable input
/// it morphs into `AddFriend` semantics (same modal recycled).
pub fn render_compose_dm(
    f: &mut Frame,
    s: &crate::app::ComposeDmState,
    app: &crate::app::TuiApp,
) {
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
    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(
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
            "HD-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX   or   alice",
            Style::default().fg(Color::DarkGray),
        )
    } else {
        Span::styled(
            s.input.clone(),
            Style::default().fg(Color::White).bold(),
        )
    };
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  enter a friend's HD ID or username.",
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            "  works for peers seen on the mesh; for cold start,",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "  paste an invite link with v instead.",
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
    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(
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

pub fn render_edit_username(f: &mut Frame, s: &crate::app::EditUsernameState) {
    let area = centered_rect(60, 10, f.area());
    f.render_widget(Clear, area);
    let displayed = if s.input.is_empty() {
        Span::styled(
            " (empty — submit to clear → [anonymous])",
            Style::default().fg(Color::DarkGray),
        )
    } else {
        Span::styled(
            s.input.clone(),
            Style::default().fg(Color::White).bold(),
        )
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
    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(
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
            Span::styled(s.room_name.clone(), Style::default().fg(Color::White).bold()),
            Span::styled(
                format!("  ({})", short_id),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("    "),
            Span::styled(
                s.code.clone(),
                Style::default().fg(Color::Yellow).bold(),
            ),
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
    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(
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
            Span::styled(s.room_name.clone(), Style::default().fg(Color::White).bold()),
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
    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(
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
    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: true })
        .block(
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
    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: true })
        .block(
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
        Span::styled(s.invite.host_multiaddr.clone(), Style::default().fg(Color::White)),
    ]));
    if let Some(room) = &s.invite.room {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("  room:        ", Style::default().fg(Color::DarkGray)),
            Span::styled(room.name.clone(), Style::default().fg(Color::White).bold()),
            Span::styled(
                if room.encrypted { "  (encrypted)" } else { "  (public)" },
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
    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(
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

    let height = (page.body.len() as u16) + 10;
    let area = centered_rect(76, height.min(24), f.area());
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

    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(
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
                Span::styled(
                    format!("  {}  ", t),
                    Style::default().fg(Color::DarkGray),
                ),
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
    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(block);
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
    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(
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
