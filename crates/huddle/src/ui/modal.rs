use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph, Wrap};

use crate::app::{
    AcceptRotationState, AttachPickerState, DialPeerState, InboundDialState, JoinRoomState,
    MemberActionKind, MemberActionState, RotateRoomState, SearchState, StartField, StartRoomState,
    VerifyState,
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

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta))
        .title(Span::styled(
            format!(" join #{} (encrypted) ", j.room_name),
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

pub fn render_help(f: &mut Frame) {
    let area = centered_rect(64, 22, f.area());
    f.render_widget(Clear, area);
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(" Lobby", Style::default().fg(Color::Cyan).bold())),
        Line::from(""),
        kv("  s", "start a new room"),
        kv("  d", "dial a peer by IP:port (Direct mode)"),
        kv("  Tab", "switch focus: known peers <-> rooms"),
        kv("  Enter", "join selected room / reconnect peer"),
        kv("  j/k or arrows", "navigate the focused list"),
        kv("  r", "refresh rooms / retry connect"),
        kv("  x", "forget the highlighted peer"),
        kv("  ?", "this help"),
        kv("  q / Ctrl-C", "quit"),
        Line::from(""),
        Line::from(Span::styled(" In a room", Style::default().fg(Color::Cyan).bold())),
        Line::from(""),
        kv("  /", "type a message"),
        kv("  Esc", "blur input / back to lobby"),
        kv("  ^Tab / ^N", "next tab"),
        kv("  ^P", "previous tab"),
        kv("  1..9", "jump to tab N"),
        kv("  ^L", "leave the current room"),
        kv("  ^B", "back to lobby (without leaving)"),
    ];
    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .padding(Padding::uniform(1))
                .title(Span::styled(
                    " help  (press any key to close) ",
                    Style::default().fg(Color::Cyan).bold(),
                )),
        );
    f.render_widget(para, area);
}

fn kv(k: &'static str, v: &'static str) -> Line<'static> {
    Line::from(vec![
        Span::styled(k, Style::default().fg(Color::Yellow)),
        Span::styled(format!("   {}", v), Style::default().fg(Color::White)),
    ])
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
        "  fingerprint:",
        Style::default().fg(Color::DarkGray),
    )));
    lines.push(Line::from(Span::styled(
        format!("  {}", fingerprint),
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
        Span::styled("  your fingerprint: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            s.our_fingerprint.clone(),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::from(Span::styled(
        "  compare each peer's fingerprint with them out-of-band",
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
            Span::styled(fp.clone(), name_style),
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
            Span::styled("  fingerprint: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                s.fingerprint.clone(),
                Style::default().fg(Color::Yellow).bold(),
            ),
        ]),
        Line::from(vec![
            Span::styled("  address:     ", Style::default().fg(Color::DarkGray)),
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
            Span::styled(fp.clone(), style),
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
