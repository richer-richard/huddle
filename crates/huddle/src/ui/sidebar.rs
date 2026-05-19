//! huddle 0.7: sidebar widget.
//!
//! Six sections (Profile, Direct messages, Group rooms, People, Activity,
//! Settings) rendered top-to-bottom. The sidebar owns selection +
//! expansion state via `SidebarState`. j/k navigates rows; Tab/Shift+Tab
//! jumps between sections; Space/←/→ toggles expand; Enter commits the
//! selection and sets `app.pane`.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use huddle_core::storage::repo::RoomKind;

use crate::app::{Pane, SidebarFocus, SidebarItem, SidebarSection, TuiApp};
use crate::ui::theme::Theme;
use crate::ui::{display_id, short_fp};

const EXPAND_GLYPH: &str = "▾";
const COLLAPSE_GLYPH: &str = "▸";

/// Compute the ordered list of selectable items in the current sidebar.
/// Order matches render order — used by j/k navigation and Tab section
/// jumping.
pub fn ordered_items(app: &TuiApp) -> Vec<SidebarItem> {
    let mut out = Vec::new();
    let sb = &app.sidebar;

    out.push(SidebarItem::Section(SidebarSection::Profile));
    if sb.expanded.contains(&SidebarSection::Profile) {
        out.push(SidebarItem::Profile);
    }

    out.push(SidebarItem::Section(SidebarSection::Direct));
    if sb.expanded.contains(&SidebarSection::Direct) {
        // huddle 0.7.8: pinned add-friend row at top, mirroring
        // DirectChat's affordance density.
        out.push(SidebarItem::DirectAddFriend);
        let mut dms: Vec<_> = app
            .handle
            .discovered_rooms()
            .into_iter()
            .filter(|r| r.kind == RoomKind::Direct)
            .collect();
        dms.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        for r in &dms {
            out.push(SidebarItem::Dm(r.room_id.clone()));
        }
    }

    out.push(SidebarItem::Section(SidebarSection::Group));
    if sb.expanded.contains(&SidebarSection::Group) {
        // huddle 0.7.8: pinned new-group row at top.
        out.push(SidebarItem::GroupNew);
        let mut groups: Vec<_> = app
            .handle
            .discovered_rooms()
            .into_iter()
            .filter(|r| r.kind != RoomKind::Direct)
            .collect();
        groups.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        for r in &groups {
            out.push(SidebarItem::Group(r.room_id.clone()));
        }
        if !groups.is_empty() {
            out.push(SidebarItem::GroupDiscover);
        }
    }

    out.push(SidebarItem::Section(SidebarSection::People));
    if sb.expanded.contains(&SidebarSection::People) {
        // huddle 0.7.8: pending-friend-request badge row appears at top
        // of an expanded People section when any are outstanding. Tap
        // jumps to People → Pending sublist.
        if !app.pending_requests.is_empty() {
            out.push(SidebarItem::PeoplePendingBadge);
        }
        for p in &app.known_peers {
            out.push(SidebarItem::Person(p.address.clone()));
        }
    }

    out.push(SidebarItem::Section(SidebarSection::Activity));
    if sb.expanded.contains(&SidebarSection::Activity) {
        out.push(SidebarItem::Activity);
    }

    out.push(SidebarItem::Section(SidebarSection::Settings));
    if sb.expanded.contains(&SidebarSection::Settings) {
        out.push(SidebarItem::Settings);
    }

    out
}

pub fn render(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme) {
    let focused = app.sidebar.focus == SidebarFocus::Sidebar;
    let block = Block::default()
        .borders(Borders::RIGHT)
        .border_style(if focused {
            theme.border_focus_style()
        } else {
            theme.border_style()
        });
    let inner = block.inner(area);
    f.render_widget(block, area);

    let items = ordered_items(app);
    let lines = build_lines(app, theme, &items);

    let vis_h = inner.height as usize;
    let sel_idx = items
        .iter()
        .position(|it| *it == app.sidebar.selection)
        .unwrap_or(0);
    let offset = scroll_to_show(sel_idx, vis_h, lines.len());

    let visible: Vec<Line> = lines
        .into_iter()
        .skip(offset)
        .take(vis_h)
        .collect();
    let para = Paragraph::new(visible);
    f.render_widget(para, inner);
}

fn scroll_to_show(sel: usize, vis_h: usize, total: usize) -> usize {
    if total <= vis_h {
        return 0;
    }
    if sel < vis_h {
        return 0;
    }
    sel.saturating_sub(vis_h - 1)
}

fn build_lines<'a>(app: &TuiApp, theme: &Theme, items: &[SidebarItem]) -> Vec<Line<'a>> {
    let sel = &app.sidebar.selection;
    let focused = app.sidebar.focus == SidebarFocus::Sidebar;
    items
        .iter()
        .map(|it| {
            let is_sel = *it == *sel;
            render_item(app, theme, it, is_sel, focused)
        })
        .collect()
}

fn highlight(theme: &Theme, focused: bool, is_sel: bool, base: Style) -> Style {
    if !is_sel {
        return base;
    }
    if focused {
        theme.select_bg_focus()
    } else {
        theme.select_bg()
    }
}

/// huddle 0.7.3: when a sidebar row is selected, force every span's
/// foreground to yellow (or text_dim when the sidebar isn't focused).
/// Ratatui's `Line.style` only affects padding, not Span text, so a bg
/// highlight alone is barely visible on dark terminals. Recoloring
/// each span gives a clearly visible cursor without relying on
/// background contrast.
fn apply_selection_fg<'a>(line: Line<'a>, theme: &Theme, focused: bool, is_sel: bool) -> Line<'a> {
    if !is_sel {
        return line;
    }
    let fg = if focused { theme.warn } else { theme.text_dim };
    let line_style = line.style;
    // huddle 0.7.11: preserve the encryption marker color. Pre-0.7.11
    // every span had its fg stomped to yellow/dim, which drowned the
    // magenta 🔒 badge on a selected encrypted room — users lost the
    // visual signal that a row was encrypted exactly when they were
    // about to act on it. Spans whose fg is `theme.encrypted` keep
    // their color but still get the bold modifier so they stay legible
    // against the selection background.
    let spans: Vec<Span<'a>> = line
        .spans
        .into_iter()
        .map(|s| {
            let keep_fg = s.style.fg == Some(theme.encrypted);
            let style = if keep_fg {
                s.style.add_modifier(Modifier::BOLD)
            } else {
                s.style.fg(fg).add_modifier(Modifier::BOLD)
            };
            Span::styled(s.content, style)
        })
        .collect();
    Line::from(spans).style(line_style)
}

fn render_item<'a>(
    app: &TuiApp,
    theme: &Theme,
    it: &SidebarItem,
    is_sel: bool,
    focused: bool,
) -> Line<'a> {
    match it {
        SidebarItem::Section(s) => {
            let expanded = app.sidebar.expanded.contains(s);
            let glyph = if expanded {
                EXPAND_GLYPH
            } else {
                COLLAPSE_GLYPH
            };
            let label = section_label(*s);
            let mut spans: Vec<Span> = vec![
                Span::styled(format!("{} ", glyph), theme.dim()),
                Span::styled(
                    label.to_string(),
                    Style::default()
                        .fg(theme.accent)
                        .add_modifier(Modifier::BOLD),
                ),
            ];
            // huddle 0.7.8: People section gets a two-part count when
            // there are pending requests: `(N known · M pending)`. Other
            // sections retain the single-number form.
            if let SidebarSection::People = s {
                let known = app.known_peers.len();
                let pending = app.pending_requests.len();
                if known > 0 || pending > 0 {
                    spans.push(Span::raw("  "));
                    spans.push(Span::styled(format!("({})", known), theme.dim()));
                    if pending > 0 {
                        spans.push(Span::raw(" "));
                        spans.push(Span::styled(
                            format!("📩 {}", pending),
                            theme.unread(),
                        ));
                    }
                }
            } else if let Some(n) = section_count(app, *s) {
                spans.push(Span::raw("  "));
                spans.push(Span::styled(format!("({})", n), theme.unread()));
            }
            let base = Style::default();
            let line = Line::from(spans).style(highlight(theme, focused, is_sel, base));
            apply_selection_fg(line, theme, focused, is_sel)
        }
        SidebarItem::Profile => {
            let our_fp = app.handle.fingerprint();
            let label = app
                .handle
                .display_name()
                .unwrap_or_else(|| "[anonymous]".into());
            let nat_glyph = match app.nat_status.as_deref() {
                Some("reachable") => "🌐",
                Some("private") => "🏠",
                _ => "🔍",
            };
            let line = Line::from(vec![
                Span::styled("  ".to_string(), theme.dim()),
                Span::styled(label, theme.text_style()),
                Span::raw("  "),
                Span::styled(short_fp(our_fp).to_uppercase(), theme.dim()),
                Span::raw("  "),
                Span::styled(nat_glyph.to_string(), theme.text_style()),
            ])
            .style(highlight(theme, focused, is_sel, Style::default()));
            apply_selection_fg(line, theme, focused, is_sel)
        }
        SidebarItem::Dm(room_id) => {
            let partner = app.handle.dm_partner_fingerprint(room_id);
            let label_str = partner
                .as_deref()
                .and_then(|fp| app.handle.lookup_username(fp))
                .unwrap_or_else(|| {
                    partner
                        .as_deref()
                        .map(short_fp)
                        .unwrap_or_else(|| "(pending)".into())
                });
            // Connection dot. huddle 0.7.11: pre-0.7.11 compared
            // `p.label` (the human-readable username) against `fp` (the
            // fingerprint), so every DM row showed ○ offline even when
            // the partner was connected. The correct field is
            // `p.fingerprint`, which Identify populates from the
            // remote peer's Ed25519 pubkey on first contact.
            let online = partner
                .as_deref()
                .map(|fp| {
                    app.known_peers.iter().any(|p| {
                        p.connected_peer_id.is_some()
                            && p.fingerprint.as_deref() == Some(fp)
                    })
                })
                .unwrap_or(false);
            let dot = if online { "●" } else { "○" };
            let mut spans = vec![
                Span::styled(format!("  {} ", dot), theme.text_style()),
                Span::styled(label_str, theme.text_style()),
            ];
            if let Some(n) = app.unread.get(room_id).copied() {
                if n > 0 {
                    spans.push(Span::raw("  "));
                    spans.push(Span::styled(format!("({})", n), theme.unread()));
                }
            }
            let line = Line::from(spans).style(highlight(theme, focused, is_sel, Style::default()));
            apply_selection_fg(line, theme, focused, is_sel)
        }
        SidebarItem::Group(room_id) => {
            let info = app.handle.active_room_info(room_id);
            let name = info
                .as_ref()
                .map(|r| r.name.clone())
                .or_else(|| {
                    app.handle
                        .discovered_rooms()
                        .into_iter()
                        .find(|d| d.room_id == *room_id)
                        .map(|d| d.name)
                })
                .unwrap_or_else(|| "(unknown)".into());
            let encrypted = info
                .as_ref()
                .map(|r| r.encrypted)
                .or_else(|| {
                    app.handle
                        .discovered_rooms()
                        .into_iter()
                        .find(|d| d.room_id == *room_id)
                        .map(|d| d.encrypted)
                })
                .unwrap_or(false);
            let members = app.handle.room_members(room_id).len();
            let mut spans = vec![
                Span::styled("  # ".to_string(), theme.dim()),
                Span::styled(name, theme.text_style()),
                Span::raw("  "),
                Span::styled(format!("({})", members), theme.dim()),
            ];
            if encrypted {
                spans.push(Span::raw("  "));
                spans.push(Span::styled("E", theme.enc()));
            }
            if let Some(n) = app.unread.get(room_id).copied() {
                if n > 0 {
                    spans.push(Span::raw("  "));
                    spans.push(Span::styled(format!("({})", n), theme.unread()));
                }
            }
            let line = Line::from(spans).style(highlight(theme, focused, is_sel, Style::default()));
            apply_selection_fg(line, theme, focused, is_sel)
        }
        SidebarItem::GroupDiscover => {
            let discovered = app
                .handle
                .discovered_rooms()
                .into_iter()
                .filter(|r| {
                    r.kind != RoomKind::Direct
                        && !app
                            .handle
                            .active_room_ids()
                            .iter()
                            .any(|aid| aid == &r.room_id)
                })
                .count();
            let line = Line::from(vec![Span::styled(
                format!("  + Discover ({})", discovered),
                theme.dim(),
            )])
            .style(highlight(theme, focused, is_sel, Style::default()));
            apply_selection_fg(line, theme, focused, is_sel)
        }
        SidebarItem::DirectAddFriend => {
            let line = Line::from(vec![
                Span::styled("  + ", theme.warn_style()),
                Span::styled("Add Friend", theme.text_style()),
                Span::raw("  "),
                Span::styled("m", theme.dim()),
            ])
            .style(highlight(theme, focused, is_sel, Style::default()));
            apply_selection_fg(line, theme, focused, is_sel)
        }
        SidebarItem::GroupNew => {
            let line = Line::from(vec![
                Span::styled("  + ", theme.warn_style()),
                Span::styled("New Group", theme.text_style()),
                Span::raw("  "),
                Span::styled("g", theme.dim()),
            ])
            .style(highlight(theme, focused, is_sel, Style::default()));
            apply_selection_fg(line, theme, focused, is_sel)
        }
        SidebarItem::PeoplePendingBadge => {
            let n = app.pending_requests.len();
            let label = if n == 1 {
                "1 friend request".to_string()
            } else {
                format!("{} friend requests", n)
            };
            let line = Line::from(vec![
                Span::styled("  📩 ", theme.warn_style()),
                Span::styled(label, theme.warn_style()),
            ])
            .style(highlight(theme, focused, is_sel, Style::default()));
            apply_selection_fg(line, theme, focused, is_sel)
        }
        SidebarItem::Person(addr) => {
            let p = app
                .known_peers
                .iter()
                .find(|p| p.address == *addr);
            let label = p
                .and_then(|p| p.label.clone())
                .unwrap_or_else(|| addr.to_string());
            let online = p.and_then(|p| p.connected_peer_id).is_some();
            let dot = if online { "●" } else { "○" };
            let line = Line::from(vec![
                Span::styled(format!("  {} ", dot), theme.text_style()),
                Span::styled(label, theme.text_style()),
            ])
            .style(highlight(theme, focused, is_sel, Style::default()));
            apply_selection_fg(line, theme, focused, is_sel)
        }
        SidebarItem::Activity => {
            let line = Line::from(vec![Span::styled("  status + transfers", theme.dim())])
                .style(highlight(theme, focused, is_sel, Style::default()));
            apply_selection_fg(line, theme, focused, is_sel)
        }
        SidebarItem::Settings => {
            let line = Line::from(vec![Span::styled("  toggles + go-dark", theme.dim())])
                .style(highlight(theme, focused, is_sel, Style::default()));
            apply_selection_fg(line, theme, focused, is_sel)
        }
    }
}

fn section_label(s: SidebarSection) -> &'static str {
    match s {
        SidebarSection::Profile => "Profile",
        SidebarSection::Direct => "Direct messages",
        SidebarSection::Group => "Group rooms",
        SidebarSection::People => "People",
        SidebarSection::Activity => "Activity",
        SidebarSection::Settings => "Settings",
    }
}

fn section_count(app: &TuiApp, s: SidebarSection) -> Option<u32> {
    match s {
        SidebarSection::Direct => {
            let dms = app
                .handle
                .discovered_rooms()
                .into_iter()
                .filter(|r| r.kind == RoomKind::Direct)
                .count();
            if dms == 0 {
                None
            } else {
                Some(dms as u32)
            }
        }
        SidebarSection::Group => {
            let groups = app
                .handle
                .discovered_rooms()
                .into_iter()
                .filter(|r| r.kind != RoomKind::Direct)
                .count();
            if groups == 0 {
                None
            } else {
                Some(groups as u32)
            }
        }
        SidebarSection::People => {
            let count = app.known_peers.len();
            let pending = app.pending_requests.len();
            // huddle 0.7.8: surface pending count even when no known
            // peers exist yet — that's the situation a first-time user
            // hits, and the pending count is the relevant signal.
            if count == 0 && pending == 0 {
                None
            } else if pending == 0 {
                Some(count as u32)
            } else {
                // section_count returns a single u32; the pending count
                // is rendered separately in render_item as a second
                // segment for clarity (see Section render path).
                Some((count + pending) as u32)
            }
        }
        _ => None,
    }
}

pub fn render_top_header(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme) {
    let parts = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(20), Constraint::Length(14)])
        .split(area);
    let title = Line::from(vec![
        Span::styled(
            format!("huddle {}", env!("CARGO_PKG_VERSION")),
            theme.accent_bold(),
        ),
        Span::raw("  ·  "),
        Span::styled(
            display_id(app.handle.fingerprint()),
            theme.dim(),
        ),
    ]);
    f.render_widget(Paragraph::new(title), parts[0]);
    let clock = Line::from(vec![Span::styled(current_hhmm(), theme.dim())]);
    f.render_widget(Paragraph::new(clock), parts[1]);
}

pub fn render_status_footer(f: &mut Frame, area: Rect, app: &TuiApp, theme: &Theme) {
    let hint_pairs = crate::keybindings::adaptive_hints(app);
    let mut spans: Vec<Span> = Vec::new();
    let mut first = true;
    for (key, label) in &hint_pairs {
        if !first {
            spans.push(Span::raw("  ·  "));
        }
        first = false;
        spans.push(Span::styled((*key).to_string(), theme.warn_style()));
        spans.push(Span::raw(" "));
        spans.push(Span::styled((*label).to_string(), theme.dim()));
    }
    if let Some(status) = app.current_status() {
        spans.push(Span::raw("  ·  "));
        spans.push(Span::styled(status, theme.text_style()));
    }
    let line = Paragraph::new(Line::from(spans));
    f.render_widget(line, area);
}

fn current_hhmm() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let h = ((secs / 3600) % 24) as u8;
    let m = ((secs / 60) % 60) as u8;
    format!("{:02}:{:02} UTC", h, m)
}

/// `Pane` <-> selection helpers — used by input handling to commit a
/// sidebar selection into a pane switch.
pub fn pane_for_item(item: &SidebarItem) -> Option<Pane> {
    match item {
        SidebarItem::Section(_) => None,
        SidebarItem::Profile => Some(Pane::Profile),
        SidebarItem::Dm(id) => Some(Pane::Dm(id.clone())),
        SidebarItem::Group(id) => Some(Pane::Group(id.clone())),
        SidebarItem::GroupDiscover => None,
        SidebarItem::Person(_) => Some(Pane::People),
        SidebarItem::Activity => Some(Pane::Activity),
        SidebarItem::Settings => Some(Pane::Settings),
        // huddle 0.7.8: action rows — cursor preview shouldn't switch
        // pane (you have to press Enter to commit).
        SidebarItem::DirectAddFriend => None,
        SidebarItem::GroupNew => None,
        SidebarItem::PeoplePendingBadge => Some(Pane::People),
    }
}
