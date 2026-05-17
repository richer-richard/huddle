//! huddle 0.7: outer layout primitives.
//!
//! Single source of truth for the top-level split: header (1 row),
//! sidebar (responsive 28-36 cols) + pane (rest), status footer (1 row).
//! All panes render into the pane rect; the sidebar widget renders into
//! the sidebar rect. The header and status footer wrap around them.

use ratatui::layout::{Constraint, Direction, Layout, Rect};

const SIDEBAR_MIN: u16 = 28;
const SIDEBAR_MAX: u16 = 36;
const HEADER_ROWS: u16 = 1;
const STATUS_ROWS: u16 = 1;

#[derive(Debug, Clone, Copy)]
pub struct OuterRects {
    pub header: Rect,
    pub sidebar: Rect,
    pub pane: Rect,
    pub status: Rect,
}

/// Split the terminal into the four named rects. Sidebar grows to 36 cols
/// on wide terminals and contracts to 28 on narrow ones; below that, the
/// sidebar takes 40% of the width as a floor so the layout doesn't
/// degenerate.
pub fn outer_split(area: Rect) -> OuterRects {
    // Vertical: header + body + status.
    let vparts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(HEADER_ROWS),
            Constraint::Min(3),
            Constraint::Length(STATUS_ROWS),
        ])
        .split(area);

    let body = vparts[1];
    let sidebar_w = if body.width >= 110 {
        SIDEBAR_MAX
    } else if body.width >= 80 {
        SIDEBAR_MIN
    } else {
        (body.width * 4 / 10).max(20)
    };

    // huddle 0.7.3: 2-col gutter between sidebar's right border and
    // pane content. Panes with `Borders::NONE` (Welcome, Profile) were
    // rendering text flush against the sidebar separator line, which
    // looked cramped. Bordered panes (Settings, People, Activity, chat)
    // get the same gutter — it just becomes blank space between two
    // borders, which is fine.
    let hparts = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(sidebar_w),
            Constraint::Length(2),
            Constraint::Min(0),
        ])
        .split(body);

    OuterRects {
        header: vparts[0],
        sidebar: hparts[0],
        pane: hparts[2],
        status: vparts[2],
    }
}
