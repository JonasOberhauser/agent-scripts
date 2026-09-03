//! The pending-request panel: a servatui-display layer fed by the
//! background poller.
//!
//! While access requests are pending, a multi-line panel floats top-right
//! of the terminal: one line per request (id + requesting process name,
//! falling back to `#pid`) with `[deny] [grant]` buttons, up to
//! [`MAX_SHOWN`] lines, and a `[deny all] [grant all]` row at the bottom.
//!
//! Keyboard: the display only offers keys to layers when the builtin
//! (log/input) layer is NOT topmost — i.e. exactly when this panel is
//! the focused window. Up/Down move between request lines and the
//! all-row, Left/Right toggle a line's deny/grant button, Enter presses
//! the selected button. Mouse clicks on buttons work regardless.
//!
//! Slot model: each shown request owns one of [`MAX_SHOWN`] fixed slots.
//! A handled (or expired) request frees its slot; everyone else keeps
//! their position; an unshown request claims the topmost free slot. The
//! cursor is slot-based, so requests appearing above never shift it.
//! After handling a request the cursor advances to the next one.

use std::path::PathBuf;

use crossterm::event::{Event, KeyCode, KeyEventKind, MouseEventKind};
use fuse_protocol::{
    poll_pending_info, run_command_once, Command, PendingAccessInfo, PendingIds,
};
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use servatui_display::{DisplayLayer, EventResult, LayerCtx, StackIntent};
use servyi_servatui::WidgetEntry;

/// Widget-name prefix of the panel rows (ownership/hit-testing key).
pub const PANEL_NAME: &str = "fuse.pending_panel";

/// How many request lines the panel shows at once.
pub const MAX_SHOWN: usize = 5;

/// Total panel width in terminal columns.
pub const PANEL_WIDTH: u16 = 42;

/// One button: per-request deny/grant, or the all-row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Button {
    Deny { id: u64 },
    Grant { id: u64 },
    DenyAll,
    GrantAll,
}

impl Button {
    /// The wire command this button triggers.
    pub fn command(&self) -> Command {
        match *self {
            Button::Deny { id } => Command::Deny { id },
            Button::Grant { id } => Command::Grant { id },
            // All-buttons expand to one command per pending request at
            // activation time (see `PendingPanelLayer::activate`).
            Button::DenyAll | Button::GrantAll => {
                unreachable!("expanded before reaching the wire")
            }
        }
    }

    fn protocol_name(&self) -> &'static str {
        match self {
            Button::Deny { .. } | Button::DenyAll => "deny",
            Button::Grant { .. } | Button::GrantAll => "grant",
        }
    }
}

/// The keyboard cursor: which request slot (or the all-row) and which of
/// its two buttons is selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cursor {
    Request { slot: usize, grant: bool },
    All { grant: bool },
}

/// A panel's slot assignment: `slots[i]` is the request shown on line
/// `i`, or `None` when that line is free.
pub type Slots = Vec<Option<PendingAccessInfo>>;

pub fn empty_slots() -> Slots {
    vec![None; MAX_SHOWN]
}

/// Reconcile the slot assignment with a fresh snapshot:
/// 1. a shown request that is gone frees its slot (others keep position);
/// 2. a shown request still pending refreshes its info in place;
/// 3. every unshown pending request claims the topmost free slot
///    (requests beyond [`MAX_SHOWN`] stay hidden).
pub fn sync_slots(slots: &mut Slots, incoming: &[PendingAccessInfo]) {
    let present = |id| incoming.iter().any(|p| p.id == id);
    for slot in slots.iter_mut() {
        if let Some(req) = slot {
            if !present(req.id) {
                *slot = None;
            } else if let Some(fresh) = incoming.iter().find(|p| p.id == req.id) {
                *req = fresh.clone();
            }
        }
    }
    for req in incoming {
        let shown = slots.iter().any(|s| s.as_ref().is_some_and(|r| r.id == req.id));
        if !shown {
            if let Some(free) = slots.iter_mut().find(|s| s.is_none()) {
                *free = Some(req.clone());
            }
        }
    }
}

/// Slot indices holding a request, bottom-to-top.
fn occupied(slots: &Slots) -> Vec<usize> {
    (0..slots.len()).filter(|&i| slots[i].is_some()).collect()
}

/// Where the cursor goes after the request in `slot` was handled: the
/// next request below (wrapping), or the all-row when it was the last.
pub fn cursor_after_action(slots: &Slots, slot: usize) -> Cursor {
    let occ = occupied(slots);
    let next = occ.iter().find(|&&i| i > slot).copied().or_else(|| occ.first().copied());
    match next {
        Some(i) => Cursor::Request { slot: i, grant: true },
        None => Cursor::All { grant: true },
    }
}

/// Move the cursor one line up (requests, then the all-row, wrapping).
pub fn cursor_up(slots: &Slots, cur: Cursor) -> Cursor {
    let occ = occupied(slots);
    if occ.is_empty() {
        return Cursor::All { grant: cur_is_grant(cur) };
    }
    match cur {
        Cursor::Request { slot, grant } => {
            let idx = occ.iter().position(|&i| i == slot);
            match idx {
                Some(0) => Cursor::All { grant },
                Some(i) => Cursor::Request { slot: occ[i - 1], grant },
                None => Cursor::Request { slot: occ[0], grant },
            }
        }
        Cursor::All { grant } => Cursor::Request { slot: *occ.last().unwrap(), grant },
    }
}

/// Move the cursor one line down (requests, then the all-row, wrapping).
pub fn cursor_down(slots: &Slots, cur: Cursor) -> Cursor {
    let occ = occupied(slots);
    if occ.is_empty() {
        return Cursor::All { grant: cur_is_grant(cur) };
    }
    match cur {
        Cursor::Request { slot, grant } => {
            let idx = occ.iter().position(|&i| i == slot);
            match idx {
                Some(i) if i + 1 < occ.len() => Cursor::Request { slot: occ[i + 1], grant },
                Some(_) => Cursor::All { grant },
                None => Cursor::Request { slot: occ[0], grant },
            }
        }
        Cursor::All { grant } => Cursor::Request { slot: occ[0], grant },
    }
}

fn cur_is_grant(cur: Cursor) -> bool {
    match cur {
        Cursor::Request { grant, .. } | Cursor::All { grant } => grant,
    }
}

/// The panel's area: fixed width against the right terminal edge.
pub fn panel_rect(terminal: Rect) -> Rect {
    let w = PANEL_WIDTH.min(terminal.width);
    let h = (1 + MAX_SHOWN as u16 + 1).min(terminal.height);
    Rect::new(terminal.right().saturating_sub(w), terminal.y, w, h)
}

/// The area of request line `i` inside the panel.
pub fn row_rect(panel: Rect, i: usize) -> Rect {
    Rect {
        x: panel.x,
        y: panel.y + 1 + i as u16,
        width: panel.width,
        height: 1,
    }
}

/// The all-row area at the panel bottom.
pub fn all_row_rect(panel: Rect) -> Rect {
    Rect {
        x: panel.x,
        y: panel.y + 1 + MAX_SHOWN as u16,
        width: panel.width,
        height: 1,
    }
}

const DENY_BTN: &str = "[deny]";
const GRANT_BTN: &str = "[grant]";
const DENY_ALL_BTN: &str = "[deny all]";
const GRANT_ALL_BTN: &str = "[grant all]";
const BTN_GAP: u16 = 1;

/// A button's area inside its line: right-aligned deny|grant pair.
pub fn request_button_rect(row: Rect, grant: bool) -> Rect {
    let grant_x = row.x + row.width.saturating_sub(GRANT_BTN.len() as u16);
    let deny_x = grant_x.saturating_sub(DENY_BTN.len() as u16 + BTN_GAP);
    let (x, w) = if grant {
        (grant_x, GRANT_BTN.len() as u16)
    } else {
        (deny_x, DENY_BTN.len() as u16)
    };
    Rect { x, y: row.y, width: w, height: 1 }
}

/// The all-row buttons: right-aligned deny-all|grant-all pair.
pub fn all_button_rect(row: Rect, grant: bool) -> Rect {
    let grant_x = row.x + row.width.saturating_sub(GRANT_ALL_BTN.len() as u16);
    let deny_x = grant_x.saturating_sub(DENY_ALL_BTN.len() as u16 + BTN_GAP);
    let (x, w) = if grant {
        (grant_x, GRANT_ALL_BTN.len() as u16)
    } else {
        (deny_x, DENY_ALL_BTN.len() as u16)
    };
    Rect { x, y: row.y, width: w, height: 1 }
}

/// Identifying text for the requesting process: its name, or `#pid`.
pub fn requester(req: &PendingAccessInfo) -> String {
    match &req.process_name {
        Some(name) => name.clone(),
        None => format!("#{}", req.pid),
    }
}

/// The pending-request panel as a display layer.
pub struct PendingPanelLayer {
    pending: PendingIds,
    socket: PathBuf,
    slots: Slots,
    cursor: Cursor,
    /// Buttons as laid out in the last frame (mouse hit-testing).
    buttons: Vec<(Button, Rect)>,
    /// Panel rows as laid out in the last frame.
    rows: Vec<Rect>,
}

impl PendingPanelLayer {
    pub fn new(pending: PendingIds, socket: impl Into<PathBuf>) -> Self {
        Self {
            pending,
            socket: socket.into(),
            slots: empty_slots(),
            cursor: Cursor::All { grant: true },
            buttons: Vec::new(),
            rows: Vec::new(),
        }
    }

    fn refresh_from_snapshot(&mut self) {
        let snapshot = self.pending.lock().unwrap().clone();
        sync_slots(&mut self.slots, &snapshot);
        // If the request under the cursor vanished (handled via another
        // path, expired, ...), move to the next remaining one.
        if let Cursor::Request { slot, .. } = self.cursor {
            if self.slots.get(slot).is_none_or(|s| s.is_none()) {
                self.cursor = cursor_after_action(&self.slots, slot);
            }
        }
    }

    /// Execute a button's action, then re-poll immediately so the panel
    /// reflects the outcome without waiting for the 1s poller tick.
    /// Failures are ignored — the next poll reconciles.
    fn activate(&mut self, button: Button) {
        let snapshot = self.pending.lock().unwrap().clone();
        let commands: Vec<Command> = match button {
            Button::DenyAll | Button::GrantAll => snapshot
                .iter()
                .map(|p| button_to_command(&button, p.id))
                .collect(),
            single => vec![single.command()],
        };
        for cmd in commands {
            let name = button.protocol_name();
            let _ = run_command_once(&self.socket, name, &cmd);
        }
        if let Ok(list) = poll_pending_info(&self.socket) {
            *self.pending.lock().unwrap() = list;
        }
        self.refresh_from_snapshot();
    }
}

fn button_to_command(button: &Button, id: u64) -> Command {
    match button {
        Button::Deny { .. } | Button::DenyAll => Command::Deny { id },
        Button::Grant { .. } | Button::GrantAll => Command::Grant { id },
    }
}

impl DisplayLayer for PendingPanelLayer {
    fn on_overlay(&mut self, ctx: &mut LayerCtx, widgets: &mut Vec<WidgetEntry>) -> StackIntent {
        self.refresh_from_snapshot();
        self.buttons.clear();
        self.rows.clear();
        if !self.slots.iter().any(|s| s.is_some()) {
            return StackIntent::Keep;
        }

        let panel = panel_rect(ctx.terminal_area);
        let total = self.pending.lock().unwrap().len();
        let title = format!(" pending requests: {}/{} ", occupied(&self.slots).len(), total);
        widgets.push(WidgetEntry {
            name: PANEL_NAME,
            widget: Box::new(Paragraph::new(Line::styled(
                title,
                Style::default().fg(Color::Black).bg(ctx.color).add_modifier(Modifier::BOLD),
            ))),
            area: panel,
        });

        for i in 0..MAX_SHOWN {
            let row = row_rect(panel, i);
            self.rows.push(row);
            let line = match &self.slots[i] {
                None => Line::styled(
                    " ".repeat(row.width as usize),
                    Style::default().bg(ctx.color),
                ),
                Some(req) => {
                    let cur_here = self.cursor == Cursor::Request { slot: i, grant: true }
                        || self.cursor == Cursor::Request { slot: i, grant: false };
                    let grant_sel = self.cursor == Cursor::Request { slot: i, grant: true };
                    let deny = request_button_rect(row, false);
                    let grant = request_button_rect(row, true);
                    self.buttons.push((Button::Deny { id: req.id }, deny));
                    self.buttons.push((Button::Grant { id: req.id }, grant));
                    request_line(req, row.width, cur_here, grant_sel, ctx.color)
                }
            };
            widgets.push(WidgetEntry {
                name: PANEL_NAME,
                widget: Box::new(Paragraph::new(line)),
                area: row,
            });
        }

        let all_row = all_row_rect(panel);
        self.rows.push(all_row);
        let grant_sel = self.cursor == Cursor::All { grant: true };
        let deny = all_button_rect(all_row, false);
        let grant = all_button_rect(all_row, true);
        self.buttons.push((Button::DenyAll, deny));
        self.buttons.push((Button::GrantAll, grant));
        widgets.push(WidgetEntry {
            name: PANEL_NAME,
            widget: Box::new(Paragraph::new(all_row_line(
                all_row.width,
                self.cursor == Cursor::All { grant: true } || self.cursor == Cursor::All { grant: false },
                grant_sel,
                ctx.color,
            ))),
            area: all_row,
        });

        StackIntent::Keep
    }

    fn on_event(&mut self, ev: &Event, _ctx: &LayerCtx) -> EventResult {
        match ev {
            Event::Mouse(m) => match m.kind {
                MouseEventKind::Down(_) => {
                    if let Some((button, _)) = self
                        .buttons
                        .iter()
                        .find(|(_, area)| contains(area, m.column, m.row))
                        .copied()
                    {
                        let next = match button {
                            Button::Deny { id } | Button::Grant { id } => {
                                let slot = self
                                    .slots
                                    .iter()
                                    .position(|s| s.as_ref().is_some_and(|r| r.id == id));
                                self.activate(button);
                                slot.map(|slot| cursor_after_action(&self.slots, slot))
                                    .unwrap_or(self.cursor)
                            }
                            _ => {
                                self.activate(button);
                                self.cursor
                            }
                        };
                        self.cursor = next;
                        return EventResult::Swallow;
                    }
                    // Presses on panel rows (not the log underneath):
                    if self.rows.iter().any(|area| contains(area, m.column, m.row)) {
                        return EventResult::Swallow;
                    }
                    EventResult::Pass
                }
                MouseEventKind::Drag(_) | MouseEventKind::Up(_) => EventResult::Swallow,
                _ => EventResult::Pass,
            },
            Event::Key(k) if k.kind == KeyEventKind::Press => {
                if !self.slots.iter().any(|s| s.is_some()) {
                    return EventResult::Pass;
                }
                match k.code {
                    KeyCode::Up => {
                        self.cursor = cursor_up(&self.slots, self.cursor);
                        EventResult::Swallow
                    }
                    KeyCode::Down => {
                        self.cursor = cursor_down(&self.slots, self.cursor);
                        EventResult::Swallow
                    }
                    KeyCode::Left | KeyCode::Right => {
                        let grant = matches!(k.code, KeyCode::Right);
                        self.cursor = match self.cursor {
                            Cursor::Request { slot, .. } => Cursor::Request { slot, grant },
                            Cursor::All { .. } => Cursor::All { grant },
                        };
                        EventResult::Swallow
                    }
                    KeyCode::Enter => {
                        let button = match self.cursor {
                            Cursor::Request { slot, grant } => self.slots[slot]
                                .as_ref()
                                .map(|r| {
                                    if grant {
                                        Button::Grant { id: r.id }
                                    } else {
                                        Button::Deny { id: r.id }
                                    }
                                }),
                            Cursor::All { grant } => Some(if grant {
                                Button::GrantAll
                            } else {
                                Button::DenyAll
                            }),
                        };
                        if let Some(button) = button {
                            let slot = match self.cursor {
                                Cursor::Request { slot, .. } => Some(slot),
                                Cursor::All { .. } => None,
                            };
                            self.activate(button);
                            if let Some(slot) = slot {
                                self.cursor = cursor_after_action(&self.slots, slot);
                            }
                        }
                        EventResult::Swallow
                    }
                    _ => EventResult::Pass,
                }
            }
            _ => EventResult::Pass,
        }
    }

    fn tab_label(&self) -> char {
        'p'
    }
}

fn contains(area: &Rect, col: u16, row: u16) -> bool {
    col >= area.x && col < area.x + area.width && row >= area.y && row < area.y + area.height
}

/// One request line: `id name ... [deny] [grant]`, buttons highlighted
/// when the cursor is on this row/button.
fn request_line(
    req: &PendingAccessInfo,
    width: u16,
    cursor_here: bool,
    grant_selected: bool,
    color: Color,
) -> Line<'static> {
    let base = Style::default().bg(color).fg(Color::White);
    let id = Span::styled(format!("{:>3} ", req.id), base.add_modifier(Modifier::BOLD));
    let name_max = (width as usize).saturating_sub(
        3 + 1 + DENY_BTN.len() + BTN_GAP as usize + GRANT_BTN.len() + 1,
    );
    let name = truncate_pad(&requester(req), name_max);
    let name = Span::styled(format!("{name} "), base);

    let (deny_style, grant_style) = if cursor_here {
        let sel = base
            .fg(Color::Black)
            .add_modifier(Modifier::BOLD | Modifier::REVERSED);
        let unsel = base.fg(Color::Black);
        if grant_selected {
            (unsel, sel)
        } else {
            (sel, unsel)
        }
    } else {
        (base.fg(Color::Red), base.fg(Color::Green))
    };
    Line::from(vec![
        id,
        name,
        Span::styled(format!("{DENY_BTN} "), deny_style),
        Span::styled(GRANT_BTN, grant_style),
    ])
}

/// The all-row: `[deny all] [grant all]` right-aligned.
fn all_row_line(width: u16, cursor_here: bool, grant_selected: bool, color: Color) -> Line<'static> {
    let base = Style::default().bg(color).fg(Color::White);
    let (deny_style, grant_style) = if cursor_here {
        let sel = base
            .fg(Color::Black)
            .add_modifier(Modifier::BOLD | Modifier::REVERSED);
        let unsel = base.fg(Color::Black);
        if grant_selected {
            (unsel, sel)
        } else {
            (sel, unsel)
        }
    } else {
        (base.fg(Color::Red), base.fg(Color::Green))
    };
    let pad = (width as usize).saturating_sub(DENY_ALL_BTN.len() + 1 + GRANT_ALL_BTN.len());
    Line::from(vec![
        Span::styled(" ".repeat(pad), base),
        Span::styled(format!("{DENY_ALL_BTN} "), deny_style),
        Span::styled(GRANT_ALL_BTN, grant_style),
    ])
}

/// Clamp to `max` columns, padded to exactly `max`.
fn truncate_pad(s: &str, max: usize) -> String {
    if s.len() >= max {
        format!("{}…", &s[..max.saturating_sub(1)])
    } else {
        format!("{s:<max$}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuse_protocol::pending_info;
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    fn ids(list: &[u64]) -> Vec<PendingAccessInfo> {
        list.iter().map(|&id| pending_info(id)).collect()
    }

    #[test]
    fn slots_fill_top_down_and_overflow_hides() {
        let mut slots = empty_slots();
        sync_slots(&mut slots, &ids(&[1, 2, 3, 4, 5, 6]));
        let shown: Vec<Option<u64>> =
            slots.iter().map(|s| s.as_ref().map(|r| r.id)).collect();
        assert_eq!(
            shown,
            vec![Some(1), Some(2), Some(3), Some(4), Some(5)],
            "six requests: the sixth stays hidden"
        );
    }

    #[test]
    fn freed_slot_keeps_position_and_new_takes_topmost_free() {
        let mut slots = empty_slots();
        sync_slots(&mut slots, &ids(&[1, 2, 3]));
        // Request 2 handled: its slot frees, 1 and 3 keep their lines.
        sync_slots(&mut slots, &ids(&[1, 3]));
        let shown: Vec<Option<u64>> =
            slots.iter().map(|s| s.as_ref().map(|r| r.id)).collect();
        assert_eq!(shown, vec![Some(1), None, Some(3), None, None]);
        // New request 9: takes the TOPMOST free slot (index 1), not the
        // bottom-most.
        sync_slots(&mut slots, &ids(&[1, 3, 9]));
        let shown: Vec<Option<u64>> =
            slots.iter().map(|s| s.as_ref().map(|r| r.id)).collect();
        assert_eq!(shown, vec![Some(1), Some(9), Some(3), None, None]);
    }

    #[test]
    fn cursor_advances_to_next_and_wraps_to_all() {
        let mut slots = empty_slots();
        sync_slots(&mut slots, &ids(&[1, 2, 3]));
        assert_eq!(cursor_after_action(&slots, 0), Cursor::Request { slot: 1, grant: true });
        // Acting on the last request wraps cyclically to the first.
        assert_eq!(cursor_after_action(&slots, 2), Cursor::Request { slot: 0, grant: true });
        // Only request 2 left (slot 1): handling it wraps to itself.
        sync_slots(&mut slots, &ids(&[2]));
        assert_eq!(cursor_after_action(&slots, 1), Cursor::Request { slot: 1, grant: true });
        // None left: the all-row.
        sync_slots(&mut slots, &[]);
        assert_eq!(cursor_after_action(&slots, 1), Cursor::All { grant: true });
    }

    #[test]
    fn cursor_stays_on_request_when_new_ones_appear_above() {
        let mut slots = empty_slots();
        sync_slots(&mut slots, &ids(&[5, 6]));
        let cursor = Cursor::Request { slot: 1, grant: true }; // on request 6
        sync_slots(&mut slots, &ids(&[4, 5, 6]));
        // 4 took the topmost FREE slot (2) — above nothing: positions of
        // 5 and 6 are unchanged, so the cursor still points at request 6.
        let shown: Vec<Option<u64>> =
            slots.iter().map(|s| s.as_ref().map(|r| r.id)).collect();
        assert_eq!(shown, vec![Some(5), Some(6), Some(4), None, None]);
        assert_eq!(cursor_up(&slots, cursor), Cursor::Request { slot: 0, grant: true });
    }

    #[test]
    fn up_down_walk_rows_and_all() {
        // Build [1, None, 3]: the freed middle slot must be skipped.
        let mut slots = empty_slots();
        sync_slots(&mut slots, &ids(&[1, 2, 3]));
        sync_slots(&mut slots, &ids(&[1, 3]));
        let c = Cursor::Request { slot: 0, grant: true };
        let c = cursor_down(&slots, c);
        assert_eq!(c, Cursor::Request { slot: 2, grant: true }, "empty slot 1 is skipped");
        let c = cursor_down(&slots, c);
        assert_eq!(c, Cursor::All { grant: true });
        let c = cursor_down(&slots, c);
        assert_eq!(c, Cursor::Request { slot: 0, grant: true }, "wraps to the top");
        assert_eq!(
            cursor_up(&slots, c),
            Cursor::All { grant: true },
            "up from the top wraps to the all-row"
        );
    }

    #[test]
    fn requester_prefers_name_over_pid() {
        let mut req = pending_info(7);
        assert_eq!(requester(&req), "#7");
        req.process_name = Some("goose".into());
        assert_eq!(requester(&req), "goose");
    }

    #[test]
    fn button_rects_sit_inside_their_rows() {
        let row = Rect::new(38, 1, 42, 1);
        let deny = request_button_rect(row, false);
        let grant = request_button_rect(row, true);
        assert_eq!((grant.x, grant.width), (38 + 42 - 7, 7), "\"[grant]\" is 7 cells");
        assert_eq!((deny.x, deny.width), (grant.x - 7, 6), "\"[deny]\" is 6 cells");
        assert_eq!(deny.y, row.y);
    }

    /// One frame with pending requests renders title, per-request lines
    /// and the all-row, and registers the buttons for hit-testing.
    #[test]
    fn frame_renders_panel_and_registers_buttons() {
        let pending: PendingIds = Arc::new(Mutex::new(ids(&[31, 37])));
        let mut display = servatui_display::Display::with_palette(vec![Color::Blue]);
        display.add_layer(Box::new(PendingPanelLayer::new(
            pending,
            "/nonexistent.sock",
        )));

        let mut widgets = vec![WidgetEntry {
            name: servyi_servatui::WIDGET_INPUT,
            widget: Box::new(Paragraph::new("")),
            area: Rect::new(0, 23, 80, 1),
        }];
        display.frame(&mut widgets);

        assert_eq!(
            widgets.iter().filter(|w| w.name == PANEL_NAME).count(),
            1 + MAX_SHOWN + 1,
            "title + request lines + all-row"
        );
    }

    /// A fake server speaking the real wire protocol: records every
    /// conversation and answers `pending` with the given ids.
    fn fake_server(
        sock: &Path,
        answer: Vec<u64>,
    ) -> std::sync::Arc<Mutex<Vec<(String, String)>>> {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::os::unix::net::UnixListener::bind(sock).unwrap();
        let seen: std::sync::Arc<Mutex<Vec<(String, String)>>> =
            std::sync::Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(stream) = conn else { break };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut w = stream;
                let mut name = String::new();
                if reader.read_line(&mut name).unwrap() == 0 {
                    continue;
                }
                let name = serde_json::from_str::<String>(name.trim()).unwrap();
                let mut payload = String::new();
                reader.read_line(&mut payload).unwrap();
                seen2.lock().unwrap().push((name.clone(), payload.trim().to_string()));
                let resp = if name == "grant" || name == "deny" {
                    serde_json::json!({"type": "ok"})
                } else {
                    serde_json::json!({
                        "type": "pending_list",
                        "pending": answer
                            .iter()
                            .map(|&id| serde_json::json!({
                                "id": id, "secret_name": "s", "process_name": "goose",
                                "pid": id, "pid_hash": null, "reason": "r",
                                "expires_at": 9999999999u64,
                            }))
                            .collect::<Vec<_>>(),
                    })
                };
                writeln!(w, "{}", resp).unwrap();
                let mut sentinel = String::new();
                reader.read_line(&mut sentinel).unwrap();
            }
        });
        seen
    }

    fn terminal80() -> Rect {
        Rect::new(0, 0, 80, 24)
    }

    fn frame_with_pending(
        display: &mut servatui_display::Display,
    ) {
        let mut widgets = vec![WidgetEntry {
            name: servyi_servatui::WIDGET_INPUT,
            widget: Box::new(Paragraph::new("")),
            area: Rect::new(0, 23, 80, 1),
        }];
        display.frame(&mut widgets);
    }

    fn key(code: KeyCode) -> Event {
        Event::Key(crossterm::event::KeyEvent::from(code))
    }

    fn click(x: u16, y: u16) -> Event {
        Event::Mouse(crossterm::event::MouseEvent {
            kind: MouseEventKind::Down(crossterm::event::MouseButton::Left),
            column: x,
            row: y,
            modifiers: crossterm::event::KeyModifiers::NONE,
        })
    }

    /// Pressing Enter grants the cursor-selected request over the wire
    /// and refreshes the snapshot from the server's answer.
    #[test]
    fn enter_grants_selected_request() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("panel.sock");
        let seen = fake_server(&sock, vec![31, 37]);

        let pending: PendingIds = Arc::new(Mutex::new(ids(&[31, 37])));
        let mut display = servatui_display::Display::with_palette(vec![Color::Blue]);
        display.add_layer(Box::new(PendingPanelLayer::new(pending.clone(), &sock)));
        frame_with_pending(&mut display);

        // Cursor starts on the all-row; Down reaches request 31's grant.
        let _ = display.route_event(&key(KeyCode::Down));
        let _ = display.route_event(&key(KeyCode::Enter));

        let conversations = seen.lock().unwrap().clone();
        assert!(
            conversations
                .iter()
                .any(|(name, payload)| name == "grant" && payload.contains("\"id\":31")),
            "grant for request 31 must hit the wire: {conversations:?}"
        );
        assert_eq!(
            pending.lock().unwrap().iter().map(|p| p.id).collect::<Vec<_>>(),
            vec![31, 37],
            "snapshot refreshed from the server's answer"
        );
    }

    /// Clicking a [deny] button denies exactly that request.
    #[test]
    fn click_denies_that_request() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("panel2.sock");
        let seen = fake_server(&sock, vec![31, 37]);

        let pending: PendingIds = Arc::new(Mutex::new(ids(&[31, 37])));
        let mut display = servatui_display::Display::with_palette(vec![Color::Blue]);
        display.add_layer(Box::new(PendingPanelLayer::new(pending, &sock)));
        frame_with_pending(&mut display);

        // Request 37 sits in slot 1; its deny button is at a computable
        // position (pure layout fns — no layer internals).
        let row = row_rect(panel_rect(terminal80()), 1);
        let deny = request_button_rect(row, false);
        assert!(
            display.route_event(&click(deny.x, deny.y)),
            "click on the button is swallowed"
        );

        let conversations = seen.lock().unwrap().clone();
        assert!(
            conversations
                .iter()
                .any(|(name, payload)| name == "deny" && payload.contains("\"id\":37")),
            "deny for request 37 must hit the wire: {conversations:?}"
        );
    }

    /// Enter on the all-row denies every pending request.
    #[test]
    fn enter_on_all_row_denies_all() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("panel3.sock");
        let seen = fake_server(&sock, vec![31, 37]);

        let pending: PendingIds = Arc::new(Mutex::new(ids(&[31, 37])));
        let mut display = servatui_display::Display::with_palette(vec![Color::Blue]);
        display.add_layer(Box::new(PendingPanelLayer::new(pending, &sock)));
        frame_with_pending(&mut display);

        // Cursor starts on the all-row's grant button; Left selects deny.
        let _ = display.route_event(&key(KeyCode::Left));
        let _ = display.route_event(&key(KeyCode::Enter));

        let conversations = seen.lock().unwrap().clone();
        let denies = conversations
            .iter()
            .filter(|(name, _)| name == "deny")
            .count();
        assert_eq!(denies, 2, "both requests denied: {conversations:?}");
    }
}
