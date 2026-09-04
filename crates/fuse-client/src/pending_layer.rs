//! The pending-request panel: a servatui-display layer fed by the
//! background poller.
//!
//! While access requests are pending, a multi-line panel floats top-right
//! of the terminal: one line per request (id + requesting process name,
//! falling back to `#pid`) with `[grant] [deny]` buttons, up to
//! [`MAX_SHOWN`] lines, and a `[deny all] [grant all]` row at the bottom.
//!
//! Layout is a button grid: [`MAX_SHOWN`] request rows plus the all-row,
//! each carrying two button children with their hit-test rects. The
//! cursor walks grid rows, skipping freed (empty) ones. A new pending
//! request raises the panel ([`StackIntent::Top`]) for one frame.
//!
//! All server I/O goes through [`ServerTalk`] so the render/event path
//! never blocks on the socket: production queues requests to a worker
//! thread ([`spawn_worker`]), tests run them inline ([`DirectTalk`]).

use std::path::{Path, PathBuf};
use std::time::Instant;

use crossterm::event::{Event, KeyCode, KeyEventKind, MouseEventKind};
use fuse_protocol::{
    poll_pending_info, poll_secret_names, run_command_once, Command, PendingAccessInfo, PendingIds,
    SecretNames,
};
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use servatui_display::{DisplayLayer, EventResult, LayerCtx, StackIntent};
use servyi_servatui::WidgetEntry;
use unicode_width::UnicodeWidthStr;

/// Widget-name of the panel rows (ownership/hit-testing key).
const PANEL_NAME: &str = "fuse.pending_panel";

/// How many request lines the panel shows at once.
const MAX_SHOWN: usize = 5;

/// Total panel width in terminal columns.
const PANEL_WIDTH: u16 = 42;

/// How often the panel polls the server for pending requests.
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

// ── Button interface ─────────────────────────────────────────────

/// One actionable button. Single buttons carry their request id; the
/// all-buttons expand over the pending snapshot at activation time —
/// both kinds implement the same interface, so activation, layout and
/// rendering are single code paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Button {
    Deny { id: u64 },
    Grant { id: u64 },
    DenyAll,
    GrantAll,
}

impl Button {
    /// Whether this button grants (green) or denies (red).
    fn is_grant(&self) -> bool {
        matches!(self, Button::Grant { .. } | Button::GrantAll)
    }

    /// The wire protocol this button speaks.
    fn protocol_name(&self) -> &'static str {
        if self.is_grant() {
            "grant"
        } else {
            "deny"
        }
    }

    /// The rendered label, brackets included.
    fn label(&self) -> &'static str {
        match self {
            Button::Deny { .. } => "[deny]",
            Button::Grant { .. } => "[grant]",
            Button::DenyAll => "[deny all]",
            Button::GrantAll => "[grant all]",
        }
    }

    /// The button's action color (brackets only; words stay normal).
    fn color(&self) -> Color {
        if self.is_grant() {
            Color::Green
        } else {
            Color::Red
        }
    }

    /// The wire commands this button triggers: single buttons map to one
    /// command; all-buttons expand to one per pending request.
    fn commands(&self, snapshot: &[PendingAccessInfo]) -> Vec<(String, Command)> {
        let one = |id: u64| {
            let command = if self.is_grant() {
                Command::Grant { id }
            } else {
                Command::Deny { id }
            };
            (self.protocol_name().to_string(), command)
        };
        match self {
            Button::Deny { id } | Button::Grant { id } => vec![one(*id)],
            Button::DenyAll | Button::GrantAll => {
                snapshot.iter().map(|p| one(p.id)).collect()
            }
        }
    }

    /// The button a cursor on `row` (a request slot index or the all-row)
    /// selects; `None` on a freed row.
    fn at_cursor(button_row: Option<&PendingAccessInfo>, all: bool, grant: bool) -> Option<Button> {
        match button_row {
            Some(req) if !all => Some(if grant {
                Button::Grant { id: req.id }
            } else {
                Button::Deny { id: req.id }
            }),
            None if all => Some(if grant {
                Button::GrantAll
            } else {
                Button::DenyAll
            }),
            _ => None,
        }
    }
}

// ── Slots + cursor model ─────────────────────────────────────────

/// The keyboard cursor: which request slot (or the all-row) and which of
/// its two buttons is selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cursor {
    Request { slot: usize, grant: bool },
    All { grant: bool },
}

/// A panel's slot assignment: `slots[i]` is the request shown on line
/// `i`, or `None` when that line is free.
pub(crate) type Slots = Vec<Option<PendingAccessInfo>>;

fn empty_slots() -> Slots {
    vec![None; MAX_SHOWN]
}

/// Reconcile the slot assignment with a fresh snapshot:
/// 1. a shown request that is gone frees its slot (others keep position);
/// 2. a shown request still pending refreshes its info in place;
/// 3. every unshown pending request claims the topmost free slot
///    (requests beyond [`MAX_SHOWN`] stay hidden).
pub(crate) fn sync_slots(slots: &mut Slots, incoming: &[PendingAccessInfo]) {
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
/// next request below (wrapping; itself when it is the only one), or
/// the all-row when none remain.
pub(crate) fn cursor_after_action(slots: &Slots, slot: usize) -> Cursor {
    let occ = occupied(slots);
    let next = occ
        .iter()
        .find(|&&i| i > slot)
        .copied()
        .or_else(|| occ.first().copied());
    match next {
        Some(i) => Cursor::Request { slot: i, grant: true },
        None => Cursor::All { grant: true },
    }
}

/// Move the cursor one line up (requests, then the all-row, wrapping;
/// freed slots are skipped).
pub(crate) fn cursor_up(slots: &Slots, cur: Cursor) -> Cursor {
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

/// Move the cursor one line down (requests, then the all-row, wrapping;
/// freed slots are skipped).
pub(crate) fn cursor_down(slots: &Slots, cur: Cursor) -> Cursor {
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

// ── Layout ────────────────────────────────────────────────────────

/// The panel's area: fixed width against the right terminal edge.
fn panel_rect(terminal: Rect) -> Rect {
    let w = PANEL_WIDTH.min(terminal.width);
    let h = (1 + MAX_SHOWN as u16 + 1).min(terminal.height);
    Rect::new(terminal.right().saturating_sub(w), terminal.y, w, h)
}

/// The area of request line `i` inside the panel.
fn row_rect(panel: Rect, i: usize) -> Rect {
    Rect {
        x: panel.x,
        y: panel.y + 1 + i as u16,
        width: panel.width,
        height: 1,
    }
}

/// The all-row area at the panel bottom.
fn all_row_rect(panel: Rect) -> Rect {
    Rect {
        x: panel.x,
        y: panel.y + 1 + MAX_SHOWN as u16,
        width: panel.width,
        height: 1,
    }
}

/// A row's two button children, right-aligned as a grant|deny pair
/// (grant on the left, deny on the right). Shared by request rows and
/// the all-row (only the labels differ).
fn button_pair(row: Rect, all: bool) -> (Rect, Rect) {
    let (deny_l, grant_l) = if all { ("[deny all]", "[grant all]") } else { ("[deny]", "[grant]") };
    let deny = Rect {
        x: row.x + row.width.saturating_sub(deny_l.len() as u16),
        y: row.y,
        width: deny_l.len() as u16,
        height: 1,
    };
    let grant = Rect {
        x: deny.x.saturating_sub(grant_l.len() as u16 + 1),
        y: row.y,
        width: grant_l.len() as u16,
        height: 1,
    };
    (deny, grant)
}

// ── Rendering ─────────────────────────────────────────────────────

/// The panel title: completely unstyled text — no modifiers, no
/// colors, no background override. It sits directly on the layer's
/// servatui-assigned backdrop like every other row.
fn title_line(shown: usize, total: usize) -> Line<'static> {
    Line::raw(format!(" pending requests: {shown}/{total} "))
}

/// Identifying text for the requesting process: its name, or `#pid`.
fn requester(req: &PendingAccessInfo) -> String {
    match &req.process_name {
        Some(name) => name.clone(),
        None => format!("#{}", req.pid),
    }
}

/// Clamp to exactly `max` DISPLAY columns (never slicing through a
/// multi-byte character), truncating with an ellipsis; non-ASCII names
/// are as wide as the terminal renders them, not as many bytes or chars
/// they contain.
fn truncate_pad(s: &str, max: usize) -> String {
    let total = s.width();
    if total <= max {
        let mut out = s.to_string();
        out.push_str(&" ".repeat(max - total));
        out
    } else {
        let keep = max.saturating_sub(1);
        let mut out = String::new();
        let mut width = 0;
        for ch in s.chars() {
            let ch_width = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
            if width + ch_width > keep {
                break;
            }
            out.push(ch);
            width += ch_width;
        }
        out.push('…');
        out.push_str(&" ".repeat(max - width - 1));
        out
    }
}

/// A button as colored brackets around plain text; the selected button
/// is reversed instead, so the cursor stays obvious.
fn button_spans(button: Button, selected: bool) -> Vec<Span<'static>> {
    if selected {
        return vec![Span::styled(
            button.label().to_string(),
            Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD),
        )];
    }
    let label = button.label();
    let word = &label[1..label.len() - 1];
    let brackets = Style::default().fg(button.color());
    vec![
        Span::styled("[", brackets),
        Span::raw(word.to_string()),
        Span::styled("]", brackets),
    ]
}

/// One grid row: a request line or the all-row (freed slots render as
/// blank filler directly, without buttons).
enum GridRow<'a> {
    Request(&'a PendingAccessInfo),
    All,
}

/// Render one grid row: content left, the grant|deny button pair right
/// (grant left, deny right). Request rows show `id name`; the all-row is
/// buttons only. The cursor selection reverses the highlighted button.
fn grid_row_line(row: GridRow, width: u16, cursor_here: bool, grant_selected: bool) -> Line<'static> {
    let all = matches!(row, GridRow::All);
    let (deny_l, grant_l) = if all { ("[deny all]", "[grant all]") } else { ("[deny]", "[grant]") };
    let buttons_w = deny_l.len() + 1 + grant_l.len();
    let mut spans: Vec<Span<'static>> = Vec::new();
    match row {
        GridRow::Request(req) => {
            spans.push(Span::styled(
                format!("{:>3} ", req.id),
                Style::default().add_modifier(Modifier::BOLD),
            ));
            let name_max = (width as usize).saturating_sub(4 + 1 + buttons_w);
            spans.push(Span::raw(format!("{} ", truncate_pad(&requester(req), name_max))));
        }
        GridRow::All => {}
    }
    let content_w: usize = spans.iter().map(|s| s.content.width()).sum();
    spans.push(Span::raw(" ".repeat(
        (width as usize).saturating_sub(content_w + buttons_w),
    )));
    let deny = if all { Button::DenyAll } else { Button::Deny { id: 0 } };
    let grant = if all { Button::GrantAll } else { Button::Grant { id: 0 } };
    spans.extend(button_spans(grant, cursor_here && grant_selected));
    spans.push(Span::raw(" "));
    spans.extend(button_spans(deny, cursor_here && !grant_selected));
    Line::from(spans)
}

// ── Server talk (non-blocking I/O) ────────────────────────────────

/// One request from the panel to the server side.
pub(crate) enum PanelRequest {
    Poll,
    Action { name: String, command: Command },
}

/// How the panel talks to the fuse server. Implementations must never
/// block the caller: the render/event path runs at frame rate, and a
/// wedged server must not freeze the TUI.
pub(crate) trait ServerTalk {
    fn request(&self, snapshot: &PendingIds, req: PanelRequest);
}

/// Service one request against the server, updating the shared
/// snapshots. Failures warn and leave the snapshots as-is — the next
/// poll reconciles.
fn service(socket: &Path, pending: &PendingIds, secrets: &SecretNames, req: PanelRequest) {
    match req {
        PanelRequest::Poll => {
            match poll_pending_info(socket) {
                Ok(list) => *pending.lock().unwrap() = list,
                Err(e) => tracing::warn!("pending poll failed: {e}"),
            }
            // The same tick refreshes the secret-name snapshot that
            // feeds reset/remove/rotate completion.
            match poll_secret_names(socket) {
                Ok(names) => *secrets.lock().unwrap() = names,
                Err(e) => tracing::warn!("secret-name poll failed: {e}"),
            }
        }
        PanelRequest::Action { name, command } => {
            if let Err(e) = run_command_once(socket, &name, &command) {
                tracing::warn!("pending action '{name}' failed: {e}");
            }
        }
    }
}

/// Blocking implementation (tests): services the request inline.
#[cfg(test)]
pub(crate) struct DirectTalk {
    socket: PathBuf,
    secrets: SecretNames,
}

#[cfg(test)]
impl DirectTalk {
    pub(crate) fn new(socket: impl Into<PathBuf>, secrets: SecretNames) -> Self {
        Self { socket: socket.into(), secrets }
    }
}

#[cfg(test)]
impl ServerTalk for DirectTalk {
    fn request(&self, snapshot: &PendingIds, req: PanelRequest) {
        service(&self.socket, snapshot, &self.secrets, req);
    }
}

/// Non-blocking implementation (production): queues requests to a worker
/// thread; sending never blocks (a gone worker drops the request).
pub(crate) struct WorkerTalk {
    tx: std::sync::mpsc::Sender<PanelRequest>,
}

/// Spawn the worker thread serving panel requests. Every action is
/// followed by a poll, so the snapshot reflects the outcome without
/// waiting for the next 1s tick.
pub(crate) fn spawn_worker(
    socket: PathBuf,
    snapshot: PendingIds,
    secrets: SecretNames,
) -> WorkerTalk {
    let (tx, rx) = std::sync::mpsc::channel::<PanelRequest>();
    std::thread::spawn(move || {
        for req in rx {
            let follow_up = matches!(req, PanelRequest::Action { .. });
            service(&socket, &snapshot, &secrets, req);
            if follow_up {
                service(&socket, &snapshot, &secrets, PanelRequest::Poll);
            }
        }
    });
    WorkerTalk { tx }
}

impl ServerTalk for WorkerTalk {
    fn request(&self, _snapshot: &PendingIds, req: PanelRequest) {
        let _ = self.tx.send(req);
    }
}

// ── The layer ─────────────────────────────────────────────────────

/// One laid-out button child of the grid.
#[derive(Debug, Clone, Copy)]
struct GridChild {
    /// The grid row (slot index; `MAX_SHOWN` = the all-row) it sits on.
    row: usize,
    button: Button,
    rect: Rect,
}

/// The button grid of the last frame: the row areas and their button
/// children (mouse hit-testing).
#[derive(Default)]
struct ButtonGrid {
    rows: Vec<Rect>,
    children: Vec<GridChild>,
}

impl ButtonGrid {
    fn clear(&mut self) {
        self.rows.clear();
        self.children.clear();
    }

    fn hit(&self, col: u16, row: u16) -> Option<GridChild> {
        self.children
            .iter()
            .copied()
            .find(|c| contains(&c.rect, col, row))
    }
}

/// The pending-request panel as a display layer.
pub(crate) struct PendingPanelLayer {
    pending: PendingIds,
    talk: Box<dyn ServerTalk>,
    slots: Slots,
    cursor: Cursor,
    grid: ButtonGrid,
    /// When the panel last requested a poll (rate-limited self-polling).
    last_poll: Option<Instant>,
    /// Request ids present in the last frame; a NEW id raises the panel.
    seen: std::collections::HashSet<u64>,
}

impl PendingPanelLayer {
    pub(crate) fn new(pending: PendingIds, talk: Box<dyn ServerTalk>) -> Self {
        Self {
            pending,
            talk,
            slots: empty_slots(),
            cursor: Cursor::All { grant: true },
            grid: ButtonGrid::default(),
            last_poll: None,
            seen: std::collections::HashSet::new(),
        }
    }

    /// Press a button: dispatch its commands through the (non-blocking)
    /// talk, then advance the cursor to the next request.
    fn press(&mut self, row: usize, button: Button) {
        let snapshot = self.pending.lock().unwrap().clone();
        for (name, command) in button.commands(&snapshot) {
            self.talk
                .request(&self.pending, PanelRequest::Action { name, command });
        }
        self.cursor = cursor_after_action(&self.slots, row);
    }
}

impl DisplayLayer for PendingPanelLayer {
    fn on_overlay(&mut self, ctx: &mut LayerCtx, widgets: &mut Vec<WidgetEntry>) -> StackIntent {
        // Self-polling: the panel owns the 1s poll cadence (the frame
        // loop ticks every ~100ms, so a fresh request appears within one
        // interval). The request itself never blocks the frame.
        let now = Instant::now();
        if self.last_poll.is_none_or(|t| now.duration_since(t) >= POLL_INTERVAL) {
            self.last_poll = Some(now);
            self.talk.request(&self.pending, PanelRequest::Poll);
        }

        // One lock scope drives the whole frame: slot sync, cursor
        // reconcile, new-request detection and the title count.
        let snapshot = self.pending.lock().unwrap().clone();
        sync_slots(&mut self.slots, &snapshot);
        if let Cursor::Request { slot, .. } = self.cursor {
            if self.slots.get(slot).is_none_or(|s| s.is_none()) {
                self.cursor = cursor_after_action(&self.slots, slot);
            }
        }
        // A NEW pending request (one not present in the last frame) raises
        // the panel above everything — requests are time-limited, so the
        // panel must be visible even if the user focused the builtin
        // input line. Disappeared ids leave `seen`, so a re-appearing id
        // (e.g. after a server restart) counts as new again.
        let has_new = snapshot.iter().any(|p| !self.seen.contains(&p.id));
        self.seen.retain(|id| snapshot.iter().any(|p| p.id == *id));
        self.seen.extend(snapshot.iter().map(|p| p.id));
        let intent = if has_new { StackIntent::Top } else { StackIntent::Keep };

        self.grid.clear();
        if !self.slots.iter().any(|s| s.is_some()) {
            return StackIntent::Keep;
        }

        let panel = panel_rect(ctx.terminal_area);
        widgets.push(WidgetEntry {
            name: PANEL_NAME,
            widget: Box::new(Paragraph::new(title_line(
                occupied(&self.slots).len(),
                snapshot.len(),
            ))),
            area: panel,
        });

        for i in 0..MAX_SHOWN {
            let row = row_rect(panel, i);
            self.grid.rows.push(row);
            let line = match &self.slots[i] {
                None => Line::raw(" ".repeat(row.width as usize)),
                Some(req) => {
                    let cursor_here = matches!(self.cursor, Cursor::Request { slot, .. } if slot == i);
                    let grant_sel = self.cursor == Cursor::Request { slot: i, grant: true };
                    let (deny, grant) = button_pair(row, false);
                    self.grid.children.push(GridChild {
                        row: i,
                        button: Button::Deny { id: req.id },
                        rect: deny,
                    });
                    self.grid.children.push(GridChild {
                        row: i,
                        button: Button::Grant { id: req.id },
                        rect: grant,
                    });
                    grid_row_line(GridRow::Request(req), row.width, cursor_here, grant_sel)
                }
            };
            widgets.push(WidgetEntry {
                name: PANEL_NAME,
                widget: Box::new(Paragraph::new(line)),
                area: row,
            });
        }

        let all_row = all_row_rect(panel);
        self.grid.rows.push(all_row);
        let cursor_here = matches!(self.cursor, Cursor::All { .. });
        let grant_sel = self.cursor == Cursor::All { grant: true };
        let (deny, grant) = button_pair(all_row, true);
        self.grid.children.push(GridChild { row: MAX_SHOWN, button: Button::DenyAll, rect: deny });
        self.grid.children.push(GridChild { row: MAX_SHOWN, button: Button::GrantAll, rect: grant });
        widgets.push(WidgetEntry {
            name: PANEL_NAME,
            widget: Box::new(Paragraph::new(grid_row_line(
                GridRow::All,
                all_row.width,
                cursor_here,
                grant_sel,
            ))),
            area: all_row,
        });

        intent
    }

    fn on_event(&mut self, ev: &Event, _ctx: &LayerCtx) -> EventResult {
        match ev {
            Event::Mouse(m) => match m.kind {
                MouseEventKind::Down(_) => {
                    if let Some(child) = self.grid.hit(m.column, m.row) {
                        self.press(child.row, child.button);
                        return EventResult::Swallow;
                    }
                    // Presses on panel rows (not the log underneath):
                    if self.grid.rows.iter().any(|area| contains(area, m.column, m.row)) {
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
                        // Spatial: Left selects the left button (grant),
                        // Right the right one (deny).
                        let grant = matches!(k.code, KeyCode::Left);
                        self.cursor = match self.cursor {
                            Cursor::Request { slot, .. } => Cursor::Request { slot, grant },
                            Cursor::All { .. } => Cursor::All { grant },
                        };
                        EventResult::Swallow
                    }
                    KeyCode::Enter => {
                        let button = match self.cursor {
                            Cursor::Request { slot, grant } => {
                                Button::at_cursor(self.slots.get(slot).and_then(|s| s.as_ref()), false, grant)
                            }
                            Cursor::All { grant } => Button::at_cursor(None, true, grant),
                        };
                        if let Some(button) = button {
                            let row = match self.cursor {
                                Cursor::Request { slot, .. } => slot,
                                Cursor::All { .. } => MAX_SHOWN,
                            };
                            self.press(row, button);
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

    /// No taskbar cell (and nothing clickable) while idle — the panel
    /// owns no widgets then; the slot stays reserved for its return.
    fn hide_when_empty(&self) -> bool {
        true
    }
}

fn contains(area: &Rect, col: u16, row: u16) -> bool {
    col >= area.x && col < area.x + area.width && row >= area.y && row < area.y + area.height
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;
    use fuse_protocol::pending_info;
    use std::sync::{Arc, Mutex};
    use std::path::Path;
    use std::time::{Duration, Instant};

    fn ids(list: &[u64]) -> Vec<PendingAccessInfo> {
        list.iter().map(|&id| pending_info(id)).collect()
    }

    fn layer(pending: PendingIds, sock: &Path) -> PendingPanelLayer {
        let secrets: SecretNames = Arc::new(Mutex::new(Vec::new()));
        PendingPanelLayer::new(pending, Box::new(DirectTalk::new(sock, secrets)))
    }

    fn key(code: KeyCode) -> Event {
        Event::Key(crossterm::event::KeyEvent::from(code))
    }

    fn click(x: u16, y: u16) -> Event {
        Event::Mouse(crossterm::event::MouseEvent {
            kind: MouseEventKind::Down(crossterm::event::MouseButton::Left),
            column: x,
            row: y,
            modifiers: KeyModifiers::NONE,
        })
    }

    fn frame_with_pending(display: &mut servatui_display::Display) {
        let mut widgets = vec![WidgetEntry {
            name: servyi_servatui::WIDGET_INPUT,
            widget: Box::new(Paragraph::new("")),
            area: Rect::new(0, 23, 80, 1),
        }];
        display.frame(&mut widgets);
    }

    // ── slots + cursor ────────────────────────────────────────────

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
        sync_slots(&mut slots, &ids(&[]));
        assert_eq!(cursor_after_action(&slots, 1), Cursor::All { grant: true });
    }

    #[test]
    fn cursor_stays_on_request_when_new_ones_appear_above() {
        let mut slots = empty_slots();
        sync_slots(&mut slots, &ids(&[5, 6]));
        let cursor = Cursor::Request { slot: 1, grant: true }; // on request 6
        sync_slots(&mut slots, &ids(&[4, 5, 6]));
        // 4 took the topmost FREE slot (2): positions of 5 and 6 are
        // unchanged, so the cursor still points at request 6.
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

    // ── rendering contracts ───────────────────────────────────────

    /// The title carries no styling at all: no fg/bg, no modifiers —
    /// plain text on the layer backdrop, like the body rows.
    #[test]
    fn title_is_completely_unstyled() {
        let line = title_line(5, 6);
        for span in &line.spans {
            assert!(span.style.fg.is_none(), "no fg: {:?}", span.style);
            assert!(span.style.bg.is_none(), "no bg: {:?}", span.style);
            assert!(span.style.add_modifier.is_empty(), "no modifiers: {:?}", span.style);
        }
    }

    /// Style contract: no span overrides the background — the layer's
    /// servatui-assigned color backdrop shows through untouched. Words
    /// carry no color; only the brackets (and the reversed selection) do.
    #[test]
    fn rows_keep_the_layer_backdrop() {
        for &grant_sel in &[false, true] {
            for line in [
                grid_row_line(GridRow::Request(&pending_info(31)), PANEL_WIDTH, true, grant_sel),
                grid_row_line(GridRow::All, PANEL_WIDTH, true, grant_sel),
            ] {
                for span in &line.spans {
                    assert!(
                        span.style.bg.is_none(),
                        "span {:?} must not override the layer backdrop",
                        span.content
                    );
                }
            }
        }
        let line = grid_row_line(GridRow::Request(&pending_info(31)), PANEL_WIDTH, false, false);
        let colors: Vec<Option<Color>> = line.spans.iter().map(|s| s.style.fg).collect();
        assert!(colors.contains(&Some(Color::Red),), "deny brackets red: {colors:?}");
        assert!(colors.contains(&Some(Color::Green)), "grant brackets green: {colors:?}");
        assert!(
            colors.iter().filter(|c| c.is_none()).count() >= 2,
            "id/name/words stay uncolored: {colors:?}"
        );
    }

    /// The id span carries no foreground color — normal text like the
    /// rest of the row (black on dark themes is invisible).
    #[test]
    fn request_line_id_is_uncolored() {
        let line = grid_row_line(GridRow::Request(&pending_info(31)), PANEL_WIDTH, false, false);
        let id_span = &line.spans[0];
        assert!(id_span.style.fg.is_none(), "id must be normal-colored: {:?}", id_span.style);
        assert_eq!(id_span.content.trim(), "31", "first span is the id");
    }

    /// Non-ASCII process names must not panic (byte-slicing on a char
    /// boundary) and must respect DISPLAY width, not char count.
    #[test]
    fn truncate_pad_is_char_safe_and_width_aware() {
        use unicode_width::UnicodeWidthStr;
        // Multibyte: 3 columns wide, 2 chars.
        assert_eq!(truncate_pad("日本", 6), "日本  ");
        // Truncation cuts by display width and pads to exactly `max`.
        let out = truncate_pad("日本語テキスト", 6);
        assert_eq!(out.width(), 6, "must be exactly max columns: {out:?}");
        assert!(out.starts_with("日本") && out.contains('…'), "truncated with an ellipsis: {out:?}");
        // ASCII behavior unchanged.
        assert_eq!(truncate_pad("goose", 8), "goose   ");
        assert_eq!(truncate_pad("abcdefg", 4), "abc…");
        assert_eq!(truncate_pad("", 3), "   ");
    }

    #[test]
    fn button_rects_sit_inside_their_rows() {
        let row = Rect::new(38, 1, 42, 1);
        let (deny, grant) = button_pair(row, false);
        // Grant on the LEFT, deny on the RIGHT.
        assert_eq!((deny.x, deny.width), (38 + 42 - 6, 6), "\"[deny]\" is 6 cells");
        assert_eq!((grant.x, grant.width), (deny.x - 8, 7), "\"[grant]\" is 7 cells, left of deny");
        assert_eq!(deny.y, row.y);
        let (deny, grant) = button_pair(row, true);
        assert_eq!((deny.x, deny.width), (38 + 42 - 10, 10));
        assert_eq!((grant.x, grant.width), (deny.x - 12, 11));
    }

    /// All-buttons expand over the snapshot; single buttons carry their
    /// own id — one interface, no unreachable paths.
    #[test]
    fn button_commands_expand_all_over_snapshot() {
        let snapshot = ids(&[31, 37]);
        assert_eq!(
            Button::Grant { id: 31 }.commands(&snapshot),
            vec![("grant".to_string(), Command::Grant { id: 31 })]
        );
        let all = Button::DenyAll.commands(&snapshot);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0], ("deny".to_string(), Command::Deny { id: 31 }));
        assert_eq!(all[1], ("deny".to_string(), Command::Deny { id: 37 }));
    }

    // ── frames ────────────────────────────────────────────────────

    /// One frame with pending requests renders title, per-request lines
    /// and the all-row, and registers the button children.
    #[test]
    fn frame_renders_panel_and_registers_buttons() {
        let pending: PendingIds = Arc::new(Mutex::new(ids(&[31, 37])));
        let mut display = servatui_display::Display::with_palette(Vec::new());
        display.add_layer(Box::new(layer(pending, Path::new("/nonexistent.sock"))));

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

    /// While idle the layer contributes nothing — it hides itself (no
    /// panel widgets, no taskbar cell) until a request exists again.
    #[test]
    fn frame_without_pending_pushes_no_panel() {
        let pending: PendingIds = Arc::new(Mutex::new(Vec::new()));
        let mut display = servatui_display::Display::with_palette(Vec::new());
        display.add_layer(Box::new(layer(pending, Path::new("/nonexistent.sock"))));
        for _ in 0..2 {
            let mut widgets = vec![WidgetEntry {
                name: servyi_servatui::WIDGET_INPUT,
                widget: Box::new(Paragraph::new("")),
                area: Rect::new(0, 23, 80, 1),
            }];
            display.frame(&mut widgets);
            assert_eq!(
                widgets.iter().filter(|w| w.name == PANEL_NAME).count(),
                0,
                "no panel widgets while idle"
            );
            assert_eq!(
                widgets.iter().filter(|w| w.name == "display.taskbar").count(),
                1,
                "hide_when_empty: only the builtin taskbar cell while idle"
            );
        }
    }

    /// The panel polls on its own inside on_overlay, rate-limited to one
    /// poll per POLL_INTERVAL: three frames in quick succession trigger
    /// exactly one `pending` query on the wire.
    #[test]
    fn self_polling_is_rate_limited() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("rate.sock");
        let seen = fake_server(&sock, vec![31]);

        let pending: PendingIds = Arc::new(Mutex::new(Vec::new()));
        let mut display = servatui_display::Display::with_palette(Vec::new());
        display.add_layer(Box::new(layer(pending.clone(), &sock)));
        frame_with_pending(&mut display);
        assert_eq!(
            pending.lock().unwrap().iter().map(|p| p.id).collect::<Vec<_>>(),
            vec![31],
            "the first frame polls and fills the snapshot"
        );
        frame_with_pending(&mut display);
        frame_with_pending(&mut display);
        let polls = seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(name, _)| name == "pending")
            .count();
        assert_eq!(polls, 1, "frames within one interval poll at most once");
    }

    /// A NEW pending request raises the panel above everything (it is
    /// time-limited and must be visible even when the user focused the
    /// builtin input line); already-seen requests never steal the focus.
    #[test]
    fn new_request_raises_panel_to_top() {
        let pending: PendingIds = Arc::new(Mutex::new(ids(&[31])));
        let mut display = servatui_display::Display::with_palette(Vec::new());
        let panel = display
            .add_layer(Box::new(layer(pending.clone(), Path::new("/nonexistent.sock"))));
        frame_with_pending(&mut display);
        assert_eq!(display.topmost(), Some(panel));

        // User focuses the builtin input line: the panel sinks below.
        display.activate(servatui_display::LayerId::BUILTIN);
        assert_eq!(display.topmost(), Some(servatui_display::LayerId::BUILTIN));

        // Same request set (already seen): the panel stays below.
        frame_with_pending(&mut display);
        assert_eq!(
            display.topmost(),
            Some(servatui_display::LayerId::BUILTIN),
            "seen requests must not steal the focus"
        );

        // A NEW request arrives: the panel raises itself.
        *pending.lock().unwrap() = ids(&[31, 77]);
        frame_with_pending(&mut display);
        assert_eq!(display.topmost(), Some(panel), "a new request raises the panel");

        // And stays up on subsequent frames without further Top intent.
        frame_with_pending(&mut display);
        assert_eq!(display.topmost(), Some(panel));
    }

    // ── wire-level interactions ───────────────────────────────────

    /// A fake server speaking the real wire protocol: records every
    /// conversation and answers `pending` with the given ids.
    fn fake_server(
        sock: &Path,
        answer: Vec<u64>,
    ) -> Arc<Mutex<Vec<(String, String)>>> {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::os::unix::net::UnixListener::bind(sock).unwrap();
        let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
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

    fn wait_until(deadline_ms: u128, cond: impl Fn() -> bool) -> bool {
        let start = Instant::now();
        while start.elapsed().as_millis() < deadline_ms {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        cond()
    }

    /// Pressing Enter grants the cursor-selected request over the wire
    /// and the direct talk refreshes the snapshot inline.
    #[test]
    fn enter_grants_selected_request() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("panel.sock");
        let seen = fake_server(&sock, vec![31, 37]);

        let pending: PendingIds = Arc::new(Mutex::new(ids(&[31, 37])));
        let mut display = servatui_display::Display::with_palette(Vec::new());
        display.add_layer(Box::new(layer(pending.clone(), &sock)));
        frame_with_pending(&mut display);

        // Cursor starts on the all-row; Down reaches request 31's grant.
        assert!(display.route_event(&key(KeyCode::Down)), "panel has focus: swallowed");
        assert!(display.route_event(&key(KeyCode::Enter)), "Enter swallowed");

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
        let mut display = servatui_display::Display::with_palette(Vec::new());
        display.add_layer(Box::new(layer(pending, &sock)));
        frame_with_pending(&mut display);

        // Request 37 sits in slot 1; its deny button is at a computable
        // position (pure layout fns — no layer internals).
        let row = row_rect(panel_rect(Rect::new(0, 0, 80, 24)), 1);
        let (deny, _) = button_pair(row, false);
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
        let mut display = servatui_display::Display::with_palette(Vec::new());
        display.add_layer(Box::new(layer(pending, &sock)));
        frame_with_pending(&mut display);

        // Cursor starts on the all-row's grant (left) button; Right
        // selects deny.
        assert!(display.route_event(&key(KeyCode::Right)), "Right swallowed");
        assert!(display.route_event(&key(KeyCode::Enter)), "Enter swallowed");

        let conversations = seen.lock().unwrap().clone();
        let denies = conversations.iter().filter(|(name, _)| name == "deny").count();
        assert_eq!(denies, 2, "both requests denied: {conversations:?}");
    }

    /// The production talk never blocks the frame: a poll request to a
    /// worker that never services it still renders instantly.
    #[test]
    fn worker_talk_never_blocks_the_frame() {
        let (tx, rx) = std::sync::mpsc::channel::<PanelRequest>();
        let talk = WorkerTalk { tx };
        let pending: PendingIds = Arc::new(Mutex::new(ids(&[31])));
        let mut layer = PendingPanelLayer::new(pending, Box::new(talk));

        let mut ctx = servatui_display::LayerCtx {
            id: servatui_display::LayerId::BUILTIN,
            color: Color::Reset,
            terminal_area: Rect::new(0, 0, 80, 24),
            my_widgets: &[],
        };
        let mut widgets = Vec::new();
        let start = Instant::now();
        // First frame: poll is due (blocking implementations would hit
        // the socket here).
        layer.on_overlay(&mut ctx, &mut widgets);
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "on_overlay must not wait on the server"
        );
        drop(rx);
    }

    /// The worker thread services actions and follows each with a poll,
    /// updating the shared snapshot asynchronously.
    #[test]
    fn worker_talk_services_actions_and_polls() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("worker.sock");
        let seen = fake_server(&sock, vec![31]);

        let pending: PendingIds = Arc::new(Mutex::new(Vec::new()));
        let secrets: SecretNames = Arc::new(Mutex::new(Vec::new()));
        let talk = spawn_worker(sock.clone(), pending.clone(), secrets.clone());
        talk.request(
            &pending,
            PanelRequest::Action {
                name: "grant".into(),
                command: Command::Grant { id: 31 },
            },
        );
        assert!(
            wait_until(5_000, || {
                seen.lock()
                    .unwrap()
                    .iter()
                    .any(|(name, payload)| name == "grant" && payload.contains("\"id\":31"))
            }),
            "the worker must execute the granted action"
        );
        assert!(
            wait_until(5_000, || !pending.lock().unwrap().is_empty()),
            "the follow-up poll must fill the snapshot"
        );
    }
}
