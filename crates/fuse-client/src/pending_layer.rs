//! The pending-request badge: a servatui-display layer fed by the
//! background poller.
//!
//! When access requests are pending, a badge floats on the top terminal
//! row listing their IDs (`grant`/`deny` complete them). Mouse presses
//! on the badge are swallowed by the layer so clicks don't select or
//! drag the log underneath; drags started on the badge stay grabbed
//! until release. The wheel passes through — scrolling the log from
//! anywhere keeps working. Activation (Shift+Tab, taskbar click, badge
//! click) comes from the display layer system.

use crossterm::event::{Event, MouseEventKind};
use fuse_protocol::PendingIds;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::Paragraph;
use servatui_display::{DisplayLayer, EventResult, LayerCtx, StackIntent};
use servyi_servatui::WidgetEntry;

/// Widget name of the badge (ownership/hit-testing key of the display).
pub const BADGE_NAME: &str = "fuse.pending_badge";

/// How many IDs the badge lists before switching to "+N more".
const MAX_IDS_SHOWN: usize = 3;

/// Badge text for the given pending IDs; `None` when nothing is pending.
pub fn badge_text(ids: &[u64]) -> Option<String> {
    if ids.is_empty() {
        return None;
    }
    let head: Vec<String> = ids.iter().take(MAX_IDS_SHOWN).map(|i| i.to_string()).collect();
    let more = ids.len().saturating_sub(MAX_IDS_SHOWN);
    let list = if more > 0 {
        format!("{} +{more} more", head.join(", "))
    } else {
        head.join(", ")
    };
    Some(format!(" pending: {list} (grant/deny id) "))
}

/// The badge's area: one row on top of the terminal, right-aligned and
/// clamped to the terminal width.
pub fn badge_rect(text_len: usize, area: Rect) -> Rect {
    let width = (text_len as u16).min(area.width);
    Rect::new(area.right().saturating_sub(width), area.y, width, 1)
}

/// A display layer showing the pending-request badge.
pub struct PendingBadgeLayer {
    pending: PendingIds,
    /// A press started on the badge: swallow the whole drag through Up.
    pressed: bool,
}

impl PendingBadgeLayer {
    pub fn new(pending: PendingIds) -> Self {
        Self { pending, pressed: false }
    }
}

impl DisplayLayer for PendingBadgeLayer {
    fn on_overlay(&mut self, ctx: &mut LayerCtx, widgets: &mut Vec<WidgetEntry>) -> StackIntent {
        let ids = self.pending.lock().unwrap().clone();
        let Some(text) = badge_text(&ids) else { return StackIntent::Keep };
        // Pending access requests are time-limited: the badge must stay
        // visible, never occluded by other layers' backdrops.
        let area = badge_rect(text.chars().count(), ctx.terminal_area);
        widgets.push(WidgetEntry {
            name: BADGE_NAME,
            widget: Box::new(Paragraph::new(Span::styled(
                text,
                Style::default()
                    .fg(Color::Black)
                    .bg(ctx.color)
                    .add_modifier(Modifier::BOLD),
            ))),
            area,
        });
        StackIntent::Top
    }

    fn on_event(&mut self, ev: &Event, ctx: &LayerCtx) -> EventResult {
        let Event::Mouse(m) = ev else { return EventResult::Pass };
        match m.kind {
            MouseEventKind::Down(_) => {
                if ctx.hit_test(m.column, m.row) {
                    self.pressed = true;
                    EventResult::Swallow
                } else {
                    EventResult::Pass
                }
            }
            MouseEventKind::Drag(_) => {
                if self.pressed {
                    EventResult::Swallow
                } else {
                    EventResult::Pass
                }
            }
            MouseEventKind::Up(_) => {
                if self.pressed {
                    self.pressed = false;
                    EventResult::Swallow
                } else {
                    EventResult::Pass
                }
            }
            _ => EventResult::Pass,
        }
    }

    fn tab_label(&self) -> char {
        'p'
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent};
    use ratatui::widgets::Paragraph;
    use servatui_display::Display;
    use servyi_servatui::WIDGET_INPUT;
    use std::sync::{Arc, Mutex};

    fn mouse(kind: MouseEventKind, col: u16, row: u16) -> Event {
        Event::Mouse(MouseEvent { kind, column: col, row, modifiers: KeyModifiers::NONE })
    }
    /// The layer demands the top of the stack only while requests are
    /// pending; idle it keeps its position (no attention stealing).
    #[test]
    fn intent_top_only_while_pending() {
        use servatui_display::LayerId;
        let pending: PendingIds = Arc::new(Mutex::new(vec![31]));
        let mut layer = PendingBadgeLayer::new(pending.clone());
        let mut ctx = LayerCtx {
            id: LayerId::BUILTIN,
            color: Color::Blue,
            terminal_area: Rect::new(0, 0, 80, 24),
            my_widgets: &[],
        };
        let mut widgets = Vec::new();
        assert_eq!(layer.on_overlay(&mut ctx, &mut widgets), StackIntent::Top);
        assert_eq!(widgets.len(), 1, "badge pushed while pending");

        *pending.lock().unwrap() = vec![];
        widgets.clear();
        assert_eq!(layer.on_overlay(&mut ctx, &mut widgets), StackIntent::Keep);
        assert!(widgets.is_empty(), "no badge while idle");
    }

    #[test]
    fn badge_text_lists_and_truncates_ids() {
        assert_eq!(badge_text(&[]), None);
        assert_eq!(
            badge_text(&[31, 37]).unwrap(),
            " pending: 31, 37 (grant/deny id) "
        );
        assert_eq!(
            badge_text(&[1, 2, 3, 4, 5]).unwrap(),
            " pending: 1, 2, 3 +2 more (grant/deny id) "
        );
    }

    #[test]
    fn badge_rect_right_aligns_and_clamps() {
        let term = Rect::new(0, 0, 80, 24);
        let r = badge_rect(30, term);
        assert_eq!((r.x, r.y, r.width, r.height), (50, 0, 30, 1));
        // Longer than the terminal: clamp to full width at x = 0.
        let r = badge_rect(100, term);
        assert_eq!((r.x, r.width), (0, 80));
    }

    /// One frame with a live pending snapshot: the badge floats top-right
    /// of the terminal area derived from the builtin input widget, and
    /// the taskbar gains the layer's cell.
    #[test]
    fn frame_shows_badge_for_pending_ids() {
        let pending: PendingIds = Arc::new(Mutex::new(vec![31, 37]));
        let mut display = Display::with_palette(vec![Color::Blue]);
        let id = display.add_layer(Box::new(PendingBadgeLayer::new(pending)));

        let mut widgets = vec![WidgetEntry {
            name: WIDGET_INPUT,
            widget: Box::new(Paragraph::new("")),
            area: Rect::new(0, 23, 80, 1),
        }];
        display.frame(&mut widgets);

        let text = badge_text(&[31, 37]).unwrap();
        let want = badge_rect(text.chars().count(), Rect::new(0, 0, 80, 24));
        let badge = widgets
            .iter()
            .find(|w| w.name == BADGE_NAME)
            .expect("badge must be pushed when ids are pending");
        assert_eq!(badge.area, want, "badge floats top-right of the terminal");
        assert_eq!(display.owner_of(BADGE_NAME), Some(id));
        assert!(
            widgets.iter().any(|w| w.name == "display.taskbar"),
            "the taskbar strip must be appended"
        );
    }

    #[test]
    fn frame_without_pending_pushes_no_badge() {
        let pending: PendingIds = Arc::new(Mutex::new(vec![]));
        let mut display = Display::with_palette(vec![Color::Blue]);
        display.add_layer(Box::new(PendingBadgeLayer::new(pending)));

        let mut widgets = vec![WidgetEntry {
            name: WIDGET_INPUT,
            widget: Box::new(Paragraph::new("")),
            area: Rect::new(0, 23, 80, 1),
        }];
        display.frame(&mut widgets);

        assert!(
            !widgets.iter().any(|w| w.name == BADGE_NAME),
            "no badge when nothing is pending"
        );
    }

    /// Clicks on the badge are swallowed (and activate the layer); clicks
    /// elsewhere fall through to servatui's builtin handling.
    #[test]
    fn badge_clicks_swallow_and_activate() {
        let pending: PendingIds = Arc::new(Mutex::new(vec![31]));
        let mut display = Display::with_palette(vec![Color::Blue]);
        let id = display.add_layer(Box::new(PendingBadgeLayer::new(pending)));

        let mut widgets = vec![WidgetEntry {
            name: WIDGET_INPUT,
            widget: Box::new(Paragraph::new("")),
            area: Rect::new(0, 23, 80, 1),
        }];
        display.frame(&mut widgets);
        let badge = widgets
            .iter()
            .find(|w| w.name == BADGE_NAME)
            .unwrap()
            .area;

        let on_badge = mouse(MouseEventKind::Down(MouseButton::Left), badge.x + 2, badge.y);
        assert!(display.route_event(&on_badge), "badge press must be swallowed");
        assert_eq!(display.topmost(), Some(id), "badge press activates the layer");

        let off_badge = mouse(MouseEventKind::Down(MouseButton::Left), 5, 12);
        assert!(
            !display.route_event(&off_badge),
            "presses outside the badge fall through to the builtin handling"
        );
    }

    /// A press on the badge grabs the whole drag (even off-badge) until
    /// Up, so the log underneath never starts a selection mid-click.
    #[test]
    fn badge_drag_stays_grabbed_until_release() {
        let pending: PendingIds = Arc::new(Mutex::new(vec![31]));
        let mut display = Display::with_palette(vec![Color::Blue]);
        display.add_layer(Box::new(PendingBadgeLayer::new(pending)));

        let mut widgets = vec![WidgetEntry {
            name: WIDGET_INPUT,
            widget: Box::new(Paragraph::new("")),
            area: Rect::new(0, 23, 80, 1),
        }];
        display.frame(&mut widgets);
        let badge = widgets.iter().find(|w| w.name == BADGE_NAME).unwrap().area;

        assert!(display.route_event(&mouse(MouseEventKind::Down(MouseButton::Left), badge.x, badge.y)));
        assert!(
            display.route_event(&mouse(MouseEventKind::Drag(MouseButton::Left), 10, 12)),
            "drag away from the badge stays swallowed while pressed"
        );
        assert!(
            display.route_event(&mouse(MouseEventKind::Up(MouseButton::Left), 10, 12)),
            "release ends the grab and is swallowed"
        );
        assert!(
            !display.route_event(&mouse(MouseEventKind::Drag(MouseButton::Left), 10, 12)),
            "after release, stray drags fall through"
        );
    }
}
