//! An in-canvas terminal: a `vt100` screen model fed by the relay's WebSocket,
//! rendered as a character grid with egui, with keyboard input translated back
//! into terminal byte sequences. Keeps history; the wheel or a touch drag scrolls.

use egui::{Color32, FontId, Key};
use ewebsock::{WsEvent, WsMessage, WsReceiver, WsSender};

/// Lines of history kept for scrolling back.
const SCROLLBACK: usize = 5000;
const FONT_SIZE: f32 = 13.0;
const KEY_BAR_BUTTON: f32 = 44.0;
const KEY_BAR_GAP: f32 = 6.0;
pub const KEY_BAR_HEIGHT: f32 = KEY_BAR_BUTTON + KEY_BAR_GAP + 4.0;

pub struct Terminal {
    parser: vt100::Parser,
    pub rows: u16,
    pub cols: u16,
    /// Fraction of a line scrolled but not yet applied to the view.
    scroll_rem: f32,
    /// `ctx.input(time)` when the session opened; the app shows its age.
    pub opened_at: Option<f64>,
    tx: WsSender,
    rx: WsReceiver,
    /// Active text selection as (anchor, head) cells, each `(row, col)`.
    /// Unnormalized; normalize with [`norm`] before use.
    sel: Option<((u16, u16), (u16, u16))>,
    /// Touch key bar: the next typed character goes out as Ctrl+character.
    ctrl_armed: bool,
    pub status: String,
    pub open: bool,
    pub closed: bool,
}

/// The grid that fits in `area`, for the size a session opens with: what the
/// shell prints first is wrapped to it, before any resize could reach the agent.
pub fn grid_for(ctx: &egui::Context, area: egui::Vec2) -> (u16, u16) {
    let font = FontId::monospace(FONT_SIZE);
    let (cw, rh) = ctx.fonts(|f| (f.glyph_width(&font, 'M').max(1.0), f.row_height(&font).max(1.0)));
    (((area.x / cw).floor() as u16).clamp(20, 400), ((area.y / rh).floor() as u16).clamp(5, 200))
}

impl Terminal {
    /// Dial `wss://<host>/ws/term?...`. `base_ws` is the relay's ws origin.
    pub fn connect(
        base_ws: &str,
        agent: &str,
        shell: Option<&str>,
        ctx: &egui::Context,
        (cols, rows): (u16, u16),
    ) -> Result<Self, String> {
        let mut url = format!(
            "{base_ws}/ws/term?agent={}&cols={cols}&rows={rows}",
            urlencode(agent)
        );
        if let Some(s) = shell {
            url.push_str(&format!("&shell={}", urlencode(s)));
        }

        let ctx = ctx.clone();
        let (tx, rx) = ewebsock::connect_with_wakeup(
            url,
            ewebsock::Options::default(),
            move || ctx.request_repaint(),
        )
        .map_err(|e| e.to_string())?;

        Ok(Self {
            parser: vt100::Parser::new(rows, cols, SCROLLBACK),
            rows,
            cols,
            scroll_rem: 0.0,
            opened_at: None,
            tx,
            rx,
            sel: None,
            ctrl_armed: false,
            status: "connecting…".to_string(),
            open: false,
            closed: false,
        })
    }

    /// Lines the view is scrolled back from the live screen.
    pub fn scrolled_back(&self) -> usize {
        self.parser.screen().scrollback()
    }

    /// Drain socket events into the screen model. Runs every frame, shown or not,
    /// so output arriving while another tab is open is not left queued.
    pub fn pump(&mut self, now: f64) {
        while let Some(ev) = self.rx.try_recv() {
            match ev {
                WsEvent::Opened => {
                    self.open = true;
                    self.opened_at = Some(now);
                    self.status = "connected".to_string();
                    // The view has usually been resized by now, and the agent
                    // only knows the size from the connect URL.
                    self.send_size();
                }
                WsEvent::Message(WsMessage::Binary(b)) => self.parser.process(&b),
                WsEvent::Message(WsMessage::Text(t)) => self.parser.process(t.as_bytes()),
                WsEvent::Message(_) => {}
                WsEvent::Error(e) => {
                    self.status = format!("error: {e}");
                    self.closed = true;
                }
                WsEvent::Closed => {
                    self.status = "session closed".to_string();
                    self.closed = true;
                }
            }
        }
    }

    fn send_bytes(&mut self, bytes: &[u8]) {
        if self.open && !self.closed {
            self.tx.send(WsMessage::Binary(bytes.to_vec()));
        }
    }

    fn resize(&mut self, cols: u16, rows: u16) {
        if cols == self.cols && rows == self.rows {
            return;
        }
        self.cols = cols.max(2);
        self.rows = rows.max(1);
        self.parser.set_size(self.rows, self.cols);
        self.send_size();
    }

    fn send_size(&mut self) {
        if self.open && !self.closed {
            self.tx.send(WsMessage::Text(format!(
                r#"{{"type":"resize","cols":{},"rows":{}}}"#,
                self.cols, self.rows
            )));
        }
    }

    /// Move the view `lines` into history (positive) or back toward live.
    fn scroll(&mut self, lines: i32) {
        let current = self.parser.screen().scrollback() as i32;
        self.parser.set_scrollback((current + lines).max(0) as usize);
    }

    /// Render the grid and handle keyboard input. Fills the available space.
    ///
    /// `capture_keys` is false while a dialog is open: the terminal must not take
    /// keyboard focus from the dialog's fields.
    pub fn ui(&mut self, ui: &mut egui::Ui, capture_keys: bool) {
        let accent = crate::theme::current(ui.ctx()).accent;
        let font = FontId::monospace(FONT_SIZE);
        let (cw, rh) = ui.fonts(|f| {
            (
                f.glyph_width(&font, 'M').max(1.0),
                f.row_height(&font).max(1.0),
            )
        });

        let touch = crate::mobile::is_touch();
        if touch && capture_keys {
            crate::mobile::text_target(ui.available_rect_before_wrap());
        }

        let mut avail = ui.available_size();
        if touch {
            avail.y = (avail.y - KEY_BAR_HEIGHT).max(rh);
        }
        let cols = ((avail.x / cw).floor() as u16).clamp(20, 400);
        let rows = ((avail.y / rh).floor() as u16).clamp(5, 200);
        self.resize(cols, rows);

        let default_fg = crate::theme::TERM_FG;
        let default_bg = crate::theme::TERM_BG;

        let (rect, response) =
            ui.allocate_exact_size(avail, egui::Sense::click_and_drag());
        let origin = rect.min;

        // Drag to select, click to clear. Selection is purely for copy — the
        // agent gets no mouse events. Anchor at the press origin (not the point
        // where egui first recognised the drag) so the whole swipe is covered.
        // On a touch screen a drag is the only way to scroll, so it scrolls.
        if touch && response.dragged() {
            self.scroll_rem += response.drag_delta().y / rh;
        } else if response.dragged() {
            let press = ui.input(|i| i.pointer.press_origin());
            if let (Some(p0), Some(p1)) = (press, response.interact_pointer_pos()) {
                self.sel = Some((
                    cell_at(p0, origin, cw, rh, self.cols, self.rows),
                    cell_at(p1, origin, cw, rh, self.cols, self.rows),
                ));
            }
        } else if response.clicked() {
            self.sel = None;
            response.request_focus();
        }
        // Copy on release (classic terminal "copy on select"), so copying works
        // without a keyboard shortcut; Cmd/Ctrl+C in handle_input also copies.
        if !touch && response.drag_stopped() {
            if let Some(text) = self.selection_text() {
                if !text.is_empty() {
                    ui.ctx().copy_text(text);
                }
            }
        }
        if response.hovered() {
            self.scroll_rem += ui.input(|i| i.smooth_scroll_delta.y) / rh;
        }
        let whole = self.scroll_rem.trunc();
        if whole != 0.0 {
            self.scroll_rem -= whole;
            self.scroll(whole as i32);
        }

        // Keep focus while a terminal is shown so keystrokes flow, and keep
        // egui from using Tab, arrows and Esc to move focus away.
        if capture_keys {
            if !response.has_focus() {
                response.request_focus();
            }
            ui.memory_mut(|m| {
                m.set_focus_lock_filter(
                    response.id,
                    egui::EventFilter {
                        tab: true,
                        horizontal_arrows: true,
                        vertical_arrows: true,
                        escape: true,
                    },
                );
            });
        }

        let sel_norm = self.sel.map(|(a, b)| norm(a, b));
        let sel_color = Color32::from_rgba_unmultiplied(accent.r(), accent.g(), accent.b(), 80);

        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, default_bg);

        let screen = self.parser.screen();
        for row in 0..self.rows {
            for col in 0..self.cols {
                let Some(cell) = screen.cell(row, col) else {
                    continue;
                };
                let x = origin.x + col as f32 * cw;
                let y = origin.y + row as f32 * rh;
                let cell_rect = egui::Rect::from_min_size(
                    egui::pos2(x, y),
                    egui::vec2(cw, rh),
                );

                let fg = map_color(cell.fgcolor(), default_fg);
                let bg = map_color(cell.bgcolor(), default_bg);
                let (fg, bg) = if cell.inverse() { (bg, fg) } else { (fg, bg) };

                if bg != default_bg {
                    painter.rect_filled(cell_rect, 0.0, bg);
                }
                if let Some((s, e)) = sel_norm {
                    if in_sel(row, col, s, e) {
                        painter.rect_filled(cell_rect, 0.0, sel_color);
                    }
                }
                let contents = cell.contents();
                if !contents.is_empty() && contents != " " {
                    painter.text(
                        egui::pos2(x, y),
                        egui::Align2::LEFT_TOP,
                        contents,
                        font.clone(),
                        fg,
                    );
                }
            }
        }

        // Cursor.
        if !screen.hide_cursor() && screen.scrollback() == 0 {
            let (cr, cc) = screen.cursor_position();
            let x = origin.x + cc as f32 * cw;
            let y = origin.y + cr as f32 * rh;
            let cur = egui::Rect::from_min_size(egui::pos2(x, y), egui::vec2(cw, rh));
            let color = if response.has_focus() {
                accent
            } else {
                accent.linear_multiply(0.5)
            };
            painter.rect_filled(cur, 0.0, color.linear_multiply(0.6));
        }

        if touch && capture_keys {
            // Asks eframe to keep its text agent, the source of the on-screen
            // keyboard's input, focused while the terminal is shown.
            ui.ctx().output_mut(|o| {
                o.ime = Some(egui::output::IMEOutput { rect, cursor_rect: rect });
            });
        }
        if touch {
            self.key_bar(ui);
        }

        if response.has_focus() {
            self.handle_input(ui);
        }
    }

    /// The keys a phone keyboard does not have.
    fn key_bar(&mut self, ui: &mut egui::Ui) {
        let p = crate::theme::current(ui.ctx());
        let keys: [(&str, Option<&[u8]>); 7] = [
            ("Esc", Some(b"\x1b")),
            ("Tab", Some(b"\t")),
            ("Ctrl", None),
            ("\u{2190}", Some(b"\x1b[D")),
            ("\u{2191}", Some(b"\x1b[A")),
            ("\u{2193}", Some(b"\x1b[B")),
            ("\u{2192}", Some(b"\x1b[C")),
        ];
        ui.add_space(KEY_BAR_GAP);
        let gap = 4.0;
        let width = (ui.available_width() - gap * (keys.len() as f32 - 1.0)) / keys.len() as f32;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = gap;
            for (label, bytes) in keys {
                let armed = bytes.is_none() && self.ctrl_armed;
                let text = egui::RichText::new(label)
                    .font(FontId::monospace(13.0))
                    .color(if armed { p.on_accent } else { p.text });
                let key = egui::Button::new(text)
                    .fill(if armed { p.accent } else { p.hover })
                    .min_size(egui::vec2(width, KEY_BAR_BUTTON));
                if ui.add(key).clicked() {
                    match bytes {
                        Some(b) => {
                            self.send_bytes(b);
                            self.parser.set_scrollback(0);
                        }
                        None => self.ctrl_armed = !self.ctrl_armed,
                    }
                }
            }
        });
    }

    fn handle_input(&mut self, ui: &mut egui::Ui) {
        let events = ui.input(|i| i.events.clone());

        // Copy shortcut (Cmd+C on macOS, Ctrl+C elsewhere). If there's a
        // selection, copy it; otherwise fall through so Ctrl+C still interrupts.
        let mut copied = false;
        if events.iter().any(|e| matches!(e, egui::Event::Copy)) {
            if let Some(text) = self.selection_text() {
                if !text.is_empty() {
                    ui.ctx().copy_text(text);
                    copied = true;
                }
            }
        }

        let mut out: Vec<u8> = Vec::new();
        for ev in events {
            match ev {
                egui::Event::Text(t) | egui::Event::Ime(egui::ImeEvent::Commit(t)) => {
                    if std::mem::take(&mut self.ctrl_armed) {
                        out.extend_from_slice(&ctrl_bytes(&t));
                    } else {
                        out.extend_from_slice(t.as_bytes());
                    }
                }
                egui::Event::Paste(t) => out.extend_from_slice(t.as_bytes()),
                egui::Event::Key {
                    key,
                    pressed: true,
                    modifiers,
                    ..
                } => {
                    // When Ctrl+C just copied a selection, don't also send SIGINT.
                    if copied && modifiers.ctrl && !modifiers.shift && key == Key::C {
                        continue;
                    }
                    if let Some(seq) = key_to_bytes(key, &modifiers) {
                        out.extend_from_slice(&seq);
                    }
                }
                _ => {}
            }
        }
        if !out.is_empty() {
            self.send_bytes(&out);
            // Typing clears the selection and returns to the live screen.
            self.sel = None;
            self.parser.set_scrollback(0);
        }
    }

    /// The currently selected text (rows joined by newlines, trailing spaces
    /// trimmed), or `None` if nothing is selected.
    fn selection_text(&self) -> Option<String> {
        let (a, b) = self.sel?;
        let (s, e) = norm(a, b);
        let screen = self.parser.screen();
        let mut lines = Vec::new();
        for r in s.0..=e.0 {
            let c0 = if r == s.0 { s.1 } else { 0 };
            let c1 = if r == e.0 { e.1 } else { self.cols.saturating_sub(1) };
            let mut line = String::new();
            for c in c0..=c1 {
                match screen.cell(r, c) {
                    Some(cell) if !cell.contents().is_empty() => line.push_str(&cell.contents()),
                    _ => line.push(' '),
                }
            }
            while line.ends_with(' ') {
                line.pop();
            }
            lines.push(line);
        }
        Some(lines.join("\n"))
    }
}

/// `text` as typed with Ctrl held: ASCII letters and the C0 punctuation become
/// control bytes, anything else goes out unchanged.
fn ctrl_bytes(text: &str) -> Vec<u8> {
    match text.as_bytes() {
        [c @ (b'a'..=b'z' | b'A'..=b'Z' | b'@' | b'[' | b'\\' | b']' | b'^' | b'_')] => {
            vec![c.to_ascii_uppercase() & 0x1f]
        }
        other => other.to_vec(),
    }
}

/// Which grid cell `(row, col)` a pointer position falls on, clamped to the grid.
fn cell_at(pos: egui::Pos2, origin: egui::Pos2, cw: f32, rh: f32, cols: u16, rows: u16) -> (u16, u16) {
    let c = (((pos.x - origin.x) / cw).floor() as i32).clamp(0, cols as i32 - 1) as u16;
    let r = (((pos.y - origin.y) / rh).floor() as i32).clamp(0, rows as i32 - 1) as u16;
    (r, c)
}

/// Order two selection endpoints in reading order (row-major).
fn norm(a: (u16, u16), b: (u16, u16)) -> ((u16, u16), (u16, u16)) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

/// Is cell `(r, c)` within the normalized selection `[s, e]` (flowing, row-major)?
fn in_sel(r: u16, c: u16, s: (u16, u16), e: (u16, u16)) -> bool {
    let p = (r, c);
    p >= s && p <= e
}

/// Translate a special key (and Ctrl-combos) into a terminal byte sequence.
/// Plain printable characters arrive via `Event::Text` and are not handled here.
fn key_to_bytes(key: Key, m: &egui::Modifiers) -> Option<Vec<u8>> {
    // Ctrl+letter -> control byte (C0). Ctrl+C = 0x03, etc.
    if m.ctrl || m.command {
        if let Some(c) = key_letter(key) {
            return Some(vec![(c.to_ascii_uppercase() as u8) & 0x1f]);
        }
    }
    let s: &[u8] = match key {
        Key::Enter => b"\r",
        Key::Backspace => b"\x7f",
        Key::Tab => b"\t",
        Key::Escape => b"\x1b",
        Key::ArrowUp => b"\x1b[A",
        Key::ArrowDown => b"\x1b[B",
        Key::ArrowRight => b"\x1b[C",
        Key::ArrowLeft => b"\x1b[D",
        Key::Home => b"\x1b[H",
        Key::End => b"\x1b[F",
        Key::Delete => b"\x1b[3~",
        Key::Insert => b"\x1b[2~",
        Key::PageUp => b"\x1b[5~",
        Key::PageDown => b"\x1b[6~",
        _ => return None,
    };
    Some(s.to_vec())
}

fn key_letter(key: Key) -> Option<char> {
    use Key::*;
    Some(match key {
        A => 'a', B => 'b', C => 'c', D => 'd', E => 'e', F => 'f', G => 'g',
        H => 'h', I => 'i', J => 'j', K => 'k', L => 'l', M => 'm', N => 'n',
        O => 'o', P => 'p', Q => 'q', R => 'r', S => 's', T => 't', U => 'u',
        V => 'v', W => 'w', X => 'x', Y => 'y', Z => 'z',
        _ => return None,
    })
}

/// Map a `vt100` colour to egui, resolving "default" to the terminal's own
/// colour and indexed colours through a standard xterm 256 palette.
fn map_color(c: vt100::Color, default: Color32) -> Color32 {
    match c {
        vt100::Color::Default => default,
        vt100::Color::Rgb(r, g, b) => Color32::from_rgb(r, g, b),
        vt100::Color::Idx(i) => {
            let (r, g, b) = xterm256(i);
            Color32::from_rgb(r, g, b)
        }
    }
}

/// Standard xterm 256-colour palette: 16 base, a 6×6×6 cube, then 24 greys.
fn xterm256(i: u8) -> (u8, u8, u8) {
    const BASE: [(u8, u8, u8); 16] = [
        (0x00, 0x00, 0x00),
        (0xcd, 0x00, 0x00),
        (0x00, 0xcd, 0x00),
        (0xcd, 0xcd, 0x00),
        (0x1e, 0x90, 0xff),
        (0xcd, 0x00, 0xcd),
        (0x00, 0xcd, 0xcd),
        (0xe5, 0xe5, 0xe5),
        (0x7f, 0x7f, 0x7f),
        (0xff, 0x00, 0x00),
        (0x00, 0xff, 0x00),
        (0xff, 0xff, 0x00),
        (0x5c, 0xa0, 0xff),
        (0xff, 0x00, 0xff),
        (0x00, 0xff, 0xff),
        (0xff, 0xff, 0xff),
    ];
    match i {
        0..=15 => BASE[i as usize],
        16..=231 => {
            let i = i - 16;
            let steps = [0u8, 95, 135, 175, 215, 255];
            let r = steps[(i / 36) as usize];
            let g = steps[((i / 6) % 6) as usize];
            let b = steps[(i % 6) as usize];
            (r, g, b)
        }
        _ => {
            let v = 8 + (i - 232) * 10;
            (v, v, v)
        }
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::ctrl_bytes;

    #[test]
    fn ctrl_maps_letters_and_leaves_the_rest() {
        assert_eq!(ctrl_bytes("c"), [0x03]);
        assert_eq!(ctrl_bytes("C"), [0x03]);
        assert_eq!(ctrl_bytes("["), [0x1b]);
        assert_eq!(ctrl_bytes("1"), b"1");
        assert_eq!(ctrl_bytes("\u{44f}"), "\u{44f}".as_bytes());
    }
}
