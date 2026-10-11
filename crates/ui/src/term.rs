//! An in-canvas terminal: a `vt100` screen model fed by the relay's WebSocket,
//! rendered as a character grid with egui, with keyboard input translated back
//! into terminal byte sequences.

use egui::{Color32, FontId, Key};
use ewebsock::{WsEvent, WsMessage, WsReceiver, WsSender};

pub struct Terminal {
    parser: vt100::Parser,
    rows: u16,
    cols: u16,
    tx: WsSender,
    rx: WsReceiver,
    /// Active text selection as (anchor, head) cells, each `(row, col)`.
    /// Unnormalized; normalize with [`norm`] before use.
    sel: Option<((u16, u16), (u16, u16))>,
    pub status: String,
    pub open: bool,
    pub closed: bool,
}

impl Terminal {
    /// Dial `wss://<host>/ws/term?...`. `base_ws` is the relay's ws origin.
    pub fn connect(
        base_ws: &str,
        agent: &str,
        shell: Option<&str>,
        ctx: &egui::Context,
    ) -> Result<Self, String> {
        let rows: u16 = 24;
        let cols: u16 = 80;
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
            parser: vt100::Parser::new(rows, cols, 0),
            rows,
            cols,
            tx,
            rx,
            sel: None,
            status: "connecting…".to_string(),
            open: false,
            closed: false,
        })
    }

    /// Drain socket events into the screen model.
    fn pump(&mut self) {
        while let Some(ev) = self.rx.try_recv() {
            match ev {
                WsEvent::Opened => {
                    self.open = true;
                    self.status = "connected".to_string();
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
        if self.open && !self.closed {
            self.tx.send(WsMessage::Text(format!(
                r#"{{"type":"resize","cols":{},"rows":{}}}"#,
                self.cols, self.rows
            )));
        }
    }

    /// Render the grid and handle keyboard input. Fills the available space.
    pub fn ui(&mut self, ui: &mut egui::Ui) {
        self.pump();

        let accent = crate::theme::current(ui.ctx()).accent;
        let font = FontId::monospace(13.0);
        let (cw, rh) = ui.fonts(|f| {
            (
                f.glyph_width(&font, 'M').max(1.0),
                f.row_height(&font).max(1.0),
            )
        });

        let avail = ui.available_size();
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
        if response.dragged() {
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
        if response.drag_stopped() {
            if let Some(text) = self.selection_text() {
                if !text.is_empty() {
                    ui.ctx().copy_text(text);
                }
            }
        }
        // Always keep focus while a terminal is shown so keystrokes flow.
        if !response.has_focus() {
            response.request_focus();
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
        if !screen.hide_cursor() {
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

        if response.has_focus() {
            self.handle_input(ui);
        }
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
                egui::Event::Text(t) => out.extend_from_slice(t.as_bytes()),
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
            // Typing clears the selection highlight, as a terminal would.
            self.sel = None;
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
