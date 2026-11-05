//! What a touch screen needs on top of eframe's web backend.
//!
//! iOS opens the on-screen keyboard only when an input is focused inside the
//! handler of the touch itself. eframe focuses its hidden text agent later, while
//! painting the frame after the tap, so on an iPhone the keyboard either needs a
//! second tap or never appears. egui only learns about a tap in that later frame,
//! so each frame the app lists where text can be typed ([`text_target`]) and a
//! capture-phase `touchend` listener focuses the agent right away when a tap lands
//! on one of those places.

#[cfg(target_arch = "wasm32")]
mod web {
    use std::cell::{Cell, RefCell};

    use eframe::wasm_bindgen::closure::Closure;
    use eframe::wasm_bindgen::JsCast as _;

    /// A touch that moved further than this (CSS px) is a drag, not a tap.
    const TAP_SLOP: f32 = 10.0;

    thread_local! {
        static TARGETS: RefCell<Vec<egui::Rect>> = const { RefCell::new(Vec::new()) };
        static IS_TOUCH: Cell<Option<bool>> = const { Cell::new(None) };
        static TOUCH_START: Cell<Option<(f32, f32)>> = const { Cell::new(None) };
    }

    pub fn is_touch() -> bool {
        IS_TOUCH.with(|c| match c.get() {
            Some(v) => v,
            None => {
                let v = web_sys::window()
                    .and_then(|w| w.match_media("(pointer: coarse)").ok().flatten())
                    .is_some_and(|m| m.matches());
                c.set(Some(v));
                v
            }
        })
    }

    pub fn begin_frame() {
        TARGETS.with(|t| t.borrow_mut().clear());
    }

    pub fn text_target(rect: egui::Rect) {
        TARGETS.with(|t| t.borrow_mut().push(rect));
    }

    fn text_agent() -> Option<web_sys::HtmlInputElement> {
        web_sys::window()?
            .document()?
            .query_selector("input[type=text]")
            .ok()??
            .dyn_into()
            .ok()
    }

    /// Call once the runner is up: its text agent exists by then.
    pub fn install() {
        let Some(window) = web_sys::window() else { return };

        if let Some(agent) = text_agent() {
            // Keyboard suggestions rewrite what was typed, which a terminal has
            // already sent. Under 16 px Safari zooms the page on focus.
            for (name, value) in [("autocorrect", "off"), ("autocomplete", "off"), ("spellcheck", "false")] {
                let _ = agent.set_attribute(name, value);
            }
            let _ = agent.style().set_property("font-size", "16px");
        }

        let on_start = Closure::<dyn FnMut(web_sys::TouchEvent)>::new(|e: web_sys::TouchEvent| {
            let pos = e.touches().get(0).map(|t| (t.client_x() as f32, t.client_y() as f32));
            TOUCH_START.with(|s| s.set(pos));
        });
        let on_end = Closure::<dyn FnMut(web_sys::TouchEvent)>::new(|e: web_sys::TouchEvent| {
            let Some(touch) = e.changed_touches().get(0) else { return };
            let (x, y) = (touch.client_x() as f32, touch.client_y() as f32);
            let is_tap = TOUCH_START
                .with(|s| s.take())
                .is_some_and(|(x0, y0)| (x - x0).hypot(y - y0) <= TAP_SLOP);
            let on_target = TARGETS.with(|t| t.borrow().iter().any(|r| r.contains(egui::pos2(x, y))));
            if is_tap && on_target {
                if let Some(agent) = text_agent() {
                    let _ = agent.focus();
                }
            }
        });

        let options = web_sys::AddEventListenerOptions::new();
        options.set_capture(true);
        options.set_passive(true);
        for (name, f) in [("touchstart", on_start.as_ref()), ("touchend", on_end.as_ref())] {
            let _ = window.add_event_listener_with_callback_and_add_event_listener_options(
                name,
                f.unchecked_ref(),
                &options,
            );
        }
        on_start.forget();
        on_end.forget();
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod web {
    pub fn is_touch() -> bool {
        false
    }
    pub fn begin_frame() {}
    pub fn text_target(_rect: egui::Rect) {}
}

#[cfg(target_arch = "wasm32")]
pub use web::install;
pub use web::{begin_frame, is_touch, text_target};
