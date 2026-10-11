//! rustlitel web UI — an egui/eframe application compiled to WebAssembly and
//! served by the relay. It replaces the old hand-written HTML/JS: login (operator
//! token or Keycloak), the agent list, an in-canvas terminal (a small VT100
//! model rendered with egui), the non-interactive `exec` panel, one-click
//! installer links, downloads, self-delete, and a dark/light/system theme
//! switch.

mod app;
mod term;
mod theme;

#[cfg(target_arch = "wasm32")]
fn main() {
    use eframe::wasm_bindgen::JsCast as _;

    console_error_panic_hook::set_once();
    let _ = console_log::init_with_level(log::Level::Info);

    let web_options = eframe::WebOptions::default();
    wasm_bindgen_futures::spawn_local(async {
        let document = web_sys::window()
            .expect("no window")
            .document()
            .expect("no document");
        let canvas = document
            .get_element_by_id("canvas")
            .expect("missing #canvas element")
            .dyn_into::<web_sys::HtmlCanvasElement>()
            .expect("#canvas is not a <canvas>");

        let result = eframe::WebRunner::new()
            .start(
                canvas,
                web_options,
                Box::new(|cc| Ok(Box::new(app::RustlitelApp::new(cc)))),
            )
            .await;
        if let Err(e) = result {
            log::error!("eframe start failed: {e:?}");
        }
    });
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    eprintln!("rustlitel-ui is a WebAssembly app — build it with `trunk build` (see the Makefile `ui` target).");
}
