//! Serve the compiled egui/WASM UI bundle.
//!
//! The bundle is built by `make ui` into `crates/ui/dist` and dropped into the
//! image at `RUSTLITEL_UI_DIR` (default `/srv/ui`). This is a `fallback` handler, so
//! the real API and WebSocket routes are matched first; anything left over is a
//! UI asset, and unknown paths fall back to `index.html` so the single-page app
//! owns its own routing.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

use crate::state::AppState;

pub async fn serve(State(state): State<Arc<AppState>>, uri: Uri) -> Response {
    let rel = uri.path().trim_start_matches('/');
    let rel = if rel.is_empty() { "index.html" } else { rel };
    // The bundle is flat and predictable; refuse anything trying to climb out.
    if rel.contains("..") {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if let Some(resp) = read_file(&state.ui_dir, rel).await {
        return resp;
    }
    match read_file(&state.ui_dir, "index.html").await {
        Some(resp) => resp,
        None => (StatusCode::NOT_FOUND, "UI bundle not available").into_response(),
    }
}

async fn read_file(dir: &str, rel: &str) -> Option<Response> {
    let path = std::path::Path::new(dir).join(rel);
    let bytes = tokio::fs::read(&path).await.ok()?;
    Some(([(header::CONTENT_TYPE, content_type(rel))], bytes).into_response())
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "wasm" => "application/wasm",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}
