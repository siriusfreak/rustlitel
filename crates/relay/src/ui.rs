//! Serve the compiled egui/WASM UI bundle.
//!
//! The bundle is built by `make ui` into `crates/ui/dist` and dropped into the
//! image at `RUSTLITEL_UI_DIR` (default `/srv/ui`). This is a `fallback` handler, so
//! the real API and WebSocket routes are matched first; anything left over is a
//! UI asset, and unknown paths fall back to `index.html` so the single-page app
//! owns its own routing.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

use crate::state::AppState;

pub async fn serve(State(state): State<Arc<AppState>>, uri: Uri, headers: HeaderMap) -> Response {
    let accepts = headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let rel = uri.path().trim_start_matches('/');
    let rel = if rel.is_empty() { "index.html" } else { rel };
    // The bundle is flat and predictable; refuse anything trying to climb out.
    if rel.contains("..") {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if let Some(resp) = read_file(&state.ui_dir, rel, accepts).await {
        return resp;
    }
    match read_file(&state.ui_dir, "index.html", accepts).await {
        Some(resp) => resp,
        None => (StatusCode::NOT_FOUND, "UI bundle not available").into_response(),
    }
}

async fn read_file(dir: &str, rel: &str, accepts: &str) -> Option<Response> {
    // `make ui` precompresses the wasm and js next to the originals.
    for (coding, suffix) in encodings(accepts) {
        if let Some(bytes) = read_confined(dir, &format!("{rel}{suffix}")).await {
            let mut resp = (
                [
                    (header::CONTENT_TYPE, content_type(rel)),
                    (header::CACHE_CONTROL, cache_control(rel)),
                    (header::CONTENT_ENCODING, coding),
                    (header::VARY, "Accept-Encoding"),
                ],
                bytes,
            )
                .into_response();
            // For the page's progress bar: it counts decoded bytes, which
            // Content-Length of a compressed file says nothing about.
            if let Ok(meta) = tokio::fs::metadata(std::path::Path::new(dir).join(rel)).await {
                resp.headers_mut().insert("x-decoded-length", meta.len().into());
            }
            return Some(resp);
        }
    }
    let bytes = read_confined(dir, rel).await?;
    Some(
        (
            [
                (header::CONTENT_TYPE, content_type(rel)),
                (header::CACHE_CONTROL, cache_control(rel)),
                (header::VARY, "Accept-Encoding"),
            ],
            bytes,
        )
            .into_response(),
    )
}

/// Which precompressed variants the browser takes, best first, as
/// (Content-Encoding, file suffix).
fn encodings(accepts: &str) -> Vec<(&'static str, &'static str)> {
    let takes = |name: &str| {
        accepts.split(',').any(|item| {
            let mut parts = item.split(';');
            parts.next().is_some_and(|c| c.trim() == name)
                && !parts.any(|p| matches!(p.trim(), "q=0" | "q=0.0" | "q=0.00" | "q=0.000"))
        })
    };
    let mut out = Vec::new();
    if takes("br") {
        out.push(("br", ".br"));
    }
    if takes("gzip") {
        out.push(("gzip", ".gz"));
    }
    out
}

async fn read_confined(dir: &str, rel: &str) -> Option<Vec<u8>> {
    let path = std::path::Path::new(dir).join(rel);
    // Confine to the bundle dir: resolve symlinks/`..` and require the result to
    // stay under the (canonicalised) UI dir, so a traversal or an escaping
    // symlink can never read files outside the bundle.
    let base = tokio::fs::canonicalize(dir).await.ok()?;
    let real = tokio::fs::canonicalize(&path).await.ok()?;
    if !real.starts_with(&base) {
        return None;
    }
    tokio::fs::read(&real).await.ok()
}

/// Caching policy. `index.html` must always be revalidated so a deploy's new
/// content-hashed asset names are picked up (otherwise a stale index points at
/// an evicted .wasm and the app fails to load). Trunk's hashed assets are
/// immutable and can be cached forever. Anything else revalidates to be safe.
fn cache_control(rel: &str) -> &'static str {
    if rel == "index.html" {
        "no-cache"
    } else if is_content_hashed(rel) {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    }
}

/// True when the filename carries a Trunk content hash (a run of >=16 hex chars,
/// e.g. `rustlitel-ui-564908b63a531906.js`), so it is safe to cache forever.
fn is_content_hashed(name: &str) -> bool {
    let mut run = 0u32;
    for c in name.chars() {
        if c.is_ascii_hexdigit() {
            run += 1;
            if run >= 16 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
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

#[cfg(test)]
mod tests {
    use super::encodings;

    #[test]
    fn picks_what_the_browser_takes() {
        assert_eq!(encodings("gzip, deflate, br"), [("br", ".br"), ("gzip", ".gz")]);
        assert_eq!(encodings("gzip"), [("gzip", ".gz")]);
        assert_eq!(encodings("br;q=0, gzip;q=0.5"), [("gzip", ".gz")]);
        assert!(encodings("").is_empty());
        assert!(encodings("identity").is_empty());
    }
}
