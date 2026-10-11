//! HTTP and WebSocket handlers.
//!
//! Routes:
//! * `GET  /`                      login page or app page, by cookie
//! * `POST /api/login`             operator token -> session cookie
//! * `POST /api/logout`            clear session
//! * `GET  /api/agents`            JSON list of connected agents (auth)
//! * `GET  /healthz`               liveness/readiness
//! * `GET  /ws/term`               operator terminal (auth, cookie)
//! * `GET  /ws/agent/control`      agent control link (token in first frame)
//! * `GET  /ws/agent/session`      agent per-session link (session+nonce)

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, oneshot};
use tokio::time::sleep;
use uuid::Uuid;
use rustlitel_proto::{AgentHello, AgentToServer, ServerToAgent, PROTOCOL_VERSION};

use crate::auth::{random_nonce, session_from_cookies};
use crate::state::{AgentConn, AppState, ExecEvent, Frame, Session, SessionSignal};

/// Cap on a single WebSocket frame. Keystrokes and terminal output are tiny;
/// this only exists to reject something pathological.
const MAX_FRAME: usize = 1 << 20;
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const CHANNEL_CAP: usize = 256;

// ---------------------------------------------------------------------------
// Pages & operator auth
// ---------------------------------------------------------------------------

pub async fn healthz() -> &'static str {
    "ok"
}

#[derive(Deserialize)]
pub struct LoginReq {
    token: String,
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<LoginReq>,
) -> Response {
    // SameSite=Strict already blocks cross-site cookie use; when an origin is
    // configured, also reject logins carrying a foreign Origin.
    if !origin_ok(&state, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !state.auth.token_ok(&req.token) {
        return (StatusCode::UNAUTHORIZED, "invalid token").into_response();
    }
    let id = state.auth.issue(None);
    let mut resp = StatusCode::NO_CONTENT.into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        state.auth.cookie_header(&id).parse().unwrap(),
    );
    resp
}

pub async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(id) = session_from_cookies(cookie_str(&headers)) {
        state.auth.revoke(&id);
    }
    let mut resp = StatusCode::NO_CONTENT.into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        state.auth.clear_cookie_header().parse().unwrap(),
    );
    resp
}

pub async fn list_agents(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !api_authed(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let agents = state.agents.lock().await;
    let mut out: Vec<_> = agents.iter().map(|(id, c)| c.info(id)).collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Json(out).into_response()
}

/// Who is signed in (for the UI header). `username` is set for OIDC logins.
pub async fn me(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let is_authed = authed(&state, &headers);
    let username = if is_authed {
        session_from_cookies(cookie_str(&headers)).and_then(|id| state.auth.username(&id))
    } else {
        None
    };
    Json(serde_json::json!({
        "authenticated": is_authed,
        "username": username,
        "oidc": state.oidc.is_some(),
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct OidcLoginQuery {
    #[serde(default)]
    rd: Option<String>,
}

/// Start the Keycloak Authorization Code flow.
pub async fn oidc_login(
    State(state): State<Arc<AppState>>,
    Query(q): Query<OidcLoginQuery>,
) -> Response {
    let Some(oidc) = state.oidc.as_ref() else {
        return (StatusCode::NOT_FOUND, "OIDC is not enabled").into_response();
    };
    match oidc.begin_login(q.rd.as_deref().unwrap_or("/")).await {
        Ok(url) => Redirect::to(&url).into_response(),
        Err(e) => {
            tracing::warn!("oidc begin_login: {e:#}");
            (StatusCode::BAD_GATEWAY, "could not reach the identity provider").into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct OidcCallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// Keycloak redirect target: verify the login and establish a session.
pub async fn oidc_callback(
    State(state): State<Arc<AppState>>,
    Query(q): Query<OidcCallbackQuery>,
) -> Response {
    let Some(oidc) = state.oidc.as_ref() else {
        return (StatusCode::NOT_FOUND, "OIDC is not enabled").into_response();
    };
    if let Some(err) = q.error {
        return (StatusCode::UNAUTHORIZED, format!("Keycloak returned: {err}")).into_response();
    }
    let (Some(code), Some(csrf)) = (q.code, q.state) else {
        return (StatusCode::BAD_REQUEST, "missing code or state").into_response();
    };
    match oidc.complete_login(&code, &csrf).await {
        Ok((identity, return_to)) => {
            tracing::info!(user = %identity.username, "oidc login");
            let id = state.auth.issue(Some(identity.username));
            let mut resp = Redirect::to(&return_to).into_response();
            resp.headers_mut().insert(
                header::SET_COOKIE,
                state.auth.cookie_header(&id).parse().unwrap(),
            );
            resp
        }
        Err(e) => {
            tracing::warn!("oidc login failed: {e:#}");
            (StatusCode::UNAUTHORIZED, format!("login failed: {e}")).into_response()
        }
    }
}

/// Clear the local session and, under OIDC, bounce through Keycloak's
/// end-session endpoint so the IdP session ends too (not just ours).
pub async fn oidc_logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(id) = session_from_cookies(cookie_str(&headers)) {
        state.auth.revoke(&id);
    }
    let clear = state.auth.clear_cookie_header();

    if let Some(oidc) = state.oidc.as_ref() {
        let post = state.public_origin.clone().unwrap_or_else(|| "/".into());
        if let Some(url) = oidc.logout_url(&post).await {
            let mut resp = Redirect::to(&url).into_response();
            resp.headers_mut()
                .insert(header::SET_COOKIE, clear.parse().unwrap());
            return resp;
        }
    }
    let mut resp = Redirect::to("/").into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, clear.parse().unwrap());
    resp
}

fn cookie_str(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::COOKIE).and_then(|v| v.to_str().ok())
}

fn authed(state: &AppState, headers: &HeaderMap) -> bool {
    match session_from_cookies(cookie_str(headers)) {
        Some(id) => state.auth.validate(&id),
        None => false,
    }
}

/// `Authorization: Bearer <token>` value, if present.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
}

/// Auth for the JSON API: a browser session cookie, a Bearer operator token
/// (scripts / LLM sessions), or a Keycloak-issued access token (the `wrs` CLI,
/// verified + group-checked like the web login).
async fn api_authed(state: &AppState, headers: &HeaderMap) -> bool {
    if authed(state, headers) {
        return true;
    }
    let Some(tok) = bearer(headers) else {
        return false;
    };
    if state.auth.token_ok(tok) {
        return true;
    }
    if let Some(oidc) = state.oidc.as_ref() {
        return oidc.authorize_bearer(tok).await.is_some();
    }
    false
}

fn origin_ok(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(expected) = state.public_origin.as_deref() else {
        return true; // not configured -> skip (local dev)
    };
    match headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        Some(o) => o == expected,
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Non-interactive exec (the scripted / LLM-session primitive)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ExecReq {
    agent: String,
    command: String,
    #[serde(default)]
    shell: Option<String>,
    #[serde(default)]
    timeout_secs: Option<u64>,
}

#[derive(Serialize)]
struct InstallerLink {
    url: String,
    expires_days: u64,
}

#[derive(Serialize)]
pub struct ExecResp {
    /// Process exit code, or null if it was killed / never started.
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    /// Output hit the relay's per-stream cap and was cut short.
    truncated: bool,
    /// Populated on timeout, spawn failure, or a declined/disconnected agent.
    error: Option<String>,
}

/// Run one command on an agent and return its result. Request and response are
/// plain JSON, so this is trivially driven from `curl`, a script, or an
/// operator's own Claude session:
///
/// ```text
/// curl -s $RELAY/api/exec -H "Authorization: Bearer $OP_TOKEN" \
///   -H 'Content-Type: application/json' \
///   -d '{"agent":"win-box","command":"Get-Service Spooler | Restart-Service"}'
/// ```
pub async fn exec(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ExecReq>,
) -> Response {
    if !api_authed(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let commands = {
        let agents = state.agents.lock().await;
        match agents.get(&req.agent) {
            Some(c) if !c.allow_remote => {
                return (
                    StatusCode::FORBIDDEN,
                    "agent has remote access disabled (started without --allow-remote)",
                )
                    .into_response();
            }
            Some(c) => c.commands.clone(),
            None => return (StatusCode::NOT_FOUND, "agent not connected").into_response(),
        }
    };

    let exec_id = Uuid::new_v4();
    let timeout = req
        .timeout_secs
        .unwrap_or(state.exec_default_timeout_secs)
        .clamp(1, 3600);

    let (tx, mut rx) = mpsc::channel::<ExecEvent>(256);
    state.execs.lock().await.insert(exec_id, tx);

    if commands
        .send(ServerToAgent::Exec {
            exec_id,
            command: req.command,
            shell: req.shell,
            timeout_secs: timeout,
        })
        .is_err()
    {
        state.execs.lock().await.remove(&exec_id);
        return (StatusCode::SERVICE_UNAVAILABLE, "agent disconnected").into_response();
    }

    let cap = state.exec_output_cap;
    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut truncated = false;

    // Give the agent a little past its own deadline to deliver the final frame.
    let deadline = sleep(Duration::from_secs(timeout + 15));
    tokio::pin!(deadline);

    let (exit_code, error) = loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Some(ExecEvent::Chunk { stream, data }) => {
                    let buf = match stream {
                        rustlitel_proto::ExecStream::Stdout => &mut stdout,
                        rustlitel_proto::ExecStream::Stderr => &mut stderr,
                    };
                    if append_capped(buf, &data, cap) {
                        truncated = true;
                    }
                }
                Some(ExecEvent::Done { exit_code, truncated: t, error }) => {
                    truncated |= t;
                    break (exit_code, error);
                }
                None => break (None, Some("agent disconnected".to_string())),
            },
            _ = &mut deadline => {
                break (None, Some("timed out waiting for the agent".to_string()));
            }
        }
    };

    state.execs.lock().await.remove(&exec_id);
    Json(ExecResp {
        exit_code,
        stdout,
        stderr,
        truncated,
        error,
    })
    .into_response()
}

#[derive(Deserialize)]
pub struct UninstallReq {
    agent: String,
}

/// Tell an agent to uninstall itself (the "self-delete" button). Fire-and-forget:
/// the agent removes itself and drops off; nothing to wait for.
pub async fn uninstall_agent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<UninstallReq>,
) -> Response {
    if !api_authed(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let commands = {
        let agents = state.agents.lock().await;
        match agents.get(&req.agent) {
            Some(c) => c.commands.clone(),
            None => return (StatusCode::NOT_FOUND, "agent not connected").into_response(),
        }
    };
    if commands.send(ServerToAgent::Uninstall).is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, "agent disconnected").into_response();
    }
    tracing::info!(agent = %req.agent, "sent uninstall");
    (StatusCode::ACCEPTED, "uninstall requested").into_response()
}

/// Append `data` to `buf` without exceeding `cap` bytes, splitting only on a
/// UTF-8 char boundary. Returns true if anything was dropped.
fn append_capped(buf: &mut String, data: &str, cap: usize) -> bool {
    if buf.len() >= cap {
        return !data.is_empty();
    }
    let mut room = cap - buf.len();
    if data.len() <= room {
        buf.push_str(data);
        return false;
    }
    while room > 0 && !data.is_char_boundary(room) {
        room -= 1;
    }
    buf.push_str(&data[..room]);
    true
}

// ---------------------------------------------------------------------------
// Agent binary downloads & one-click installer generation
// ---------------------------------------------------------------------------

/// Serve a stock agent binary from the agents directory (operator-gated).
pub async fn download(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(file): Path<String>,
) -> Response {
    if !api_authed(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    // No path traversal: a bare filename only.
    if file.is_empty() || file.contains('/') || file.contains('\\') || file.contains("..") {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let path = std::path::Path::new(&state.agents_dir).join(&file);
    match tokio::fs::read(&path).await {
        Ok(bytes) => binary_download(&file, bytes),
        Err(_) => (StatusCode::NOT_FOUND, "binary not available").into_response(),
    }
}

#[derive(Deserialize)]
pub struct InstallerReq {
    #[serde(default)]
    os: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    ttl_days: Option<u64>,
}

/// Mint a join key and return a shareable download LINK with the key embedded.
/// The link is meant to be opened on the target machine (the download endpoint
/// is authorised by the key itself), not to download here.
pub async fn make_installer(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<InstallerReq>,
) -> Response {
    if !api_authed(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let os = req.os.as_deref().unwrap_or("windows");
    let Some((base_file, _)) = installer_bases(os) else {
        return (StatusCode::BAD_REQUEST, "unknown os").into_response();
    };
    let Some(origin) = state.public_origin.as_deref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "RUSTLITEL_PUBLIC_ORIGIN is not set").into_response();
    };
    // Don't hand out a link to a binary we don't actually have bundled.
    let path = std::path::Path::new(&state.agents_dir).join(base_file);
    if tokio::fs::metadata(&path).await.is_err() {
        return (
            StatusCode::NOT_FOUND,
            format!("base binary {base_file} is not bundled"),
        )
            .into_response();
    }

    // The baked key is the installed agent's standing credential (used on every
    // reconnect), so default it long-lived; revoke by rotating RUSTLITEL_AGENT_TOKEN.
    let ttl_days = req.ttl_days.unwrap_or(3650).clamp(1, 3650);
    let label = req.name.clone().unwrap_or_else(|| "installer".into());
    let join = crate::installer::mint_join_key(&state.agent_token, &label, ttl_days * 86400);

    // Store the (long) baked params behind a short code so the copied URL is
    // short: https://relay/i/<code>. The link itself expires with short_link_ttl.
    let code = crate::installer::short_code();
    {
        let mut links = state.short_links.lock().await;
        let now = std::time::Instant::now();
        links.retain(|_, v| v.expiry > now);
        links.insert(
            code.clone(),
            crate::state::ShortLink {
                os: os.to_string(),
                name: req.name.clone(),
                join_key: join,
                expiry: now + state.short_link_ttl,
            },
        );
    }

    let mut url = match url::Url::parse(origin) {
        Ok(u) => u,
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "bad public origin").into_response(),
    };
    url.set_path(&format!("/i/{code}"));

    tracing::info!(os = %os, label = %label, ttl_days, "generated installer short link");
    Json(InstallerLink {
        url: url.to_string(),
        expires_days: state.short_link_ttl.as_secs() / 86400,
    })
    .into_response()
}

#[derive(Deserialize)]
pub struct InstallerDownloadQuery {
    #[serde(default)]
    os: Option<String>,
    #[serde(default)]
    name: Option<String>,
    key: String,
}

/// Serve the baked installer named by a generated link. Unauthenticated on
/// purpose: the signed, unexpired join key in `key` is itself the capability
/// (so the link works when opened on a machine with no operator session).
pub async fn download_installer(
    State(state): State<Arc<AppState>>,
    Query(q): Query<InstallerDownloadQuery>,
) -> Response {
    if !crate::installer::validate_join_key(&state.agent_token, &q.key) {
        return (StatusCode::FORBIDDEN, "invalid or expired installer link").into_response();
    }
    let os = q.os.as_deref().unwrap_or("windows");
    serve_baked(&state, os, q.name, q.key).await
}

/// Serve the baked installer for a short link `/i/<code>`. Unauthenticated: the
/// (unexpired) short code is the capability, standing in for the join key.
pub async fn download_short(
    State(state): State<Arc<AppState>>,
    Path(code): Path<String>,
) -> Response {
    let link = {
        let mut links = state.short_links.lock().await;
        let now = std::time::Instant::now();
        links.retain(|_, v| v.expiry > now);
        links.get(&code).cloned()
    };
    match link {
        Some(l) => serve_baked(&state, &l.os, l.name, l.join_key).await,
        None => (StatusCode::NOT_FOUND, "installer link expired or invalid").into_response(),
    }
}

/// Bake and serve the installer binary for `os` with the given name + join key.
async fn serve_baked(
    state: &AppState,
    os: &str,
    name: Option<String>,
    key: String,
) -> Response {
    let Some((base_file, out_file)) = installer_bases(os) else {
        return (StatusCode::BAD_REQUEST, "unknown os").into_response();
    };
    let Some(origin) = state.public_origin.as_deref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "RUSTLITEL_PUBLIC_ORIGIN is not set").into_response();
    };
    let Some(relay_ws) = crate::installer::origin_to_ws(origin) else {
        return (StatusCode::SERVICE_UNAVAILABLE, "bad public origin").into_response();
    };
    let path = std::path::Path::new(&state.agents_dir).join(base_file);
    let base = match tokio::fs::read(&path).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::NOT_FOUND, "base binary not bundled").into_response(),
    };
    let cfg = rustlitel_proto::InstallerConfig {
        relay: relay_ws,
        token: key,
        name,
        auto: Some("install".into()),
    };
    binary_download(out_file, crate::installer::bake(&base, &cfg))
}

/// Public config the `wrs` CLI fetches to start its Keycloak device-flow login.
pub async fn auth_config(State(state): State<Arc<AppState>>) -> Response {
    match state.oidc.as_ref() {
        Some(oidc) => Json(oidc.public_config(&state.oidc_cli_client_id)).into_response(),
        None => Json(serde_json::json!({ "issuer": null })).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Agent self-update
// ---------------------------------------------------------------------------

/// Auth for the agent-facing update endpoints: the master agent token or a
/// valid join key (Bearer), exactly what the control link accepts. Operators
/// use their own session/token on `/download/:file`; agents use this.
fn agent_authed(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(tok) = bearer(headers) else {
        return false;
    };
    let master: bool = tok.as_bytes().ct_eq(state.agent_token.as_bytes()).into();
    master || crate::installer::validate_join_key(&state.agent_token, tok)
}

#[derive(Deserialize)]
pub struct AgentUpdateQuery {
    os: String,
}

#[derive(Serialize)]
struct UpdateManifest {
    version: String,
    sha256: String,
    size: u64,
}

/// What build the relay is serving for `os`. `version` is the relay's own build
/// id; an agent compares it to its baked [`rustlitel_proto::BUILD_ID`] and, when they
/// differ, pulls `GET /api/agent/binary` — whose exact bytes `sha256`/`size`
/// describe, so the agent can verify the download before swapping.
pub async fn agent_update(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<AgentUpdateQuery>,
) -> Response {
    if !agent_authed(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some((base_file, _)) = installer_bases(&q.os) else {
        return (StatusCode::BAD_REQUEST, "unknown os").into_response();
    };
    let path = std::path::Path::new(&state.agents_dir).join(base_file);
    let bytes = match tokio::fs::read(&path).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::NOT_FOUND, "binary not available").into_response(),
    };
    Json(UpdateManifest {
        version: rustlitel_proto::BUILD_ID.to_string(),
        sha256: sha256_hex(&bytes),
        size: bytes.len() as u64,
    })
    .into_response()
}

/// Serve the stock agent binary for `os` to a token-bearing agent (the bytes
/// the manifest describes). Distinct from the operator `GET /download/:file` so
/// an agent authenticates with its own token rather than an operator session.
pub async fn agent_binary(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<AgentUpdateQuery>,
) -> Response {
    if !agent_authed(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some((base_file, _)) = installer_bases(&q.os) else {
        return (StatusCode::BAD_REQUEST, "unknown os").into_response();
    };
    let path = std::path::Path::new(&state.agents_dir).join(base_file);
    match tokio::fs::read(&path).await {
        Ok(bytes) => binary_download(base_file, bytes),
        Err(_) => (StatusCode::NOT_FOUND, "binary not available").into_response(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn installer_bases(os: &str) -> Option<(&'static str, &'static str)> {
    match os {
        "windows" => Some(("rustlitel-agent-windows.exe", "rustlitel-agent-installer.exe")),
        "linux" => Some(("rustlitel-agent-linux", "rustlitel-agent-installer")),
        "macos" => Some(("rustlitel-agent-macos", "rustlitel-agent-installer")),
        _ => None,
    }
}

fn binary_download(filename: &str, bytes: Vec<u8>) -> Response {
    let mut resp = bytes.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        "application/octet-stream".parse().unwrap(),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{filename}\"").parse().unwrap(),
    );
    resp
}

// ---------------------------------------------------------------------------
// Operator terminal link
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TermQuery {
    agent: String,
    #[serde(default)]
    cols: Option<u16>,
    #[serde(default)]
    rows: Option<u16>,
    #[serde(default)]
    shell: Option<String>,
}

pub async fn term_ws(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<TermQuery>,
) -> Response {
    if !authed(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !origin_ok(&state, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    // Short-circuit a nicer 404 if the agent is plainly not here.
    if !state.agents.lock().await.contains_key(&q.agent) {
        return (StatusCode::NOT_FOUND, "agent not connected").into_response();
    }
    let cols = q.cols.unwrap_or(80).clamp(1, 1000);
    let rows = q.rows.unwrap_or(24).clamp(1, 1000);
    ws.max_message_size(MAX_FRAME)
        .on_upgrade(move |socket| handle_term(socket, state, q.agent, cols, rows, q.shell))
}

async fn handle_term(
    socket: WebSocket,
    state: Arc<AppState>,
    agent_id: String,
    cols: u16,
    rows: u16,
    shell: Option<String>,
) {
    let (mut op_sink, op_stream) = socket.split();

    // Grab a sender to the agent's control task.
    let commands = {
        let agents = state.agents.lock().await;
        match agents.get(&agent_id) {
            Some(c) => c.commands.clone(),
            None => {
                let _ = op_sink
                    .send(Message::Text("\r\nAgent disconnected.\r\n".into()))
                    .await;
                return;
            }
        }
    };

    let session_id = Uuid::new_v4();
    let nonce = random_nonce();

    // operator -> agent, agent -> operator, verdict, and the attach signal.
    let (op2a_tx, op2a_rx) = mpsc::channel::<Frame>(CHANNEL_CAP);
    let (a2o_tx, a2o_rx) = mpsc::channel::<Frame>(CHANNEL_CAP);
    let (sig_tx, mut sig_rx) = mpsc::channel::<SessionSignal>(4);
    let (ready_tx, ready_rx) = oneshot::channel::<()>();

    let session = Arc::new(Session {
        agent_id: agent_id.clone(),
        nonce: nonce.clone(),
        op_to_agent_rx: tokio::sync::Mutex::new(Some(op2a_rx)),
        agent_to_op_tx: a2o_tx,
        signal_tx: sig_tx,
        ready_tx: tokio::sync::Mutex::new(Some(ready_tx)),
    });
    state.sessions.lock().await.insert(session_id, session.clone());

    // Ask the agent to open the session. It will run its consent check, then
    // either dial the session link (fires ready_rx) or reply declined.
    if commands
        .send(ServerToAgent::OpenSession {
            session: session_id,
            nonce,
            cols,
            rows,
            shell,
        })
        .is_err()
    {
        let _ = op_sink
            .send(Message::Text("\r\nAgent disconnected.\r\n".into()))
            .await;
        state.remove_session(&session_id).await;
        return;
    }

    // Wait for attach / decline / timeout.
    let timeout = sleep(Duration::from_secs(state.open_timeout_secs));
    tokio::pin!(timeout);
    tokio::pin!(ready_rx);
    let proceed = loop {
        tokio::select! {
            r = &mut ready_rx => { break r.is_ok(); }
            s = sig_rx.recv() => match s {
                Some(SessionSignal::Accepted) => {
                    let _ = op_sink
                        .send(Message::Text("\r\n\x1b[90mapproved, starting…\x1b[0m\r\n".into()))
                        .await;
                    continue;
                }
                Some(SessionSignal::Declined(reason)) => {
                    let _ = op_sink
                        .send(Message::Text(format!(
                            "\r\n\x1b[31mAgent declined the session: {reason}\x1b[0m\r\n"
                        )))
                        .await;
                    break false;
                }
                None => break false, // agent control link gone
            },
            _ = &mut timeout => {
                let _ = op_sink
                    .send(Message::Text(
                        "\r\n\x1b[31mAgent did not open the session (timeout).\x1b[0m\r\n".into(),
                    ))
                    .await;
                break false;
            }
        }
    };

    if !proceed {
        let _ = op_sink.send(Message::Close(None)).await;
        state.remove_session(&session_id).await;
        return;
    }

    let _ = op_sink
        .send(Message::Text("\x1b[90m— session active —\x1b[0m\r\n".into()))
        .await;

    // Bridge: operator socket <-> relay channels <-> agent session socket.
    let reader = tokio::spawn(socket_to_channel(op_stream, op2a_tx));
    channel_to_socket(a2o_rx, op_sink).await;
    reader.abort();
    state.remove_session(&session_id).await;
}

// ---------------------------------------------------------------------------
// Agent control link
// ---------------------------------------------------------------------------

pub async fn agent_control_ws(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> Response {
    ws.max_message_size(MAX_FRAME)
        .on_upgrade(move |socket| handle_agent_control(socket, state))
}

async fn handle_agent_control(socket: WebSocket, state: Arc<AppState>) {
    let (sink, mut stream) = socket.split();

    // First frame must be a valid, correctly-tokened Hello within the window.
    let hello: AgentHello = match tokio::time::timeout(HELLO_TIMEOUT, stream.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => match serde_json::from_str(&t) {
            Ok(h) => h,
            Err(_) => return,
        },
        _ => return,
    };
    if hello.protocol != PROTOCOL_VERSION {
        return;
    }
    // Accept either the master agent token or a valid (signed, unexpired) join
    // key minted for a one-click installer.
    let master_ok: bool = hello
        .token
        .as_bytes()
        .ct_eq(state.agent_token.as_bytes())
        .into();
    let token_ok = master_ok || crate::installer::validate_join_key(&state.agent_token, &hello.token);
    if !token_ok {
        tracing::warn!(agent_id = %hello.agent_id, "agent rejected: bad token");
        return;
    }

    let conn_id = Uuid::new_v4();
    let agent_id = hello.agent_id.clone();
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<ServerToAgent>();

    {
        let mut agents = state.agents.lock().await;
        agents.insert(
            agent_id.clone(),
            AgentConn {
                conn_id,
                name: hello.name.clone(),
                os: hello.os.clone(),
                shells: hello.shells.clone(),
                allow_remote: hello.allow_remote,
                connected_at: Instant::now(),
                commands: cmd_tx,
            },
        );
    }
    tracing::info!(agent_id = %agent_id, name = %hello.name, "agent connected");

    // Writer: forward commands, heartbeat every 30s.
    let writer = tokio::spawn(control_writer(sink, cmd_rx));

    // Reader: handle agent replies until the link drops.
    control_reader(&mut stream, &state).await;

    writer.abort();
    // Only evict if we still own the registration (a reconnect may have won).
    let mut agents = state.agents.lock().await;
    if agents.get(&agent_id).map(|c| c.conn_id) == Some(conn_id) {
        agents.remove(&agent_id);
        tracing::info!(agent_id = %agent_id, "agent disconnected");
    }
}

async fn control_writer(
    mut sink: SplitSink<WebSocket, Message>,
    mut cmd_rx: mpsc::UnboundedReceiver<ServerToAgent>,
) {
    let mut ping = tokio::time::interval(Duration::from_secs(30));
    ping.tick().await; // consume the immediate first tick
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => match cmd {
                Some(cmd) => {
                    let txt = serde_json::to_string(&cmd).unwrap();
                    if sink.send(Message::Text(txt)).await.is_err() { break; }
                }
                None => break,
            },
            _ = ping.tick() => {
                let txt = serde_json::to_string(&ServerToAgent::Ping).unwrap();
                if sink.send(Message::Text(txt)).await.is_err() { break; }
            }
        }
    }
    let _ = sink.close().await;
}

async fn control_reader(stream: &mut SplitStream<WebSocket>, state: &Arc<AppState>) {
    while let Some(msg) = stream.next().await {
        let Ok(msg) = msg else { break };
        let text = match msg {
            Message::Text(t) => t,
            Message::Close(_) => break,
            Message::Ping(_) | Message::Pong(_) | Message::Binary(_) => continue,
        };
        let Ok(reply) = serde_json::from_str::<AgentToServer>(&text) else {
            continue;
        };
        match reply {
            AgentToServer::Pong => {}
            AgentToServer::SessionAccepted { session } => {
                signal_session(state, session, SessionSignal::Accepted).await;
            }
            AgentToServer::SessionDeclined { session, reason } => {
                signal_session(state, session, SessionSignal::Declined(reason)).await;
            }
            AgentToServer::ExecChunk {
                exec_id,
                stream,
                data,
            } => {
                forward_exec(state, exec_id, ExecEvent::Chunk { stream, data }).await;
            }
            AgentToServer::ExecDone {
                exec_id,
                exit_code,
                truncated,
                error,
            } => {
                forward_exec(
                    state,
                    exec_id,
                    ExecEvent::Done {
                        exit_code,
                        truncated,
                        error,
                    },
                )
                .await;
            }
        }
    }
}

async fn forward_exec(state: &Arc<AppState>, exec_id: Uuid, event: ExecEvent) {
    let maybe = state.execs.lock().await.get(&exec_id).cloned();
    if let Some(tx) = maybe {
        let _ = tx.send(event).await;
    }
}

async fn signal_session(state: &Arc<AppState>, session: Uuid, sig: SessionSignal) {
    let maybe = state.sessions.lock().await.get(&session).cloned();
    if let Some(s) = maybe {
        let _ = s.signal_tx.send(sig).await;
    }
}

// ---------------------------------------------------------------------------
// Agent session link
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SessionQuery {
    session: Uuid,
    nonce: String,
}

pub async fn agent_session_ws(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Query(q): Query<SessionQuery>,
) -> Response {
    ws.max_message_size(MAX_FRAME)
        .on_upgrade(move |socket| handle_agent_session(socket, state, q.session, q.nonce))
}

async fn handle_agent_session(
    socket: WebSocket,
    state: Arc<AppState>,
    session_id: Uuid,
    nonce: String,
) {
    let session = match state.sessions.lock().await.get(&session_id).cloned() {
        Some(s) => s,
        None => return, // unknown or already-finished session
    };

    // The nonce ties this dial to the exact OpenSession the relay authorised.
    let nonce_ok: bool = nonce.as_bytes().ct_eq(session.nonce.as_bytes()).into();
    if !nonce_ok {
        tracing::warn!(%session_id, "agent session rejected: bad nonce");
        return;
    }

    // Exactly one agent dial per session.
    let op2a_rx = match session.op_to_agent_rx.lock().await.take() {
        Some(rx) => rx,
        None => return,
    };
    let a2o_tx = session.agent_to_op_tx.clone();

    // Release the waiting operator.
    if let Some(tx) = session.ready_tx.lock().await.take() {
        let _ = tx.send(());
    }

    let (agent_sink, agent_stream) = socket.split();
    let reader = tokio::spawn(socket_to_channel(agent_stream, a2o_tx));
    channel_to_socket(op2a_rx, agent_sink).await;
    reader.abort();
}

// ---------------------------------------------------------------------------
// Generic byte bridge
// ---------------------------------------------------------------------------

/// Pump WebSocket messages into a channel, preserving binary vs text. Ends when
/// the socket closes/errors or the channel receiver is gone.
async fn socket_to_channel(mut stream: SplitStream<WebSocket>, tx: mpsc::Sender<Frame>) {
    while let Some(msg) = stream.next().await {
        let Ok(msg) = msg else { break };
        let frame = match msg {
            Message::Binary(b) => Frame::Binary(b),
            Message::Text(t) => Frame::Text(t),
            Message::Close(_) => break,
            Message::Ping(_) | Message::Pong(_) => continue,
        };
        if tx.send(frame).await.is_err() {
            break;
        }
    }
}

/// Pump frames from a channel to a WebSocket sink. Ends when all senders drop
/// (the other side closed) or the socket errors.
async fn channel_to_socket(mut rx: mpsc::Receiver<Frame>, mut sink: SplitSink<WebSocket, Message>) {
    while let Some(frame) = rx.recv().await {
        let msg = match frame {
            Frame::Binary(b) => Message::Binary(b),
            Frame::Text(t) => Message::Text(t),
        };
        if sink.send(msg).await.is_err() {
            break;
        }
    }
    let _ = sink.close().await;
}
