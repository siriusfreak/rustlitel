//! In-memory state for the relay: connected agents and in-flight shell
//! sessions. One process, one replica — everything lives in `Mutex`-guarded
//! maps, no external store.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{mpsc, oneshot, Mutex};
use uuid::Uuid;
use rustlitel_proto::{AgentInfo, ExecStream, ServerToAgent};

use crate::auth::Auth;

/// One frame crossing a bridged session, carrying its WebSocket message kind so
/// binary PTY bytes and JSON control text stay distinct end to end.
#[derive(Debug, Clone)]
pub enum Frame {
    Binary(Vec<u8>),
    Text(String),
}

/// What the control link learned about an [`OpenSession`](ServerToAgent::OpenSession)
/// request, delivered to the waiting operator task.
#[derive(Debug, Clone)]
pub enum SessionSignal {
    Accepted,
    Declined(String),
}

/// A short installer link: a small random code standing in for the (long) baked
/// join key, so the URL an operator copies stays short. Kept in memory with a
/// TTL; lost on relay restart (just regenerate the link).
#[derive(Debug, Clone)]
pub struct ShortLink {
    pub os: String,
    pub name: Option<String>,
    pub join_key: String,
    pub expiry: Instant,
}

/// An exec event coming back on the control link, delivered to the waiting
/// `POST /api/exec` handler for its `exec_id`.
#[derive(Debug, Clone)]
pub enum ExecEvent {
    Chunk {
        stream: ExecStream,
        data: String,
    },
    Done {
        exit_code: Option<i32>,
        truncated: bool,
        error: Option<String>,
    },
}

/// A live agent's control link, as seen by the rest of the relay.
pub struct AgentConn {
    /// Identifies this specific control connection. When an agent reconnects
    /// with the same `agent_id` it replaces the map entry with a new `conn_id`;
    /// the old task then sees the mismatch on exit and does not evict the new
    /// registration.
    pub conn_id: Uuid,
    pub name: String,
    pub os: String,
    pub shells: Vec<String>,
    pub allow_remote: bool,
    pub connected_at: Instant,
    /// Push commands to the task that owns this agent's control socket.
    pub commands: mpsc::UnboundedSender<ServerToAgent>,
}

impl AgentConn {
    pub fn info(&self, agent_id: &str) -> AgentInfo {
        AgentInfo {
            agent_id: agent_id.to_string(),
            name: self.name.clone(),
            os: self.os.clone(),
            shells: self.shells.clone(),
            allow_remote: self.allow_remote,
            connected_secs: self.connected_at.elapsed().as_secs(),
        }
    }
}

/// One interactive shell being set up or bridged.
///
/// Created by the operator handler before it asks the agent to open a session,
/// so both the agent's session dial and the control-link reply can find it by
/// id. The two sockets never meet; they exchange [`Frame`]s through the two
/// channels held here.
pub struct Session {
    /// Owner agent; kept for diagnostics/inspection of the session table.
    #[allow(dead_code)]
    pub agent_id: String,
    /// Single-use secret the agent must present when it dials the session link.
    pub nonce: String,
    /// operator -> agent frames. Filled by the operator, taken (once) by the
    /// agent session handler.
    pub op_to_agent_rx: Mutex<Option<mpsc::Receiver<Frame>>>,
    /// agent -> operator frames. The agent session handler sends here; the
    /// operator reads the paired receiver it kept.
    pub agent_to_op_tx: mpsc::Sender<Frame>,
    /// Accept/decline verdict from the control link.
    pub signal_tx: mpsc::Sender<SessionSignal>,
    /// Taken and fired by the agent session handler when its link attaches,
    /// releasing the operator from its wait.
    pub ready_tx: Mutex<Option<oneshot::Sender<()>>>,
}

/// Everything the HTTP/WS handlers share.
pub struct AppState {
    pub agents: Mutex<HashMap<String, AgentConn>>,
    pub sessions: Mutex<HashMap<Uuid, Arc<Session>>>,
    /// In-flight non-interactive commands, keyed by exec id. The control-link
    /// reader forwards output/finish events here to the waiting HTTP handler.
    pub execs: Mutex<HashMap<Uuid, mpsc::Sender<ExecEvent>>>,
    pub auth: Auth,
    /// Enrollment token every agent must present. Compared constant-time.
    pub agent_token: String,
    /// Expected browser Origin for WS upgrades and login, or `None` to skip the
    /// check (local dev). e.g. `https://relay.example.com`.
    pub public_origin: Option<String>,
    /// How long the operator waits for an agent to accept + dial before giving
    /// up, in seconds.
    pub open_timeout_secs: u64,
    /// Per-stream output cap (bytes) the relay keeps for an exec result.
    pub exec_output_cap: usize,
    /// Default exec wall-clock limit when the caller does not specify one.
    pub exec_default_timeout_secs: u64,
    /// Directory holding stock agent binaries to download / bake installers from.
    pub agents_dir: String,
    /// Directory holding the compiled egui/WASM UI bundle (index.html + assets).
    pub ui_dir: String,
    /// OIDC (Keycloak) operator login, when configured; `None` falls back to
    /// operator-token login.
    pub oidc: Option<crate::oidc::Oidc>,
    /// Short installer links: code -> baked-installer params. In memory, TTL'd.
    pub short_links: Mutex<HashMap<String, ShortLink>>,
    /// How long a short installer link stays valid.
    pub short_link_ttl: std::time::Duration,
    /// Public Keycloak client id the `wrs` CLI uses for its device-flow login.
    pub oidc_cli_client_id: String,
}

impl AppState {
    /// Drop a session from the table. Both bridge handlers call this on exit;
    /// removing an absent id is a no-op, so a double call is harmless.
    pub async fn remove_session(&self, id: &Uuid) {
        self.sessions.lock().await.remove(id);
    }
}
