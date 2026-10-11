//! Wire protocol shared by the relay and the agent.
//!
//! Two kinds of links exist between an agent and the relay:
//!
//! * the **control** link — one long-lived WebSocket per agent. The agent sends
//!   [`AgentHello`] once, then the relay pushes [`ServerToAgent`] commands and
//!   the agent answers with [`AgentToServer`] messages. All JSON text frames.
//! * a **session** link — one short-lived WebSocket per interactive shell. Raw
//!   PTY bytes travel as binary frames; small JSON [`SessionControl`] messages
//!   (resize) travel as text frames. The relay never interprets the binary
//!   bytes, it only bridges them to the operator's browser socket.
//!
//! The agent cannot be dialled (it lives behind NAT with no public IP), so the
//! agent always *dials out* to the relay for both links. A session link is
//! authorised by a single-use [`ServerToAgent::OpenSession::nonce`] rather than
//! by re-sending the agent token in a URL.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Current protocol version. The agent sends it in [`AgentHello`] so the relay
/// can refuse an agent that is too old/new to bridge safely.
pub const PROTOCOL_VERSION: u32 = 1;

/// Build identifier, baked in at compile time (see this crate's `build.rs`).
/// The relay and the agent are compiled from the same tree, so they share this
/// value; a self-updating agent compares the relay's `BUILD_ID` to its own and
/// pulls a fresh binary when they differ.
pub const BUILD_ID: &str = env!("RUSTLITEL_BUILD_ID");

/// Monotonic build epoch (a unix timestamp by default; see `build.rs`). A
/// self-updating agent installs a relay's build only when its epoch is
/// *strictly greater* than the agent's own, so a rolled-back or hostile relay
/// cannot force a downgrade to an older, known-vulnerable build.
pub fn build_epoch() -> u64 {
    env!("RUSTLITEL_BUILD_EPOCH").parse().unwrap_or(0)
}

/// Base64 (standard) ed25519 public key the agent verifies a self-update
/// signature against, baked in at build time. Empty when update signing isn't
/// configured — the agent then refuses to self-update (fail closed), because an
/// unsigned update would reduce to "trust whatever the relay serves".
pub const UPDATE_PUBKEY: &str = env!("RUSTLITEL_UPDATE_PUBKEY");

/// Context prefix mixed into the signed self-update message, so an ed25519
/// signature can never be confused with a signature over anything else.
pub const UPDATE_SIG_CONTEXT: &str = "rustlitel-update-v1";

/// Build the exact bytes an update signature covers: the context, version,
/// epoch, binary sha256 (lowercase hex) and size, one per line. Both the
/// offline signer and the agent reconstruct this identically.
pub fn update_signing_message(version: &str, build_epoch: u64, sha256_hex: &str, size: u64) -> String {
    format!(
        "{UPDATE_SIG_CONTEXT}\n{version}\n{build_epoch}\n{}\n{size}",
        sha256_hex.to_ascii_lowercase()
    )
}

/// First frame the agent sends on the control link, right after connecting.
///
/// The relay validates `token` (constant-time) before registering the agent;
/// an agent whose token does not match is dropped without ever appearing in the
/// operator's agent list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHello {
    pub protocol: u32,
    /// Enrollment token. Must equal the relay's configured agent token.
    pub token: String,
    /// Stable identifier for this machine (defaults to the hostname). Used as
    /// the key operators address; a reconnecting agent with the same id
    /// replaces its previous registration.
    pub agent_id: String,
    /// Human-friendly label shown in the web UI.
    pub name: String,
    /// e.g. "windows 10.0.22631" — informational only.
    pub os: String,
    /// Shells the agent is willing to launch, e.g. `["powershell", "cmd"]`.
    pub shells: Vec<String>,
    /// False when the agent was started without `--allow-remote`: it is visible
    /// but will decline every session. Lets the operator see *why* nothing
    /// opens instead of staring at a silent timeout.
    pub allow_remote: bool,
}

/// Commands the relay pushes to the agent over the control link (JSON text).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerToAgent {
    /// An operator asked for an interactive shell. The agent performs its local
    /// consent check and, if it agrees, dials
    /// `GET {base}/ws/agent/session?session={session}&nonce={nonce}` and runs a
    /// PTY over that link. If it refuses it answers with
    /// [`AgentToServer::SessionDeclined`] and dials nothing.
    OpenSession {
        session: Uuid,
        /// Single-use secret tying the session dial to this authorised command.
        nonce: String,
        cols: u16,
        rows: u16,
        /// Requested shell; the agent falls back to its default if unknown.
        shell: Option<String>,
    },
    /// Run one command non-interactively and stream its output back. This is
    /// the primitive a scripted/LLM operator uses: discrete command in,
    /// stdout/stderr + exit code out — no PTY parsing. The agent captures
    /// output as [`ExecChunk`](AgentToServer::ExecChunk) frames and finishes
    /// with [`ExecDone`](AgentToServer::ExecDone). Gated by `--allow-remote`
    /// (but never by the interactive `--confirm` prompt).
    Exec {
        exec_id: Uuid,
        command: String,
        /// Which shell to run under; agent falls back to its default.
        shell: Option<String>,
        /// Hard wall-clock limit; the agent kills the process when it elapses.
        timeout_secs: u64,
    },
    /// Self-delete: the agent uninstalls itself (on Windows: stop + delete the
    /// service and remove its installed copy) and exits. Triggered by the
    /// operator's "uninstall" button.
    Uninstall,
    /// Liveness probe; the agent answers [`AgentToServer::Pong`].
    Ping,
}

/// Which captured stream an [`ExecChunk`](AgentToServer::ExecChunk) carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecStream {
    Stdout,
    Stderr,
}

/// Messages the agent sends back on the control link (JSON text).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentToServer {
    Pong,
    /// The agent will not open the requested session. `reason` is surfaced to
    /// the operator in the browser so a refusal never looks like a hang.
    SessionDeclined { session: Uuid, reason: String },
    /// The operator-side consent prompt was accepted; purely informational so
    /// the UI can show "starting…" instead of a blank screen.
    SessionAccepted { session: Uuid },
    /// A piece of a running command's output. `data` is UTF-8 (lossy); binary
    /// command output is rare and not a goal of the exec path.
    ExecChunk {
        exec_id: Uuid,
        stream: ExecStream,
        data: String,
    },
    /// A command finished (or was refused / timed out / killed). Exactly one of
    /// these ends each exec. `exit_code` is `None` if the process was killed or
    /// never started; `error` carries a human-readable reason in that case.
    ExecDone {
        exec_id: Uuid,
        exit_code: Option<i32>,
        /// Output hit the per-stream cap and was cut short.
        truncated: bool,
        error: Option<String>,
    },
}

/// Text control frames on a *session* link (both directions use the same type;
/// today only the operator -> agent resize is defined).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionControl {
    Resize { cols: u16, rows: u16 },
}

/// Magic marking an installer config trailer appended to an agent binary.
/// Layout at EOF: `<json><INSTALLER_MAGIC (8 bytes)><u32 LE json length>`.
pub const INSTALLER_MAGIC: &[u8; 8] = b"RUSTLTL1";

/// Config baked into a generated one-click installer binary. When the agent
/// starts with no arguments and finds this trailer, it acts on `auto`:
/// `"install"` runs the consent dialog + autostart install (Windows), anything
/// else runs in the foreground (useful for testing a baked binary).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallerConfig {
    pub relay: String,
    /// The per-installer join key.
    pub token: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub auto: Option<String>,
}

/// A single row in the operator's `GET /api/agents` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub agent_id: String,
    pub name: String,
    pub os: String,
    pub shells: Vec<String>,
    pub allow_remote: bool,
    /// Seconds since the agent connected.
    pub connected_secs: u64,
}
