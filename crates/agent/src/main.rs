//! rustlitel-agent — runs on the machine behind NAT (typically Windows). It dials out
//! to the relay, registers, and runs shells / commands only when an operator
//! asks *and* local consent allows it.
//!
//! Subcommands:
//!   (none) / `run`   run in the foreground (dev, or a hand-managed process)
//!   `install`        Windows: ask for consent, then install an auto-starting
//!                    service for UNATTENDED access
//!   `uninstall`      Windows: stop and remove that service
//!   `service`        Windows: SCM entry point (used by the service itself)
//!
//! Consent, from weakest to strongest:
//!   * without `--allow-remote` the agent connects and is listed, but declines
//!     every session/exec — running it is harmless until you opt in;
//!   * with `--allow-remote` it accepts them (running it *is* the grant);
//!   * `install` shows a dialog that spells out unattended access and only
//!     proceeds on "Yes"; the installed service then runs with `--allow-remote`;
//!   * `--confirm` (foreground only) additionally requires an interactive y/N
//!     in the console for every interactive session.

mod embedded;
mod exec;
mod platform;
mod session;
mod update;

use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use rustlitel_proto::{AgentHello, AgentToServer, InstallerConfig, ServerToAgent, PROTOCOL_VERSION};

#[derive(Parser, Debug)]
#[command(name = "rustlitel-agent", about = "Remote-shell agent that dials out to a relay")]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
    #[command(flatten)]
    run: RunArgs,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run in the foreground (default when no subcommand is given).
    Run,
    /// Windows: consent to, and install, the unattended-access service.
    Install,
    /// Windows: stop and remove the service.
    Uninstall,
    /// Windows: service entry point (invoked by the Service Control Manager).
    #[command(hide = true)]
    Service,
}

/// Shared configuration. relay/token are optional here so `uninstall` can run
/// without them; the paths that need them validate at runtime.
// Args are `global` so they are accepted whether they appear before or after a
// subcommand — the Windows service is launched as `rustlitel-agent service --relay …`,
// and without this clap rejects the flags that follow the subcommand.
#[derive(Args, Debug, Clone)]
pub struct RunArgs {
    /// Relay base URL, e.g. wss://relay.example.com (ws:// for local dev).
    #[arg(long, env = "RUSTLITEL_RELAY", global = true)]
    pub relay: Option<String>,

    /// Enrollment token (must match the relay's RUSTLITEL_AGENT_TOKEN).
    #[arg(long, env = "RUSTLITEL_AGENT_TOKEN", global = true)]
    pub token: Option<String>,

    /// Display name in the web UI (defaults to the hostname).
    #[arg(long, global = true)]
    pub name: Option<String>,

    /// Stable id operators address (defaults to the hostname).
    #[arg(long, global = true)]
    pub id: Option<String>,

    /// Allowed shells, first is the default. Defaults per-OS.
    #[arg(long = "shell", global = true)]
    pub shells: Vec<String>,

    /// Accept sessions/exec. Without it, the agent connects but declines
    /// everything. `install` turns this on after the consent dialog.
    #[arg(long, global = true)]
    pub allow_remote: bool,

    /// Foreground only: also require an interactive y/N for every session.
    #[arg(long, global = true)]
    pub confirm: bool,

    /// Reconnect backoff in seconds after the control link drops.
    #[arg(long, default_value = "5", global = true)]
    pub reconnect_secs: u64,

    /// Keep the installed binary current by pulling fresh builds from the relay
    /// (the service turns this on; off by default so a dev `run` is never
    /// overwritten by the deployed build).
    #[arg(long, global = true)]
    pub self_update: bool,

    /// How often (seconds) to poll the relay for a newer build. A check also
    /// runs on every (re)connect, so a relay rollout propagates within one
    /// reconnect regardless of this interval.
    #[arg(long, default_value = "21600", global = true)]
    pub update_interval_secs: u64,
}

fn main() {
    // rustls 0.23 refuses to pick a crypto provider on its own; install one
    // before any wss:// dial. Idempotent-safe: ignore "already installed".
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    match cli.command {
        Some(Cmd::Install) => {
            init_logging();
            platform::install(cli.run);
        }
        Some(Cmd::Uninstall) => {
            init_logging();
            platform::uninstall();
        }
        Some(Cmd::Service) => {
            // The SCM dispatcher manages its own lifecycle; it builds the tokio
            // runtime internally.
            platform::run_service(cli.run);
        }
        Some(Cmd::Run) => {
            init_logging();
            block_on_foreground(cli.run);
        }
        None => {
            init_logging();
            // A generated one-click installer is a stock binary with a config
            // trailer and no arguments: honour that trailer here.
            if cli.run.relay.is_none() {
                if let Some(cfg) = embedded::read() {
                    run_from_embedded(cfg);
                    return;
                }
            }
            block_on_foreground(cli.run);
        }
    }
}

fn block_on_foreground(args: RunArgs) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(run_foreground(args));
}

/// Act on a baked installer config: install (Windows) or, as a fallback on
/// other platforms / `auto != "install"`, run in the foreground.
fn run_from_embedded(cfg: InstallerConfig) {
    let auto = cfg.auto.clone().unwrap_or_else(|| "install".into());
    let args = RunArgs {
        relay: Some(cfg.relay),
        token: Some(cfg.token),
        name: cfg.name,
        id: None,
        shells: vec![],
        allow_remote: true,
        confirm: false,
        reconnect_secs: 5,
        self_update: true,
        update_interval_secs: 21600,
    };

    if auto == "install" && cfg!(windows) {
        platform::install(args);
    } else {
        block_on_foreground(args);
    }
}

fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("RUSTLITEL_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
}

/// Foreground entry: print a banner, then serve until Ctrl-C.
async fn run_foreground(args: RunArgs) {
    print_banner(&args);
    tokio::select! {
        _ = serve(args) => {},
        _ = tokio::signal::ctrl_c() => { tracing::info!("interrupted, exiting"); }
    }
}

fn print_banner(args: &RunArgs) {
    let host = gethostname::gethostname().to_string_lossy().to_string();
    eprintln!("rustlitel-agent — host={host}");
    eprintln!("  relay:         {}", args.relay.as_deref().unwrap_or("(unset!)"));
    eprintln!(
        "  remote access: {}{}",
        if args.allow_remote { "ENABLED" } else { "disabled (declines everything)" },
        if args.confirm { ", per-session confirm required" } else { "" }
    );
}

/// Reconnecting control loop. Runs forever (callers add their own shutdown).
pub async fn serve(args: RunArgs) {
    let host = gethostname::gethostname().to_string_lossy().to_string();
    let agent_id = args.id.clone().unwrap_or_else(|| host.clone());
    let name = args.name.clone().unwrap_or_else(|| host.clone());
    let shells = if args.shells.is_empty() {
        default_shells()
    } else {
        args.shells.clone()
    };
    let Some(relay) = args.relay.clone() else {
        tracing::error!("no relay URL configured (--relay / RUSTLITEL_RELAY)");
        return;
    };
    let base_ws = relay.trim_end_matches('/').to_string();

    // Self-update (installed agents only): a periodic poller plus a check on
    // every (re)connect, so a relay rollout reaches agents within one reconnect.
    let updater = args
        .self_update
        .then(|| args.token.clone())
        .flatten()
        .and_then(|tok| update::Updater::new(&base_ws, tok, Duration::from_secs(30)));
    if let Some(u) = &updater {
        update::spawn(
            u.clone(),
            Duration::from_secs(args.update_interval_secs.max(60)),
        );
    }

    loop {
        if let Err(e) = run_control(&args, &base_ws, &agent_id, &name, &shells, updater.as_ref()).await
        {
            tracing::warn!("control link ended: {e:#}");
        }
        tracing::info!("reconnecting in {}s", args.reconnect_secs);
        tokio::time::sleep(Duration::from_secs(args.reconnect_secs)).await;
    }
}

/// Connect the control link, register, and service commands until it drops.
async fn run_control(
    args: &RunArgs,
    base_ws: &str,
    agent_id: &str,
    name: &str,
    shells: &[String],
    updater: Option<&std::sync::Arc<update::Updater>>,
) -> anyhow::Result<()> {
    let token = args
        .token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("no agent token configured (--token / RUSTLITEL_AGENT_TOKEN)"))?;

    let url = format!("{base_ws}/ws/agent/control");
    let (ws, _) = tokio_tungstenite::connect_async(&url).await?;
    let (mut ws_sink, mut ws_stream) = ws.split();

    let (ctl_tx, mut ctl_rx) = mpsc::unbounded_channel::<Message>();

    let hello = AgentHello {
        protocol: PROTOCOL_VERSION,
        token,
        agent_id: agent_id.to_string(),
        name: name.to_string(),
        os: os_string(),
        shells: shells.to_vec(),
        allow_remote: args.allow_remote,
    };
    ws_sink
        .send(Message::Text(serde_json::to_string(&hello)?))
        .await?;
    tracing::info!("registered with relay as {agent_id}");

    // A relay rollout drops every control link; the reconnect that follows is
    // our cue to check for a fresh build (rate-limited inside the updater).
    if let Some(u) = updater {
        let u = u.clone();
        tokio::spawn(async move { u.maybe_check().await });
    }

    let writer = tokio::spawn(async move {
        while let Some(msg) = ctl_rx.recv().await {
            if ws_sink.send(msg).await.is_err() {
                break;
            }
        }
    });

    while let Some(msg) = ws_stream.next().await {
        let msg = msg?;
        match msg {
            Message::Text(t) => {
                let Ok(cmd) = serde_json::from_str::<ServerToAgent>(&t) else {
                    continue;
                };
                dispatch(cmd, args, base_ws, shells, &ctl_tx);
            }
            Message::Ping(p) => {
                let _ = ctl_tx.send(Message::Pong(p));
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    writer.abort();
    Ok(())
}

fn dispatch(
    cmd: ServerToAgent,
    args: &RunArgs,
    base_ws: &str,
    shells: &[String],
    ctl_tx: &mpsc::UnboundedSender<Message>,
) {
    match cmd {
        ServerToAgent::Ping => {
            let _ = ctl_tx.send(reply(&AgentToServer::Pong));
        }
        ServerToAgent::Uninstall => {
            tracing::warn!("uninstall requested by operator — removing self");
            tokio::spawn(async move {
                // Give in-flight control frames a moment to flush, then kick off
                // the (detached) self-removal and exit.
                tokio::time::sleep(Duration::from_millis(400)).await;
                platform::self_uninstall();
                tokio::time::sleep(Duration::from_millis(400)).await;
                std::process::exit(0);
            });
        }
        ServerToAgent::OpenSession {
            session,
            nonce,
            cols,
            rows,
            shell,
        } => {
            let allow = args.allow_remote;
            let confirm = args.confirm;
            let shells = shells.to_vec();
            let base_ws = base_ws.to_string();
            let ctl_tx = ctl_tx.clone();
            tokio::spawn(async move {
                handle_open(
                    allow, confirm, &shells, base_ws, session, nonce, cols, rows, shell, ctl_tx,
                )
                .await;
            });
        }
        ServerToAgent::Exec {
            exec_id,
            command,
            shell,
            timeout_secs,
        } => {
            let allow = args.allow_remote;
            let shells = shells.to_vec();
            let ctl_tx = ctl_tx.clone();
            tokio::spawn(async move {
                exec::run(allow, &shells, exec_id, command, shell, timeout_secs, ctl_tx).await;
            });
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_open(
    allow_remote: bool,
    confirm: bool,
    shells: &[String],
    base_ws: String,
    session: uuid::Uuid,
    nonce: String,
    cols: u16,
    rows: u16,
    requested_shell: Option<String>,
    ctl_tx: mpsc::UnboundedSender<Message>,
) {
    if !allow_remote {
        let _ = ctl_tx.send(reply(&AgentToServer::SessionDeclined {
            session,
            reason: "remote access is not enabled on this host".into(),
        }));
        return;
    }
    if confirm && !confirm_prompt(&session).await {
        let _ = ctl_tx.send(reply(&AgentToServer::SessionDeclined {
            session,
            reason: "operator confirmation was denied at the host".into(),
        }));
        return;
    }

    let shell = resolve_shell(shells, requested_shell.as_deref());
    let _ = ctl_tx.send(reply(&AgentToServer::SessionAccepted { session }));
    tracing::info!(%session, shell = %shell, "opening session");

    if let Err(e) = session::run(&base_ws, session, &nonce, cols, rows, &shell).await {
        tracing::warn!(%session, "session ended with error: {e:#}");
    } else {
        tracing::info!(%session, "session closed");
    }
}

/// Block up to 30s for a y/N in the agent's console. EOF / timeout / anything
/// other than y|yes counts as "no".
async fn confirm_prompt(session: &uuid::Uuid) -> bool {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let short = &session.to_string()[..8];
    eprintln!("\n*** Remote shell session requested (id {short}). Allow? [y/N] ***");
    let mut line = String::new();
    let mut stdin = BufReader::new(tokio::io::stdin());
    let read = tokio::time::timeout(Duration::from_secs(30), stdin.read_line(&mut line)).await;
    match read {
        Ok(Ok(n)) if n > 0 => matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"),
        _ => {
            eprintln!("(no answer — session declined)");
            false
        }
    }
}

fn reply(msg: &AgentToServer) -> Message {
    Message::Text(serde_json::to_string(msg).unwrap())
}

fn default_shells() -> Vec<String> {
    if cfg!(windows) {
        vec!["powershell".into(), "cmd".into()]
    } else {
        vec!["bash".into(), "sh".into()]
    }
}

/// Map a logical shell name to an interactive program for the current OS.
fn resolve_shell(allowed: &[String], requested: Option<&str>) -> String {
    let pick = match requested {
        Some("default") | None => allowed.first().map(String::as_str).unwrap_or("sh"),
        Some(r) if allowed.iter().any(|a| a == r) => r,
        Some(_) => allowed.first().map(String::as_str).unwrap_or("sh"),
    };
    if cfg!(windows) {
        match pick {
            "powershell" => "powershell.exe",
            "pwsh" => "pwsh.exe",
            "cmd" => "cmd.exe",
            other => other,
        }
        .to_string()
    } else {
        match pick {
            "bash" => "/bin/bash",
            "sh" => "/bin/sh",
            "zsh" => "/bin/zsh",
            other => other,
        }
        .to_string()
    }
}

fn os_string() -> String {
    format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
}
