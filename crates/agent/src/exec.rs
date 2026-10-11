//! Non-interactive command execution on the agent side.
//!
//! This is the primitive a scripted operator (or an operator's own LLM session)
//! uses to inspect and fix the machine: one command in, stdout/stderr streamed
//! back as they arrive, a single exit code at the end, and a hard timeout that
//! kills the whole process tree. No PTY, no shell prompt to parse.

use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;
use rustlitel_proto::{AgentToServer, ExecStream};

/// How long to keep draining buffered output after the process has exited or
/// been killed, so a lingering grandchild that holds the pipe cannot hang us.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// Run `command` and report back over the control link via `ctl_tx`.
pub async fn run(
    allow_remote: bool,
    allowed_shells: &[String],
    exec_id: Uuid,
    command: String,
    requested_shell: Option<String>,
    timeout_secs: u64,
    ctl_tx: mpsc::UnboundedSender<Message>,
) {
    if !allow_remote {
        done(
            &ctl_tx,
            exec_id,
            None,
            Some("remote access is not enabled on this host".into()),
        );
        return;
    }

    let mut cmd = build_command(allowed_shells, requested_shell.as_deref(), &command);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // Own process group (unix) so a timeout kills the whole command tree, not
    // just the shell — otherwise a child like `sleep` keeps the pipe open.
    #[cfg(unix)]
    cmd.process_group(0);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            done(&ctl_tx, exec_id, None, Some(format!("spawn failed: {e}")));
            return;
        }
    };
    let pid = child.id();

    let out_task = child.stdout.take().map(|s| {
        let tx = ctl_tx.clone();
        tokio::spawn(pump(s, tx, exec_id, ExecStream::Stdout))
    });
    let err_task = child.stderr.take().map(|s| {
        let tx = ctl_tx.clone();
        tokio::spawn(pump(s, tx, exec_id, ExecStream::Stderr))
    });

    let (exit_code, error) =
        match tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait()).await {
            Ok(Ok(status)) => (status.code(), None),
            Ok(Err(e)) => (None, Some(format!("wait failed: {e}"))),
            Err(_) => {
                // Kill the tree BEFORE draining, so output stops and the pipes
                // close promptly.
                kill_tree(&mut child, pid).await;
                (
                    None,
                    Some(format!("timed out after {timeout_secs}s (process killed)")),
                )
            }
        };

    drain(out_task).await;
    drain(err_task).await;
    done(&ctl_tx, exec_id, exit_code, error);
}

/// Read a child stream and forward chunks as [`AgentToServer::ExecChunk`].
async fn pump<R: AsyncReadExt + Unpin>(
    mut reader: R,
    ctl_tx: mpsc::UnboundedSender<Message>,
    exec_id: Uuid,
    stream: ExecStream,
) {
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                let data = String::from_utf8_lossy(&buf[..n]).into_owned();
                let msg = AgentToServer::ExecChunk {
                    exec_id,
                    stream,
                    data,
                };
                if ctl_tx
                    .send(Message::Text(serde_json::to_string(&msg).unwrap()))
                    .is_err()
                {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

/// Await a pump task, but never longer than the drain grace — a grandchild that
/// still holds the pipe open must not stall the Done frame.
async fn drain(task: Option<JoinHandle<()>>) {
    if let Some(task) = task {
        let abort = task.abort_handle();
        if tokio::time::timeout(DRAIN_GRACE, task).await.is_err() {
            abort.abort();
        }
    }
}

/// Kill the process and, where possible, its whole tree.
async fn kill_tree(child: &mut Child, pid: Option<u32>) {
    #[cfg(unix)]
    {
        if let Some(pid) = pid {
            // Negative pid => the whole process group (we are the leader).
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
    }
    #[cfg(windows)]
    {
        if let Some(pid) = pid {
            // taskkill /T kills the child and its descendants.
            let _ = Command::new("taskkill")
                .args(["/PID", &pid.to_string(), "/T", "/F"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await;
        }
    }
    let _ = child.start_kill();
}

fn done(
    ctl_tx: &mpsc::UnboundedSender<Message>,
    exec_id: Uuid,
    exit_code: Option<i32>,
    error: Option<String>,
) {
    let msg = AgentToServer::ExecDone {
        exec_id,
        exit_code,
        truncated: false, // the relay owns the output cap / truncation flag
        error,
    };
    let _ = ctl_tx.send(Message::Text(serde_json::to_string(&msg).unwrap()));
}

/// Pick the shell and wrap `command` the way that shell expects.
fn build_command(allowed: &[String], requested: Option<&str>, command: &str) -> Command {
    let pick = match requested {
        Some("default") | None => allowed.first().map(String::as_str).unwrap_or("sh"),
        Some(r) if allowed.iter().any(|a| a == r) => r,
        Some(_) => allowed.first().map(String::as_str).unwrap_or("sh"),
    };

    if cfg!(windows) {
        match pick {
            "cmd" => {
                let mut c = Command::new("cmd.exe");
                c.args(["/C", command]);
                c
            }
            "pwsh" => powershell("pwsh.exe", command),
            _ => powershell("powershell.exe", command),
        }
    } else {
        let prog = match pick {
            "bash" => "/bin/bash",
            "zsh" => "/bin/zsh",
            _ => "/bin/sh",
        };
        let mut c = Command::new(prog);
        c.args(["-c", command]);
        c
    }
}

fn powershell(prog: &str, command: &str) -> Command {
    let mut c = Command::new(prog);
    c.args(["-NoProfile", "-NonInteractive", "-Command", command]);
    c
}
