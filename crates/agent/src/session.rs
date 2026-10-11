//! One interactive shell session on the agent side.
//!
//! portable-pty gives a real PTY on every platform — ConPTY on Windows, a
//! Unix98 pty elsewhere — so arrow keys, colours, resizing and full-screen TUIs
//! all work. Its reader/writer handles are blocking, so the blocking I/O lives
//! on dedicated OS threads and talks to the async WebSocket task over channels.

use std::io::{Read, Write};
use std::sync::mpsc as stdmpsc;

use anyhow::Context;
use futures_util::{SinkExt, StreamExt};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;
use rustlitel_proto::SessionControl;

/// Run a shell for one session: open a PTY, dial the relay's session link, and
/// pump bytes until either side closes or the shell exits.
pub async fn run(
    base_ws: &str,
    session: Uuid,
    nonce: &str,
    cols: u16,
    rows: u16,
    shell: &str,
) -> anyhow::Result<()> {
    // --- PTY + shell -------------------------------------------------------
    let pty = native_pty_system();
    let pair = pty
        .openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .context("openpty")?;

    let mut cmd = CommandBuilder::new(shell);
    cmd.env("TERM", "xterm-256color");
    if let Some(home) = dirs_home() {
        cmd.cwd(home);
    }

    let mut child = pair.slave.spawn_command(cmd).context("spawn shell")?;
    let mut killer = child.clone_killer();
    // Drop the slave so the master sees EOF once the shell exits.
    drop(pair.slave);

    let mut reader = pair.master.try_clone_reader().context("clone reader")?;
    let mut writer = pair.master.take_writer().context("take writer")?;
    let master = pair.master; // kept only for resize

    // --- relay session link ------------------------------------------------
    let url = format!("{base_ws}/ws/agent/session?session={session}&nonce={nonce}");
    let (ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .context("dial session link")?;
    let (mut ws_sink, mut ws_stream) = ws.split();

    // PTY -> async: a blocking thread reads the master and forwards chunks.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if out_tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // async -> PTY: a blocking thread drains keystrokes into the master writer.
    let (in_tx, in_rx) = stdmpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        while let Ok(bytes) = in_rx.recv() {
            if writer.write_all(&bytes).is_err() {
                break;
            }
            let _ = writer.flush();
        }
    });

    // Child reaper: fire a signal when the shell exits.
    let (done_tx, mut done_rx) = mpsc::channel::<()>(1);
    std::thread::spawn(move || {
        let _ = child.wait();
        let _ = done_tx.blocking_send(());
    });

    // --- bridge ------------------------------------------------------------
    loop {
        tokio::select! {
            // Terminal output -> operator (binary frames).
            chunk = out_rx.recv() => match chunk {
                Some(bytes) => {
                    if ws_sink.send(Message::Binary(bytes)).await.is_err() { break; }
                }
                None => break, // PTY closed
            },
            // Operator input -> terminal.
            msg = ws_stream.next() => match msg {
                Some(Ok(Message::Binary(b))) => { let _ = in_tx.send(b); }
                Some(Ok(Message::Text(t))) => {
                    if let Ok(SessionControl::Resize { cols, rows }) = serde_json::from_str(&t) {
                        let _ = master.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 });
                    }
                }
                Some(Ok(Message::Ping(p))) => { let _ = ws_sink.send(Message::Pong(p)).await; }
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                _ => {}
            },
            // Shell exited.
            _ = done_rx.recv() => break,
        }
    }

    // Best-effort cleanup: kill the shell, close the socket. Dropping in_tx
    // stops the writer thread; the reader thread ends when the PTY closes.
    let _ = killer.kill();
    let _ = ws_sink.send(Message::Close(None)).await;
    Ok(())
}

#[cfg(unix)]
fn dirs_home() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(Into::into)
}

#[cfg(windows)]
fn dirs_home() -> Option<std::path::PathBuf> {
    std::env::var_os("USERPROFILE").map(Into::into)
}
