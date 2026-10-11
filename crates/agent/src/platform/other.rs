//! Non-Windows stubs. On Unix, run the agent in the foreground, or wrap it in a
//! systemd unit / launchd plist for unattended operation.

use crate::RunArgs;

pub fn install(_args: RunArgs) {
    eprintln!(
        "`install` is Windows-only. On Unix, run `rustlitel-agent` in the foreground \
         or under systemd/launchd for unattended operation."
    );
}

pub fn uninstall() {
    eprintln!("`uninstall` is Windows-only.");
}

pub fn run_service(_args: RunArgs) {
    eprintln!("`service` is Windows-only.");
}

/// Self-delete: a foreground Unix agent just removes its own binary (unlinking a
/// running executable is allowed on Unix); the caller then exits.
pub fn self_uninstall() {
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::fs::remove_file(exe);
    }
}

/// Swap our own binary for `new_bytes` and re-exec. Unix lets us rename over a
/// running executable, so we stage the new file in the same directory (same
/// filesystem, for an atomic rename), make it executable, move it into place,
/// then launch a fresh process with our original arguments and exit. Under a
/// supervisor (systemd/launchd with restart-on-exit) the plain exit alone also
/// brings the new binary back up; the explicit re-exec just makes a foreground
/// run self-heal too.
pub fn apply_update(new_bytes: &[u8]) -> anyhow::Result<()> {
    use anyhow::Context;

    let exe = std::env::current_exe().context("current_exe")?;
    let dir = exe.parent().context("exe has no parent dir")?;
    let staged = dir.join(".rustlitel-agent.new");
    std::fs::write(&staged, new_bytes)
        .with_context(|| format!("stage update at {}", staged.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))
            .context("chmod staged binary")?;
    }

    std::fs::rename(&staged, &exe).with_context(|| format!("replace {}", exe.display()))?;

    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::Command::new(&exe)
        .args(&args)
        .spawn()
        .context("re-exec updated binary")?;
    tracing::info!("self-update applied; restarting");
    std::process::exit(0);
}
