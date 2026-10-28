//! Windows install / uninstall / service runtime.
//!
//! `install` shows a consent dialog that spells out unattended access; only on
//! "Yes" does it register an auto-start Windows service (so the agent comes up
//! at every boot with no one logged in) and start it immediately. `uninstall`
//! stops and removes it. `service` is the Service Control Manager entry point:
//! it runs the same reconnecting agent loop and shuts it down on the Stop
//! control.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::mpsc as stdmpsc;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::Context;

use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, IDYES, MB_ICONERROR, MB_ICONINFORMATION, MB_ICONWARNING, MB_OK, MB_TOPMOST,
    MB_YESNO,
};

use crate::RunArgs;

const SERVICE_NAME: &str = "rustlitel-agent";
const SERVICE_DISPLAY: &str = "rustlitel agent";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// Args handed from the `service` subcommand into the SCM-invoked service_main.
static SERVICE_ARGS: OnceLock<RunArgs> = OnceLock::new();

// --- install ---------------------------------------------------------------

pub fn install(mut args: RunArgs) {
    if args.relay.as_deref().unwrap_or("").is_empty() || args.token.as_deref().unwrap_or("").is_empty()
    {
        message(
            "Missing configuration",
            "Both --relay and --token are required to install the agent.",
            MB_ICONERROR,
        );
        eprintln!("install: --relay and --token are required");
        return;
    }
    let relay = args.relay.clone().unwrap();

    // The consent dialog is the grant. Make the consequences explicit.
    let prompt = format!(
        "Install the Remote Shell Agent on THIS computer for UNATTENDED access?\r\n\r\n\
         Relay: {relay}\r\n\r\n\
         While installed, whoever holds the agent token on that relay can open a \
         shell and run commands on this PC AT ANY TIME, with no further prompt here. \
         The agent is installed as a Windows service and starts automatically at \
         every boot, even when no one is signed in.\r\n\r\n\
         Only continue if you trust that operator and intend to grant this access.\r\n\r\n\
         Proceed with the installation?"
    );
    if !confirm(&prompt, "Grant unattended remote access?") {
        eprintln!("install: cancelled by user");
        return;
    }

    // Creating a service needs Administrator. If we are not elevated, relaunch
    // ourselves through UAC and let that instance do the work — so a plain
    // double-click works without "Run as administrator".
    if !is_elevated() {
        if relaunch_elevated() {
            return; // the elevated instance takes over
        }
        fail(
            "Installing the service needs Administrator rights, and elevation was \
             cancelled.\r\n\r\nRight-click the installer and choose \"Run as administrator\".",
        );
        return;
    }

    // The dialog is the consent, so the service always runs with remote enabled.
    args.allow_remote = true;

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            fail(&format!("Cannot determine the agent's own path: {e}"));
            return;
        }
    };

    let started = match do_install(&exe, &args) {
        Ok(started) => started,
        Err(e) => {
            fail(&format!(
                "Failed to install the service: {e:#}\r\n\r\n\
                 Try `rustlitel-agent uninstall` (as Administrator), then run the \
                 installer again."
            ));
            return;
        }
    };

    let note = if started {
        "installed and running"
    } else {
        "installed; it will start on the next boot"
    };
    message(
        "Installed",
        &format!(
            "The Remote Shell Agent is {note}.\r\n\r\n\
             It was copied to Program Files and reconnects to {relay}, starting \
             automatically at every boot — you can delete this downloaded \
             installer now.\r\n\r\n\
             To remove it later, run:  rustlitel-agent uninstall  (as Administrator)."
        ),
        MB_ICONINFORMATION,
    );
    println!("install: service '{SERVICE_NAME}' created (auto-start), started={started}");
}

/// Install the service. Copies the binary to a stable location (so deleting the
/// downloaded installer does not break the service), removes any previous
/// registration first (idempotent reinstall), registers it as auto-start, and
/// tries to start it. Returns whether it started.
fn do_install(src_exe: &Path, args: &RunArgs) -> anyhow::Result<bool> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;

    // Stop + delete any previous install first, which also frees its binary so
    // we can overwrite the installed copy below.
    remove_existing(&manager);

    // Copy ourselves to Program Files so the service survives deleting the
    // download. The binary carries an installer config trailer, but the service
    // runs with an explicit `service ...` command line, so the trailer is
    // ignored at runtime — harmless.
    let target = install_dir().join("rustlitel-agent.exe");
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create {}", parent.display()))?;
    }
    if !same_file(src_exe, &target) {
        std::fs::copy(src_exe, &target)
            .with_context(|| format!("copy agent to {}", target.display()))?;
    }

    // Write the enrollment token to an admin-only file rather than onto the
    // service command line (which Windows persists in the world-readable
    // registry ImagePath). The service reads it via `--token-file`.
    let token_path = install_dir().join("agent.token");
    if let Some(tok) = args.token.as_deref().filter(|t| !t.is_empty()) {
        std::fs::write(&token_path, tok)
            .with_context(|| format!("write token file {}", token_path.display()))?;
        restrict_acl(&token_path);
    }

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY),
        service_type: SERVICE_TYPE,
        // AutoStart == "прописаться в автозагрузку": launched by the SCM at boot.
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: target.clone(),
        launch_arguments: service_launch_args(args, &token_path),
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    let service = manager.create_service(
        &info,
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
    )?;
    let _ = service.set_description(
        "Dials out to the configured relay to allow unattended remote shell / exec \
         access to this machine.",
    );
    // Starting may legitimately fail (e.g. a slow SCM) while the service is
    // correctly installed as auto-start; report that rather than failing.
    let started = service.start::<&std::ffi::OsStr>(&[]).is_ok();
    Ok(started)
}

/// Where the service binary is installed: `%ProgramFiles%\rustlitel-agent`.
fn install_dir() -> PathBuf {
    std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\Program Files"))
        .join("rustlitel-agent")
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// Lock a file down to SYSTEM + Administrators (drop inherited Users access), so
/// a standard local user can't read it. Used for the enrollment-token file.
/// Best-effort: a failure leaves the inherited ACL in place.
fn restrict_acl(path: &Path) {
    // Well-known SIDs (locale-independent): S-1-5-18 = LocalSystem,
    // S-1-5-32-544 = BUILTIN\Administrators.
    let status = std::process::Command::new("icacls")
        .arg(path)
        .args([
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:F",
            "/grant:r",
            "*S-1-5-32-544:F",
        ])
        .status();
    if !matches!(status, Ok(s) if s.success()) {
        tracing::warn!("could not restrict ACL on {}", path.display());
    }
}

/// Best-effort removal of a previous `rustlitel-agent` service so install is idempotent.
fn remove_existing(manager: &ServiceManager) {
    let Ok(svc) = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    ) else {
        return; // not installed
    };
    if let Ok(status) = svc.query_status() {
        if status.current_state != ServiceState::Stopped {
            let _ = svc.stop();
            std::thread::sleep(Duration::from_secs(2));
        }
    }
    let _ = svc.delete();
    // Deletion is asynchronous; give the SCM a moment to free the name.
    std::thread::sleep(Duration::from_secs(1));
}

/// The command line the SCM will run at boot: `service --relay ... --token-file ...`.
/// The token is passed by *file path*, never inline, so it never lands in the
/// registry ImagePath.
fn service_launch_args(args: &RunArgs, token_path: &Path) -> Vec<OsString> {
    let mut v: Vec<OsString> = vec![OsString::from("service")];
    if let Some(relay) = &args.relay {
        v.push("--relay".into());
        v.push(relay.into());
    }
    v.push("--token-file".into());
    v.push(token_path.into());
    if let Some(name) = &args.name {
        v.push("--name".into());
        v.push(name.into());
    }
    if let Some(id) = &args.id {
        v.push("--id".into());
        v.push(id.into());
    }
    for s in &args.shells {
        v.push("--shell".into());
        v.push(s.into());
    }
    // Unattended by definition: remote enabled, no interactive confirm, and
    // self-updating so the installed fleet tracks the relay's build.
    v.push("--allow-remote".into());
    v.push("--self-update".into());
    v.push("--reconnect-secs".into());
    v.push(args.reconnect_secs.to_string().into());
    v
}

// --- uninstall -------------------------------------------------------------

pub fn uninstall() {
    if !is_elevated() {
        if relaunch_elevated() {
            return;
        }
        fail("Removing the service needs Administrator rights (elevation cancelled).");
        return;
    }
    match remove() {
        Ok(()) => {
            message(
                "Uninstalled",
                "The Remote Shell Agent service has been stopped and removed.",
                MB_ICONINFORMATION,
            );
            println!("uninstall: service '{SERVICE_NAME}' removed");
        }
        Err(e) => {
            fail(&format!("Failed to remove the service: {e:?}"));
        }
    }
}

fn remove() -> windows_service::Result<()> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    )?;
    // Best-effort stop before delete; ignore "not running".
    if let Ok(status) = service.query_status() {
        if status.current_state != ServiceState::Stopped {
            let _ = service.stop();
            // Give it a moment to wind down.
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    service.delete()?;
    // Best-effort removal of the installed copy in Program Files.
    std::thread::sleep(Duration::from_secs(1));
    let _ = std::fs::remove_dir_all(install_dir());
    Ok(())
}

/// Self-delete, driven by the operator's "uninstall" button. Spawns a detached
/// cleanup process that outlives us: it stops + deletes the service (which ends
/// this process) and then removes the installed copy. Returns immediately.
/// The pauses are `ping`: `timeout` exits at once without a console.
pub fn self_uninstall() {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

    let dir = install_dir();
    let script = format!(
        "ping -n 2 127.0.0.1 >nul & sc stop {name} >nul 2>&1 & sc delete {name} >nul 2>&1 & \
         ping -n 4 127.0.0.1 >nul & rmdir /s /q \"{dir}\"",
        name = SERVICE_NAME,
        dir = dir.display()
    );
    let _ = std::process::Command::new("cmd")
        .args(["/C", &script])
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .spawn();
}

// --- self-update ------------------------------------------------------------

/// Swap the installed service binary for `new_bytes` and restart the service.
///
/// Windows won't overwrite or delete a running image, but it does let one be
/// renamed. So the swap happens here, while we still run: the fresh binary is
/// written beside us as `rustlitel-agent.new.exe`, we move ourselves aside to
/// `rustlitel-agent.old.exe` and the new file into our place. Only the restart
/// needs a helper that outlives us: a detached PowerShell `Restart-Service`,
/// which waits for the stop to finish before it starts the service again, now
/// from the new binary. `rustlitel-agent.old.exe` stays until the next update,
/// for a manual rollback.
///
/// The first version left the move to a `cmd` helper behind `timeout /t 3`.
/// Without a console (a detached process has none) `timeout` exits at once, so
/// the move ran while this process still held the file and failed, and the
/// helper started the old binary again. That one found the update on connect
/// and went round again, pulling the whole binary every ~9 s (2026-10-28).
pub fn apply_update(new_bytes: &[u8]) -> anyhow::Result<()> {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

    let exe = std::env::current_exe().context("current_exe")?;
    let dir = exe.parent().context("exe has no parent dir")?;
    let staged = dir.join("rustlitel-agent.new.exe");
    let old = dir.join("rustlitel-agent.old.exe");
    std::fs::write(&staged, new_bytes)
        .with_context(|| format!("stage update at {}", staged.display()))?;

    // The previous update's leftover; nothing runs from it any more.
    let _ = std::fs::remove_file(&old);
    retry_io(|| std::fs::rename(&exe, &old))
        .with_context(|| format!("move {} aside", exe.display()))?;
    if let Err(e) = retry_io(|| std::fs::rename(&staged, &exe)) {
        let _ = std::fs::rename(&old, &exe);
        return Err(e).with_context(|| format!("move {} into place", staged.display()));
    }

    let script = format!("Start-Sleep -Seconds 1; Restart-Service -Name {SERVICE_NAME} -Force");
    std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .spawn()
        .context("spawn restart helper")?;
    tracing::info!("self-update swapped in; service restarting on the new binary");
    Ok(())
}

/// Retry a file operation for up to 5 s: an antivirus keeps a freshly written
/// executable open while it scans it.
fn retry_io(mut op: impl FnMut() -> std::io::Result<()>) -> std::io::Result<()> {
    let mut attempts = 0;
    loop {
        match op() {
            Err(_) if attempts < 10 => {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(500));
            }
            result => return result,
        }
    }
}

// --- service runtime -------------------------------------------------------

pub fn run_service(args: RunArgs) {
    let _ = SERVICE_ARGS.set(args);
    // Hands control to the SCM, which calls `service_main` on its own thread.
    if let Err(e) = service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        eprintln!("service dispatcher failed: {e}");
    }
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_scm_args: Vec<OsString>) {
    let args = match SERVICE_ARGS.get().cloned() {
        Some(a) => a,
        None => return,
    };
    init_service_logging();
    if let Err(e) = service_body(args) {
        tracing::error!("service error: {e}");
    }
}

fn service_body(args: RunArgs) -> windows_service::Result<()> {
    let (stop_tx, stop_rx) = stdmpsc::channel::<()>();

    let handler = move |control| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, handler)?;

    let set_state = |state: ServiceState, accept: ServiceControlAccept| ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };

    status_handle.set_service_status(set_state(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
    ))?;
    tracing::info!("service running");

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let shutdown = async move {
            // Bridge the blocking SCM stop channel into async.
            let _ = tokio::task::spawn_blocking(move || {
                let _ = stop_rx.recv();
            })
            .await;
        };
        tokio::select! {
            _ = crate::serve(args) => {},
            _ = shutdown => { tracing::info!("stop requested by SCM"); }
        }
    });

    status_handle
        .set_service_status(set_state(ServiceState::Stopped, ServiceControlAccept::empty()))?;
    Ok(())
}

/// Services have no console; log to a file under %ProgramData%\rustlitel-agent.
fn init_service_logging() {
    let dir = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"))
        .join("rustlitel-agent");
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("agent.log"))
    {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_env("RUSTLITEL_LOG")
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with_writer(std::sync::Mutex::new(file))
            .with_ansi(false)
            .try_init();
    }
}

// --- elevation -------------------------------------------------------------

/// True if the current process has an elevated (Administrator) token.
fn is_elevated() -> bool {
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret_len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// Relaunch this executable elevated (UAC `runas`), preserving our arguments.
/// Returns true if the elevated process was started.
fn relaunch_elevated() -> bool {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let exe_w = wide(&exe.to_string_lossy());
    let verb = wide("runas");
    // A baked installer has no args (config is in the trailer); an explicit
    // `install --relay ...` invocation is preserved verbatim (quoted).
    let params: Vec<String> = std::env::args()
        .skip(1)
        .map(|a| {
            if a.contains(' ') {
                format!("\"{a}\"")
            } else {
                a
            }
        })
        .collect();
    let params_w = wide(&params.join(" "));

    let ret = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            exe_w.as_ptr(),
            params_w.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL as i32,
        )
    };
    // ShellExecuteW returns a value > 32 on success.
    (ret as isize) > 32
}

// --- dialogs ---------------------------------------------------------------

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn confirm(text: &str, caption: &str) -> bool {
    let text = wide(text);
    let caption = wide(caption);
    // SAFETY: both strings are NUL-terminated UTF-16; null HWND = no owner.
    let ret = unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            caption.as_ptr(),
            MB_YESNO | MB_ICONWARNING | MB_TOPMOST,
        )
    };
    ret == IDYES as i32
}

fn message(caption: &str, text: &str, icon: u32) {
    let text = wide(text);
    let caption = wide(caption);
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            caption.as_ptr(),
            MB_OK | icon | MB_TOPMOST,
        );
    }
}

fn fail(text: &str) {
    eprintln!("error: {text}");
    message("Error", text, MB_ICONERROR);
}
