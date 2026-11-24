//! Windows side of the desktop commands: picking the user's session, starting
//! the helper there, and the Win32 work the helper does (GDI capture, the
//! window list, ShowWindow/SetWindowPos/WM_CLOSE).

use std::ffi::c_void;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use serde_json::{json, Value};
use windows_sys::Win32::Foundation::{CloseHandle, BOOL, HANDLE, HWND, LPARAM, RECT, TRUE, FALSE, WAIT_OBJECT_0};
use windows_sys::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_CLOAKED, DWMWA_EXTENDED_FRAME_BOUNDS};
use windows_sys::Win32::Graphics::Gdi::{
    BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, EnumDisplayMonitors,
    GetDC, GetDIBits, ReleaseDC, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, CAPTUREBLT,
    DIB_RGB_COLORS, HDC, HMONITOR, SRCCOPY,
};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, SecurityImpersonation, SetTokenInformation, TokenPrimary, TokenSessionId,
};
use windows_sys::Win32::Storage::Xps::PrintWindow;
use windows_sys::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSActive, WTSEnumerateSessionsW, WTSFreeMemory, WTSGetActiveConsoleSessionId,
    WTSQuerySessionInformationW, WTSUserName, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW,
};
use windows_sys::Win32::System::StationsAndDesktops::{GetThreadDesktop, OpenInputDesktop, SetThreadDesktop};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, GetExitCodeProcess,
    OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
    AttachThreadInput, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, STARTUPINFOW,
};
use windows_sys::Win32::UI::HiDpi::{SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{SendInput, INPUT, INPUT_0, INPUT_MOUSE, MOUSEEVENTF_MOVE, MOUSEINPUT};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BringWindowToTop, EnumWindows, GetClassNameW, GetForegroundWindow, GetSystemMetrics, GetWindowLongW,
    GetWindowRect, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, IsIconic, IsWindow,
    IsWindowVisible, IsZoomed, PostMessageW, SetForegroundWindow, SetWindowPos, ShowWindowAsync,
    GWL_EXSTYLE, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN, SWP_NOACTIVATE,
    SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, SW_MAXIMIZE, SW_MINIMIZE, SW_RESTORE, WM_CLOSE, WS_EX_TOOLWINDOW,
};

use rustlitel_proto::{DesktopRequest, WindowOp, WindowTarget};

use super::Bgra;

const PW_RENDERFULLCONTENT: u32 = 2;
const GENERIC_ALL: u32 = 0x1000_0000;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

// --- service side: where and how to run the helper --------------------------

pub async fn answer(request: DesktopRequest, session: Option<u32>, timeout_secs: u64) -> Result<String> {
    if let DesktopRequest::Sessions = request {
        let list = tokio::task::spawn_blocking(list_sessions).await??;
        return Ok(json!({ "ok": true, "sessions": list }).to_string());
    }
    let req = serde_json::to_vec(&request)?;
    tokio::task::spawn_blocking(move || run_helper(&req, session, timeout_secs)).await?
}

fn own_session() -> u32 {
    let mut s = 0u32;
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut s) };
    s
}

fn wide_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0usize;
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn state_name(s: i32) -> &'static str {
    match s {
        0 => "active",
        1 => "connected",
        2 => "connect_query",
        3 => "shadow",
        4 => "disconnected",
        5 => "idle",
        6 => "listen",
        7 => "reset",
        8 => "down",
        9 => "init",
        _ => "unknown",
    }
}

struct SessionRow {
    id: u32,
    name: String,
    user: String,
    state: i32,
}

fn sessions() -> Result<Vec<SessionRow>> {
    let mut info: *mut WTS_SESSION_INFOW = null_mut();
    let mut count = 0u32;
    if unsafe { WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut info, &mut count) } == 0 {
        bail!("WTSEnumerateSessions failed: {}", std::io::Error::last_os_error());
    }
    let mut rows = Vec::new();
    for i in 0..count as usize {
        let s = unsafe { &*info.add(i) };
        let mut buf: *mut u16 = null_mut();
        let mut len = 0u32;
        let user = if unsafe { WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, s.SessionId, WTSUserName, &mut buf, &mut len) } != 0 {
            let u = wide_to_string(buf);
            unsafe { WTSFreeMemory(buf as *mut c_void) };
            u
        } else {
            String::new()
        };
        rows.push(SessionRow {
            id: s.SessionId,
            name: wide_to_string(s.pWinStationName),
            user,
            state: s.State,
        });
    }
    unsafe { WTSFreeMemory(info as *mut c_void) };
    Ok(rows)
}

fn list_sessions() -> Result<Value> {
    let console = unsafe { WTSGetActiveConsoleSessionId() };
    let default = pick_session(None).ok();
    Ok(Value::Array(
        sessions()?
            .into_iter()
            .map(|s| {
                json!({
                    "id": s.id, "name": s.name, "user": s.user, "state": state_name(s.state),
                    "console": s.id == console, "default": Some(s.id) == default,
                })
            })
            .collect(),
    ))
}

/// The session a request acts in: the asked one, else the console session when
/// someone is logged on there, else the first active session with a user.
fn pick_session(asked: Option<u32>) -> Result<u32> {
    let all = sessions()?;
    if let Some(id) = asked {
        let s = all.iter().find(|s| s.id == id).ok_or_else(|| anyhow!("no session {id}"))?;
        if s.user.is_empty() {
            bail!("nobody is logged on in session {id}");
        }
        return Ok(id);
    }
    let console = unsafe { WTSGetActiveConsoleSessionId() };
    if let Some(s) = all.iter().find(|s| s.id == console && !s.user.is_empty()) {
        return Ok(s.id);
    }
    all.iter()
        .find(|s| s.state == WTSActive && !s.user.is_empty() && s.id != 0)
        .map(|s| s.id)
        .ok_or_else(|| anyhow!("no interactive session: nobody is logged on (see `sessions`)"))
}

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// Start `rustlitel-agent desktop-helper` in the target session and return the
/// JSON it wrote.
fn run_helper(req: &[u8], asked: Option<u32>, timeout_secs: u64) -> Result<String> {
    let exe = std::env::current_exe().context("own path")?;
    let out = std::env::temp_dir().join(format!("rustlitel-desktop-{}.json", uuid::Uuid::new_v4()));
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(req);
    let mine = own_session();
    let target = if mine != 0 && asked.is_none_or(|a| a == mine) {
        mine
    } else {
        pick_session(asked)?
    };

    let result = if target == mine {
        run_plain(&exe, &b64, &out, timeout_secs)
    } else {
        run_in_session(&exe, &b64, &out, target, timeout_secs)
    };
    let text = std::fs::read_to_string(&out);
    let _ = std::fs::remove_file(&out);
    let code = result?;
    match text {
        Ok(t) if !t.trim().is_empty() => {
            // Note which session answered; cheap to patch into the document.
            Ok(match serde_json::from_str::<Value>(&t) {
                Ok(mut v) if v.is_object() => {
                    v["session"] = json!(target);
                    if let Some(row) = sessions().ok().and_then(|all| all.into_iter().find(|s| s.id == target)) {
                        v["session_user"] = json!(row.user);
                        v["session_state"] = json!(state_name(row.state));
                        if row.state != WTSActive {
                            v["warning"] = json!(
                                "this session is not active (no one is connected to it): Windows does not draw \
                                 it, so a screen capture is assembled from its windows (no shadows or \
                                 transparency, a window that does not paint itself stays black)"
                            );
                        }
                    }
                    v.to_string()
                }
                _ => t,
            })
        }
        _ => bail!("the desktop helper in session {target} exited with code {code} and no answer"),
    }
}

fn run_plain(exe: &Path, b64: &str, out: &Path, timeout_secs: u64) -> Result<u32> {
    use std::os::windows::process::CommandExt;
    let mut child = std::process::Command::new(exe)
        .args(["desktop-helper", "--request", b64, "--out"])
        .arg(out)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start the desktop helper")?;
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if let Some(st) = child.try_wait()? {
            return Ok(st.code().unwrap_or(-1) as u32);
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            bail!("the desktop helper timed out after {timeout_secs}s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// LocalSystem's own token, moved into `session`: the helper keeps the
/// service's rights (so it can act on elevated windows too) but sees that
/// session's desktop.
fn run_in_session(exe: &Path, b64: &str, out: &Path, session: u32, timeout_secs: u64) -> Result<u32> {
    unsafe {
        let mut tok: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &mut tok) == 0 {
            bail!("OpenProcessToken: {}", std::io::Error::last_os_error());
        }
        let tok = OwnedHandle(tok);
        let mut dup: HANDLE = null_mut();
        if DuplicateTokenEx(tok.0, MAXIMUM_ALLOWED, null(), SecurityImpersonation, TokenPrimary, &mut dup) == 0 {
            bail!("DuplicateTokenEx: {}", std::io::Error::last_os_error());
        }
        let dup = OwnedHandle(dup);
        let sid = session;
        if SetTokenInformation(dup.0, TokenSessionId, &sid as *const u32 as *const c_void, 4) == 0 {
            bail!(
                "moving the token to session {session} failed ({}); the agent must run as the service (LocalSystem)",
                std::io::Error::last_os_error()
            );
        }
        let mut cmdline = wide(&format!(
            "\"{}\" desktop-helper --request {b64} --out \"{}\"",
            exe.display(),
            out.display()
        ));
        let mut desktop = wide("winsta0\\default");
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.lpDesktop = desktop.as_mut_ptr();
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        if CreateProcessAsUserW(
            dup.0,
            null(),
            cmdline.as_mut_ptr(),
            null(),
            null(),
            FALSE,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            null(),
            null(),
            &si,
            &mut pi,
        ) == 0
        {
            bail!("CreateProcessAsUser in session {session}: {}", std::io::Error::last_os_error());
        }
        let proc_ = OwnedHandle(pi.hProcess);
        let _thread = OwnedHandle(pi.hThread);
        let ms = (timeout_secs.saturating_mul(1000)).min(u32::MAX as u64 - 1) as u32;
        if WaitForSingleObject(proc_.0, ms) != WAIT_OBJECT_0 {
            TerminateProcess(proc_.0, 1);
            bail!("the desktop helper timed out after {timeout_secs}s");
        }
        let mut code = 0u32;
        GetExitCodeProcess(proc_.0, &mut code);
        Ok(code)
    }
}

// --- helper side: the actual Win32 work --------------------------------------

pub fn helper(req: DesktopRequest) -> Result<Value> {
    // Physical pixels everywhere, whatever the display scaling.
    unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
    match req {
        DesktopRequest::Sessions => Ok(json!({ "sessions": list_sessions()? })),
        DesktopRequest::ListWindows { all } => {
            let fg = unsafe { GetForegroundWindow() };
            let windows: Vec<Value> = top_windows()
                .into_iter()
                .filter_map(|h| {
                    let w = info(h, fg);
                    (all || w.listed()).then(|| w.to_json())
                })
                .collect();
            Ok(json!({ "windows": windows, "monitors": monitors_json() }))
        }
        DesktopRequest::Screenshot { window, monitor, format, quality, max_width } => {
            let mut composed = false;
            let format = format.unwrap_or_else(|| "png".into()).to_ascii_lowercase();
            let (img, win) = match window {
                Some(t) => {
                    let h = find(&t)?;
                    (capture_window(h)?, Some(info(h, unsafe { GetForegroundWindow() }).to_json()))
                }
                None => {
                    // Follow the input desktop, so a lock screen or a UAC prompt
                    // shows up as what it is instead of a stale picture.
                    let own_desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
                    unsafe {
                        let d = OpenInputDesktop(0, FALSE, GENERIC_ALL);
                        if !d.is_null() {
                            SetThreadDesktop(d);
                        }
                    }
                    let r = match monitor {
                        Some(i) => *monitors()
                            .get(i as usize)
                            .ok_or_else(|| anyhow!("no monitor {i} (there are {})", monitors().len()))?,
                        None => virtual_screen(),
                    };
                    // A disconnected session has no screen to copy (access
                    // denied, or black): assemble it from its windows instead.
                    match capture_screen(&r) {
                        Ok(img) if !img.is_blank() => (img, None),
                        _ => {
                            // The windows live on the session's own desktop,
                            // not necessarily on the input one we moved to.
                            unsafe { SetThreadDesktop(own_desktop) };
                            composed = true;
                            (compose(&r)?, None)
                        }
                    }
                }
            };
            let img = img.downscale(max_width.unwrap_or(0));
            let (fmt, bytes) = img.encode(&format, quality.unwrap_or(80))?;
            let mut v = json!({
                "format": fmt, "width": img.width, "height": img.height,
                "data": base64::engine::general_purpose::STANDARD.encode(bytes),
            });
            if let Some(w) = win {
                v["window"] = w;
            }
            if composed {
                v["composed"] = json!(true);
            }
            Ok(v)
        }
        DesktopRequest::Window { target, op, x, y, width, height } => window_op(&target, op, x, y, width, height),
    }
}

fn virtual_screen() -> RECT {
    unsafe {
        let x = GetSystemMetrics(SM_XVIRTUALSCREEN);
        let y = GetSystemMetrics(SM_YVIRTUALSCREEN);
        RECT {
            left: x,
            top: y,
            right: x + GetSystemMetrics(SM_CXVIRTUALSCREEN),
            bottom: y + GetSystemMetrics(SM_CYVIRTUALSCREEN),
        }
    }
}

unsafe extern "system" fn monitor_cb(_m: HMONITOR, _dc: HDC, r: *mut RECT, lp: LPARAM) -> BOOL {
    let v = &mut *(lp as *mut Vec<RECT>);
    v.push(*r);
    TRUE
}

/// Monitors, primary (the one at 0,0) first, then left to right.
fn monitors() -> Vec<RECT> {
    let mut v: Vec<RECT> = Vec::new();
    unsafe { EnumDisplayMonitors(null_mut(), null(), Some(monitor_cb), &mut v as *mut _ as LPARAM) };
    v.sort_by_key(|r| (!(r.left == 0 && r.top == 0), r.left, r.top));
    v
}

fn monitors_json() -> Value {
    Value::Array(
        monitors()
            .iter()
            .enumerate()
            .map(|(i, r)| {
                json!({"index": i, "x": r.left, "y": r.top, "width": r.right - r.left,
                       "height": r.bottom - r.top, "primary": r.left == 0 && r.top == 0})
            })
            .collect(),
    )
}

/// Copy a rectangle of the screen (or of `src`, a window DC) into BGRA.
fn capture_screen(r: &RECT) -> Result<Bgra> {
    let (w, h) = (r.right - r.left, r.bottom - r.top);
    if w <= 0 || h <= 0 {
        bail!("empty capture area");
    }
    unsafe {
        let screen = GetDC(null_mut());
        if screen.is_null() {
            bail!("GetDC: no desktop to capture ({})", std::io::Error::last_os_error());
        }
        let res = blit(screen, w, h, |mem| {
            BitBlt(mem, 0, 0, w, h, screen, r.left, r.top, SRCCOPY | CAPTUREBLT) != 0
        });
        ReleaseDC(null_mut(), screen);
        res
    }
}

/// Make a w×h bitmap, let `draw` paint into its DC, read it back as BGRA.
unsafe fn blit(reference: HDC, w: i32, h: i32, draw: impl FnOnce(HDC) -> bool) -> Result<Bgra> {
    let mem = CreateCompatibleDC(reference);
    let bmp = CreateCompatibleBitmap(reference, w, h);
    if mem.is_null() || bmp.is_null() {
        if !mem.is_null() {
            DeleteDC(mem);
        }
        bail!("could not allocate a {w}x{h} bitmap");
    }
    let old = SelectObject(mem, bmp);
    let ok = draw(mem);
    SelectObject(mem, old);
    let mut bmi: BITMAPINFO = std::mem::zeroed();
    bmi.bmiHeader = BITMAPINFOHEADER {
        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: w,
        biHeight: -h, // top-down rows
        biPlanes: 1,
        biBitCount: 32,
        biCompression: BI_RGB,
        biSizeImage: 0,
        biXPelsPerMeter: 0,
        biYPelsPerMeter: 0,
        biClrUsed: 0,
        biClrImportant: 0,
    };
    let mut data = vec![0u8; (w as usize) * (h as usize) * 4];
    let lines = GetDIBits(mem, bmp, 0, h as u32, data.as_mut_ptr() as *mut c_void, &mut bmi, DIB_RGB_COLORS);
    DeleteObject(bmp);
    DeleteDC(mem);
    if !ok {
        bail!("capture failed: {}", std::io::Error::last_os_error());
    }
    if lines == 0 {
        bail!("GetDIBits failed");
    }
    Ok(Bgra {
        width: w as u32,
        height: h as u32,
        data,
    })
}

/// A window as it draws itself (PrintWindow renders it even when covered,
/// and in a disconnected session), cropped to its visible frame. Returns the
/// image and the frame's screen position.
fn print_window(h: HWND) -> Result<(Bgra, RECT)> {
    let wr = window_rect(h);
    let (w, hh) = (wr.right - wr.left, wr.bottom - wr.top);
    if w <= 0 || hh <= 0 {
        bail!("the window has no area");
    }
    let frame = frame_rect(h).unwrap_or(wr);
    let img = unsafe {
        let screen = GetDC(null_mut());
        let mut r = blit(screen, w, hh, |mem| PrintWindow(h, mem, PW_RENDERFULLCONTENT) != 0);
        if r.as_ref().map_or(true, |i| i.is_blank()) {
            // Without DWM (a disconnected session) the full-content flag can
            // come back empty; the classic WM_PRINT path still draws.
            r = blit(screen, w, hh, |mem| PrintWindow(h, mem, 0) != 0);
        }
        ReleaseDC(null_mut(), screen);
        r?
    };
    if img.is_blank() {
        bail!("the window drew nothing");
    }
    let img = img.crop(
        (frame.left - wr.left).max(0) as u32,
        (frame.top - wr.top).max(0) as u32,
        (frame.right - frame.left) as u32,
        (frame.bottom - frame.top) as u32,
    );
    Ok((img, frame))
}

/// One window; falls back to the screen area it occupies.
fn capture_window(h: HWND) -> Result<Bgra> {
    if unsafe { IsIconic(h) } != 0 {
        bail!("the window is minimized; `window restore` or `window focus` it first");
    }
    match print_window(h) {
        Ok((img, _)) => Ok(img),
        Err(_) => {
            let frame = frame_rect(h).unwrap_or_else(|| window_rect(h));
            capture_screen(&frame)
        }
    }
}

/// The area `r` assembled from the windows' own rendering, bottom of the
/// z-order first: what the screen would show, for a session Windows does not
/// draw (disconnected RDP). DWM-only effects (shadows, transparency) are missing.
fn compose(r: &RECT) -> Result<Bgra> {
    let (w, h) = ((r.right - r.left).max(0) as u32, (r.bottom - r.top).max(0) as u32);
    if w == 0 || h == 0 {
        bail!("empty capture area");
    }
    let mut canvas = Bgra { width: w, height: h, data: vec![0u8; (w * h * 4) as usize] };
    let mut drawn = 0;
    for hw in top_windows().into_iter().rev() {
        unsafe {
            if IsWindowVisible(hw) == 0 || IsIconic(hw) != 0 {
                continue;
            }
            let mut cloaked = 0u32;
            DwmGetWindowAttribute(hw, DWMWA_CLOAKED as u32, &mut cloaked as *mut _ as *mut c_void, 4);
            if cloaked != 0 {
                continue;
            }
        }
        let f = frame_rect(hw).unwrap_or_else(|| window_rect(hw));
        if f.right <= r.left || f.bottom <= r.top || f.left >= r.right || f.top >= r.bottom {
            continue;
        }
        if let Ok((img, frame)) = print_window(hw) {
            canvas.paste(&img, frame.left - r.left, frame.top - r.top);
            drawn += 1;
        }
    }
    if drawn == 0 {
        bail!("nothing to capture: the session has no visible window that draws itself");
    }
    Ok(canvas)
}

fn window_rect(h: HWND) -> RECT {
    let mut r = RECT { left: 0, top: 0, right: 0, bottom: 0 };
    unsafe { GetWindowRect(h, &mut r) };
    r
}

/// The visible frame (without the invisible resize borders of Windows 10/11).
fn frame_rect(h: HWND) -> Option<RECT> {
    let mut r = RECT { left: 0, top: 0, right: 0, bottom: 0 };
    let hr = unsafe {
        DwmGetWindowAttribute(h, DWMWA_EXTENDED_FRAME_BOUNDS as u32, &mut r as *mut _ as *mut c_void, std::mem::size_of::<RECT>() as u32)
    };
    (hr == 0 && r.right > r.left && r.bottom > r.top).then_some(r)
}

unsafe extern "system" fn enum_cb(h: HWND, lp: LPARAM) -> BOOL {
    let v = &mut *(lp as *mut Vec<HWND>);
    v.push(h);
    TRUE
}

/// Top-level windows, in z-order (topmost first).
fn top_windows() -> Vec<HWND> {
    let mut v: Vec<HWND> = Vec::new();
    unsafe { EnumWindows(Some(enum_cb), &mut v as *mut _ as LPARAM) };
    v
}

struct WinInfo {
    hwnd: HWND,
    title: String,
    class: String,
    pid: u32,
    process: String,
    rect: RECT,
    visible: bool,
    minimized: bool,
    maximized: bool,
    foreground: bool,
    cloaked: bool,
    tool: bool,
}

impl WinInfo {
    /// What a person would call "the open windows".
    fn listed(&self) -> bool {
        self.visible && !self.title.is_empty() && !self.cloaked && !self.tool
    }

    fn to_json(&self) -> Value {
        json!({
            "hwnd": self.hwnd as usize as u64,
            "title": self.title, "class": self.class,
            "pid": self.pid, "process": self.process,
            "x": self.rect.left, "y": self.rect.top,
            "width": self.rect.right - self.rect.left, "height": self.rect.bottom - self.rect.top,
            "visible": self.visible, "minimized": self.minimized, "maximized": self.maximized,
            "foreground": self.foreground, "cloaked": self.cloaked,
        })
    }
}

fn info(h: HWND, fg: HWND) -> WinInfo {
    unsafe {
        let len = GetWindowTextLengthW(h);
        let mut buf = vec![0u16; (len.max(0) as usize) + 1];
        let n = GetWindowTextW(h, buf.as_mut_ptr(), buf.len() as i32);
        let title = String::from_utf16_lossy(&buf[..n.max(0) as usize]);
        let mut cbuf = [0u16; 256];
        let n = GetClassNameW(h, cbuf.as_mut_ptr(), cbuf.len() as i32);
        let class = String::from_utf16_lossy(&cbuf[..n.max(0) as usize]);
        let mut pid = 0u32;
        GetWindowThreadProcessId(h, &mut pid);
        let mut cloaked = 0u32;
        DwmGetWindowAttribute(h, DWMWA_CLOAKED as u32, &mut cloaked as *mut _ as *mut c_void, 4);
        let ex = GetWindowLongW(h, GWL_EXSTYLE) as u32;
        WinInfo {
            hwnd: h,
            title,
            class,
            pid,
            process: process_name(pid),
            rect: frame_rect(h).unwrap_or_else(|| window_rect(h)),
            visible: IsWindowVisible(h) != 0,
            minimized: IsIconic(h) != 0,
            maximized: IsZoomed(h) != 0,
            foreground: h == fg,
            cloaked: cloaked != 0,
            tool: ex & WS_EX_TOOLWINDOW != 0,
        }
    }
}

fn process_name(pid: u32) -> String {
    unsafe {
        let p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if p.is_null() {
            return String::new();
        }
        let p = OwnedHandle(p);
        let mut buf = [0u16; 1024];
        let mut n = buf.len() as u32;
        if QueryFullProcessImageNameW(p.0, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut n) == 0 {
            return String::new();
        }
        let full = String::from_utf16_lossy(&buf[..n as usize]);
        full.rsplit(['\\', '/']).next().unwrap_or(&full).to_string()
    }
}

/// Resolve a target to exactly one window.
fn find(t: &WindowTarget) -> Result<HWND> {
    if let Some(raw) = t.hwnd {
        let h = raw as usize as HWND;
        if unsafe { IsWindow(h) } == 0 {
            bail!("no window with hwnd {raw}");
        }
        return Ok(h);
    }
    if t.title.is_none() && t.process.is_none() && t.pid.is_none() {
        bail!("say which window: hwnd, title, process or pid");
    }
    let fg = unsafe { GetForegroundWindow() };
    let title = t.title.as_ref().map(|s| s.to_lowercase());
    let process = t.process.as_ref().map(|s| s.to_lowercase());
    let hits: Vec<WinInfo> = top_windows()
        .into_iter()
        .map(|h| info(h, fg))
        .filter(|w| w.listed())
        .filter(|w| title.as_ref().is_none_or(|s| w.title.to_lowercase().contains(s)))
        .filter(|w| process.as_ref().is_none_or(|s| w.process.to_lowercase().contains(s)))
        .filter(|w| t.pid.is_none_or(|p| w.pid == p))
        .collect();
    match hits.len() {
        0 => bail!("no visible window matches {}", serde_json::to_string(t)?),
        1 => Ok(hits[0].hwnd),
        n => {
            let list: Vec<String> = hits
                .iter()
                .take(10)
                .map(|w| format!("{} {:?} ({})", w.hwnd as usize, w.title, w.process))
                .collect();
            bail!("{n} windows match; pick one by hwnd: {}", list.join("; "))
        }
    }
}

fn window_op(t: &WindowTarget, op: WindowOp, x: Option<i32>, y: Option<i32>, width: Option<i32>, height: Option<i32>) -> Result<Value> {
    let h = find(t)?;
    unsafe {
        match op {
            WindowOp::Focus => {
                if IsIconic(h) != 0 {
                    ShowWindowAsync(h, SW_RESTORE);
                    std::thread::sleep(Duration::from_millis(200));
                }
                focus(h);
            }
            WindowOp::Minimize => {
                ShowWindowAsync(h, SW_MINIMIZE);
            }
            WindowOp::Maximize => {
                ShowWindowAsync(h, SW_MAXIMIZE);
            }
            WindowOp::Restore => {
                ShowWindowAsync(h, SW_RESTORE);
            }
            WindowOp::Move => {
                if x.is_none() && y.is_none() && width.is_none() && height.is_none() {
                    bail!("move needs x, y, width and/or height");
                }
                if IsIconic(h) != 0 || IsZoomed(h) != 0 {
                    ShowWindowAsync(h, SW_RESTORE);
                    std::thread::sleep(Duration::from_millis(200));
                }
                let r = window_rect(h);
                let mut flags = SWP_NOZORDER | SWP_NOACTIVATE;
                if x.is_none() && y.is_none() {
                    flags |= SWP_NOMOVE;
                }
                if width.is_none() && height.is_none() {
                    flags |= SWP_NOSIZE;
                }
                if SetWindowPos(
                    h,
                    null_mut(),
                    x.unwrap_or(r.left),
                    y.unwrap_or(r.top),
                    width.unwrap_or(r.right - r.left),
                    height.unwrap_or(r.bottom - r.top),
                    flags,
                ) == 0
                {
                    bail!("SetWindowPos: {}", std::io::Error::last_os_error());
                }
            }
            WindowOp::Close => {
                if PostMessageW(h, WM_CLOSE, 0, 0) == 0 {
                    bail!("PostMessage(WM_CLOSE): {}", std::io::Error::last_os_error());
                }
                for _ in 0..20 {
                    std::thread::sleep(Duration::from_millis(100));
                    if IsWindow(h) == 0 {
                        return Ok(json!({ "closed": true }));
                    }
                }
                let w = info(h, GetForegroundWindow());
                return Ok(json!({
                    "closed": false,
                    "note": "the window is still there after 2 s: it may be asking to save, see a screenshot",
                    "window": w.to_json(),
                }));
            }
        }
        std::thread::sleep(Duration::from_millis(300));
        let fg = GetForegroundWindow();
        Ok(json!({ "window": info(h, fg).to_json(), "foreground": fg == h }))
    }
}

/// SetForegroundWindow is refused to a process that did not get the last
/// input. Count as having it (a zero mouse move) and share the input state of
/// the current foreground thread, then ask.
unsafe fn focus(h: HWND) {
    let mut input: INPUT = std::mem::zeroed();
    input.r#type = INPUT_MOUSE;
    input.Anonymous = INPUT_0 {
        mi: MOUSEINPUT {
            dx: 0,
            dy: 0,
            mouseData: 0,
            dwFlags: MOUSEEVENTF_MOVE,
            time: 0,
            dwExtraInfo: 0,
        },
    };
    SendInput(1, &input, std::mem::size_of::<INPUT>() as i32);
    let fg = GetForegroundWindow();
    let fg_thread = GetWindowThreadProcessId(fg, null_mut());
    let me = GetCurrentThreadId();
    let attached = fg_thread != 0 && fg_thread != me && AttachThreadInput(me, fg_thread, TRUE) != 0;
    BringWindowToTop(h);
    SetForegroundWindow(h);
    if attached {
        AttachThreadInput(me, fg_thread, FALSE);
    }
}
