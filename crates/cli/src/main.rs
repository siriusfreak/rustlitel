//! `wrs` — console client for the remote-shell relay.
//!
//! Auth is the OAuth 2.0 Device Authorization Grant against the relay's Keycloak
//! (a public client, no secret): `rustlitel login` prints a URL + code, you approve in
//! a browser, and the CLI caches the tokens (refreshing as needed). The relay
//! verifies the Keycloak access token the same way it verifies the web login.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "rustlitel", about = "rustlitel — remote-shell relay console client")]
struct Cli {
    /// Relay base URL, e.g. https://relay.example.com. Saved after `login`.
    #[arg(long, env = "RUSTLITEL_RELAY", global = true)]
    relay: Option<String>,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Sign in via Keycloak device flow.
    Login,
    /// Forget the cached tokens for this relay.
    Logout,
    /// Show who you're signed in as.
    Whoami,
    /// List connected agents.
    Agents,
    /// Run a command on an agent: `rustlitel exec <agent> <command...>`.
    Exec {
        agent: String,
        /// Command (remaining args are joined with spaces).
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
        /// Shell: powershell|cmd|pwsh (Windows) / bash|sh (Unix).
        #[arg(long)]
        shell: Option<String>,
        /// Wall-clock timeout, seconds.
        #[arg(long)]
        timeout: Option<u64>,
    },
    /// Logon sessions on a Windows agent (console, RDP); pick one with --session.
    Sessions {
        agent: String,
        #[arg(long)]
        json: bool,
    },
    /// List the open windows on a Windows agent.
    Windows {
        agent: String,
        /// Include hidden, untitled and tool windows.
        #[arg(long)]
        all: bool,
        /// Print the agent's JSON (windows + monitors) instead of a table.
        #[arg(long)]
        json: bool,
        /// Session id (see `sessions`); default: console, else the active RDP one.
        #[arg(long)]
        session: Option<u32>,
    },
    /// Take a screenshot of the screen, one monitor, or one window.
    Screenshot {
        agent: String,
        /// Output file; default <agent>-<time>.<png|jpg>. `-` writes to stdout.
        #[arg(short, long)]
        out: Option<String>,
        #[command(flatten)]
        target: Target,
        /// 0-based monitor (`windows --json` lists them); default all monitors.
        #[arg(long)]
        monitor: Option<u32>,
        /// png (default) or jpeg.
        #[arg(long)]
        format: Option<String>,
        /// JPEG quality 1-100.
        #[arg(long)]
        quality: Option<u8>,
        /// Downscale to at most this width.
        #[arg(long)]
        max_width: Option<u32>,
        /// Session id (see `sessions`); default: console, else the active RDP one.
        #[arg(long, conflicts_with = "all_sessions")]
        session: Option<u32>,
        /// One screenshot per session that has a user logged on (files get `-s<id>`).
        #[arg(long)]
        all_sessions: bool,
    },
    /// Act on a window: focus, minimize, maximize, restore, move, close.
    Window {
        agent: String,
        #[arg(value_enum)]
        op: Op,
        #[command(flatten)]
        target: Target,
        /// For `move`: new left edge / top edge / width / height (pixels).
        #[arg(long, allow_negative_numbers = true)]
        x: Option<i32>,
        #[arg(long, allow_negative_numbers = true)]
        y: Option<i32>,
        #[arg(long)]
        width: Option<i32>,
        #[arg(long)]
        height: Option<i32>,
        #[arg(long)]
        session: Option<u32>,
    },
}

/// Which window. Title and process are case-insensitive substrings; exactly
/// one window may match.
#[derive(clap::Args, Default)]
struct Target {
    /// Window handle from `windows` (decimal or 0x hex).
    #[arg(long, value_parser = parse_hwnd)]
    hwnd: Option<u64>,
    /// Part of the window title.
    #[arg(long)]
    title: Option<String>,
    /// Part of the process name, e.g. notepad.exe.
    #[arg(long)]
    process: Option<String>,
    #[arg(long)]
    pid: Option<u32>,
}

impl Target {
    fn json(&self) -> Option<serde_json::Value> {
        if self.hwnd.is_none() && self.title.is_none() && self.process.is_none() && self.pid.is_none() {
            return None;
        }
        Some(serde_json::json!({
            "hwnd": self.hwnd, "title": self.title, "process": self.process, "pid": self.pid,
        }))
    }
}

fn parse_hwnd(s: &str) -> Result<u64, String> {
    let r = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16),
        None => s.parse(),
    };
    r.map_err(|e| e.to_string())
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Op {
    Focus,
    Minimize,
    Maximize,
    Restore,
    Move,
    Close,
}

impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::Focus => "focus",
            Op::Minimize => "minimize",
            Op::Maximize => "maximize",
            Op::Restore => "restore",
            Op::Move => "move",
            Op::Close => "close",
        }
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

// --- token cache -----------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct Tokens {
    relay: String,
    token_endpoint: String,
    client_id: String,
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    expires_at: u64,
}

fn config_dir() -> Result<std::path::PathBuf> {
    let d = dirs::config_dir()
        .ok_or_else(|| anyhow!("no config dir"))?
        .join("rustlitel");
    std::fs::create_dir_all(&d).ok();
    Ok(d)
}

fn host_of(relay: &str) -> String {
    relay
        .trim_end_matches('/')
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .replace(['/', ':'], "_")
}

fn token_path(relay: &str) -> Result<std::path::PathBuf> {
    Ok(config_dir()?.join(format!("{}.json", host_of(relay))))
}

fn save_default_relay(relay: &str) {
    if let Ok(d) = config_dir() {
        let _ = std::fs::write(d.join("relay"), relay.trim_end_matches('/'));
    }
}

fn resolve_relay(arg: Option<String>) -> Result<String> {
    if let Some(r) = arg {
        return Ok(r.trim_end_matches('/').to_string());
    }
    let p = config_dir()?.join("relay");
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("no relay set; pass --relay or set RUSTLITEL_RELAY, or run `rustlitel login`"))
}

fn load_tokens(relay: &str) -> Result<Tokens> {
    let p = token_path(relay)?;
    let data = std::fs::read(&p).map_err(|_| anyhow!("not signed in — run `rustlitel login`"))?;
    Ok(serde_json::from_slice(&data)?)
}

/// The file holds a long-lived refresh token: readable by the owner only.
fn save_tokens(relay: &str, tokens: &Tokens) -> Result<()> {
    let path = token_path(relay)?;
    let data = serde_json::to_vec_pretty(tokens)?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        // `mode` applies only to a new file; one from an older version is 0644.
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.write_all(&data)?;
    }
    #[cfg(not(unix))]
    std::fs::write(&path, data)?;
    Ok(())
}

// --- auth ------------------------------------------------------------------

#[derive(Deserialize)]
struct AuthConfig {
    issuer: Option<String>,
    cli_client_id: Option<String>,
}

#[derive(Deserialize)]
struct Discovery {
    device_authorization_endpoint: String,
    token_endpoint: String,
}

#[derive(Deserialize)]
struct DeviceAuth {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    #[serde(default = "default_interval")]
    interval: u64,
    expires_in: u64,
}
fn default_interval() -> u64 {
    5
}

#[derive(Deserialize)]
struct TokenResp {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    expires_in: u64,
}

#[derive(Deserialize)]
struct TokenErr {
    error: String,
}

async fn login(relay: &str) -> Result<()> {
    let http = reqwest::Client::new();

    let cfg: AuthConfig = http
        .get(format!("{relay}/api/auth-config"))
        .send()
        .await?
        .error_for_status()
        .context("fetch /api/auth-config")?
        .json()
        .await?;
    let issuer = cfg
        .issuer
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("this relay has no Keycloak configured; use a Bearer token instead"))?;
    let client_id = cfg.cli_client_id.unwrap_or_else(|| "rustlitel-cli".into());

    let disc: Discovery = http
        .get(format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        ))
        .send()
        .await?
        .error_for_status()
        .context("OIDC discovery")?
        .json()
        .await?;

    // offline_access: a plain refresh token dies with the realm's SSO session
    // (30 min idle, 10 h at most on ours); an offline one lasts until it goes
    // unused for the realm's offline idle timeout. Some realms refuse the scope.
    let mut resp = http
        .post(&disc.device_authorization_endpoint)
        .form(&[("client_id", client_id.as_str()), ("scope", "openid profile offline_access")])
        .send()
        .await?;
    if resp.status() == reqwest::StatusCode::BAD_REQUEST {
        eprintln!("note: the realm refused offline_access; this login will expire with the SSO session");
        resp = http
            .post(&disc.device_authorization_endpoint)
            .form(&[("client_id", client_id.as_str()), ("scope", "openid profile")])
            .send()
            .await?;
    }
    let da: DeviceAuth = resp
        .error_for_status()
        .context("device authorization (is the CLI client public + device flow enabled?)")?
        .json()
        .await?;

    println!("\nTo sign in, open this URL and confirm the code:\n");
    if let Some(c) = &da.verification_uri_complete {
        println!("  {c}");
    }
    println!("  {}\n  code: {}\n", da.verification_uri, da.user_code);

    let deadline = now() + da.expires_in;
    let mut interval = da.interval.max(1);
    loop {
        if now() >= deadline {
            bail!("login timed out — run `rustlitel login` again");
        }
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        let resp = http
            .post(&disc.token_endpoint)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", &da.device_code),
                ("client_id", &client_id),
            ])
            .send()
            .await?;
        if resp.status().is_success() {
            let t: TokenResp = resp.json().await?;
            let tokens = Tokens {
                relay: relay.to_string(),
                token_endpoint: disc.token_endpoint.clone(),
                client_id: client_id.clone(),
                access_token: t.access_token,
                refresh_token: t.refresh_token,
                expires_at: now() + t.expires_in.saturating_sub(30),
            };
            save_tokens(relay, &tokens)?;
            save_default_relay(relay);
            println!("✓ signed in. Tokens cached.");
            return Ok(());
        }
        let err: TokenErr = resp.json().await.unwrap_or(TokenErr {
            error: "unknown".into(),
        });
        match err.error.as_str() {
            "authorization_pending" => continue,
            "slow_down" => {
                interval += 5;
                continue;
            }
            "access_denied" => bail!("access denied at the login page"),
            "expired_token" => bail!("login code expired — run `rustlitel login` again"),
            other => bail!("login failed: {other}"),
        }
    }
}

/// Return a valid access token, refreshing if needed.
async fn access_token(relay: &str) -> Result<String> {
    let mut t = load_tokens(relay)?;
    if now() < t.expires_at {
        return Ok(t.access_token);
    }
    let Some(rt) = t.refresh_token.clone() else {
        bail!("session expired — run `rustlitel login`");
    };
    let http = reqwest::Client::new();
    let resp = http
        .post(&t.token_endpoint)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &rt),
            ("client_id", &t.client_id),
        ])
        .send()
        .await?;
    let status = resp.status();
    if status == reqwest::StatusCode::BAD_REQUEST || status == reqwest::StatusCode::UNAUTHORIZED {
        bail!("session expired — run `rustlitel login`");
    }
    // Anything else (Keycloak restarting, a proxy error) says nothing about the
    // login, which stays cached for the next try.
    if !status.is_success() {
        bail!("could not refresh the session: the identity provider returned {status}");
    }
    let nt: TokenResp = resp.json().await?;
    t.access_token = nt.access_token;
    if nt.refresh_token.is_some() {
        t.refresh_token = nt.refresh_token;
    }
    t.expires_at = now() + nt.expires_in.saturating_sub(30);
    save_tokens(relay, &t)?;
    Ok(t.access_token)
}

// --- API -------------------------------------------------------------------

#[derive(Deserialize)]
struct AgentInfo {
    agent_id: String,
    name: String,
    os: String,
    allow_remote: bool,
    connected_secs: u64,
}

async fn agents(relay: &str) -> Result<()> {
    let tok = access_token(relay).await?;
    let list: Vec<AgentInfo> = reqwest::Client::new()
        .get(format!("{relay}/api/agents"))
        .bearer_auth(tok)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    if list.is_empty() {
        println!("(no agents connected)");
        return Ok(());
    }
    println!("{:<24} {:<22} {:<16} {:<8} UP", "ID", "NAME", "OS", "REMOTE");
    for a in list {
        println!(
            "{:<24} {:<22} {:<16} {:<8} {}s",
            a.agent_id,
            a.name,
            a.os,
            if a.allow_remote { "yes" } else { "no" },
            a.connected_secs
        );
    }
    Ok(())
}

#[derive(Deserialize)]
struct ExecResp {
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    #[serde(default)]
    error: Option<String>,
}

async fn exec(
    relay: &str,
    agent: &str,
    command: &str,
    shell: Option<String>,
    timeout: Option<u64>,
) -> Result<i32> {
    let tok = access_token(relay).await?;
    let body = serde_json::json!({
        "agent": agent, "command": command, "shell": shell, "timeout_secs": timeout,
    });
    let resp = reqwest::Client::new()
        .post(format!("{relay}/api/exec"))
        .bearer_auth(tok)
        .json(&body)
        .send()
        .await?;
    if !resp.status().is_success() {
        let s = resp.status();
        let t = resp.text().await.unwrap_or_default();
        bail!("relay returned {s}: {t}");
    }
    let r: ExecResp = resp.json().await?;
    if !r.stdout.is_empty() {
        print!("{}", r.stdout);
    }
    if !r.stderr.is_empty() {
        eprint!("{}", r.stderr);
    }
    if let Some(e) = r.error {
        eprintln!("\n[exec error] {e}");
    }
    Ok(r.exit_code.unwrap_or(1))
}

// --- desktop ---------------------------------------------------------------

/// POST /api/desktop and return the agent's `{"ok":true,...}` document, or
/// fail with its error.
async fn desktop(relay: &str, agent: &str, mut body: serde_json::Value) -> Result<serde_json::Value> {
    let tok = access_token(relay).await?;
    body["agent"] = serde_json::Value::String(agent.to_string());
    let resp = reqwest::Client::new()
        .post(format!("{relay}/api/desktop"))
        .bearer_auth(tok)
        .json(&body)
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await?;
    let v: serde_json::Value = serde_json::from_str(&text)
        .map_err(|_| anyhow!("relay returned {status}: {}", text.trim()))?;
    if v.get("ok").and_then(|x| x.as_bool()) != Some(true) {
        let e = v.get("error").and_then(|x| x.as_str()).unwrap_or("unknown error");
        bail!("{e}");
    }
    if let Some(w) = v.get("warning").and_then(|x| x.as_str()) {
        eprintln!("warning: {w}");
    }
    Ok(v)
}

fn s<'a>(v: &'a serde_json::Value, k: &str) -> &'a str {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("")
}
fn n(v: &serde_json::Value, k: &str) -> i64 {
    v.get(k).and_then(|x| x.as_i64()).unwrap_or(0)
}
fn b(v: &serde_json::Value, k: &str) -> bool {
    v.get(k).and_then(|x| x.as_bool()).unwrap_or(false)
}

fn print_window(w: &serde_json::Value) {
    let mut flags = Vec::new();
    if b(w, "foreground") {
        flags.push("fg");
    }
    if b(w, "minimized") {
        flags.push("min");
    }
    if b(w, "maximized") {
        flags.push("max");
    }
    if !b(w, "visible") {
        flags.push("hidden");
    }
    if b(w, "cloaked") {
        flags.push("cloaked");
    }
    let mut title: String = s(w, "title").chars().take(60).collect();
    if title.is_empty() {
        title = format!("[{}]", s(w, "class"));
    }
    println!(
        "{:<12} {:<7} {:<22} {:>6},{:<6} {:>5}x{:<5} {:<11} {}",
        format!("0x{:x}", n(w, "hwnd")),
        n(w, "pid"),
        s(w, "process").chars().take(22).collect::<String>(),
        n(w, "x"),
        n(w, "y"),
        n(w, "width"),
        n(w, "height"),
        flags.join(","),
        title
    );
}

async fn sessions_cmd(relay: &str, agent: &str, json: bool) -> Result<()> {
    let v = desktop(relay, agent, serde_json::json!({"action": "sessions"})).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&v["sessions"])?);
        return Ok(());
    }
    println!("{:<5} {:<16} {:<22} {:<13} NOTE", "ID", "STATION", "USER", "STATE");
    for x in v["sessions"].as_array().into_iter().flatten() {
        let mut note = Vec::new();
        if b(x, "console") {
            note.push("console");
        }
        if b(x, "default") {
            note.push("default");
        }
        println!(
            "{:<5} {:<16} {:<22} {:<13} {}",
            n(x, "id"),
            s(x, "name"),
            s(x, "user"),
            s(x, "state"),
            note.join(",")
        );
    }
    Ok(())
}

async fn windows_cmd(relay: &str, agent: &str, all: bool, json: bool, session: Option<u32>) -> Result<()> {
    let v = desktop(
        relay,
        agent,
        serde_json::json!({"action": "list_windows", "all": all, "session": session}),
    )
    .await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    println!(
        "session {} ({}), monitors: {}",
        n(&v, "session"),
        s(&v, "session_user"),
        v["monitors"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|m| format!("#{} {}x{}@{},{}", n(m, "index"), n(m, "width"), n(m, "height"), n(m, "x"), n(m, "y")))
            .collect::<Vec<_>>()
            .join("  ")
    );
    println!(
        "{:<12} {:<7} {:<22} {:>13} {:<11} {:<11} TITLE",
        "HWND", "PID", "PROCESS", "POSITION", "SIZE", "STATE"
    );
    for w in v["windows"].as_array().into_iter().flatten() {
        print_window(w);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn screenshot_cmd(
    relay: &str,
    agent: &str,
    out: Option<String>,
    target: &Target,
    monitor: Option<u32>,
    format: Option<String>,
    quality: Option<u8>,
    max_width: Option<u32>,
    session: Option<u32>,
    all_sessions: bool,
) -> Result<()> {
    let mut req = serde_json::json!({
        "action": "screenshot", "window": target.json(), "monitor": monitor,
        "format": format, "quality": quality, "max_width": max_width,
        "timeout_secs": 120,
    });
    let sessions: Vec<Option<u32>> = if all_sessions {
        let v = desktop(relay, agent, serde_json::json!({"action": "sessions"})).await?;
        let ids: Vec<Option<u32>> = v["sessions"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|x| !s(x, "user").is_empty())
            .map(|x| Some(n(x, "id") as u32))
            .collect();
        if ids.is_empty() {
            bail!("nobody is logged on to {agent}");
        }
        ids
    } else {
        vec![session]
    };
    let mut failed = 0;
    for sess in &sessions {
        req["session"] = serde_json::json!(sess);
        let v = match desktop(relay, agent, req.clone()).await {
            Ok(v) => v,
            Err(e) if all_sessions => {
                eprintln!("session {}: {e:#}", sess.unwrap_or(0));
                failed += 1;
                continue;
            }
            Err(e) => return Err(e),
        };
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(s(&v, "data"))
            .context("decode the image")?;
        let ext = if s(&v, "format") == "jpeg" { "jpg" } else { "png" };
        let path = match (&out, all_sessions) {
            (Some(o), _) if o == "-" => {
                use std::io::Write;
                std::io::stdout().write_all(&bytes)?;
                continue;
            }
            (Some(o), false) => o.clone(),
            (Some(o), true) => {
                let p = std::path::Path::new(o);
                let stem = p.file_stem().and_then(|x| x.to_str()).unwrap_or("screenshot");
                let e = p.extension().and_then(|x| x.to_str()).unwrap_or(ext);
                p.with_file_name(format!("{stem}-s{}.{e}", n(&v, "session")))
                    .to_string_lossy()
                    .into_owned()
            }
            (None, _) => {
                let suffix = if all_sessions { format!("-s{}", n(&v, "session")) } else { String::new() };
                format!("{agent}-{}{suffix}.{ext}", now())
            }
        };
        std::fs::write(&path, &bytes).with_context(|| format!("write {path}"))?;
        let what = match v.get("window") {
            Some(w) => format!("window {:?}", s(w, "title")),
            None => "screen".into(),
        };
        eprintln!(
            "{path}: {}x{} {}, {what}, session {} ({})",
            n(&v, "width"),
            n(&v, "height"),
            s(&v, "format"),
            n(&v, "session"),
            s(&v, "session_user")
        );
    }
    if failed == sessions.len() {
        bail!("no session could be captured");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn window_cmd(
    relay: &str,
    agent: &str,
    op: Op,
    target: &Target,
    x: Option<i32>,
    y: Option<i32>,
    width: Option<i32>,
    height: Option<i32>,
    session: Option<u32>,
) -> Result<()> {
    let t = target
        .json()
        .ok_or_else(|| anyhow!("say which window: --hwnd, --title, --process or --pid"))?;
    let v = desktop(
        relay,
        agent,
        serde_json::json!({
            "action": "window", "op": op.name(), "target": t,
            "x": x, "y": y, "width": width, "height": height, "session": session,
        }),
    )
    .await?;
    if let Some(closed) = v.get("closed").and_then(|c| c.as_bool()) {
        println!("{}", if closed { "closed" } else { "still open" });
        if let Some(note) = v.get("note").and_then(|x| x.as_str()) {
            eprintln!("{note}");
        }
        return Ok(());
    }
    if let Some(w) = v.get("window") {
        print_window(w);
    }
    if matches!(op, Op::Focus) && !b(&v, "foreground") {
        eprintln!("note: Windows did not move it to the foreground (someone may be using the machine)");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Login => {
            let relay = resolve_relay(cli.relay)?;
            login(&relay).await?;
        }
        Cmd::Logout => {
            let relay = resolve_relay(cli.relay)?;
            let _ = std::fs::remove_file(token_path(&relay)?);
            println!("signed out of {relay}");
        }
        Cmd::Whoami => {
            let relay = resolve_relay(cli.relay)?;
            let t = load_tokens(&relay)?;
            // Pull preferred_username out of the JWT payload (no verification —
            // display only).
            let name = t
                .access_token
                .split('.')
                .nth(1)
                .and_then(|p| base64_url_decode(p))
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .and_then(|v| {
                    v.get("preferred_username")
                        .or_else(|| v.get("name"))
                        .and_then(|x| x.as_str().map(String::from))
                })
                .unwrap_or_else(|| "unknown".into());
            println!("{name} @ {relay}");
        }
        Cmd::Agents => {
            let relay = resolve_relay(cli.relay)?;
            agents(&relay).await?;
        }
        Cmd::Exec {
            agent,
            command,
            shell,
            timeout,
        } => {
            let relay = resolve_relay(cli.relay)?;
            let code = exec(&relay, &agent, &command.join(" "), shell, timeout).await?;
            std::process::exit(code);
        }
        Cmd::Sessions { agent, json } => {
            let relay = resolve_relay(cli.relay)?;
            sessions_cmd(&relay, &agent, json).await?;
        }
        Cmd::Windows { agent, all, json, session } => {
            let relay = resolve_relay(cli.relay)?;
            windows_cmd(&relay, &agent, all, json, session).await?;
        }
        Cmd::Screenshot {
            agent,
            out,
            target,
            monitor,
            format,
            quality,
            max_width,
            session,
            all_sessions,
        } => {
            let relay = resolve_relay(cli.relay)?;
            screenshot_cmd(
                &relay, &agent, out, &target, monitor, format, quality, max_width, session, all_sessions,
            )
            .await?;
        }
        Cmd::Window {
            agent,
            op,
            target,
            x,
            y,
            width,
            height,
            session,
        } => {
            let relay = resolve_relay(cli.relay)?;
            window_cmd(&relay, &agent, op, &target, x, y, width, height, session).await?;
        }
    }
    Ok(())
}

fn base64_url_decode(s: &str) -> Option<Vec<u8>> {
    // minimal base64url decode (JWT payload), tolerant of missing padding
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s.bytes().filter_map(val).collect();
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1)?;
        out.push((b0 << 2) | (b1 >> 4));
        if let Some(&b2) = chunk.get(2) {
            out.push((b1 << 4) | (b2 >> 2));
            if let Some(&b3) = chunk.get(3) {
                out.push((b2 << 6) | b3);
            }
        }
    }
    Some(out)
}
