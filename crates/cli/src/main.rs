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

    let da: DeviceAuth = http
        .post(&disc.device_authorization_endpoint)
        .form(&[("client_id", client_id.as_str()), ("scope", "openid profile")])
        .send()
        .await?
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
            std::fs::write(token_path(relay)?, serde_json::to_vec_pretty(&tokens)?)?;
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
    if !resp.status().is_success() {
        bail!("session expired — run `rustlitel login`");
    }
    let nt: TokenResp = resp.json().await?;
    t.access_token = nt.access_token;
    if nt.refresh_token.is_some() {
        t.refresh_token = nt.refresh_token;
    }
    t.expires_at = now() + nt.expires_in.saturating_sub(30);
    std::fs::write(token_path(relay)?, serde_json::to_vec_pretty(&t)?)?;
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
