//! rustlitel-relay — the public rendezvous between a browser and an agent that lives
//! behind NAT. Agents dial in over WSS; operators reach it from a browser. The
//! relay authenticates both sides and bridges bytes; it never spawns a shell
//! itself.
//!
//! Configuration is entirely environment-driven (12-factor, friendly to a k8s
//! Deployment). Required: `RUSTLITEL_OPERATOR_TOKEN`, `RUSTLITEL_AGENT_TOKEN`.

mod auth;
mod handlers;
mod installer;
mod oidc;
mod state;
mod ui;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::{get, post};
use axum::Router;
use tokio::sync::Mutex;

use crate::auth::Auth;
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("RUSTLITEL_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let listen = env_or("RUSTLITEL_LISTEN_ADDR", "0.0.0.0:8080");
    let operator_token = require_env("RUSTLITEL_OPERATOR_TOKEN")?;
    let agent_token = require_env("RUSTLITEL_AGENT_TOKEN")?;
    let public_origin = std::env::var("RUSTLITEL_PUBLIC_ORIGIN").ok().filter(|s| !s.is_empty());
    let ttl_hours: u64 = env_or("RUSTLITEL_SESSION_TTL_HOURS", "12").parse().unwrap_or(12);
    let cookie_secure = env_or("RUSTLITEL_COOKIE_SECURE", "1") != "0";
    let open_timeout_secs: u64 = env_or("RUSTLITEL_OPEN_TIMEOUT_SECS", "30").parse().unwrap_or(30);
    let exec_output_cap: usize = env_or("RUSTLITEL_EXEC_OUTPUT_CAP", "1048576")
        .parse()
        .unwrap_or(1_048_576);
    let exec_default_timeout_secs: u64 = env_or("RUSTLITEL_EXEC_DEFAULT_TIMEOUT_SECS", "120")
        .parse()
        .unwrap_or(120);
    let agents_dir = env_or("RUSTLITEL_AGENTS_DIR", "/srv/agents");
    let ui_dir = env_or("RUSTLITEL_UI_DIR", "/srv/ui");
    let short_link_ttl_days: u64 = env_or("RUSTLITEL_SHORT_LINK_TTL_DAYS", "7").parse().unwrap_or(7);

    let oidc = oidc::OidcConfig::from_env().map(oidc::Oidc::new);
    if oidc.is_some() {
        tracing::info!("OIDC operator login enabled");
    } else {
        tracing::info!("OIDC not configured; using operator-token login");
    }

    if operator_token == agent_token {
        anyhow::bail!("RUSTLITEL_OPERATOR_TOKEN and RUSTLITEL_AGENT_TOKEN must differ");
    }

    let state = Arc::new(AppState {
        agents: Mutex::new(HashMap::new()),
        sessions: Mutex::new(HashMap::new()),
        execs: Mutex::new(HashMap::new()),
        auth: Auth::new(
            operator_token,
            Duration::from_secs(ttl_hours * 3600),
            cookie_secure,
        ),
        agent_token,
        public_origin: public_origin.clone(),
        open_timeout_secs,
        exec_output_cap,
        exec_default_timeout_secs,
        agents_dir,
        ui_dir,
        oidc,
        short_links: Mutex::new(HashMap::new()),
        short_link_ttl: Duration::from_secs(short_link_ttl_days * 86400),
        oidc_cli_client_id: env_or("RUSTLITEL_OIDC_CLI_CLIENT_ID", "rustlitel-cli"),
    });

    let app = Router::new()
        .route("/healthz", get(handlers::healthz))
        .route("/api/login", post(handlers::login))
        .route("/api/logout", post(handlers::logout))
        .route("/api/me", get(handlers::me))
        .route("/oauth2/login", get(handlers::oidc_login))
        .route("/oauth2/callback", get(handlers::oidc_callback))
        .route("/oauth2/logout", get(handlers::oidc_logout))
        .route("/api/agents", get(handlers::list_agents))
        .route("/api/exec", post(handlers::exec))
        .route("/api/uninstall", post(handlers::uninstall_agent))
        .route("/api/installer", post(handlers::make_installer))
        .route("/installer", get(handlers::download_installer))
        .route("/i/:code", get(handlers::download_short))
        .route("/api/auth-config", get(handlers::auth_config))
        .route("/api/agent/update", get(handlers::agent_update))
        .route("/api/agent/binary", get(handlers::agent_binary))
        .route("/download/:file", get(handlers::download))
        .route("/ws/term", get(handlers::term_ws))
        .route("/ws/agent/control", get(handlers::agent_control_ws))
        .route("/ws/agent/session", get(handlers::agent_session_ws))
        // Everything else is a UI asset (served from RUSTLITEL_UI_DIR); the SPA
        // handles its own routing, so unknown paths fall back to index.html.
        .fallback(ui::serve)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!(%listen, origin = ?public_origin, "rustlitel-relay listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn require_env(key: &str) -> anyhow::Result<String> {
    std::env::var(key)
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{key} is required"))
}

/// Resolve on Ctrl-C or SIGTERM (k8s rolling update / pod shutdown).
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
    tracing::info!("shutting down");
}
