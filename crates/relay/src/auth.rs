//! Operator authentication: one shared operator token exchanged for a random,
//! server-side session cookie. Single replica, so the valid-session set lives
//! in memory and is wiped on restart (operators simply log in again).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::RngCore;
use subtle::ConstantTimeEq;

/// Name of the session cookie.
pub const COOKIE_NAME: &str = "rustlitel_session";

struct Session {
    expiry: Instant,
    /// Display name for OIDC logins; `None` for token logins.
    username: Option<String>,
}

pub struct Auth {
    operator_token: String,
    sessions: Mutex<HashMap<String, Session>>,
    ttl: Duration,
    /// Set the `Secure` attribute on the cookie (true behind TLS/ingress).
    pub cookie_secure: bool,
}

impl Auth {
    pub fn new(operator_token: String, ttl: Duration, cookie_secure: bool) -> Self {
        Self {
            operator_token,
            sessions: Mutex::new(HashMap::new()),
            ttl,
            cookie_secure,
        }
    }

    /// Constant-time check of a presented operator token.
    pub fn token_ok(&self, presented: &str) -> bool {
        // Hash-free compare is fine: both sides are already high-entropy
        // secrets, and ConstantTimeEq keeps the comparison length-safe.
        presented
            .as_bytes()
            .ct_eq(self.operator_token.as_bytes())
            .into()
    }

    /// Issue a fresh session id, optionally bound to a username (OIDC login).
    pub fn issue(&self, username: Option<String>) -> String {
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        let id = hex(&raw);
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(
            id.clone(),
            Session {
                expiry: Instant::now() + self.ttl,
                username,
            },
        );
        // Opportunistically drop expired entries so the map cannot grow without
        // bound across a long-lived process.
        let now = Instant::now();
        sessions.retain(|_, s| s.expiry > now);
        id
    }

    /// True if `id` is a known, unexpired session.
    pub fn validate(&self, id: &str) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        match sessions.get(id) {
            Some(s) if s.expiry > Instant::now() => true,
            Some(_) => {
                sessions.remove(id);
                false
            }
            None => false,
        }
    }

    /// The username bound to a valid session, if any (OIDC logins only).
    pub fn username(&self, id: &str) -> Option<String> {
        let sessions = self.sessions.lock().unwrap();
        sessions
            .get(id)
            .filter(|s| s.expiry > Instant::now())
            .and_then(|s| s.username.clone())
    }

    pub fn revoke(&self, id: &str) {
        self.sessions.lock().unwrap().remove(id);
    }

    /// `Set-Cookie` value for a freshly issued session.
    pub fn cookie_header(&self, id: &str) -> String {
        let secure = if self.cookie_secure { "; Secure" } else { "" };
        format!(
            "{COOKIE_NAME}={id}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}{secure}",
            self.ttl.as_secs()
        )
    }

    /// `Set-Cookie` value that clears the session (logout).
    pub fn clear_cookie_header(&self) -> String {
        let secure = if self.cookie_secure { "; Secure" } else { "" };
        format!("{COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{secure}")
    }
}

/// Extract the `rustlitel_session` value from a `Cookie` header, if present.
pub fn session_from_cookies(cookie_header: Option<&str>) -> Option<String> {
    cookie_value(cookie_header, COOKIE_NAME)
}

/// Extract a named cookie's value from a `Cookie` header, if present.
pub fn cookie_value(cookie_header: Option<&str>, name: &str) -> Option<String> {
    let header = cookie_header?;
    for part in header.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix(name) {
            if let Some(val) = rest.strip_prefix('=') {
                return Some(val.to_string());
            }
        }
    }
    None
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Random single-use nonce (session dial authorisation).
pub fn random_nonce() -> String {
    let mut raw = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut raw);
    hex(&raw)
}
