//! Operator authentication: one shared operator token (or a Keycloak login)
//! exchanged for a session cookie.
//!
//! The cookie is self-contained: `S1.<base64url(claims)>.<base64url(HMAC)>`, so a
//! session outlives a relay restart, a rollout or an OOM kill. The HMAC key is
//! derived from the operator token, so rotating that token ends every session.
//! Logout clears the browser's cookie and remembers the session id in memory
//! until it expires; that memory does not survive a restart.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// Name of the session cookie.
pub const COOKIE_NAME: &str = "rustlitel_session";

/// Keeps a session key from ever equalling a key signing anything else.
const SESSION_KEY_LABEL: &[u8] = b"rustlitel session cookie v1";

#[derive(Serialize, Deserialize)]
struct Claims {
    /// Random id; what logout revokes.
    sid: String,
    /// Unix seconds.
    exp: u64,
    /// Display name for OIDC logins; `None` for token logins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user: Option<String>,
}

pub struct Auth {
    operator_token: String,
    session_key: Vec<u8>,
    /// Logged-out session ids -> their expiry.
    revoked: Mutex<HashMap<String, u64>>,
    ttl: Duration,
    /// Set the `Secure` attribute on the cookie (true behind TLS/ingress).
    pub cookie_secure: bool,
}

impl Auth {
    pub fn new(operator_token: String, ttl: Duration, cookie_secure: bool) -> Self {
        let session_key = mac(operator_token.as_bytes(), SESSION_KEY_LABEL);
        Self {
            operator_token,
            session_key,
            revoked: Mutex::new(HashMap::new()),
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

    /// Issue a fresh session cookie value, optionally bound to a username.
    pub fn issue(&self, username: Option<String>) -> String {
        let claims = Claims {
            sid: random_nonce(),
            exp: now() + self.ttl.as_secs(),
            user: username,
        };
        let payload = B64.encode(serde_json::to_vec(&claims).expect("serialize claims"));
        let sig = B64.encode(mac(&self.session_key, payload.as_bytes()));
        format!("S1.{payload}.{sig}")
    }

    /// The claims of a correctly signed, unexpired, not logged-out session.
    fn claims(&self, id: &str) -> Option<Claims> {
        let rest = id.strip_prefix("S1.")?;
        let (payload, sig) = rest.split_once('.')?;
        let expected = B64.encode(mac(&self.session_key, payload.as_bytes()));
        if !bool::from(expected.as_bytes().ct_eq(sig.as_bytes())) {
            return None;
        }
        let claims: Claims = serde_json::from_slice(&B64.decode(payload).ok()?).ok()?;
        if claims.exp <= now() || self.revoked.lock().unwrap().contains_key(&claims.sid) {
            return None;
        }
        Some(claims)
    }

    /// True if `id` is a valid session.
    pub fn validate(&self, id: &str) -> bool {
        self.claims(id).is_some()
    }

    /// The username bound to a valid session, if any (OIDC logins only).
    pub fn username(&self, id: &str) -> Option<String> {
        self.claims(id).and_then(|c| c.user)
    }

    pub fn revoke(&self, id: &str) {
        if let Some(c) = self.claims(id) {
            let mut revoked = self.revoked.lock().unwrap();
            let t = now();
            revoked.retain(|_, exp| *exp > t);
            revoked.insert(c.sid, c.exp);
        }
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

fn mac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(token: &str, ttl: u64) -> Auth {
        Auth::new(token.into(), Duration::from_secs(ttl), true)
    }

    #[test]
    fn session_survives_a_restart() {
        let id = auth("operator-token-1", 60).issue(Some("sirius".into()));
        let restarted = auth("operator-token-1", 60);
        assert!(restarted.validate(&id));
        assert_eq!(restarted.username(&id).as_deref(), Some("sirius"));
    }

    #[test]
    fn rotating_the_operator_token_ends_sessions() {
        let id = auth("operator-token-1", 60).issue(None);
        assert!(!auth("operator-token-2", 60).validate(&id));
    }

    #[test]
    fn expired_forged_and_revoked_sessions_are_refused() {
        let a = auth("operator-token-1", 0);
        assert!(!a.validate(&a.issue(None)));

        let a = auth("operator-token-1", 60);
        let id = a.issue(Some("alice".into()));
        let (head, sig) = id.rsplit_once('.').unwrap();
        let forged_payload = B64.encode(br#"{"sid":"x","exp":99999999999,"user":"admin"}"#);
        assert!(!a.validate(&format!("S1.{forged_payload}.{sig}")));
        assert!(!a.validate(&format!("{head}.AAAA")));
        assert!(!a.validate("not-a-session"));

        assert!(a.validate(&id));
        a.revoke(&id);
        assert!(!a.validate(&id));
    }
}
