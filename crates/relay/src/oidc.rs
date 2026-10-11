//! In-app OpenID Connect (Keycloak) login for the operator UI.
//!
//! The relay itself is the OIDC client: it runs the Authorization Code flow
//! with PKCE, verifies the returned ID token (RS256 against the issuer's JWKS,
//! plus `iss`/`aud`/`exp`/`nonce`), enforces a required group claim, and then
//! establishes its own session carrying the username. The browser login
//! switches to "Sign in with Keycloak" when this is configured; scripts keep
//! using the Bearer operator token for `/api/exec`.
//!
//! The per-login secrets (`state`/`nonce`/PKCE verifier/return-to) are carried
//! in a short-lived, HMAC-signed, HttpOnly cookie — not in relay memory — so a
//! relay restart/rollout or a second replica never invalidates an in-flight
//! login, and the login is bound to the browser that started it (closing a
//! login-CSRF/fixation gap).
//!
//! Enabled only when the `RUSTLITEL_OIDC_*` env is present, so the operator-token
//! login keeps working until Keycloak is wired up.

use std::sync::Mutex;

use anyhow::{anyhow, bail, Context};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
use base64::Engine;
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use url::Url;

type HmacSha256 = Hmac<Sha256>;

/// Name of the short-lived cookie carrying the signed login state.
pub const LOGIN_COOKIE: &str = "rustlitel_login";
/// How long a started login may take to complete (seconds).
pub const LOGIN_TTL_SECS: u64 = 600;

pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    /// Required group/role value; empty = any authenticated user in the realm.
    pub allowed_group: String,
    pub username_claim: String,
    pub groups_claim: String,
    /// Public client id the `rustlitel` CLI uses for its device-flow login; its
    /// access tokens are also accepted on the API, so it is an allowed audience.
    pub cli_client_id: String,
}

impl OidcConfig {
    /// Build from env, or `None` if the required pieces are missing.
    pub fn from_env() -> Option<Self> {
        let issuer = nonempty("RUSTLITEL_OIDC_ISSUER")?;
        let client_id = nonempty("RUSTLITEL_OIDC_CLIENT_ID")?;
        let client_secret = nonempty("RUSTLITEL_OIDC_CLIENT_SECRET")?;
        let redirect_url = nonempty("RUSTLITEL_OIDC_REDIRECT_URL")?;
        // Be forgiving: accept the full discovery URL and reduce it to the
        // issuer the token's `iss` will actually carry.
        let issuer = issuer
            .trim()
            .trim_end_matches('/')
            .strip_suffix("/.well-known/openid-configuration")
            .unwrap_or_else(|| issuer.trim().trim_end_matches('/'));
        let issuer = issuer.trim_end_matches('/').to_string();
        Some(Self {
            issuer,
            client_id,
            client_secret,
            redirect_url,
            allowed_group: std::env::var("RUSTLITEL_OIDC_ALLOWED_GROUP").unwrap_or_default(),
            username_claim: env_or("RUSTLITEL_OIDC_USERNAME_CLAIM", "preferred_username"),
            groups_claim: env_or("RUSTLITEL_OIDC_GROUPS_CLAIM", "groups"),
            cli_client_id: env_or("RUSTLITEL_OIDC_CLI_CLIENT_ID", "rustlitel-cli"),
        })
    }

    /// Reject a cleartext issuer (discovery/JWKS/token would travel in the
    /// clear). A loopback issuer is allowed for local development.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.issuer.starts_with("https://") {
            return Ok(());
        }
        let loopback = self
            .issuer
            .strip_prefix("http://")
            .map(|rest| {
                rest.starts_with("localhost")
                    || rest.starts_with("127.0.0.1")
                    || rest.starts_with("[::1]")
            })
            .unwrap_or(false);
        if loopback {
            Ok(())
        } else {
            bail!("RUSTLITEL_OIDC_ISSUER must be https:// (got {})", self.issuer)
        }
    }
}

#[derive(Deserialize)]
struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    end_session_endpoint: Option<String>,
}

#[derive(Deserialize, Clone)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

/// The per-login secrets, carried in a signed cookie (not relay memory).
#[derive(Serialize, Deserialize)]
struct LoginState {
    state: String,
    nonce: String,
    pkce_verifier: String,
    return_to: String,
    /// Unix seconds when this login attempt expires.
    exp: u64,
}

pub struct Oidc {
    pub cfg: OidcConfig,
    http: reqwest::Client,
    disc: tokio::sync::OnceCell<Discovery>,
    jwks: Mutex<Vec<Jwk>>,
    /// HMAC key for the signed login-state cookie (a server-side secret).
    state_secret: String,
}

/// Verified identity extracted from an ID token.
pub struct Identity {
    pub username: String,
    pub groups: Vec<String>,
}

impl Oidc {
    pub fn new(cfg: OidcConfig, state_secret: String) -> Self {
        Self {
            cfg,
            http: reqwest::Client::new(),
            disc: tokio::sync::OnceCell::new(),
            jwks: Mutex::new(Vec::new()),
            state_secret,
        }
    }

    async fn discovery(&self) -> anyhow::Result<&Discovery> {
        self.disc
            .get_or_try_init(|| async {
                let url = format!("{}/.well-known/openid-configuration", self.cfg.issuer);
                let d: Discovery = self
                    .http
                    .get(&url)
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await
                    .context("parse discovery")?;
                Ok::<_, anyhow::Error>(d)
            })
            .await
    }

    /// Build the authorize URL and the signed login-state cookie value to set.
    pub async fn begin_login(&self, return_to: &str) -> anyhow::Result<(String, String)> {
        let disc = self.discovery().await?;
        let state = rand_tok();
        let nonce = rand_tok();
        let verifier = rand_verifier();
        let challenge = B64U.encode(Sha256::digest(verifier.as_bytes()));

        let ls = LoginState {
            state: state.clone(),
            nonce: nonce.clone(),
            pkce_verifier: verifier,
            return_to: sanitize_return(return_to),
            exp: now() + LOGIN_TTL_SECS,
        };
        let cookie = self.sign_state(&ls);

        let mut u = Url::parse(&disc.authorization_endpoint).context("auth endpoint url")?;
        u.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.cfg.client_id)
            .append_pair("redirect_uri", &self.cfg.redirect_url)
            .append_pair("scope", "openid profile")
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        Ok((u.to_string(), cookie))
    }

    /// Exchange the code, verify the ID token, enforce the group. The login
    /// state comes from the signed cookie set at `begin_login`; the `state`
    /// query param must match it (CSRF / browser binding). Returns the identity
    /// and where to send the browser next.
    pub async fn complete_login(
        &self,
        code: &str,
        state: &str,
        cookie: Option<&str>,
    ) -> anyhow::Result<(Identity, String)> {
        let cookie = cookie.ok_or_else(|| anyhow!("missing login state"))?;
        let ls = self
            .verify_state(cookie)
            .ok_or_else(|| anyhow!("invalid login state"))?;
        if ls.exp <= now() {
            bail!("login attempt expired");
        }
        // Bind the returned `state` to the browser's signed cookie.
        let state_ok: bool = state.as_bytes().ct_eq(ls.state.as_bytes()).into();
        if !state_ok {
            bail!("login state mismatch");
        }

        let disc = self.discovery().await?;
        // client auth via HTTP Basic (client_secret_basic), so client_id/secret
        // are not repeated in the body.
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.cfg.redirect_url.as_str()),
            ("code_verifier", ls.pkce_verifier.as_str()),
        ];
        let resp = self
            .http
            .post(&disc.token_endpoint)
            .basic_auth(&self.cfg.client_id, Some(&self.cfg.client_secret))
            .form(&params)
            .send()
            .await
            .context("token request")?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            // Log the IdP detail server-side; don't reflect it to the browser.
            let snippet: String = body.chars().take(300).collect();
            tracing::warn!(status = %status.as_u16(), "token endpoint error: {snippet}");
            bail!("token exchange failed");
        }
        #[derive(Deserialize)]
        struct TokenResp {
            id_token: String,
            #[serde(default)]
            access_token: String,
        }
        let tok: TokenResp = serde_json::from_str(&body).context("parse token response")?;

        let mut identity = self.verify_id_token(&tok.id_token, &ls.nonce).await?;

        // Keycloak puts realm roles in the access token by default, not the ID
        // token, so merge those in for the group check.
        if !tok.access_token.is_empty() {
            let more = self.access_token_groups(&tok.access_token).await;
            identity.groups.extend(more);
        }

        if !self.cfg.allowed_group.is_empty() {
            // Tolerate oauth2-proxy's `role:` prefix and Keycloak group paths
            // (`/name`), so `allowed_group` matches realm roles and groups alike.
            let want = self.cfg.allowed_group.trim_start_matches("role:");
            let ok = identity.groups.iter().any(|g| {
                g == &self.cfg.allowed_group
                    || g.trim_start_matches("role:") == want
                    || g.trim_start_matches('/') == want
            });
            if !ok {
                tracing::warn!(
                    user = %identity.username,
                    "login denied: not in required group '{}'",
                    self.cfg.allowed_group
                );
                bail!("you are not in the required group");
            }
        }
        Ok((identity, ls.return_to))
    }

    async fn verify_id_token(&self, jwt: &str, nonce: &str) -> anyhow::Result<Identity> {
        let header = decode_header(jwt).context("decode header")?;
        let kid = header.kid.ok_or_else(|| anyhow!("id token has no kid"))?;

        let jwk = match self.find_jwk(&kid) {
            Some(j) => j,
            None => {
                self.refresh_jwks().await?;
                self.find_jwk(&kid)
                    .ok_or_else(|| anyhow!("no signing key for kid {kid}"))?
            }
        };

        let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e).context("build rsa key")?;
        let mut val = Validation::new(Algorithm::RS256);
        val.set_issuer(&[self.cfg.issuer.as_str()]);
        val.set_audience(&[self.cfg.client_id.as_str()]);
        let data = decode::<serde_json::Value>(jwt, &key, &val).context("verify id token")?;
        let c = data.claims;

        if c.get("nonce").and_then(|v| v.as_str()) != Some(nonce) {
            bail!("nonce mismatch");
        }

        let username = c
            .get(&self.cfg.username_claim)
            .and_then(|v| v.as_str())
            .or_else(|| c.get("name").and_then(|v| v.as_str()))
            .or_else(|| c.get("email").and_then(|v| v.as_str()))
            .unwrap_or("user")
            .to_string();

        Ok(Identity {
            username,
            groups: extract_groups(&c, &self.cfg.groups_claim),
        })
    }

    /// Best-effort group/role extraction from the access token: verify its
    /// signature + issuer, confirm it was issued to one of our clients
    /// (azp/aud), then read `groups` and `realm_access.roles`. On any failure,
    /// no groups.
    async fn access_token_groups(&self, jwt: &str) -> Vec<String> {
        let Ok(header) = decode_header(jwt) else {
            return Vec::new();
        };
        let Some(kid) = header.kid else {
            return Vec::new();
        };
        let jwk = match self.find_jwk(&kid) {
            Some(j) => j,
            None => {
                let _ = self.refresh_jwks().await;
                match self.find_jwk(&kid) {
                    Some(j) => j,
                    None => return Vec::new(),
                }
            }
        };
        let Ok(key) = DecodingKey::from_rsa_components(&jwk.n, &jwk.e) else {
            return Vec::new();
        };
        // Keycloak access-token `aud` varies, so validate the authorized party
        // (azp)/audience ourselves against our own client ids below.
        let mut val = Validation::new(Algorithm::RS256);
        val.set_issuer(&[self.cfg.issuer.as_str()]);
        val.validate_aud = false;
        match decode::<serde_json::Value>(jwt, &key, &val) {
            Ok(data) if self.audience_ok(&data.claims) => {
                extract_groups(&data.claims, &self.cfg.groups_claim)
            }
            _ => Vec::new(),
        }
    }

    /// Verify a Bearer *access* token (signature + issuer + expiry + that it was
    /// issued to one of our clients) and enforce the group. Used to authorize
    /// API clients like the `rustlitel` CLI. Returns the username.
    pub async fn authorize_bearer(&self, token: &str) -> Option<String> {
        let header = decode_header(token).ok()?;
        let kid = header.kid?;
        let jwk = match self.find_jwk(&kid) {
            Some(j) => j,
            None => {
                self.refresh_jwks().await.ok()?;
                self.find_jwk(&kid)?
            }
        };
        let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e).ok()?;
        let mut val = Validation::new(Algorithm::RS256);
        val.set_issuer(&[self.cfg.issuer.as_str()]);
        // Keycloak access-token `aud` varies; we check azp/aud ourselves.
        val.validate_aud = false;
        let data = decode::<serde_json::Value>(token, &key, &val).ok()?;
        let c = data.claims;

        // The token must have been issued to one of our own clients — otherwise
        // a token minted for a *different* client in the same realm would be
        // accepted here (cross-client confusion).
        if !self.audience_ok(&c) {
            return None;
        }

        if !self.cfg.allowed_group.is_empty() {
            let groups = extract_groups(&c, &self.cfg.groups_claim);
            let want = self.cfg.allowed_group.trim_start_matches("role:");
            let ok = groups.iter().any(|g| {
                g == &self.cfg.allowed_group
                    || g.trim_start_matches("role:") == want
                    || g.trim_start_matches('/') == want
            });
            if !ok {
                return None;
            }
        }
        Some(
            c.get(&self.cfg.username_claim)
                .and_then(|v| v.as_str())
                .or_else(|| c.get("preferred_username").and_then(|v| v.as_str()))
                .unwrap_or("user")
                .to_string(),
        )
    }

    /// True if the token's `azp` (authorized party) — or, absent that, its
    /// `aud` — names one of our own clients (the web client or the CLI client).
    fn audience_ok(&self, c: &serde_json::Value) -> bool {
        let allowed = [self.cfg.client_id.as_str(), self.cfg.cli_client_id.as_str()];
        if let Some(azp) = c.get("azp").and_then(|v| v.as_str()) {
            return allowed.contains(&azp);
        }
        match c.get("aud") {
            Some(serde_json::Value::String(a)) => allowed.contains(&a.as_str()),
            Some(serde_json::Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str())
                .any(|a| allowed.contains(&a)),
            _ => false,
        }
    }

    /// Public config the CLI needs to start a device-flow login.
    pub fn public_config(&self) -> serde_json::Value {
        serde_json::json!({
            "issuer": self.cfg.issuer,
            "cli_client_id": self.cfg.cli_client_id,
            "allowed_group": self.cfg.allowed_group,
        })
    }

    fn find_jwk(&self, kid: &str) -> Option<Jwk> {
        self.jwks.lock().unwrap().iter().find(|j| j.kid == kid).cloned()
    }

    async fn refresh_jwks(&self) -> anyhow::Result<()> {
        let disc = self.discovery().await?;
        let jwks: Jwks = self
            .http
            .get(&disc.jwks_uri)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .context("parse jwks")?;
        *self.jwks.lock().unwrap() = jwks.keys;
        Ok(())
    }

    // --- signed login-state cookie -----------------------------------------

    fn sign_state(&self, ls: &LoginState) -> String {
        let json = serde_json::to_vec(ls).expect("serialize login state");
        let pb = B64U.encode(json);
        let sig = self.state_mac(pb.as_bytes());
        format!("{pb}.{sig}")
    }

    fn verify_state(&self, token: &str) -> Option<LoginState> {
        let (pb, sig) = token.split_once('.')?;
        let expected = self.state_mac(pb.as_bytes());
        let ok: bool = expected.as_bytes().ct_eq(sig.as_bytes()).into();
        if !ok {
            return None;
        }
        let json = B64U.decode(pb).ok()?;
        serde_json::from_slice(&json).ok()
    }

    fn state_mac(&self, data: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(self.state_secret.as_bytes()).expect("hmac key");
        mac.update(data);
        B64U.encode(mac.finalize().into_bytes())
    }

    /// RP-initiated logout URL (ends the Keycloak session too), if advertised.
    pub async fn logout_url(&self, post_logout: &str) -> Option<String> {
        let disc = self.discovery().await.ok()?;
        let end = disc.end_session_endpoint.clone()?;
        let mut u = Url::parse(&end).ok()?;
        u.query_pairs_mut()
            .append_pair("client_id", &self.cfg.client_id)
            .append_pair("post_logout_redirect_uri", post_logout);
        Some(u.to_string())
    }
}

/// Pull group/role strings from a claims object. Supports a flat array claim
/// (default `groups`) and Keycloak's `realm_access.roles`.
fn extract_groups(c: &serde_json::Value, claim: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(arr) = c.get(claim).and_then(|v| v.as_array()) {
        out.extend(arr.iter().filter_map(|v| v.as_str().map(String::from)));
    }
    if let Some(roles) = c
        .get("realm_access")
        .and_then(|v| v.get("roles"))
        .and_then(|v| v.as_array())
    {
        out.extend(roles.iter().filter_map(|v| v.as_str().map(String::from)));
    }
    out
}

/// Only allow a same-origin path as the post-login redirect. Rejects absolute
/// URLs, scheme-relative `//host`, and the `/\host` backslash bypass (browsers
/// normalise `\` to `/`, so `/\evil.com` would resolve to `//evil.com`).
fn sanitize_return(path: &str) -> String {
    if path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains('\\')
        && !path.chars().any(|c| c.is_control())
    {
        path.to_string()
    } else {
        "/".to_string()
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn rand_tok() -> String {
    let mut raw = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut raw);
    B64U.encode(raw)
}

/// PKCE code_verifier: 48 bytes -> 64 base64url chars, within the RFC 7636
/// 43–128 range that Keycloak enforces (a shorter one 400s the token endpoint).
fn rand_verifier() -> String {
    let mut raw = [0u8; 48];
    rand::thread_rng().fill_bytes(&mut raw);
    B64U.encode(raw)
}

fn nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> OidcConfig {
        OidcConfig {
            issuer: "https://kc.example/realms/main".into(),
            client_id: "web".into(),
            client_secret: "s".into(),
            redirect_url: "https://r/oauth2/callback".into(),
            allowed_group: String::new(),
            username_claim: "preferred_username".into(),
            groups_claim: "groups".into(),
            cli_client_id: "rustlitel-cli".into(),
        }
    }

    #[test]
    fn login_state_cookie_roundtrip() {
        let o = Oidc::new(cfg(), "server-secret".into());
        let ls = LoginState {
            state: "st".into(),
            nonce: "no".into(),
            pkce_verifier: "ve".into(),
            return_to: "/".into(),
            exp: now() + 60,
        };
        let token = o.sign_state(&ls);
        let back = o.verify_state(&token).expect("verify");
        assert_eq!(back.state, "st");
        assert_eq!(back.pkce_verifier, "ve");
        // Tamper → reject.
        let mut bad = token.clone();
        bad.push('x');
        assert!(o.verify_state(&bad).is_none());
        // Different secret → reject.
        let o2 = Oidc::new(cfg(), "other".into());
        assert!(o2.verify_state(&token).is_none());
    }

    #[test]
    fn sanitize_return_blocks_bypasses() {
        assert_eq!(sanitize_return("/app"), "/app");
        assert_eq!(sanitize_return("//evil.com"), "/");
        assert_eq!(sanitize_return("/\\evil.com"), "/");
        assert_eq!(sanitize_return("https://evil.com"), "/");
    }

    #[test]
    fn audience_checks_azp_then_aud() {
        let o = Oidc::new(cfg(), "s".into());
        assert!(o.audience_ok(&serde_json::json!({ "azp": "web" })));
        assert!(o.audience_ok(&serde_json::json!({ "azp": "rustlitel-cli" })));
        assert!(!o.audience_ok(&serde_json::json!({ "azp": "other-app" })));
        assert!(o.audience_ok(&serde_json::json!({ "aud": ["account", "web"] })));
        assert!(!o.audience_ok(&serde_json::json!({ "aud": "account" })));
        assert!(!o.audience_ok(&serde_json::json!({})));
    }

    #[test]
    fn issuer_scheme_enforced() {
        let mut c = cfg();
        assert!(c.validate().is_ok());
        c.issuer = "http://keycloak.evil".into();
        assert!(c.validate().is_err());
        c.issuer = "http://localhost:8080/realms/main".into();
        assert!(c.validate().is_ok());
    }
}
