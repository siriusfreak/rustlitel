//! In-app OpenID Connect (Keycloak) login for the operator UI.
//!
//! The relay itself is the OIDC client: it runs the Authorization Code flow
//! with PKCE, verifies the returned ID token (RS256 against the issuer's JWKS,
//! plus `iss`/`aud`/`exp`/`nonce`), enforces a required group claim, and then
//! establishes its own session carrying the username. The browser login
//! switches to "Sign in with Keycloak" when this is configured; scripts keep
//! using the Bearer operator token for `/api/exec`.
//!
//! Enabled only when the `RUSTLITEL_OIDC_*` env is present, so the operator-token
//! login keeps working until Keycloak is wired up.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
use base64::Engine;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    /// Required group/role value; empty = any authenticated user in the realm.
    pub allowed_group: String,
    pub username_claim: String,
    pub groups_claim: String,
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
        Some(Self {
            issuer: issuer.trim_end_matches('/').to_string(),
            client_id,
            client_secret,
            redirect_url,
            allowed_group: std::env::var("RUSTLITEL_OIDC_ALLOWED_GROUP").unwrap_or_default(),
            username_claim: env_or("RUSTLITEL_OIDC_USERNAME_CLAIM", "preferred_username"),
            groups_claim: env_or("RUSTLITEL_OIDC_GROUPS_CLAIM", "groups"),
        })
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

struct Pending {
    nonce: String,
    pkce_verifier: String,
    return_to: String,
    created: Instant,
}

pub struct Oidc {
    pub cfg: OidcConfig,
    http: reqwest::Client,
    disc: tokio::sync::OnceCell<Discovery>,
    jwks: Mutex<Vec<Jwk>>,
    pending: Mutex<HashMap<String, Pending>>,
}

/// Verified identity extracted from an ID token.
pub struct Identity {
    pub username: String,
    pub groups: Vec<String>,
}

impl Oidc {
    pub fn new(cfg: OidcConfig) -> Self {
        Self {
            cfg,
            http: reqwest::Client::new(),
            disc: tokio::sync::OnceCell::new(),
            jwks: Mutex::new(Vec::new()),
            pending: Mutex::new(HashMap::new()),
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

    /// Build the authorize URL and remember the per-login state.
    pub async fn begin_login(&self, return_to: &str) -> anyhow::Result<String> {
        let disc = self.discovery().await?;
        let state = rand_tok();
        let nonce = rand_tok();
        let verifier = rand_verifier();
        let challenge = B64U.encode(Sha256::digest(verifier.as_bytes()));

        self.pending.lock().unwrap().insert(
            state.clone(),
            Pending {
                nonce: nonce.clone(),
                pkce_verifier: verifier,
                return_to: sanitize_return(return_to),
                created: Instant::now(),
            },
        );
        self.gc_pending();

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
        Ok(u.to_string())
    }

    /// Exchange the code, verify the ID token, enforce the group. Returns the
    /// identity and where to send the browser next.
    pub async fn complete_login(&self, code: &str, state: &str) -> anyhow::Result<(Identity, String)> {
        let pending = self
            .pending
            .lock()
            .unwrap()
            .remove(state)
            .ok_or_else(|| anyhow!("unknown or reused login state"))?;
        if pending.created.elapsed() > Duration::from_secs(600) {
            bail!("login attempt expired");
        }

        let disc = self.discovery().await?;
        // client auth via HTTP Basic (client_secret_basic), so client_id/secret
        // are not repeated in the body.
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.cfg.redirect_url.as_str()),
            ("code_verifier", pending.pkce_verifier.as_str()),
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
            // Keycloak returns {"error":...,"error_description":...}; surface it.
            let snippet: String = body.chars().take(300).collect();
            bail!("token endpoint {}: {}", status.as_u16(), snippet);
        }
        #[derive(Deserialize)]
        struct TokenResp {
            id_token: String,
            #[serde(default)]
            access_token: String,
        }
        let tok: TokenResp = serde_json::from_str(&body).context("parse token response")?;

        let mut identity = self.verify_id_token(&tok.id_token, &pending.nonce).await?;

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
                bail!(
                    "'{}' is not in the required group '{}' (token groups: {:?})",
                    identity.username,
                    self.cfg.allowed_group,
                    identity.groups
                );
            }
        }
        Ok((identity, pending.return_to))
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
    /// signature + issuer (Keycloak access-token `aud` varies, so skip it),
    /// then read `groups` and `realm_access.roles`. On any failure, no groups.
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
        let mut val = Validation::new(Algorithm::RS256);
        val.set_issuer(&[self.cfg.issuer.as_str()]);
        val.validate_aud = false;
        match decode::<serde_json::Value>(jwt, &key, &val) {
            Ok(data) => extract_groups(&data.claims, &self.cfg.groups_claim),
            Err(_) => Vec::new(),
        }
    }

    /// Verify a Bearer *access* token (signature + issuer + expiry; access-token
    /// `aud` varies in Keycloak so it is not checked) and enforce the group.
    /// Used to authorize API clients like the `wrs` CLI. Returns the username.
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
        val.validate_aud = false;
        let data = decode::<serde_json::Value>(token, &key, &val).ok()?;
        let c = data.claims;

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

    /// Public config the CLI needs to start a device-flow login.
    pub fn public_config(&self, cli_client_id: &str) -> serde_json::Value {
        serde_json::json!({
            "issuer": self.cfg.issuer,
            "cli_client_id": cli_client_id,
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

    fn gc_pending(&self) {
        let mut p = self.pending.lock().unwrap();
        p.retain(|_, v| v.created.elapsed() < Duration::from_secs(600));
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

/// Only allow a same-origin path as the post-login redirect.
fn sanitize_return(path: &str) -> String {
    if path.starts_with('/') && !path.starts_with("//") {
        path.to_string()
    } else {
        "/".to_string()
    }
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
