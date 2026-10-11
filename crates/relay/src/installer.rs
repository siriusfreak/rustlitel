//! Join keys and one-click installer baking.
//!
//! A **join key** is a per-installer enrollment credential, separate from the
//! master agent token. It is a stateless, HMAC-signed token — no database — so
//! the relay stays single-replica and in-memory:
//!
//! ```text
//! J1.<base64url(payload)>.<base64url(HMAC_SHA256(payload, secret))>
//! payload = {"exp": <unix secs>, "label": "<who/what>"}
//! ```
//!
//! The relay validates one by recomputing the HMAC (constant-time) and checking
//! expiry. The signing secret is the master agent token, so no extra config is
//! needed; rotating the agent token invalidates every outstanding join key
//! (the coarse "revoke all" knob). An agent may present either the master agent
//! token or a valid join key.
//!
//! A **baked installer** is a stock agent binary with an [`InstallerConfig`]
//! JSON trailer appended (`<json><MAGIC><u32 len>`), so running it needs no
//! flags — it reads its own relay URL + join key and installs itself.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use rustlitel_proto::{InstallerConfig, INSTALLER_MAGIC};

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize, Deserialize)]
struct JoinPayload {
    exp: u64,
    label: String,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sign(secret: &str, data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(data);
    B64.encode(mac.finalize().into_bytes())
}

/// Mint a join key valid for `ttl_secs`.
pub fn mint_join_key(secret: &str, label: &str, ttl_secs: u64) -> String {
    let payload = JoinPayload {
        exp: now() + ttl_secs,
        label: label.to_string(),
    };
    let pj = serde_json::to_vec(&payload).expect("serialize payload");
    let pb = B64.encode(pj);
    let sig = sign(secret, pb.as_bytes());
    format!("J1.{pb}.{sig}")
}

/// Validate a join key against `secret`: correct signature and not expired.
pub fn validate_join_key(secret: &str, token: &str) -> bool {
    let mut parts = token.split('.');
    if parts.next() != Some("J1") {
        return false;
    }
    let (Some(pb), Some(sig)) = (parts.next(), parts.next()) else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    let expected = sign(secret, pb.as_bytes());
    let sig_ok: bool = expected.as_bytes().ct_eq(sig.as_bytes()).into();
    if !sig_ok {
        return false;
    }
    let Ok(pj) = B64.decode(pb) else {
        return false;
    };
    let Ok(payload) = serde_json::from_slice::<JoinPayload>(&pj) else {
        return false;
    };
    payload.exp > now()
}

/// Append an [`InstallerConfig`] trailer to a stock agent binary.
pub fn bake(base: &[u8], cfg: &InstallerConfig) -> Vec<u8> {
    let json = serde_json::to_vec(cfg).expect("serialize config");
    let mut out = Vec::with_capacity(base.len() + json.len() + 12);
    out.extend_from_slice(base);
    out.extend_from_slice(&json);
    out.extend_from_slice(INSTALLER_MAGIC);
    out.extend_from_slice(&(json.len() as u32).to_le_bytes());
    out
}

/// A short, URL-safe code for an installer link (7 bytes -> ~10 chars).
pub fn short_code() -> String {
    let mut raw = [0u8; 7];
    rand::thread_rng().fill_bytes(&mut raw);
    B64.encode(raw)
}

/// Turn the public HTTP origin into the wss/ws URL agents dial.
pub fn origin_to_ws(origin: &str) -> Option<String> {
    if let Some(rest) = origin.strip_prefix("https://") {
        Some(format!("wss://{rest}"))
    } else if let Some(rest) = origin.strip_prefix("http://") {
        Some(format!("ws://{rest}"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_key_roundtrip() {
        let s = "super-secret";
        let k = mint_join_key(s, "box-1", 60);
        assert!(validate_join_key(s, &k));
        assert!(!validate_join_key("other-secret", &k));
        assert!(!validate_join_key(s, "J1.garbage.sig"));
        assert!(!validate_join_key(s, &mint_join_key(s, "x", 0))); // already expired
    }

    #[test]
    fn bake_appends_trailer() {
        let cfg = InstallerConfig {
            relay: "wss://r".into(),
            token: "J1.x.y".into(),
            name: None,
            auto: Some("install".into()),
        };
        let out = bake(b"BINARY", &cfg);
        assert_eq!(&out[out.len() - 12..out.len() - 4], INSTALLER_MAGIC);
        let n = u32::from_le_bytes(out[out.len() - 4..].try_into().unwrap()) as usize;
        assert!(out.starts_with(b"BINARY"));
        assert!(n > 0 && n < out.len());
    }

    #[test]
    fn origin_conversion() {
        assert_eq!(origin_to_ws("https://a.b").as_deref(), Some("wss://a.b"));
        assert_eq!(origin_to_ws("http://a.b").as_deref(), Some("ws://a.b"));
        assert_eq!(origin_to_ws("ftp://a.b"), None);
    }
}
