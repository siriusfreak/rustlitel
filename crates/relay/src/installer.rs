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
//! (the coarse "revoke all" knob). A single key can't be withdrawn by deleting
//! it, so the relay refuses the ones whose SHA-256 is listed in
//! `RUSTLITEL_REVOKED_KEYS` ([`key_fingerprint`]). An agent may present either
//! the master agent token or a valid join key.
//!
//! An **installer link** (`/i/<code>`) is stateless too, so it outlives a relay
//! restart: the code is `<base64url(payload)>.<base64url(truncated HMAC)>` naming
//! the OS, the machine's name and when the link expires. The join key is minted
//! when the link is opened. Rotating the agent token invalidates every link, and
//! `RUSTLITEL_REVOKED_KEYS` refuses one by the SHA-256 of its code.
//!
//! A **baked installer** is a stock agent binary with an [`InstallerConfig`]
//! JSON trailer appended (`<json><MAGIC><u32 len>`), so running it needs no
//! flags — it reads its own relay URL + join key and installs itself.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
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

/// Lowercase hex SHA-256 of a join key: how `RUSTLITEL_REVOKED_KEYS` names a
/// key without holding the key itself.
pub fn key_fingerprint(key: &str) -> String {
    use sha2::Digest;
    Sha256::digest(key.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The trailer that turns a stock agent binary into a baked installer.
pub fn trailer(cfg: &InstallerConfig) -> Vec<u8> {
    let mut out = serde_json::to_vec(cfg).expect("serialize config");
    let len = out.len() as u32;
    out.extend_from_slice(INSTALLER_MAGIC);
    out.extend_from_slice(&len.to_le_bytes());
    out
}

/// What an installer link stands for.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct InstallerLink {
    pub os: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Lifetime of the join key minted when the link is opened.
    pub key_ttl_days: u64,
    /// When the link itself stops working (unix seconds).
    pub exp: u64,
}

/// 128 bits of HMAC are plenty and keep the link short. The key is distinct from
/// the one signing join keys, so neither can pass for the other.
fn link_sig(secret: &str, payload: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(format!("installer-link-v1:{secret}").as_bytes())
        .expect("hmac key");
    mac.update(payload.as_bytes());
    B64.encode(&mac.finalize().into_bytes()[..16])
}

/// Sign `link` into the code that goes into `/i/<code>`.
pub fn mint_link(secret: &str, link: &InstallerLink) -> String {
    let payload = B64.encode(serde_json::to_vec(link).expect("serialize link"));
    let sig = link_sig(secret, &payload);
    format!("{payload}.{sig}")
}

/// Check a link code: correct signature and not expired.
pub fn open_link(secret: &str, code: &str) -> Option<InstallerLink> {
    let (payload, sig) = code.split_once('.')?;
    let expected = link_sig(secret, payload);
    if !bool::from(expected.as_bytes().ct_eq(sig.as_bytes())) {
        return None;
    }
    let link: InstallerLink = serde_json::from_slice(&B64.decode(payload).ok()?).ok()?;
    (link.exp > now()).then_some(link)
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
    fn fingerprint_is_sha256_hex() {
        assert_eq!(
            key_fingerprint(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let k = mint_join_key("secret", "a", 60);
        assert_eq!(key_fingerprint(&k), key_fingerprint(&k));
        assert_ne!(key_fingerprint(&k), key_fingerprint(&mint_join_key("secret", "b", 60)));
    }

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
    fn trailer_is_what_the_agent_parses() {
        let cfg = InstallerConfig {
            relay: "wss://r".into(),
            token: "J1.x.y".into(),
            name: None,
            auto: Some("install".into()),
        };
        let out = trailer(&cfg);
        assert_eq!(&out[out.len() - 12..out.len() - 4], INSTALLER_MAGIC);
        let n = u32::from_le_bytes(out[out.len() - 4..].try_into().unwrap()) as usize;
        assert_eq!(n, out.len() - 12);
        assert!(serde_json::from_slice::<InstallerConfig>(&out[..n]).is_ok());
    }

    #[test]
    fn link_roundtrip_and_refusals() {
        let link = |exp| InstallerLink {
            os: "macos".into(),
            name: Some("mac".into()),
            key_ttl_days: 3650,
            exp,
        };
        let code = mint_link("secret", &link(now() + 60));
        assert_eq!(open_link("secret", &code), Some(link(code_exp(&code))));
        assert_eq!(open_link("other", &code), None);
        assert_eq!(open_link("secret", &mint_link("secret", &link(now() - 1))), None);
        assert_eq!(open_link("secret", "garbage"), None);
        // A join key is not a link, even with the same secret.
        assert_eq!(open_link("secret", &mint_join_key("secret", "x", 60)), None);
    }

    fn code_exp(code: &str) -> u64 {
        let payload = code.split('.').next().unwrap();
        serde_json::from_slice::<InstallerLink>(&B64.decode(payload).unwrap()).unwrap().exp
    }

    #[test]
    fn origin_conversion() {
        assert_eq!(origin_to_ws("https://a.b").as_deref(), Some("wss://a.b"));
        assert_eq!(origin_to_ws("http://a.b").as_deref(), Some("ws://a.b"));
        assert_eq!(origin_to_ws("ftp://a.b"), None);
    }
}
