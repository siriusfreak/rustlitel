//! Agent self-update.
//!
//! An installed (unattended) agent periodically — and right after each
//! (re)connect, so a relay rollout propagates fast — asks the relay what build
//! it is serving. If that build is *strictly newer* than our own, we pull the
//! binary and hand it to the platform swapper.
//!
//! Trust model: the binary runs as SYSTEM, so "the relay said so" is not a
//! sufficient anchor — a compromised relay, or anyone able to write the relay's
//! `agents_dir`, or an on-path attacker, must not be able to push arbitrary
//! code. So before swapping we require an **ed25519 signature**, produced
//! OFFLINE by the release signer, over `{version, build_epoch, sha256, size}`,
//! verified against a public key **baked into this agent at build time**
//! ([`rustlitel_proto::UPDATE_PUBKEY`]). The relay cannot mint that signature.
//! We additionally require a strictly-greater build epoch (no downgrade to an
//! older, known-vulnerable build), a size cap, and the usual sha256 + TLS. If
//! no public key is baked in, we refuse to self-update at all (fail closed).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::platform;

/// Hard cap on a self-update download, so a hostile relay/MITM can't exhaust
/// memory on a SYSTEM service. Agent binaries are a few tens of MiB.
const MAX_UPDATE_BYTES: u64 = 256 * 1024 * 1024;

/// What the relay reports at `GET /api/agent/update`.
#[derive(Debug, Deserialize)]
struct Manifest {
    /// The served binary's [`rustlitel_proto::BUILD_ID`].
    version: String,
    /// The served binary's monotonic build epoch (we only move strictly up).
    #[serde(default)]
    build_epoch: u64,
    /// Lowercase hex SHA-256 of the binary the relay would serve.
    sha256: String,
    /// Expected length in bytes.
    size: u64,
    /// Base64 ed25519 signature over
    /// [`rustlitel_proto::update_signing_message`]. Absent = unsigned.
    #[serde(default)]
    sig: Option<String>,
}

/// Drives self-update for one agent. Cheap to clone via `Arc`.
pub struct Updater {
    http_base: String,
    os: String,
    token: String,
    client: reqwest::Client,
    /// Rate-limit: minimum gap between checks (connect storms would otherwise
    /// trigger a flurry). Unix-seconds of the last check.
    min_gap: Duration,
    last: AtomicU64,
}

impl Updater {
    /// Build an updater, or `None` if the relay URL isn't a usable HTTPS base.
    pub fn new(relay_ws: &str, token: String, min_gap: Duration) -> Option<Arc<Self>> {
        let http_base = ws_to_http(relay_ws)?;
        // Never fetch a SYSTEM binary over cleartext. ws_to_http already rejects
        // a non-loopback ws:// relay, but guard here too (defence in depth).
        if http_base.starts_with("http://") && !is_loopback_http(&http_base) {
            tracing::warn!("self-update disabled: relay is not https");
            return None;
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent(concat!("rustlitel-agent/", env!("CARGO_PKG_VERSION")))
            .build()
            .ok()?;
        Some(Arc::new(Self {
            http_base,
            os: std::env::consts::OS.to_string(),
            token,
            client,
            min_gap,
            last: AtomicU64::new(0),
        }))
    }

    /// Run a check now unless one ran within `min_gap`. Errors are logged, not
    /// propagated — a failed check must never take the agent down.
    pub async fn maybe_check(self: &Arc<Self>) {
        let now = unix_now();
        let prev = self.last.load(Ordering::Relaxed);
        if now.saturating_sub(prev) < self.min_gap.as_secs() {
            return;
        }
        self.last.store(now, Ordering::Relaxed);
        if let Err(e) = self.check().await {
            tracing::debug!("self-update check skipped: {e:#}");
        }
    }

    async fn check(&self) -> anyhow::Result<()> {
        let manifest = self.fetch_manifest().await?;
        if manifest.version == rustlitel_proto::BUILD_ID {
            tracing::debug!(version = %manifest.version, "self-update: already current");
            return Ok(());
        }
        // Strictly-newer only: refuse a downgrade to an older build (which a
        // rolled-back or hostile relay could otherwise force).
        let ours = rustlitel_proto::build_epoch();
        if manifest.build_epoch <= ours {
            tracing::debug!(
                ours,
                theirs = manifest.build_epoch,
                "self-update: relay build is not newer, ignoring"
            );
            return Ok(());
        }

        // Authenticate the manifest with the baked public key BEFORE fetching or
        // trusting anything the relay said about the binary.
        verify_signature(&manifest)?;

        if manifest.size > MAX_UPDATE_BYTES {
            bail!("refusing update: size {} exceeds cap", manifest.size);
        }

        tracing::info!(
            from = %rustlitel_proto::BUILD_ID,
            to = %manifest.version,
            "self-update: newer signed build on relay, downloading"
        );

        let bytes = self.download_binary(manifest.size).await?;
        verify_hash(&bytes, &manifest)?;

        tracing::info!(size = bytes.len(), "self-update: verified, applying");
        // The Windows swap sleeps between retries; keep it off the async workers.
        tokio::task::spawn_blocking(move || platform::apply_update(&bytes))
            .await
            .context("self-update task")??;
        Ok(())
    }

    async fn fetch_manifest(&self) -> anyhow::Result<Manifest> {
        let url = format!("{}/api/agent/update?os={}", self.http_base, self.os);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await?
            .error_for_status()?;
        let body = resp.bytes().await?;
        Ok(serde_json::from_slice::<Manifest>(&body)?)
    }

    /// Download the binary, streaming with a hard byte cap so an oversized body
    /// can't exhaust memory even if the manifest lied about `size`.
    async fn download_binary(&self, expected: u64) -> anyhow::Result<Vec<u8>> {
        let url = format!("{}/api/agent/binary?os={}", self.http_base, self.os);
        let mut resp = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await?
            .error_for_status()?;
        let cap = expected.min(MAX_UPDATE_BYTES);
        let mut buf = Vec::with_capacity(cap as usize);
        while let Some(chunk) = resp.chunk().await? {
            if buf.len() as u64 + chunk.len() as u64 > cap {
                bail!("update download exceeded {cap} bytes");
            }
            buf.extend_from_slice(&chunk);
        }
        Ok(buf)
    }
}

/// Spawn the background loop: an early check, then one every `interval`.
pub fn spawn(updater: Arc<Updater>, interval: Duration) {
    tokio::spawn(async move {
        // A short settle before the first check so startup isn't contended.
        tokio::time::sleep(Duration::from_secs(15)).await;
        loop {
            updater.maybe_check().await;
            tokio::time::sleep(interval).await;
        }
    });
}

/// Verify the manifest's ed25519 signature against the baked public key. Fails
/// closed: no baked key, or no/invalid signature, means "do not update".
fn verify_signature(m: &Manifest) -> anyhow::Result<()> {
    let pubkey_b64 = rustlitel_proto::UPDATE_PUBKEY;
    if pubkey_b64.is_empty() {
        bail!("self-update refused: no update public key baked into this agent");
    }
    let sig_b64 = m
        .sig
        .as_deref()
        .ok_or_else(|| anyhow!("self-update refused: relay manifest is unsigned"))?;
    let pubkey = B64
        .decode(pubkey_b64.trim())
        .context("decode baked update public key")?;
    let sig = B64.decode(sig_b64.trim()).context("decode update signature")?;
    let msg = rustlitel_proto::update_signing_message(&m.version, m.build_epoch, &m.sha256, m.size);
    UnparsedPublicKey::new(&ED25519, pubkey)
        .verify(msg.as_bytes(), &sig)
        .map_err(|_| anyhow!("self-update refused: update signature did not verify"))?;
    Ok(())
}

fn verify_hash(bytes: &[u8], manifest: &Manifest) -> anyhow::Result<()> {
    if bytes.len() as u64 != manifest.size {
        bail!("size mismatch: got {}, expected {}", bytes.len(), manifest.size);
    }
    let got = sha256_hex(bytes);
    if got != manifest.sha256.to_ascii_lowercase() {
        bail!("sha256 mismatch: got {got}, expected {}", manifest.sha256);
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// True for an `http://localhost`/`127.0.0.1`/`[::1]` base (dev only).
fn is_loopback_http(http: &str) -> bool {
    http.strip_prefix("http://")
        .map(|rest| {
            rest.starts_with("localhost")
                || rest.starts_with("127.0.0.1")
                || rest.starts_with("[::1]")
        })
        .unwrap_or(false)
}

/// `wss://host/…` → `https://host/…`. `ws://…` → `http://…` only for loopback
/// (dev); a non-loopback `ws://` is rejected so a SYSTEM binary is never fetched
/// over cleartext. Anything that isn't ws/wss/http/https is rejected.
fn ws_to_http(ws: &str) -> Option<String> {
    let ws = ws.trim_end_matches('/');
    if let Some(rest) = ws.strip_prefix("wss://") {
        Some(format!("https://{rest}"))
    } else if let Some(rest) = ws.strip_prefix("ws://") {
        let http = format!("http://{rest}");
        is_loopback_http(&http).then_some(http)
    } else if ws.starts_with("https://") {
        Some(ws.to_string())
    } else if ws.starts_with("http://") {
        is_loopback_http(ws).then(|| ws.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_conversion() {
        assert_eq!(ws_to_http("wss://a.b/").as_deref(), Some("https://a.b"));
        assert_eq!(ws_to_http("https://a.b").as_deref(), Some("https://a.b"));
        // cleartext only for loopback
        assert_eq!(ws_to_http("ws://127.0.0.1:8099").as_deref(), Some("http://127.0.0.1:8099"));
        assert_eq!(ws_to_http("ws://localhost:8099").as_deref(), Some("http://localhost:8099"));
        assert_eq!(ws_to_http("ws://relay.example.com"), None);
        assert_eq!(ws_to_http("http://relay.example.com"), None);
        assert_eq!(ws_to_http("ftp://a.b"), None);
    }

    #[test]
    fn sha_hex_known() {
        // SHA-256 of the empty input.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn unsigned_or_unkeyed_is_refused() {
        // No baked key (tests build without RUSTLITEL_UPDATE_PUBKEY) → refuse.
        let m = Manifest {
            version: "new".into(),
            build_epoch: 1,
            sha256: "00".into(),
            size: 1,
            sig: Some("AAAA".into()),
        };
        assert!(verify_signature(&m).is_err());
    }
}
