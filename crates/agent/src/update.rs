//! Agent self-update.
//!
//! The relay and the agent are built from the same tree and share
//! [`rustlitel_proto::BUILD_ID`]. An installed (unattended) agent periodically — and
//! right after each (re)connect, so a relay rollout propagates fast — asks the
//! relay what build it is serving. If that differs from our own baked id, we
//! pull the fresh binary and hand it to the platform swapper.
//!
//! Trust model: the manifest and the binary are fetched over TLS from the relay
//! and gated by the agent token, and we verify the download's SHA-256 against
//! the manifest before swapping. The relay is already fully trusted (it can run
//! arbitrary commands on us via `exec`), so TLS + token + hash is the right
//! anchor here; the Windows binary additionally carries its Authenticode
//! signature, which survives the byte-for-byte swap for the OS to check.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::platform;

/// What the relay reports at `GET /api/agent/update`.
#[derive(Debug, Deserialize)]
struct Manifest {
    /// The relay's own [`rustlitel_proto::BUILD_ID`].
    version: String,
    /// Lowercase hex SHA-256 of the binary the relay would serve.
    sha256: String,
    /// Expected length in bytes.
    size: u64,
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
    /// Build an updater, or `None` if the relay URL can't be turned into HTTP.
    pub fn new(relay_ws: &str, token: String, min_gap: Duration) -> Option<Arc<Self>> {
        let http_base = ws_to_http(relay_ws)?;
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
        tracing::info!(
            from = %rustlitel_proto::BUILD_ID,
            to = %manifest.version,
            "self-update: newer build on relay, downloading"
        );

        let bytes = self.download_binary().await?;
        verify(&bytes, &manifest)?;

        tracing::info!(size = bytes.len(), "self-update: verified, applying");
        platform::apply_update(&bytes)?;
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

    async fn download_binary(&self) -> anyhow::Result<Vec<u8>> {
        let url = format!("{}/api/agent/binary?os={}", self.http_base, self.os);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.bytes().await?.to_vec())
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

fn verify(bytes: &[u8], manifest: &Manifest) -> anyhow::Result<()> {
    if bytes.len() as u64 != manifest.size {
        anyhow::bail!(
            "size mismatch: got {}, expected {}",
            bytes.len(),
            manifest.size
        );
    }
    let got = sha256_hex(bytes);
    if got != manifest.sha256.to_ascii_lowercase() {
        anyhow::bail!("sha256 mismatch: got {got}, expected {}", manifest.sha256);
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

/// `wss://host/…` → `https://host/…`, `ws://…` → `http://…` (trailing slashes
/// trimmed). Anything else is rejected.
fn ws_to_http(ws: &str) -> Option<String> {
    let ws = ws.trim_end_matches('/');
    if let Some(rest) = ws.strip_prefix("wss://") {
        Some(format!("https://{rest}"))
    } else if let Some(rest) = ws.strip_prefix("ws://") {
        Some(format!("http://{rest}"))
    } else if ws.starts_with("https://") || ws.starts_with("http://") {
        Some(ws.to_string())
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
        assert_eq!(ws_to_http("ws://a.b").as_deref(), Some("http://a.b"));
        assert_eq!(ws_to_http("https://a.b").as_deref(), Some("https://a.b"));
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
}
