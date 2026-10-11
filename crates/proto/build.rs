//! Bake a build identifier, a monotonic build epoch, and the self-update
//! signing public key into the protocol crate, so the relay and the agent
//! (compiled from the same tree) agree on "what version is this" and the agent
//! can verify a signed update.
//!
//! * `RUSTLITEL_BUILD_ID` — an explicit id (the Docker image build sets this per
//!   build) → the current git short SHA → the crate version. Every distinct
//!   build must carry a distinct id.
//! * `RUSTLITEL_BUILD_EPOCH` — a monotonically increasing integer (the agent only
//!   self-updates to a *strictly newer* epoch, so a rolled-back relay can't
//!   force a downgrade). An explicit value → the git commit timestamp → now.
//! * `RUSTLITEL_UPDATE_PUBKEY` — base64 ed25519 public key the agent verifies a
//!   self-update signature against. Empty when self-update signing isn't wired
//!   up (the agent then refuses to self-update — fail closed).

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=RUSTLITEL_BUILD_ID");
    println!("cargo:rerun-if-env-changed=RUSTLITEL_BUILD_EPOCH");
    println!("cargo:rerun-if-env-changed=RUSTLITEL_UPDATE_PUBKEY");

    let id = std::env::var("RUSTLITEL_BUILD_ID")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(git_short_sha)
        .unwrap_or_else(|| std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".into()));
    println!("cargo:rustc-env=RUSTLITEL_BUILD_ID={id}");

    let epoch = std::env::var("RUSTLITEL_BUILD_EPOCH")
        .ok()
        .filter(|s| s.chars().all(|c| c.is_ascii_digit()) && !s.is_empty())
        .or_else(git_commit_epoch)
        .unwrap_or_else(now_epoch);
    println!("cargo:rustc-env=RUSTLITEL_BUILD_EPOCH={epoch}");

    let pubkey = std::env::var("RUSTLITEL_UPDATE_PUBKEY").unwrap_or_default();
    println!("cargo:rustc-env=RUSTLITEL_UPDATE_PUBKEY={pubkey}");
}

fn git_short_sha() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Unix timestamp of HEAD — a stable, monotonic-with-history build epoch.
fn git_commit_epoch() -> Option<String> {
    let out = Command::new("git")
        .args(["log", "-1", "--format=%ct"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!s.is_empty() && s.chars().all(|c| c.is_ascii_digit())).then_some(s)
}

fn now_epoch() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .to_string()
}
