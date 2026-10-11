//! Bake a build identifier into the protocol crate so the relay and the agent,
//! which are compiled from the same tree, agree on "what version is this".
//!
//! Precedence: an explicit `RUSTLITEL_BUILD_ID` (the Docker image build sets this to a
//! fresh value per build) → the current git short SHA → the crate version. The
//! agent compares its own baked `BUILD_ID` to the relay's to decide whether to
//! self-update, so every distinct build must carry a distinct id.

use std::process::Command;

fn main() {
    // Re-run (and thus re-bake) whenever the override changes.
    println!("cargo:rerun-if-env-changed=RUSTLITEL_BUILD_ID");

    let id = std::env::var("RUSTLITEL_BUILD_ID")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(git_short_sha)
        .unwrap_or_else(|| std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".into()));

    println!("cargo:rustc-env=RUSTLITEL_BUILD_ID={id}");
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
