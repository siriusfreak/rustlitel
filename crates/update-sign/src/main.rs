//! Offline release signing for agent self-updates.
//!
//! The agent will only install a self-update whose manifest carries a valid
//! ed25519 signature made with the **private** key held here (in 1Password /
//! on the release machine), verified against the **public** key baked into the
//! agent at build time. The relay never holds the private key and cannot mint a
//! signature, so a relay compromise can no longer push arbitrary code.
//!
//!   # one-time: make a key. Store PRIVATE in 1Password; bake PUBLIC into builds
//!   rustlitel-update-sign keygen
//!
//!   # per release: sign each stock agent binary, writing <binary>.sig.json
//!   RUSTLITEL_UPDATE_SIGNING_KEY="$(op read op://…/private)" \
//!     rustlitel-update-sign sign --version "$BUILD_ID" --build-epoch "$EPOCH" dist/rustlitel-agent-windows.exe

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use clap::{Parser, Subcommand};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(name = "rustlitel-update-sign", about = "Offline signer for agent self-updates")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate an ed25519 keypair. Prints the private key (PKCS#8, base64) and
    /// the public key (base64) to bake into the agent as RUSTLITEL_UPDATE_PUBKEY.
    Keygen,
    /// Sign a stock agent binary, writing `<binary>.sig.json` beside it.
    Sign(SignArgs),
}

#[derive(Parser)]
struct SignArgs {
    /// Private signing key (PKCS#8, base64). Prefer the env var
    /// RUSTLITEL_UPDATE_SIGNING_KEY so the key never lands in a process list.
    #[arg(long, env = "RUSTLITEL_UPDATE_SIGNING_KEY", hide_env_values = true)]
    key: String,
    /// Build id baked into this binary (must equal RUSTLITEL_BUILD_ID at build).
    #[arg(long)]
    version: String,
    /// Monotonic build epoch baked into this binary (RUSTLITEL_BUILD_EPOCH).
    #[arg(long)]
    build_epoch: u64,
    /// The agent binary to sign.
    binary: PathBuf,
}

#[derive(Serialize)]
struct Sidecar {
    version: String,
    build_epoch: u64,
    sha256: String,
    size: u64,
    sig: String,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen => keygen(),
        Cmd::Sign(a) => sign(a),
    }
}

fn keygen() -> Result<()> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| anyhow!("generate key"))?;
    let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| anyhow!("parse key"))?;
    println!("# Private key (PKCS#8, base64) — store in 1Password, never commit:");
    println!("RUSTLITEL_UPDATE_SIGNING_KEY={}", B64.encode(pkcs8.as_ref()));
    println!();
    println!("# Public key (base64) — bake into agent + relay builds:");
    println!("UPDATE_PUBKEY={}", B64.encode(kp.public_key().as_ref()));
    Ok(())
}

fn sign(a: SignArgs) -> Result<()> {
    let pkcs8 = B64
        .decode(a.key.trim())
        .context("decode RUSTLITEL_UPDATE_SIGNING_KEY (base64 PKCS#8)")?;
    let kp = Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| anyhow!("invalid signing key"))?;

    let data = std::fs::read(&a.binary)
        .with_context(|| format!("read {}", a.binary.display()))?;
    if data.is_empty() {
        bail!("{} is empty", a.binary.display());
    }
    let sha = sha256_hex(&data);
    let size = data.len() as u64;

    let msg = rustlitel_proto::update_signing_message(&a.version, a.build_epoch, &sha, size);
    let sig = kp.sign(msg.as_bytes());

    let sidecar = Sidecar {
        version: a.version,
        build_epoch: a.build_epoch,
        sha256: sha,
        size,
        sig: B64.encode(sig.as_ref()),
    };
    let out = a.binary.with_file_name(format!(
        "{}.sig.json",
        a.binary
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow!("bad binary path"))?
    ));
    std::fs::write(&out, serde_json::to_vec_pretty(&sidecar)?)
        .with_context(|| format!("write {}", out.display()))?;
    println!("signed {} -> {} ({} bytes)", a.binary.display(), out.display(), size);
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

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{UnparsedPublicKey, ED25519};

    /// Sign a message and verify it with `ring` exactly as the agent does, so
    /// the signer and the agent's verifier are provably compatible.
    #[test]
    fn sign_then_verify_like_the_agent() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pubkey = kp.public_key().as_ref().to_vec();

        let bin = b"some agent bytes";
        let sha = sha256_hex(bin);
        let msg = rustlitel_proto::update_signing_message("v2", 1_700_000_001, &sha, bin.len() as u64);
        let sig = kp.sign(msg.as_bytes());

        // The agent reconstructs the same message and verifies.
        let agent_msg =
            rustlitel_proto::update_signing_message("v2", 1_700_000_001, &sha, bin.len() as u64);
        assert!(UnparsedPublicKey::new(&ED25519, &pubkey)
            .verify(agent_msg.as_bytes(), sig.as_ref())
            .is_ok());

        // A tampered field must fail.
        let bad = rustlitel_proto::update_signing_message("v3", 1_700_000_001, &sha, bin.len() as u64);
        assert!(UnparsedPublicKey::new(&ED25519, &pubkey)
            .verify(bad.as_bytes(), sig.as_ref())
            .is_err());
    }
}
