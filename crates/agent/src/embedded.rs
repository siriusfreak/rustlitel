//! Read an installer config trailer appended to our own executable.
//!
//! The relay bakes `<json><MAGIC><u32 len>` onto the end of a stock agent
//! binary when an operator generates a one-click installer. Appending bytes
//! after a PE/ELF image does not affect execution, so the same binary runs
//! normally and also carries its enrollment config.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use rustlitel_proto::{InstallerConfig, INSTALLER_MAGIC};

/// Parse the trailer from the current executable, if present and well-formed.
pub fn read() -> Option<InstallerConfig> {
    let exe = std::env::current_exe().ok()?;
    let mut f = File::open(exe).ok()?;
    let total = f.metadata().ok()?.len();
    if total < 12 {
        return None;
    }

    // Last 12 bytes: 8-byte magic + 4-byte little-endian JSON length.
    f.seek(SeekFrom::End(-12)).ok()?;
    let mut tail = [0u8; 12];
    f.read_exact(&mut tail).ok()?;
    if &tail[0..8] != INSTALLER_MAGIC {
        return None;
    }
    let json_len = u32::from_le_bytes([tail[8], tail[9], tail[10], tail[11]]) as u64;
    if json_len == 0 || json_len > total - 12 {
        return None;
    }

    f.seek(SeekFrom::End(-(12 + json_len as i64))).ok()?;
    let mut buf = vec![0u8; json_len as usize];
    f.read_exact(&mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}
