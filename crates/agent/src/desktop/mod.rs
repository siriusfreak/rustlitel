//! Desktop commands: screenshots and window management.
//!
//! The installed Windows agent is a service in session 0, which has no
//! desktop of its own: nothing a user sees can be captured or moved from
//! there. So the agent answers a [`DesktopRequest`] by starting a copy of
//! itself (`rustlitel-agent desktop-helper`) inside the interactive user's
//! session, still as LocalSystem, and relays the JSON document that helper
//! writes. A foreground agent already running in a user's session does the
//! same with a plain child process.
//!
//! The answer goes back like an exec: the JSON as stdout chunks, then
//! `ExecDone`. It is always JSON: `{"ok":true,...}` or `{"ok":false,"error":...}`.

#[cfg(windows)]
mod win;

use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;
use rustlitel_proto::{AgentToServer, DesktopRequest, ExecStream};

/// Bytes of JSON per ExecChunk frame (the relay caps a frame at 1 MiB).
const CHUNK: usize = 256 * 1024;

/// Whether this build can answer desktop requests (advertised in the hello).
pub const SUPPORTED: bool = cfg!(windows);

pub async fn run(
    allow_remote: bool,
    exec_id: Uuid,
    request: DesktopRequest,
    session: Option<u32>,
    timeout_secs: u64,
    ctl_tx: mpsc::UnboundedSender<Message>,
) {
    let answer = if !allow_remote {
        error_json("remote access is not enabled on this host")
    } else {
        match answer(request, session, timeout_secs).await {
            Ok(json) => json,
            Err(e) => error_json(&format!("{e:#}")),
        }
    };
    // Window titles can be non-ASCII: cut on char boundaries.
    let mut rest = answer.as_str();
    while !rest.is_empty() {
        let mut cut = rest.len().min(CHUNK);
        while !rest.is_char_boundary(cut) {
            cut -= 1;
        }
        let (head, tail) = rest.split_at(cut);
        let msg = AgentToServer::ExecChunk {
            exec_id,
            stream: ExecStream::Stdout,
            data: head.to_string(),
        };
        if ctl_tx
            .send(Message::Text(serde_json::to_string(&msg).unwrap()))
            .is_err()
        {
            return;
        }
        rest = tail;
    }
    let done = AgentToServer::ExecDone {
        exec_id,
        exit_code: Some(0),
        truncated: false,
        error: None,
    };
    let _ = ctl_tx.send(Message::Text(serde_json::to_string(&done).unwrap()));
}

pub fn error_json(msg: &str) -> String {
    serde_json::json!({ "ok": false, "error": msg }).to_string()
}

#[cfg(windows)]
async fn answer(request: DesktopRequest, session: Option<u32>, timeout_secs: u64) -> anyhow::Result<String> {
    win::answer(request, session, timeout_secs).await
}

#[cfg(not(windows))]
async fn answer(_request: DesktopRequest, _session: Option<u32>, _timeout_secs: u64) -> anyhow::Result<String> {
    anyhow::bail!("desktop commands are implemented for Windows agents only")
}

/// `rustlitel-agent desktop-helper --request <b64 json> --out <file>`: runs in
/// the user's session, does the work, writes the JSON answer to `out`.
pub fn helper_main(request_b64: &str, out: &std::path::Path) -> i32 {
    use base64::Engine;
    let json = match base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(request_b64)
        .map_err(anyhow::Error::from)
        .and_then(|b| serde_json::from_slice::<DesktopRequest>(&b).map_err(anyhow::Error::from))
    {
        Ok(req) => helper_answer(req),
        Err(e) => error_json(&format!("bad helper request: {e}")),
    };
    match std::fs::write(out, json) {
        Ok(()) => 0,
        Err(_) => 2,
    }
}

#[cfg(windows)]
fn helper_answer(req: DesktopRequest) -> String {
    match win::helper(req) {
        Ok(mut v) => {
            v["ok"] = serde_json::Value::Bool(true);
            v.to_string()
        }
        Err(e) => error_json(&format!("{e:#}")),
    }
}

#[cfg(not(windows))]
fn helper_answer(_req: DesktopRequest) -> String {
    error_json("desktop commands are implemented for Windows agents only")
}

// --- images (platform independent) -----------------------------------------

/// A captured image: top-down rows of BGRA pixels, as GDI hands them out.
pub struct Bgra {
    pub width: u32,
    pub height: u32,
    pub data: Vec<u8>,
}

impl Bgra {
    /// Box-filter downscale to at most `max_width` pixels wide.
    pub fn downscale(self, max_width: u32) -> Bgra {
        if max_width == 0 || self.width <= max_width {
            return self;
        }
        let (sw, sh) = (self.width as usize, self.height as usize);
        let dw = max_width as usize;
        let dh = ((sh as u64 * dw as u64) / sw as u64).max(1) as usize;
        let mut out = vec![0u8; dw * dh * 4];
        for dy in 0..dh {
            let y0 = dy * sh / dh;
            let y1 = ((dy + 1) * sh / dh).max(y0 + 1);
            for dx in 0..dw {
                let x0 = dx * sw / dw;
                let x1 = ((dx + 1) * sw / dw).max(x0 + 1);
                let mut acc = [0u32; 4];
                for y in y0..y1 {
                    let row = &self.data[(y * sw + x0) * 4..(y * sw + x1) * 4];
                    for px in row.chunks_exact(4) {
                        for c in 0..4 {
                            acc[c] += px[c] as u32;
                        }
                    }
                }
                let n = ((y1 - y0) * (x1 - x0)) as u32;
                let o = (dy * dw + dx) * 4;
                for c in 0..4 {
                    out[o + c] = (acc[c] / n) as u8;
                }
            }
        }
        Bgra {
            width: dw as u32,
            height: dh as u32,
            data: out,
        }
    }

    /// Crop to `(x, y, w, h)`, clamped to the image.
    pub fn crop(self, x: u32, y: u32, w: u32, h: u32) -> Bgra {
        let x = x.min(self.width);
        let y = y.min(self.height);
        let w = w.min(self.width - x);
        let h = h.min(self.height - y);
        if (x, y, w, h) == (0, 0, self.width, self.height) || w == 0 || h == 0 {
            return self;
        }
        let mut out = Vec::with_capacity((w * h * 4) as usize);
        for row in y..y + h {
            let s = ((row * self.width + x) * 4) as usize;
            out.extend_from_slice(&self.data[s..s + (w * 4) as usize]);
        }
        Bgra {
            width: w,
            height: h,
            data: out,
        }
    }

    /// True if every pixel is black (what PrintWindow gives for some windows).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn is_blank(&self) -> bool {
        self.data.chunks_exact(4).all(|p| p[0] == 0 && p[1] == 0 && p[2] == 0)
    }

    fn rgb(&self) -> Vec<u8> {
        let mut rgb = Vec::with_capacity((self.width * self.height * 3) as usize);
        for p in self.data.chunks_exact(4) {
            rgb.extend_from_slice(&[p[2], p[1], p[0]]);
        }
        rgb
    }

    /// Encode as "png" or "jpeg"; returns (format, bytes).
    pub fn encode(&self, format: &str, quality: u8) -> anyhow::Result<(&'static str, Vec<u8>)> {
        let rgb = self.rgb();
        let mut out = Vec::new();
        match format {
            "jpeg" | "jpg" => {
                anyhow::ensure!(
                    self.width <= 65535 && self.height <= 65535,
                    "image too large for JPEG"
                );
                let enc = jpeg_encoder::Encoder::new(&mut out, quality.clamp(1, 100));
                enc.encode(&rgb, self.width as u16, self.height as u16, jpeg_encoder::ColorType::Rgb)?;
                Ok(("jpeg", out))
            }
            "png" => {
                let mut enc = png::Encoder::new(&mut out, self.width, self.height);
                enc.set_color(png::ColorType::Rgb);
                enc.set_depth(png::BitDepth::Eight);
                enc.set_compression(png::Compression::Fast);
                let mut w = enc.write_header()?;
                w.write_image_data(&rgb)?;
                w.finish()?;
                Ok(("png", out))
            }
            other => anyhow::bail!("unknown image format {other:?} (png or jpeg)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn img(w: u32, h: u32) -> Bgra {
        let mut data = Vec::new();
        for i in 0..w * h {
            data.extend_from_slice(&[(i % 256) as u8, 10, 20, 255]);
        }
        Bgra { width: w, height: h, data }
    }

    #[test]
    fn downscale_keeps_aspect() {
        let s = img(400, 200).downscale(100);
        assert_eq!((s.width, s.height), (100, 50));
        assert_eq!(s.data.len(), 100 * 50 * 4);
        let same = img(50, 20).downscale(100);
        assert_eq!((same.width, same.height), (50, 20));
    }

    #[test]
    fn crop_clamps() {
        let c = img(10, 10).crop(2, 3, 100, 4);
        assert_eq!((c.width, c.height), (8, 4));
        assert_eq!(c.data.len(), 8 * 4 * 4);
    }

    #[test]
    fn encodes_png_and_jpeg() {
        let i = img(16, 8);
        let (f, png) = i.encode("png", 80).unwrap();
        assert_eq!(f, "png");
        assert_eq!(&png[1..4], b"PNG");
        let (f, jpg) = i.encode("jpeg", 80).unwrap();
        assert_eq!(f, "jpeg");
        assert_eq!(&jpg[..2], &[0xFF, 0xD8]);
        assert!(i.encode("bmp", 80).is_err());
    }
}
