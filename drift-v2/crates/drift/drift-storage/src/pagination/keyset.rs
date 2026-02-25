//! Keyset cursor pagination — no OFFSET/LIMIT.
//! Constant-time page retrieval regardless of position.

use serde::{Deserialize, Serialize};

/// A cursor for keyset pagination. Composite: (sort_value, id).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationCursor {
    pub last_sort_value: String,
    pub last_id: String,
}

impl PaginationCursor {
    /// Encode cursor as base64 JSON.
    pub fn encode(&self) -> String {
        let json = serde_json::to_string(self).unwrap_or_default();
        base64_encode(&json)
    }

    /// Decode cursor from base64 JSON.
    pub fn decode(encoded: &str) -> Option<Self> {
        let json = base64_decode(encoded)?;
        serde_json::from_str(&json).ok()
    }
}

/// A paginated result set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResult<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub has_more: bool,
    pub next_cursor: Option<String>,
}

impl<T> PaginatedResult<T> {
    /// Create an empty result.
    pub fn empty() -> Self {
        Self {
            items: Vec::new(),
            total: 0,
            has_more: false,
            next_cursor: None,
        }
    }
}

// Simple base64 encode/decode (no external dep needed for this)
fn base64_encode(input: &str) -> String {
    use std::io::Write;
    let mut buf = Vec::new();
    {
        let mut encoder = Base64Encoder::new(&mut buf);
        encoder.write_all(input.as_bytes()).ok();
    }
    String::from_utf8(buf).unwrap_or_default()
}

fn base64_decode(input: &str) -> Option<String> {
    let bytes = base64_decode_bytes(input)?;
    String::from_utf8(bytes).ok()
}

// Minimal base64 implementation (avoids adding base64 crate dep for pagination)
struct Base64Encoder<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> Base64Encoder<'a> {
    fn new(out: &'a mut Vec<u8>) -> Self {
        Self { out }
    }
}

const B64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

impl<'a> std::io::Write for Base64Encoder<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for chunk in buf.chunks(3) {
            match chunk.len() {
                3 => {
                    self.out.push(B64_CHARS[(chunk[0] >> 2) as usize]);
                    self.out.push(B64_CHARS[((chunk[0] & 0x03) << 4 | chunk[1] >> 4) as usize]);
                    self.out.push(B64_CHARS[((chunk[1] & 0x0f) << 2 | chunk[2] >> 6) as usize]);
                    self.out.push(B64_CHARS[(chunk[2] & 0x3f) as usize]);
                }
                2 => {
                    self.out.push(B64_CHARS[(chunk[0] >> 2) as usize]);
                    self.out.push(B64_CHARS[((chunk[0] & 0x03) << 4 | chunk[1] >> 4) as usize]);
                    self.out.push(B64_CHARS[((chunk[1] & 0x0f) << 2) as usize]);
                    self.out.push(b'=');
                }
                1 => {
                    self.out.push(B64_CHARS[(chunk[0] >> 2) as usize]);
                    self.out.push(B64_CHARS[((chunk[0] & 0x03) << 4) as usize]);
                    self.out.push(b'=');
                    self.out.push(b'=');
                }
                _ => {}
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn base64_decode_bytes(input: &str) -> Option<Vec<u8>> {
    let input = input.trim_end_matches('=');
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;

    for c in input.bytes() {
        let val = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}
