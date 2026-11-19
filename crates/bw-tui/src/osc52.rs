//! OSC 52 terminal clipboard fallback (SSH / headless terminals without arboard).

use std::io::{self, Write};

/// Copy plain text to the terminal clipboard via OSC 52 when supported.
///
/// Many modern terminals (iTerm2, Kitty, WezTerm, recent VTE) honor this sequence.
/// Returns `false` if writing fails or the payload is empty.
pub fn try_copy_osc52(text: &str) -> bool {
    if text.is_empty() {
        return false;
    }
    let encoded = base64_encode(text.as_bytes());
    // `\x1b]52;c;<base64>\x07` — c = system clipboard
    let seq = format!("\x1b]52;c;{encoded}\x07");
    io::stdout().write_all(seq.as_bytes()).is_ok() && io::stdout().flush().is_ok()
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let n = (bytes[i] as u32) << 16;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push('=');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip_ascii() {
        assert_eq!(base64_encode(b"hi"), "aGk=");
    }
}
