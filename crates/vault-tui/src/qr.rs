//! Terminal QR codes rendered with Unicode half-block characters.
//!
//! Two vertical modules are packed into one terminal cell (`▀`, `▄`, `█`, ` `), which keeps the
//! code roughly square in typical 1:2 cell aspect ratios. Rendering assumes a dark-on-light
//! scheme *inverted* for dark terminals: dark modules are drawn as background (blank) and light
//! modules as filled blocks, which is what phone scanners expect on a dark terminal.

use qrcode::{Color, EcLevel, QrCode};

/// Quiet-zone width (in modules) added around the symbol.
pub const QUIET_ZONE: usize = 2;

/// Error building a QR code (usually: payload too large).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrError(pub String);

impl std::fmt::Display for QrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for QrError {}

/// Module matrix (true = dark module) including the quiet zone.
pub fn qr_matrix(data: &str) -> Result<Vec<Vec<bool>>, QrError> {
    if data.is_empty() {
        return Err(QrError("nothing to encode".into()));
    }
    let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::M)
        .map_err(|e| QrError(format!("cannot encode QR: {e}")))?;
    let width = code.width();
    let colors = code.to_colors();
    let size = width + QUIET_ZONE * 2;
    let mut m = vec![vec![false; size]; size];
    for y in 0..width {
        for x in 0..width {
            m[y + QUIET_ZONE][x + QUIET_ZONE] = colors[y * width + x] == Color::Dark;
        }
    }
    Ok(m)
}

/// Render a module matrix as lines of half-block characters.
///
/// `invert` draws dark modules as filled cells (light-on-dark terminals scan best with
/// `invert = false`, i.e. light modules filled; pass `true` for light terminals).
pub fn render_half_blocks(matrix: &[Vec<bool>], invert: bool) -> Vec<String> {
    let h = matrix.len();
    let mut out = Vec::with_capacity(h.div_ceil(2));
    let mut y = 0;
    while y < h {
        let w = matrix[y].len();
        let mut line = String::with_capacity(w);
        for x in 0..w {
            let top = matrix[y][x] ^ !invert;
            // Missing last row behaves like a light module (quiet zone).
            let bottom = matrix.get(y + 1).map(|r| r[x] ^ !invert).unwrap_or(!invert);
            // `top`/`bottom` true => filled cell.
            line.push(match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push(line);
        y += 2;
    }
    out
}

/// Encode `data` and return half-block lines ready for a `Paragraph`.
pub fn qr_lines(data: &str) -> Result<Vec<String>, QrError> {
    let matrix = qr_matrix(data)?;
    Ok(render_half_blocks(&matrix, false))
}

/// Terminal size (columns, rows) needed to show `data` as a QR code.
pub fn qr_dimensions(data: &str) -> Result<(u16, u16), QrError> {
    let m = qr_matrix(data)?;
    Ok((m.len() as u16, m.len().div_ceil(2) as u16))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_square_matrix_with_quiet_zone() {
        let m = qr_matrix("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(m.len(), m[0].len());
        // Quiet zone is light.
        assert!(m[0].iter().all(|d| !d));
        assert!(m.iter().all(|r| !r[0]));
    }

    #[test]
    fn half_block_height_is_half_rounded_up() {
        let m = qr_matrix("hello").unwrap();
        let lines = render_half_blocks(&m, false);
        assert_eq!(lines.len(), m.len().div_ceil(2));
        assert!(lines.iter().all(|l| l.chars().count() == m.len()));
    }

    #[test]
    fn empty_payload_is_error() {
        assert!(qr_lines("").is_err());
    }

    #[test]
    fn oversized_payload_is_error() {
        let big = "x".repeat(5000);
        assert!(qr_lines(&big).is_err());
    }

    #[test]
    fn invert_flips_cells() {
        let m = vec![vec![true, false], vec![false, true]];
        assert_eq!(render_half_blocks(&m, true), vec!["▀▄".to_string()]);
        assert_eq!(render_half_blocks(&m, false), vec!["▄▀".to_string()]);
    }
}
