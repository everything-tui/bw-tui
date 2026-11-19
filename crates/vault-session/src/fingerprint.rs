//! Account fingerprint phrase (Bitwarden-style word list from public key hash).

use sha2::{Digest, Sha256};
use std::sync::OnceLock;

fn word_list() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        include_str!("../data/eff_large_wordlist.txt")
            .lines()
            .filter(|l| !l.is_empty())
            .collect()
    })
}

/// Five-word hyphenated fingerprint from SPKI / public key DER bytes.
pub fn fingerprint_phrase_from_public_der(public_der: &[u8]) -> String {
    let words = word_list();
    let hash = Sha256::digest(public_der);
    let n = words.len().max(1);
    let mut out = Vec::with_capacity(5);
    for i in 0..5 {
        let b0 = hash[i * 2] as usize;
        let b1 = hash[i * 2 + 1] as usize;
        let idx = (b0 << 8 | b1) % n;
        out.push(words[idx]);
    }
    out.join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_phrase() {
        let a = fingerprint_phrase_from_public_der(b"test-public-key-bytes");
        let b = fingerprint_phrase_from_public_der(b"test-public-key-bytes");
        assert_eq!(a, b);
        assert_eq!(a.matches('-').count(), 4);
    }
}
