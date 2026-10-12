use rand::rngs::OsRng;
use rand::Rng;

const LOWER: &str = "abcdefghijkmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &str = "23456789";
const SYMBOLS: &str = "!@#$%^&*-_=+?";

/// EFF-inspired short word list for passphrase mode (subset for offline use).
const WORDLIST: &[&str] = &[
    "acid", "acre", "also", "aqua", "arch", "area", "army", "atom", "aunt", "auto", "away", "axis",
    "back", "bake", "ball", "band", "bank", "bark", "barn", "base", "bath", "bead", "beam", "bean",
    "bear", "beat", "beef", "been", "bell", "belt", "best", "bike", "bill", "bind", "bird", "bite",
    "blow", "blue", "boat", "body", "boil", "bold", "bolt", "bomb", "bond", "bone", "book", "boom",
    "boot", "bore", "both", "bowl", "brag", "brew", "bulb", "bulk", "bull", "bump", "burn", "bush",
    "busy", "cage", "cake", "calf", "call", "calm", "came", "camp", "card", "care", "cart", "case",
    "cash", "cast", "cave", "cell", "chat", "chef", "chip", "city", "clam", "clan", "claw", "clay",
    "clip", "club", "clue", "coal", "coat", "code", "coil", "coin", "cold", "colt", "coma", "comb",
    "come", "cook", "cool", "cope", "copy", "cord", "cork", "corn", "cost", "crab", "crew", "crop",
    "crow", "cube", "cult", "curb", "cure", "curl", "cute", "damp", "dare", "dark", "dart", "dash",
    "data", "date", "dawn", "dead", "deal", "dear", "debt", "deck", "deep", "deer", "desk", "dial",
    "dice", "dirt", "dish", "dock", "doll", "dome", "door", "dose", "down", "draw", "drip", "drop",
    "drum", "dual", "duck", "duct", "duel", "duke", "dune", "dusk", "dust", "duty", "each", "earn",
    "ease", "east", "easy", "edge", "edit", "else", "emit", "envy", "epic", "even", "ever", "evil",
    "exam", "exit", "face", "fact", "fade", "fail", "fair", "fake", "fall", "fame", "fang", "farm",
    "fast", "fate", "fear", "feed", "feel", "feet", "fell", "felt", "fern", "file",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneratorOptions {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
        }
    }
}

/// Generate a password with per-class guarantees using `OsRng`.
///
/// Returns an error if `length` is outside 8..=128 or no character classes are enabled.
pub fn generate_password_checked(opts: GeneratorOptions) -> Result<String, String> {
    if !(8..=128).contains(&opts.length) {
        return Err(format!(
            "length must be between 8 and 128 (got {})",
            opts.length
        ));
    }

    let mut classes: Vec<&str> = Vec::new();
    if opts.lowercase {
        classes.push(LOWER);
    }
    if opts.uppercase {
        classes.push(UPPER);
    }
    if opts.digits {
        classes.push(DIGITS);
    }
    if opts.symbols {
        classes.push(SYMBOLS);
    }
    if classes.is_empty() {
        return Err("enable at least one character class".into());
    }
    if opts.length < classes.len() {
        return Err(format!(
            "length {} too short for {} character classes",
            opts.length,
            classes.len()
        ));
    }

    let charset: Vec<char> = classes.iter().flat_map(|s| s.chars()).collect();
    let mut rng = OsRng;
    let mut out: Vec<char> = classes
        .iter()
        .map(|cls| {
            let chars: Vec<char> = cls.chars().collect();
            chars[rng.gen_range(0..chars.len())]
        })
        .collect();
    while out.len() < opts.length {
        out.push(charset[rng.gen_range(0..charset.len())]);
    }
    // Fisher–Yates shuffle
    for i in (1..out.len()).rev() {
        let j = rng.gen_range(0..=i);
        out.swap(i, j);
    }
    Ok(out.into_iter().collect())
}

/// Backward-compatible API: clamps length and never errors.
pub fn generate_password(
    length: usize,
    uppercase: bool,
    lowercase: bool,
    digits: bool,
    symbols: bool,
) -> String {
    let opts = GeneratorOptions {
        length: length.clamp(8, 128),
        uppercase,
        lowercase,
        digits,
        symbols,
    };
    generate_password_checked(opts).unwrap_or_else(|_| {
        // Fallback if all classes disabled.
        generate_password_checked(GeneratorOptions::default()).expect("defaults valid")
    })
}

/// Diceware-style passphrase from the embedded wordlist.
pub fn generate_passphrase(words: usize, separator: &str) -> String {
    let n = words.clamp(3, 12);
    let mut rng = OsRng;
    (0..n)
        .map(|_| WORDLIST[rng.gen_range(0..WORDLIST.len())])
        .collect::<Vec<_>>()
        .join(separator)
}

/// Approximate entropy bits for a generated password charset size.
pub fn password_entropy_bits(length: usize, charset_size: usize) -> f64 {
    if charset_size == 0 || length == 0 {
        return 0.0;
    }
    (length as f64) * (charset_size as f64).log2()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_class_coverage() {
        let pw = generate_password_checked(GeneratorOptions {
            length: 12,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
        })
        .unwrap();
        assert_eq!(pw.len(), 12);
        assert!(pw.chars().any(|c| LOWER.contains(c)));
        assert!(pw.chars().any(|c| UPPER.contains(c)));
        assert!(pw.chars().any(|c| DIGITS.contains(c)));
        assert!(pw.chars().any(|c| SYMBOLS.contains(c)));
    }

    #[test]
    fn rejects_short_length() {
        assert!(generate_password_checked(GeneratorOptions {
            length: 4,
            ..Default::default()
        })
        .is_err());
    }

    #[test]
    fn passphrase_word_count() {
        let p = generate_passphrase(5, "-");
        assert_eq!(p.split('-').count(), 5);
    }
}
