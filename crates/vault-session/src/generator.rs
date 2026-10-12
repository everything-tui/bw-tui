use rand::rngs::OsRng;
use rand::Rng;

const LOWER: &str = "abcdefghijkmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &str = "23456789";
const SYMBOLS: &str = "!@#$%^&*-_=+?";
/// Ambiguous characters excluded when `avoid_ambiguous` is set.
const AMBIGUOUS: &str = "O0Il1";

/// EFF large wordlist (7776 words) embedded at compile time.
const EFF_WORDLIST: &str = include_str!("../data/eff_large_wordlist.txt");

fn wordlist() -> Vec<&'static str> {
    EFF_WORDLIST
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() {
                return None;
            }
            // EFF large wordlist lines: `11111\tword`
            l.split('\t').nth(1).or_else(|| l.split_whitespace().last())
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneratorOptions {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
    pub min_numbers: usize,
    pub min_special: usize,
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
            min_numbers: 1,
            min_special: 1,
        }
    }
}

fn filter_ambiguous(s: &str, avoid: bool) -> String {
    if !avoid {
        return s.to_string();
    }
    s.chars().filter(|c| !AMBIGUOUS.contains(*c)).collect()
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

    let lower = filter_ambiguous(LOWER, opts.avoid_ambiguous);
    let upper = filter_ambiguous(UPPER, opts.avoid_ambiguous);
    let digits = filter_ambiguous(DIGITS, opts.avoid_ambiguous);
    let symbols = SYMBOLS.to_string();

    let mut classes: Vec<&str> = Vec::new();
    if opts.lowercase && !lower.is_empty() {
        classes.push(&lower);
    }
    if opts.uppercase && !upper.is_empty() {
        classes.push(&upper);
    }
    if opts.digits && !digits.is_empty() {
        classes.push(&digits);
    }
    if opts.symbols {
        classes.push(&symbols);
    }
    if classes.is_empty() {
        return Err("enable at least one character class".into());
    }

    let min_extra = opts.min_numbers.saturating_add(opts.min_special);
    let required = classes.len().saturating_add(min_extra.saturating_sub(classes.len().min(2)));
    if opts.length < required.max(classes.len()) {
        return Err(format!(
            "length {} too short for selected character classes / minimums",
            opts.length
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

    // Enforce minimum numbers / specials beyond the per-class seed char.
    let digit_chars: Vec<char> = digits.chars().collect();
    let symbol_chars: Vec<char> = symbols.chars().collect();
    let mut numbers_added = if opts.digits { 1usize } else { 0 };
    let mut specials_added = if opts.symbols { 1usize } else { 0 };
    while opts.digits && numbers_added < opts.min_numbers && out.len() < opts.length {
        if digit_chars.is_empty() {
            break;
        }
        out.push(digit_chars[rng.gen_range(0..digit_chars.len())]);
        numbers_added += 1;
    }
    while opts.symbols && specials_added < opts.min_special && out.len() < opts.length {
        out.push(symbol_chars[rng.gen_range(0..symbol_chars.len())]);
        specials_added += 1;
    }

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
        ..Default::default()
    };
    generate_password_checked(opts).unwrap_or_else(|_| {
        generate_password_checked(GeneratorOptions::default()).expect("defaults valid")
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassphraseOptions {
    pub words: usize,
    pub capitalize: bool,
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 4,
            capitalize: false,
            include_number: false,
        }
    }
}

/// Diceware-style passphrase from the embedded EFF large wordlist.
pub fn generate_passphrase(words: usize, separator: &str) -> String {
    generate_passphrase_opts(
        PassphraseOptions {
            words,
            ..Default::default()
        },
        separator,
    )
}

/// Passphrase with capitalize / include-number options (official client parity).
pub fn generate_passphrase_opts(opts: PassphraseOptions, separator: &str) -> String {
    let list = wordlist();
    let n = opts.words.clamp(3, 20);
    let mut rng = OsRng;
    let mut parts: Vec<String> = (0..n)
        .map(|_| {
            let mut w = list[rng.gen_range(0..list.len())].to_string();
            if opts.capitalize && !w.is_empty() {
                let mut chars = w.chars();
                if let Some(first) = chars.next() {
                    w = format!("{}{}", first.to_ascii_uppercase(), chars.as_str());
                }
            }
            w
        })
        .collect();
    if opts.include_number && !parts.is_empty() {
        let idx = rng.gen_range(0..parts.len());
        let num: u8 = rng.gen_range(0..10);
        parts[idx].push(char::from(b'0' + num));
    }
    parts.join(separator)
}

/// Random username word from the EFF wordlist.
pub fn generate_username_word() -> String {
    let list = wordlist();
    let mut rng = OsRng;
    list[rng.gen_range(0..list.len())].to_string()
}

/// Plus-addressed email: `local+tag@domain`.
pub fn generate_username_plus_address(email: &str) -> Result<String, String> {
    let (local, domain) = email
        .split_once('@')
        .ok_or_else(|| "email must contain @".to_string())?;
    if local.is_empty() || domain.is_empty() {
        return Err("invalid email".into());
    }
    let tag = generate_username_word();
    Ok(format!("{local}+{tag}@{domain}"))
}

/// Catch-all username: `word@domain`.
pub fn generate_username_catchall(domain: &str) -> Result<String, String> {
    let d = domain.trim().trim_start_matches('@');
    if d.is_empty() {
        return Err("domain required".into());
    }
    Ok(format!("{}@{d}", generate_username_word()))
}

/// Approximate entropy bits for a generated password charset size.
pub fn password_entropy_bits(length: usize, charset_size: usize) -> f64 {
    if charset_size == 0 || length == 0 {
        return 0.0;
    }
    (length as f64) * (charset_size as f64).log2()
}

fn estimate_charset_size(password: &str) -> usize {
    let mut classes = 0usize;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        classes += 26;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        classes += 26;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        classes += 10;
    }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        classes += 32;
    }
    classes.max(1)
}

/// Entropy estimate for a generated or pasted password string.
pub fn password_entropy_for_string(password: &str) -> f64 {
    password_entropy_bits(password.len(), estimate_charset_size(password))
}

/// Rough strength label from entropy bits.
pub fn password_strength_label(bits: f64) -> &'static str {
    if bits < 40.0 {
        "weak"
    } else if bits < 60.0 {
        "fair"
    } else if bits < 80.0 {
        "good"
    } else {
        "strong"
    }
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
            ..Default::default()
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

    #[test]
    fn eff_wordlist_loaded() {
        assert_eq!(wordlist().len(), 7776);
    }

    #[test]
    fn passphrase_capitalize_and_number() {
        let p = generate_passphrase_opts(
            PassphraseOptions {
                words: 4,
                capitalize: true,
                include_number: true,
            },
            "-",
        );
        let parts: Vec<_> = p.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert!(parts.iter().any(|w| w.chars().next().unwrap().is_uppercase()));
        assert!(p.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn plus_address() {
        let u = generate_username_plus_address("user@example.com").unwrap();
        assert!(u.starts_with("user+"));
        assert!(u.ends_with("@example.com"));
    }
}
