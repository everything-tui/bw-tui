//! Password strength estimation backed by `zxcvbn` (pattern / dictionary aware).

use zxcvbn::zxcvbn;

/// zxcvbn gets slow on very long inputs; anything this long is already maxed out.
const MAX_EVALUATED_CHARS: usize = 128;

/// Scores below this (0–4) are treated as weak in reports.
pub const WEAK_SCORE_THRESHOLD: u8 = 2;

#[derive(Debug, Clone, PartialEq)]
pub struct PasswordStrength {
    /// zxcvbn score, 0 (very weak) – 4 (strong).
    pub score: u8,
    pub label: &'static str,
    /// Estimated entropy in bits (`log2(guesses)`).
    pub entropy_bits: f64,
    pub guesses_log10: f64,
    pub warning: Option<String>,
    pub suggestions: Vec<String>,
}

impl PasswordStrength {
    pub fn is_weak(&self) -> bool {
        self.score < WEAK_SCORE_THRESHOLD
    }
}

/// Human label for a zxcvbn score (0–4).
pub fn score_label(score: u8) -> &'static str {
    match score {
        0 => "very weak",
        1 => "weak",
        2 => "fair",
        3 => "good",
        _ => "strong",
    }
}

/// Evaluate `password`; `user_inputs` (username, site name, …) are penalised as guessable.
pub fn evaluate_password(password: &str, user_inputs: &[&str]) -> PasswordStrength {
    let truncated: String;
    let pw = if password.chars().count() > MAX_EVALUATED_CHARS {
        truncated = password.chars().take(MAX_EVALUATED_CHARS).collect();
        truncated.as_str()
    } else {
        password
    };
    let result = zxcvbn(pw, user_inputs);
    let score: u8 = result.score().into();
    let guesses_log10 = result.guesses_log10();
    let entropy_bits = if guesses_log10.is_finite() && guesses_log10 > 0.0 {
        guesses_log10 * std::f64::consts::LOG2_10
    } else {
        0.0
    };
    let (warning, suggestions) = match result.feedback() {
        Some(fb) => (
            fb.warning().map(|w| w.to_string()),
            fb.suggestions().iter().map(|s| s.to_string()).collect(),
        ),
        None => (None, Vec::new()),
    };
    PasswordStrength {
        score,
        label: score_label(score),
        entropy_bits,
        guesses_log10: if guesses_log10.is_finite() {
            guesses_log10
        } else {
            0.0
        },
        warning,
        suggestions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_password_is_weak() {
        let s = evaluate_password("password", &[]);
        assert!(s.is_weak());
        assert_eq!(s.score, 0);
        assert!(s.warning.is_some());
    }

    #[test]
    fn random_password_is_strong() {
        let s = evaluate_password("x7#Qm!9vLp2$Zr8@Tn4^", &[]);
        assert_eq!(s.score, 4);
        assert_eq!(s.label, "strong");
        assert!(s.entropy_bits > 40.0);
    }

    #[test]
    fn user_inputs_penalised() {
        let plain = evaluate_password("alicewonderland", &[]);
        let ctx = evaluate_password("alicewonderland", &["alicewonderland"]);
        assert!(ctx.guesses_log10 <= plain.guesses_log10);
    }

    #[test]
    fn empty_and_long_do_not_panic() {
        assert_eq!(evaluate_password("", &[]).entropy_bits, 0.0);
        let long = "aB3$".repeat(500);
        let _ = evaluate_password(&long, &[]);
    }
}
