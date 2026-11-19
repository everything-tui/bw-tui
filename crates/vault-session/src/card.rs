//! Card brand detection, Luhn validation, and expiry helpers.

use chrono::{Datelike, Local};

/// Detect card brand from the PAN prefix (digits only).
pub fn detect_card_brand(number: &str) -> Option<&'static str> {
    let digits: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    if digits.starts_with('4') && (digits.len() == 13 || digits.len() == 16 || digits.len() == 19) {
        return Some("Visa");
    }
    if digits.len() == 16 {
        if let Ok(prefix2) = digits[..2].parse::<u32>() {
            if (51..=55).contains(&prefix2) {
                return Some("Mastercard");
            }
        }
        if let Ok(prefix4) = digits[..4].parse::<u32>() {
            if (2221..=2720).contains(&prefix4) {
                return Some("Mastercard");
            }
        }
    }
    if (digits.starts_with("34") || digits.starts_with("37")) && digits.len() == 15 {
        return Some("Amex");
    }
    if digits.starts_with("6011")
        || digits.starts_with("65")
        || digits
            .get(..3)
            .and_then(|s| s.parse::<u32>().ok())
            .is_some_and(|p| (644..=649).contains(&p))
    {
        return Some("Discover");
    }
    if digits.starts_with("35") && digits.len() == 16 {
        return Some("JCB");
    }
    if (digits.starts_with("36") || digits.starts_with("38") || digits.starts_with("30"))
        && digits.len() == 14
    {
        return Some("Diners Club");
    }
    None
}

/// Luhn checksum validation for a card number.
pub fn luhn_valid(number: &str) -> bool {
    let digits: Vec<u32> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() < 12 {
        return false;
    }
    let mut sum = 0u32;
    let mut alt = false;
    for &d in digits.iter().rev() {
        let mut v = d;
        if alt {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        alt = !alt;
    }
    sum.is_multiple_of(10)
}

/// Parse expiry month/year strings into (month, full_year).
pub fn parse_expiry(month: &str, year: &str) -> Option<(u32, i32)> {
    let m: u32 = month.trim().parse().ok()?;
    if !(1..=12).contains(&m) {
        return None;
    }
    let y_raw: i32 = year.trim().parse().ok()?;
    let y = if y_raw < 100 { 2000 + y_raw } else { y_raw };
    Some((m, y))
}

/// True when the card is expired as of the current local month.
pub fn card_is_expired(month: &str, year: &str) -> bool {
    let Some((m, y)) = parse_expiry(month, year) else {
        return false;
    };
    let now = Local::now().date_naive();
    let cur_y = now.year();
    let cur_m = now.month();
    y < cur_y || (y == cur_y && m < cur_m)
}

/// True when the card expires within the next `months` months (inclusive of current).
pub fn card_expires_soon(month: &str, year: &str, months: u32) -> bool {
    let Some((m, y)) = parse_expiry(month, year) else {
        return false;
    };
    if card_is_expired(month, year) {
        return true;
    }
    let now = Local::now().date_naive();
    let mut ey = now.year();
    let mut em = now.month() + months;
    while em > 12 {
        em -= 12;
        ey += 1;
    }
    y < ey || (y == ey && m <= em)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visa_and_luhn() {
        assert_eq!(detect_card_brand("4111111111111111"), Some("Visa"));
        assert!(luhn_valid("4111111111111111"));
        assert!(!luhn_valid("4111111111111112"));
    }

    #[test]
    fn mastercard_prefix() {
        assert_eq!(detect_card_brand("5555555555554444"), Some("Mastercard"));
        assert!(luhn_valid("5555555555554444"));
    }

    #[test]
    fn amex() {
        assert_eq!(detect_card_brand("378282246310005"), Some("Amex"));
        assert!(luhn_valid("378282246310005"));
    }

    #[test]
    fn expiry_parse() {
        assert_eq!(parse_expiry("12", "25"), Some((12, 2025)));
        assert_eq!(parse_expiry("1", "2030"), Some((1, 2030)));
        assert!(parse_expiry("13", "25").is_none());
    }
}
