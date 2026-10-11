use rand::Rng;

pub fn generate_password(length: usize, uppercase: bool, lowercase: bool, digits: bool, symbols: bool) -> String {
    let mut charset = String::new();
    if lowercase {
        charset.push_str("abcdefghijkmnopqrstuvwxyz");
    }
    if uppercase {
        charset.push_str("ABCDEFGHJKLMNPQRSTUVWXYZ");
    }
    if digits {
        charset.push_str("23456789");
    }
    if symbols {
        charset.push_str("!@#$%^&*-_=+?");
    }
    if charset.is_empty() {
        charset.push_str("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789");
    }
    let chars: Vec<char> = charset.chars().collect();
    let mut rng = rand::thread_rng();
    let len = length.clamp(8, 128);
    (0..len)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect()
}
