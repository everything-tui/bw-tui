//! Ed25519 SSH key generation for new vault SSH-key items.

use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use zeroize::Zeroizing;

use crate::error::{Result, SessionError};

/// Freshly generated key material in the formats stored on a Bitwarden SSH-key cipher.
pub struct GeneratedSshKey {
    /// OpenSSH-format private key (`-----BEGIN OPENSSH PRIVATE KEY-----`).
    pub private_key: Zeroizing<String>,
    /// `ssh-ed25519 AAAA… comment` line.
    pub public_key: String,
    /// `SHA256:…` fingerprint.
    pub fingerprint: String,
}

/// Generate an unencrypted Ed25519 key pair. `comment` is embedded in the public key line.
pub fn generate_ed25519_ssh_key(comment: &str) -> Result<GeneratedSshKey> {
    let mut key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .map_err(|e| SessionError::Other(format!("ssh keygen failed: {e}")))?;
    let comment = comment.trim();
    if !comment.is_empty() {
        key.set_comment(comment);
    }
    let private_key = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| SessionError::Other(format!("ssh key encode failed: {e}")))?;
    let public_key = key
        .public_key()
        .to_openssh()
        .map_err(|e| SessionError::Other(format!("ssh public key encode failed: {e}")))?;
    let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
    // `private_key` is already `Zeroizing<String>` in ssh-key; re-wrap to own the type.
    Ok(GeneratedSshKey {
        private_key: Zeroizing::new(private_key.as_str().to_owned()),
        public_key,
        fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_parseable_ed25519() {
        let k = generate_ed25519_ssh_key("test@bw-tui").unwrap();
        assert!(k
            .private_key
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(k.public_key.starts_with("ssh-ed25519 "));
        assert!(k.public_key.ends_with("test@bw-tui"));
        assert!(k.fingerprint.starts_with("SHA256:"));
        let parsed = PrivateKey::from_openssh(k.private_key.as_str()).unwrap();
        assert_eq!(
            parsed.fingerprint(HashAlg::Sha256).to_string(),
            k.fingerprint
        );
    }
}
