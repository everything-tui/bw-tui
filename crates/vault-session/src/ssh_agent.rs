//! SSH agent: load vault SSH keys into a local `ssh-agent` socket (Unix MVP).

use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use crate::error::{Result, SessionError};
use crate::models::{DecryptedItem, ItemType};
use crate::paths::{ensure_dir, write_atomic};

/// Default OpenSSH agent socket path when `SSH_AUTH_SOCK` is unset (platform hint only).
pub fn default_agent_socket_hint() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/private/tmp/com.openssh.ssh-agent")
    }
    #[cfg(not(target_os = "macos"))]
    {
        PathBuf::from("/run/user/1000/openssh_agent")
    }
}

/// Resolve the agent socket: `SSH_AUTH_SOCK` env, else [`default_agent_socket_hint`].
pub fn agent_socket_path() -> PathBuf {
    std::env::var("SSH_AUTH_SOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_agent_socket_hint())
}

/// Parsed SSH key material from a vault item (PEM/OpenSSH private key text).
#[derive(Debug, Clone)]
pub struct ParsedSshKey {
    pub item_id: String,
    pub name: String,
    pub private_key_pem: String,
    pub public_key: Option<String>,
    pub fingerprint: Option<String>,
}

/// Running local ssh-agent started by this app.
pub struct SshAgentHandle {
    socket: PathBuf,
    agent_child: Child,
    key_dir: PathBuf,
}

impl SshAgentHandle {
    pub fn socket_path(&self) -> &Path {
        &self.socket
    }
}

impl Drop for SshAgentHandle {
    fn drop(&mut self) {
        let _ = self.agent_child.kill();
        let _ = self.agent_child.wait();
        let _ = std::fs::remove_dir_all(&self.key_dir);
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// Extract SSH key fields from a decrypted cipher when `item_type == SshKey`.
pub fn parse_ssh_key_item(item: &DecryptedItem) -> Result<ParsedSshKey> {
    if item.item_type != ItemType::SshKey {
        return Err(SessionError::Other("not an SSH key item".into()));
    }
    let private_key_pem = item
        .ssh_private_key
        .clone()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| SessionError::Other("SSH key item has no private key".into()))?;
    Ok(ParsedSshKey {
        item_id: item.id.clone(),
        name: item.name.clone(),
        private_key_pem,
        public_key: item.ssh_public_key.clone(),
        fingerprint: item.ssh_fingerprint.clone(),
    })
}

/// Start a dedicated `ssh-agent` and load `keys` via `ssh-add`.
#[cfg(unix)]
pub fn start_agent_with_keys(data_dir: &Path, keys: &[ParsedSshKey]) -> Result<SshAgentHandle> {
    if keys.is_empty() {
        return Err(SessionError::Other("no SSH keys to load".into()));
    }
    let agent_dir = data_dir.join("ssh-agent");
    ensure_dir(&agent_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&agent_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| SessionError::Other(e.to_string()))?;
    }
    let socket = agent_dir.join("agent.sock");
    let _ = std::fs::remove_file(&socket);
    let key_dir = agent_dir.join("keys");
    ensure_dir(&key_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| SessionError::Other(e.to_string()))?;
    }

    let mut agent_child = Command::new("ssh-agent")
        .arg("-a")
        .arg(&socket)
        .arg("-D")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            SessionError::Other(format!(
                "failed to start ssh-agent (is OpenSSH installed?): {e}"
            ))
        })?;

    // Brief wait for the socket to appear.
    for _ in 0..50 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    if !socket.exists() {
        let _ = agent_child.kill();
        return Err(SessionError::Other(
            "ssh-agent did not create a socket".into(),
        ));
    }

    add_keys_to_agent(&socket, keys, &key_dir)?;

    Ok(SshAgentHandle {
        socket,
        agent_child,
        key_dir,
    })
}

#[cfg(not(unix))]
pub fn start_agent_with_keys(_data_dir: &Path, _keys: &[ParsedSshKey]) -> Result<SshAgentHandle> {
    Err(SessionError::Other(
        "SSH agent integration is only supported on Unix".into(),
    ))
}

/// Load private keys into an existing agent socket (writes restricted temp key files, `ssh-add`).
pub fn add_keys_to_agent(
    socket: &Path,
    keys: &[ParsedSshKey],
    key_dir: &Path,
) -> Result<()> {
    if keys.is_empty() {
        return Ok(());
    }
    ensure_dir(key_dir)?;
    for (i, key) in keys.iter().enumerate() {
        let path = key_dir.join(format!("vault-ssh-{i}.key"));
        write_atomic(&path, key.private_key_pem.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| SessionError::Other(e.to_string()))?;
        }
        let status = Command::new("ssh-add")
            .env("SSH_AUTH_SOCK", socket)
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()
            .map_err(|e| SessionError::Other(format!("ssh-add failed to run: {e}")))?;
        if !status.success() {
            return Err(SessionError::Other(format!(
                "ssh-add failed for `{}` (exit {:?})",
                key.name,
                status.code()
            )));
        }
    }
    Ok(())
}

/// Human-readable instructions when only key files are exported (no agent).
pub fn ssh_add_instructions(socket: &Path, key_paths: &[PathBuf]) -> String {
    let mut out = format!(
        "export SSH_AUTH_SOCK={}\n",
        shell_escape_path(socket)
    );
    for p in key_paths {
        let _ = writeln!(
            out,
            "ssh-add {}",
            shell_escape_path(p)
        );
    }
    out
}

fn shell_escape_path(path: &Path) -> String {
    let s = path.to_string_lossy();
    if s.contains(' ') || s.contains('\'') {
        format!("'{s}'")
    } else {
        s.into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ItemType;

    #[test]
    fn rejects_non_ssh_items() {
        let item = DecryptedItem {
            id: "x".into(),
            name: "login".into(),
            item_type: ItemType::Login,
            folder_id: None,
            organization_id: None,
            collection_ids: Vec::new(),
            favorite: false,
            deleted: false,
            reprompt: false,
            notes: None,
            username: None,
            password: None,
            totp: None,
            uris: vec![],
            custom_fields: vec![],
            password_history: vec![],
            password_revision_date: None,
            creation_date: None,
            revision_date: None,
            cardholder_name: None,
            card_brand: None,
            card_number: None,
            card_exp_month: None,
            card_exp_year: None,
            card_code: None,
            identity_title: None,
            identity_first_name: None,
            identity_middle_name: None,
            identity_last_name: None,
            identity_email: None,
            identity_phone: None,
            identity_username: None,
            identity_address1: None,
            identity_address2: None,
            identity_address3: None,
            identity_city: None,
            identity_state: None,
            identity_postal_code: None,
            identity_country: None,
            identity_company: None,
            identity_ssn: None,
            identity_passport_number: None,
            identity_license_number: None,
            ssh_private_key: None,
            ssh_public_key: None,
            ssh_fingerprint: None,
            has_item_key: false,
        };
        assert!(parse_ssh_key_item(&item).is_err());
    }
}
