//! Power-user session APIs: recent-use cache, domain rules editor, SSH agent options.

use std::path::PathBuf;

use super::Session;
use crate::domain_rules::DomainRules;
use crate::error::{Result, SessionError};
use crate::recent::{load_recent, save_recent, RecentMap};
use crate::ssh_agent::start_agent_with_keys_opts;
use crate::SessionStatus;

impl Session {
    /// Decrypt the local "last used" map (empty when locked or absent).
    pub fn recent_map(&self) -> RecentMap {
        match self.user_key.as_ref() {
            Some(key) => load_recent(&self.data_dir, key),
            None => RecentMap::new(),
        }
    }

    /// Persist the (already updated) recent map encrypted with the user key.
    pub fn save_recent_map(&self, map: &RecentMap) -> Result<()> {
        let key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        save_recent(&self.data_dir, key, map)
    }

    /// Fetch the full domain-rule set (custom groups + global groups with exclusion flags).
    pub async fn fetch_domain_rules(&self) -> Result<DomainRules> {
        self.ensure_online()?;
        let raw = self.client.get_domain_rules().await?;
        DomainRules::from_json(&raw)
    }

    /// Save custom equivalent domains / excluded global groups, then re-sync so URI matching
    /// picks the change up.
    pub async fn save_domain_rules(&mut self, rules: &DomainRules) -> Result<()> {
        self.ensure_online()?;
        let body = serde_json::to_value(rules.to_request())
            .map_err(|e| SessionError::Other(e.to_string()))?;
        self.client.put_domain_rules(&body).await?;
        self.sync().await
    }

    /// Names of vault SSH keys that would be loaded into the agent.
    pub fn ssh_agent_key_names(&self) -> Result<Vec<String>> {
        Ok(self
            .list_ssh_keys_for_agent()?
            .into_iter()
            .map(|k| k.name)
            .collect())
    }

    /// Start the dedicated ssh-agent; `confirm_each_use` adds keys with `ssh-add -c`.
    pub fn start_ssh_agent_opts(&mut self, confirm_each_use: bool) -> Result<PathBuf> {
        if self.status != SessionStatus::Unlocked {
            return Err(SessionError::Locked);
        }
        self.stop_ssh_agent();
        let keys = self.list_ssh_keys_for_agent()?;
        let handle = start_agent_with_keys_opts(&self.data_dir, &keys, confirm_each_use)?;
        let socket = handle.socket_path().to_path_buf();
        self.ssh_agent = Some(handle);
        Ok(socket)
    }
}
