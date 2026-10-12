//! Organization policy parsing from sync payloads.

use serde::Deserialize;
use serde_json::Value;

use crate::generator::GeneratorOptions;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PolicyType {
    TwoFactorAuthentication = 0,
    MasterPassword = 1,
    PasswordGenerator = 2,
    SingleOrg = 3,
    RequireSso = 4,
    OrganizationDataOwnership = 5,
    DisableSend = 6,
    SendOptions = 7,
    ResetPassword = 8,
    MaximumVaultTimeout = 9,
    Unknown(u8),
}

impl PolicyType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::TwoFactorAuthentication,
            1 => Self::MasterPassword,
            2 => Self::PasswordGenerator,
            3 => Self::SingleOrg,
            4 => Self::RequireSso,
            5 => Self::OrganizationDataOwnership,
            6 => Self::DisableSend,
            7 => Self::SendOptions,
            8 => Self::ResetPassword,
            9 => Self::MaximumVaultTimeout,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub id: String,
    pub organization_id: String,
    pub policy_type: PolicyType,
    pub enabled: bool,
    pub data: Value,
}

#[derive(Debug, Clone, Default)]
pub struct GeneratorPolicy {
    pub min_length: Option<u32>,
    pub use_uppercase: Option<bool>,
    pub use_lowercase: Option<bool>,
    pub use_numbers: Option<bool>,
    pub use_special: Option<bool>,
    pub min_numbers: Option<u32>,
    pub min_special: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct SendPolicy {
    /// Org policy type 6 — Send feature disabled entirely.
    pub send_disabled: bool,
    pub disable_hide_email: Option<bool>,
    pub disable_anonymous_sends: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawPolicy {
    id: String,
    organization_id: String,
    #[serde(rename = "type")]
    policy_type: u8,
    enabled: bool,
    #[serde(default)]
    data: Value,
}

/// Parse sync `policies` JSON values into typed policies.
pub fn parse_policies(raw: &[Value]) -> Vec<Policy> {
    raw.iter()
        .filter_map(|v| serde_json::from_value::<RawPolicy>(v.clone()).ok())
        .map(|p| Policy {
            id: p.id,
            organization_id: p.organization_id,
            policy_type: PolicyType::from_u8(p.policy_type),
            enabled: p.enabled,
            data: p.data,
        })
        .collect()
}

/// Extract password generator constraints from enabled generator policies.
pub fn generator_policy(policies: &[Policy]) -> GeneratorPolicy {
    let mut out = GeneratorPolicy::default();
    for p in policies
        .iter()
        .filter(|p| p.enabled && p.policy_type == PolicyType::PasswordGenerator)
    {
        merge_generator(&mut out, &p.data);
    }
    out
}

fn merge_generator(out: &mut GeneratorPolicy, data: &Value) {
    if let Some(n) = data.get("minLength").and_then(|v| v.as_u64()) {
        out.min_length = Some(n as u32);
    }
    if let Some(b) = data.get("useUpper").and_then(|v| v.as_bool()) {
        out.use_uppercase = Some(b);
    }
    if let Some(b) = data.get("useLower").and_then(|v| v.as_bool()) {
        out.use_lowercase = Some(b);
    }
    if let Some(b) = data.get("useNumbers").and_then(|v| v.as_bool()) {
        out.use_numbers = Some(b);
    }
    if let Some(b) = data.get("useSpecial").and_then(|v| v.as_bool()) {
        out.use_special = Some(b);
    }
    if let Some(n) = data.get("minNumbers").and_then(|v| v.as_u64()) {
        out.min_numbers = Some(n as u32);
    }
    if let Some(n) = data.get("minSpecial").and_then(|v| v.as_u64()) {
        out.min_special = Some(n as u32);
    }
}

/// Extract Send-related policy flags.
pub fn send_policy(policies: &[Policy]) -> SendPolicy {
    let mut out = SendPolicy::default();
    for p in policies.iter().filter(|p| p.enabled) {
        match p.policy_type {
            PolicyType::DisableSend => {
                out.send_disabled = true;
                out.disable_anonymous_sends = Some(true);
            }
            PolicyType::SendOptions => merge_send_options(&mut out, &p.data),
            _ => {}
        }
    }
    out
}

/// Clamp generator options to organization policy (does not regenerate).
pub fn apply_generator_policy(opts: &mut GeneratorOptions, policy: &GeneratorPolicy) {
    if let Some(min) = policy.min_length {
        opts.length = opts.length.max(min as usize);
    }
    if let Some(v) = policy.use_uppercase {
        opts.uppercase = v;
    }
    if let Some(v) = policy.use_lowercase {
        opts.lowercase = v;
    }
    if let Some(v) = policy.use_numbers {
        opts.digits = v;
    }
    if let Some(v) = policy.use_special {
        opts.symbols = v;
    }
    if let Some(n) = policy.min_numbers {
        opts.min_numbers = opts.min_numbers.max(n as usize);
    }
    if let Some(n) = policy.min_special {
        opts.min_special = opts.min_special.max(n as usize);
    }
}

fn merge_send_options(out: &mut SendPolicy, data: &Value) {
    if let Some(b) = data.get("disableHideEmail").and_then(|v| v.as_bool()) {
        out.disable_hide_email = Some(b);
    }
    if let Some(b) = data
        .get("disableAnonymousSend")
        .and_then(|v| v.as_bool())
        .or_else(|| data.get("disableAnonymousSendCreates").and_then(|v| v.as_bool()))
    {
        out.disable_anonymous_sends = Some(b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_generator_policy() {
        let raw = vec![json!({
            "id": "p1",
            "organizationId": "org1",
            "type": 2,
            "enabled": true,
            "data": { "minLength": 14, "useSpecial": true }
        })];
        let policies = parse_policies(&raw);
        assert_eq!(policies.len(), 1);
        let gen = generator_policy(&policies);
        assert_eq!(gen.min_length, Some(14));
        assert_eq!(gen.use_special, Some(true));
    }

    #[test]
    fn apply_generator_policy_clamps_length() {
        let policy = GeneratorPolicy {
            min_length: Some(16),
            use_special: Some(false),
            min_numbers: Some(2),
            ..Default::default()
        };
        let mut opts = GeneratorOptions {
            length: 12,
            symbols: true,
            min_numbers: 1,
            ..Default::default()
        };
        apply_generator_policy(&mut opts, &policy);
        assert_eq!(opts.length, 16);
        assert!(!opts.symbols);
        assert_eq!(opts.min_numbers, 2);
    }

    #[test]
    fn disable_send_policy() {
        let raw = vec![json!({
            "id": "p3",
            "organizationId": "org1",
            "type": 6,
            "enabled": true,
            "data": {}
        })];
        let policies = parse_policies(&raw);
        let send = send_policy(&policies);
        assert!(send.send_disabled);
    }

    #[test]
    fn send_options_policy() {
        let raw = vec![json!({
            "id": "p2",
            "organizationId": "org1",
            "type": 7,
            "enabled": true,
            "data": { "disableHideEmail": true }
        })];
        let policies = parse_policies(&raw);
        let send = send_policy(&policies);
        assert_eq!(send.disable_hide_email, Some(true));
    }
}
