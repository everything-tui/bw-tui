//! Organization policy parsing from sync payloads.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Result, SessionError};
use crate::generator::GeneratorOptions;
use crate::paths::write_atomic;

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
    DisablePersonalVaultExport = 10,
    ActivateAutofill = 11,
    AutomaticAppLogIn = 12,
    FreeFamiliesSponsorship = 13,
    /// Org policy type 14 — PIN unlock is not allowed.
    RemoveUnlockWithPin = 14,
    /// Org policy type 15 — listed cipher types may not be created.
    RestrictedItemTypes = 15,
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
            10 => Self::DisablePersonalVaultExport,
            11 => Self::ActivateAutofill,
            12 => Self::AutomaticAppLogIn,
            13 => Self::FreeFamiliesSponsorship,
            14 => Self::RemoveUnlockWithPin,
            15 => Self::RestrictedItemTypes,
            other => Self::Unknown(other),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::TwoFactorAuthentication => 0,
            Self::MasterPassword => 1,
            Self::PasswordGenerator => 2,
            Self::SingleOrg => 3,
            Self::RequireSso => 4,
            Self::OrganizationDataOwnership => 5,
            Self::DisableSend => 6,
            Self::SendOptions => 7,
            Self::ResetPassword => 8,
            Self::MaximumVaultTimeout => 9,
            Self::DisablePersonalVaultExport => 10,
            Self::ActivateAutofill => 11,
            Self::AutomaticAppLogIn => 12,
            Self::FreeFamiliesSponsorship => 13,
            Self::RemoveUnlockWithPin => 14,
            Self::RestrictedItemTypes => 15,
            Self::Unknown(v) => v,
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
        .or_else(|| {
            data.get("disableAnonymousSendCreates")
                .and_then(|v| v.as_bool())
        })
    {
        out.disable_anonymous_sends = Some(b);
    }
}

// ---------------------------------------------------------------------------
// Vault timeout (type 9)
// ---------------------------------------------------------------------------

/// What happens when the vault timeout fires (or the system locks / sleeps).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TimeoutAction {
    /// Wipe keys from memory; master password (or PIN) required to unlock.
    #[default]
    Lock,
    /// Lock and drop the persisted session; full login required.
    Logout,
}

impl TimeoutAction {
    pub fn label(self) -> &'static str {
        match self {
            Self::Lock => "lock",
            Self::Logout => "log out",
        }
    }

    pub fn toggled(self) -> Self {
        match self {
            Self::Lock => Self::Logout,
            Self::Logout => Self::Lock,
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw
            .trim()
            .to_ascii_lowercase()
            .replace(['_', '-', ' '], "")
            .as_str()
        {
            "lock" => Some(Self::Lock),
            "logout" => Some(Self::Logout),
            _ => None,
        }
    }
}

/// Merged organization vault-timeout restrictions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VaultTimeoutPolicy {
    /// Maximum idle minutes allowed (smallest across enabled policies).
    pub max_minutes: Option<u64>,
    /// Forced timeout action (`Logout` wins over `Lock` across orgs).
    pub action: Option<TimeoutAction>,
}

impl VaultTimeoutPolicy {
    pub fn is_active(&self) -> bool {
        self.max_minutes.is_some() || self.action.is_some()
    }
}

/// Extract the vault timeout policy (type 9) from enabled policies.
pub fn vault_timeout_policy(policies: &[Policy]) -> VaultTimeoutPolicy {
    let mut out = VaultTimeoutPolicy::default();
    for p in policies
        .iter()
        .filter(|p| p.enabled && p.policy_type == PolicyType::MaximumVaultTimeout)
    {
        let minutes = match p.data.get("type").and_then(|v| v.as_str()) {
            Some("immediately") => Some(1),
            Some("never") => None,
            _ => p
                .data
                .get("minutes")
                .and_then(|v| v.as_u64().or_else(|| v.as_f64().map(|f| f.max(0.0) as u64))),
        };
        if let Some(m) = minutes {
            let m = m.max(1);
            out.max_minutes = Some(out.max_minutes.map_or(m, |cur| cur.min(m)));
        }
        let action = p
            .data
            .get("action")
            .and_then(|v| v.as_str())
            .and_then(TimeoutAction::parse);
        if let Some(a) = action {
            out.action = Some(match (out.action, a) {
                (Some(TimeoutAction::Logout), _) | (_, TimeoutAction::Logout) => {
                    TimeoutAction::Logout
                }
                _ => TimeoutAction::Lock,
            });
        }
    }
    out
}

/// Idle minutes after applying the org maximum (`None` = never).
pub fn effective_timeout_minutes(
    profile_minutes: Option<u64>,
    policy: &VaultTimeoutPolicy,
) -> Option<u64> {
    match (profile_minutes, policy.max_minutes) {
        (Some(p), Some(m)) => Some(p.min(m)),
        (None, Some(m)) => Some(m),
        (p, None) => p,
    }
}

/// Timeout action after applying an org-enforced action.
pub fn effective_timeout_action(
    profile_action: TimeoutAction,
    policy: &VaultTimeoutPolicy,
) -> TimeoutAction {
    policy.action.unwrap_or(profile_action)
}

// ---------------------------------------------------------------------------
// Master password requirements (type 1)
// ---------------------------------------------------------------------------

/// Merged master-password requirements (strictest value across organizations).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MasterPasswordPolicy {
    /// Minimum zxcvbn score, 0–4.
    pub min_complexity: Option<u8>,
    pub min_length: Option<u32>,
    pub require_upper: bool,
    pub require_lower: bool,
    pub require_numbers: bool,
    pub require_special: bool,
    pub enforce_on_login: bool,
}

const MASTER_SPECIAL_CHARS: &str = "!@#$%^&*";

impl MasterPasswordPolicy {
    pub fn is_active(&self) -> bool {
        self.min_complexity.is_some_and(|c| c > 0)
            || self.min_length.is_some_and(|l| l > 0)
            || self.require_upper
            || self.require_lower
            || self.require_numbers
            || self.require_special
    }

    /// Human-readable requirement list.
    pub fn requirements(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(c) = self.min_complexity.filter(|c| *c > 0) {
            out.push(format!("minimum strength score {c}/4"));
        }
        if let Some(l) = self.min_length.filter(|l| *l > 0) {
            out.push(format!("at least {l} characters"));
        }
        if self.require_upper {
            out.push("an uppercase letter".into());
        }
        if self.require_lower {
            out.push("a lowercase letter".into());
        }
        if self.require_numbers {
            out.push("a number".into());
        }
        if self.require_special {
            out.push(format!("a special character ({MASTER_SPECIAL_CHARS})"));
        }
        out
    }

    /// Returns one message per unmet requirement (empty = compliant).
    pub fn validate(&self, password: &str, user_inputs: &[&str]) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(l) = self.min_length.filter(|l| *l > 0) {
            if password.chars().count() < l as usize {
                out.push(format!("must be at least {l} characters"));
            }
        }
        if self.require_upper && !password.chars().any(|c| c.is_uppercase()) {
            out.push("must contain an uppercase letter".into());
        }
        if self.require_lower && !password.chars().any(|c| c.is_lowercase()) {
            out.push("must contain a lowercase letter".into());
        }
        if self.require_numbers && !password.chars().any(|c| c.is_ascii_digit()) {
            out.push("must contain a number".into());
        }
        if self.require_special && !password.chars().any(|c| MASTER_SPECIAL_CHARS.contains(c)) {
            out.push(format!(
                "must contain a special character ({MASTER_SPECIAL_CHARS})"
            ));
        }
        if let Some(min) = self.min_complexity.filter(|c| *c > 0) {
            let score = password_score(password, user_inputs);
            if score < min {
                out.push(format!("is too weak (strength {score}/4, need {min}/4)"));
            }
        }
        out
    }
}

fn password_score(password: &str, user_inputs: &[&str]) -> u8 {
    // zxcvbn is slow on very long inputs; anything this long is already maxed out.
    let pw: String = password.chars().take(128).collect();
    zxcvbn::zxcvbn(&pw, user_inputs).score().into()
}

/// Merge enabled master-password policies (type 1).
pub fn master_password_policy(policies: &[Policy]) -> MasterPasswordPolicy {
    let mut out = MasterPasswordPolicy::default();
    for p in policies
        .iter()
        .filter(|p| p.enabled && p.policy_type == PolicyType::MasterPassword)
    {
        let d = &p.data;
        if let Some(n) = d.get("minComplexity").and_then(|v| v.as_u64()) {
            let n = n.min(4) as u8;
            out.min_complexity = Some(out.min_complexity.map_or(n, |c| c.max(n)));
        }
        if let Some(n) = d.get("minLength").and_then(|v| v.as_u64()) {
            let n = n as u32;
            out.min_length = Some(out.min_length.map_or(n, |c| c.max(n)));
        }
        let flag = |k: &str| d.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
        out.require_upper |= flag("requireUpper");
        out.require_lower |= flag("requireLower");
        out.require_numbers |= flag("requireNumbers");
        out.require_special |= flag("requireSpecial");
        out.enforce_on_login |= flag("enforceOnLogin");
    }
    out
}

// ---------------------------------------------------------------------------
// Simple flag policies + restricted item types
// ---------------------------------------------------------------------------

/// True when any organization has `ty` enabled.
pub fn policy_enabled(policies: &[Policy], ty: PolicyType) -> bool {
    policies.iter().any(|p| p.enabled && p.policy_type == ty)
}

/// Type 14 — PIN unlock must be removed / disallowed.
pub fn pin_unlock_disabled(policies: &[Policy]) -> bool {
    policy_enabled(policies, PolicyType::RemoveUnlockWithPin)
}

/// Type 5 — items must be owned by an organization (no personal vault items).
pub fn personal_vault_disabled(policies: &[Policy]) -> bool {
    policy_enabled(policies, PolicyType::OrganizationDataOwnership)
}

/// Type 15 — Bitwarden cipher type numbers (1 login, 2 note, 3 card, 4 identity, 5 SSH key)
/// that may not be created. Union across organizations.
pub fn restricted_item_types(policies: &[Policy]) -> Vec<u8> {
    fn parse_one(v: &Value) -> Option<u8> {
        if let Some(n) = v.as_u64() {
            return u8::try_from(n).ok();
        }
        match v.as_str()?.trim().to_ascii_lowercase().as_str() {
            "login" => Some(1),
            "note" | "securenote" | "secure_note" => Some(2),
            "card" => Some(3),
            "identity" => Some(4),
            "sshkey" | "ssh_key" | "ssh" => Some(5),
            other => other.parse().ok(),
        }
    }

    let mut out: Vec<u8> = Vec::new();
    for p in policies
        .iter()
        .filter(|p| p.enabled && p.policy_type == PolicyType::RestrictedItemTypes)
    {
        let list = match &p.data {
            Value::Array(a) => Some(a),
            Value::Object(o) => ["types", "restrictedTypes", "itemTypes", "cipherTypes"]
                .iter()
                .find_map(|k| o.get(*k).and_then(|v| v.as_array())),
            _ => None,
        };
        for v in list.into_iter().flatten() {
            // Entries may be bare numbers/strings or `{ "cipherType": 3 }` objects.
            let parsed = parse_one(v)
                .or_else(|| v.get("cipherType").and_then(parse_one))
                .or_else(|| v.get("type").and_then(parse_one));
            if let Some(n) = parsed {
                if !out.contains(&n) {
                    out.push(n);
                }
            }
        }
    }
    out.sort_unstable();
    out
}

// ---------------------------------------------------------------------------
// Persistence (policies are not secret; needed before unlock for PIN / timeout)
// ---------------------------------------------------------------------------

const POLICIES_FILE: &str = "policies.json";

#[derive(Serialize, Deserialize)]
struct StoredPolicy {
    id: String,
    organization_id: String,
    #[serde(rename = "type")]
    policy_type: u8,
    enabled: bool,
    #[serde(default)]
    data: Value,
}

/// Persist policies next to `auth.json` so they apply on the locked screen.
pub fn save_policies(data_dir: &Path, policies: &[Policy]) -> Result<()> {
    let stored: Vec<StoredPolicy> = policies
        .iter()
        .map(|p| StoredPolicy {
            id: p.id.clone(),
            organization_id: p.organization_id.clone(),
            policy_type: p.policy_type.as_u8(),
            enabled: p.enabled,
            data: p.data.clone(),
        })
        .collect();
    let json = serde_json::to_string(&stored).map_err(|e| SessionError::Other(e.to_string()))?;
    write_atomic(&data_dir.join(POLICIES_FILE), json.as_bytes())
}

/// Load persisted policies (empty when missing or unreadable).
pub fn load_policies(data_dir: &Path) -> Vec<Policy> {
    let Ok(json) = std::fs::read_to_string(data_dir.join(POLICIES_FILE)) else {
        return Vec::new();
    };
    let Ok(stored) = serde_json::from_str::<Vec<StoredPolicy>>(&json) else {
        return Vec::new();
    };
    stored
        .into_iter()
        .map(|p| Policy {
            id: p.id,
            organization_id: p.organization_id,
            policy_type: PolicyType::from_u8(p.policy_type),
            enabled: p.enabled,
            data: p.data,
        })
        .collect()
}

/// Remove persisted policies.
pub fn clear_policies(data_dir: &Path) {
    let _ = std::fs::remove_file(data_dir.join(POLICIES_FILE));
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

    fn pol(ty: u8, data: Value) -> Policy {
        parse_policies(&[json!({
            "id": format!("p{ty}"),
            "organizationId": "org1",
            "type": ty,
            "enabled": true,
            "data": data
        })])
        .remove(0)
    }

    #[test]
    fn policy_type_round_trips() {
        for n in 0u8..=20 {
            assert_eq!(PolicyType::from_u8(n).as_u8(), n);
        }
        assert_eq!(PolicyType::from_u8(14), PolicyType::RemoveUnlockWithPin);
        assert_eq!(PolicyType::from_u8(15), PolicyType::RestrictedItemTypes);
    }

    #[test]
    fn vault_timeout_policy_takes_strictest() {
        let policies = vec![
            pol(9, json!({ "minutes": 60, "action": "lock" })),
            pol(9, json!({ "minutes": 15, "action": "logOut" })),
        ];
        let t = vault_timeout_policy(&policies);
        assert_eq!(t.max_minutes, Some(15));
        assert_eq!(t.action, Some(TimeoutAction::Logout));
        assert_eq!(effective_timeout_minutes(None, &t), Some(15));
        assert_eq!(effective_timeout_minutes(Some(5), &t), Some(5));
        assert_eq!(effective_timeout_minutes(Some(120), &t), Some(15));
        assert_eq!(
            effective_timeout_action(TimeoutAction::Lock, &t),
            TimeoutAction::Logout
        );
        let none = VaultTimeoutPolicy::default();
        assert_eq!(effective_timeout_minutes(None, &none), None);
        assert_eq!(
            effective_timeout_action(TimeoutAction::Logout, &none),
            TimeoutAction::Logout
        );
    }

    #[test]
    fn master_password_policy_validates() {
        let policies = vec![pol(
            1,
            json!({
                "minLength": 12, "requireUpper": true, "requireNumbers": true,
                "requireSpecial": true, "minComplexity": 0
            }),
        )];
        let mp = master_password_policy(&policies);
        assert!(mp.is_active());
        assert!(mp.validate("short", &[]).len() >= 3);
        assert!(mp.validate("Correct-Horse-Battery9!", &[]).is_empty());
        assert!(!mp.validate("alllowercase1234567", &[]).is_empty());
    }

    #[test]
    fn simple_flag_policies() {
        let policies = vec![
            pol(14, json!({})),
            pol(5, json!({})),
            pol(15, json!([3, 5])),
        ];
        assert!(pin_unlock_disabled(&policies));
        assert!(personal_vault_disabled(&policies));
        assert_eq!(restricted_item_types(&policies), vec![3, 5]);
        let obj = vec![pol(15, json!({ "types": ["card", 2] }))];
        assert_eq!(restricted_item_types(&obj), vec![2, 3]);
        assert!(!pin_unlock_disabled(&[]));
    }

    #[test]
    fn policies_persist_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let policies = vec![pol(9, json!({ "minutes": 30 })), pol(14, json!({}))];
        save_policies(tmp.path(), &policies).unwrap();
        let loaded = load_policies(tmp.path());
        assert_eq!(loaded.len(), 2);
        assert_eq!(vault_timeout_policy(&loaded).max_minutes, Some(30));
        assert!(pin_unlock_disabled(&loaded));
        clear_policies(tmp.path());
        assert!(load_policies(tmp.path()).is_empty());
    }
}
