//! Vault session: login, unlock, sync, decrypt, CRUD, clipboard.

mod biometric;
mod browser;
mod card;
mod clipboard;
mod decrypt;
mod domain_rules;
mod domains;
mod error;
mod export;
mod export_zip;
mod fingerprint;
mod forwarders;
mod generator;
pub mod import;
mod loopback;
mod models;
mod org_share;
mod paths;
mod pin;
mod policies;
mod recent;
mod reports;
mod secure_storage;
mod send;
mod send_crypto;
mod session;
mod ssh_agent;
mod ssh_keygen;
mod strength;
mod uri_match;
mod vault_cache;
mod webauthn;

pub use biometric::{
    authenticate as biometric_authenticate, available as biometric_available,
    clear_enrollment as biometric_clear_enrollment, is_enrolled as biometric_is_enrolled,
    mark_enrolled as biometric_mark_enrolled, status_hint as biometric_status_hint, BiometricError,
};
pub use browser::open_url;
pub use card::{card_expires_soon, card_is_expired, detect_card_brand, luhn_valid, parse_expiry};
pub use clipboard::ClipboardService;
pub use domain_rules::{
    format_domain_group, normalize_domain, parse_domain_group, DomainRules, DomainRulesRequest,
    GlobalDomainGroup,
};
pub use domains::{parse_domains, VaultDomains};
pub use error::{Result, SessionError};
pub use export::{
    export_csv, export_csv_full, export_encrypted_json, export_json, export_organization_csv,
    export_organization_json, import_bitwarden_json, import_encrypted_json,
    organization_export_endpoint, EncryptedExport, ImportBundle,
};
pub use export_zip::{collect_attachments, export_zip, ExportAttachment};
pub use fingerprint::fingerprint_phrase_from_public_der;
pub use forwarders::{
    delete_forwarder_credentials, generate_forwarded_alias, generate_forwarded_alias_blocking,
    load_forwarder_credentials, store_forwarder_credentials, ForwarderCredentials,
    ForwarderService,
};
pub use generator::{
    generate_passphrase, generate_passphrase_opts, generate_password, generate_password_checked,
    generate_password_min_score, generate_username_catchall, generate_username_plus_address,
    generate_username_word, password_entropy_bits, password_entropy_for_string,
    password_strength_label, GeneratorOptions, PassphraseOptions,
};
pub use import::{
    import_1password_1pux, import_1password_csv, import_bitwarden_csv, import_browser_csv,
    import_from_bytes, import_from_text, import_keepass_csv, import_keepass_xml,
    import_lastpass_csv, import_proton_csv, import_proton_json, BrowserKind, ImportFormat,
};
pub use loopback::LoopbackListener;
pub use models::*;
pub use org_share::{
    reencrypt_cipher_for_org, seal_new_cipher, CollectionChoice, EmergencyAccessOverview,
    OrgCollectionGroup, OrgPlacement,
};
pub use paths::{app_data_dir, ensure_dir, profile_dir, profiles_dir, profiles_file, write_atomic};
pub use pin::{
    clear_pin, pin_configured, random_numeric_pin, store_pin_wrapped_key, unlock_with_pin,
    MAX_PIN_FAILURES,
};
pub use policies::{
    apply_generator_policy, clear_policies, effective_timeout_action, effective_timeout_minutes,
    generator_policy, load_policies, master_password_policy, parse_policies,
    personal_vault_disabled, pin_unlock_disabled, policy_enabled, restricted_item_types,
    save_policies, send_policy, vault_timeout_policy, GeneratorPolicy, MasterPasswordPolicy,
    Policy, PolicyType, SendPolicy, TimeoutAction, VaultTimeoutPolicy,
};
pub use recent::{clear_recent, load_recent, save_recent, RecentMap};
pub use reports::{
    build_health_report, build_health_report_with, collect_breach_check_emails,
    find_duplicate_items, find_expired_cards, find_inactive_2fa, find_old_passwords,
    find_reused_passwords, find_unsecured_http, find_weak_passwords, hibp_api_key_from_env,
    hibp_email_breaches, hibp_password_pwned_count, DuplicateItemGroup, ExpiredCardEntry,
    HealthOptions, HibpError, Inactive2faEntry, OldPasswordEntry, ReusedPasswordGroup,
    TwoFactorDirectory, UnsecuredHttpEntry, VaultHealthReport, WeakPasswordEntry,
    DEFAULT_OLD_PASSWORD_DAYS, HIBP_API_KEY_ENV_VARS,
};
pub use secure_storage::{
    with_refresh_token_store_for_tests, FailingRefreshTokenStore, MemoryRefreshTokenStore,
    RefreshTokenStore,
};
pub use send::{
    download_received_file, format_file_size, is_send_password_error, parse_send_date,
    receive_send, sanitize_file_name, save_received_file, ReceivedSend, ReceivedSendFile,
    SendOptions, DEFAULT_SEND_LIFETIME_DAYS, MAX_SEND_FILE_BYTES, MAX_SEND_LIFETIME_DAYS,
    SEND_TYPE_FILE, SEND_TYPE_TEXT,
};
pub use send_crypto::{
    decode_send_key_material, decrypt_send_file_bytes, derive_send_key, encode_send_key,
    encrypt_send_file_bytes, encrypt_send_meta, encrypt_send_text, generate_send_key_material,
    hash_send_password, parse_send_url, ParsedSendUrl, SEND_PASSWORD_ITERATIONS,
};
pub use session::{
    pkce_pair, plaintext_token_allowed, totp_display_from_secret, totp_from_secret,
    AuthenticatorSetupInfo, DeviceLoginStart, DeviceLoginStatus, IncomingAuthRequest, LoginResult,
    Session, SessionStatus, SsoStart, SyncOutcome, TotpDisplay,
};
pub use ssh_agent::{
    add_keys_to_agent, add_keys_to_agent_opts, agent_socket_path, default_agent_socket_hint,
    parse_ssh_key_item, ssh_add_instructions, start_agent_with_keys, start_agent_with_keys_opts,
    ParsedSshKey, SshAgentHandle,
};
pub use ssh_keygen::{generate_ed25519_ssh_key, GeneratedSshKey};
pub use strength::{evaluate_password, score_label, PasswordStrength, WEAK_SCORE_THRESHOLD};
pub use uri_match::{
    item_matches_uri, item_matches_uri_decrypted, registrable_domain, uri_host, uri_matches,
    UriMatchType,
};
pub use vault_api::{normalize_server_url, ApiError};
pub use vault_api::{
    parse_callback_params, parse_duo_callback, selectable_two_factor_providers,
    two_factor_provider_name, TWO_FACTOR_AUTHENTICATOR, TWO_FACTOR_DUO, TWO_FACTOR_EMAIL,
    TWO_FACTOR_ORG_DUO, TWO_FACTOR_U2F, TWO_FACTOR_WEBAUTHN, TWO_FACTOR_YUBIKEY,
};
pub use vault_crypto::KdfParams;
pub use webauthn::{
    assertion_token as webauthn_assertion_token, client_data_json as webauthn_client_data_json,
    is_supported as webauthn_supported, parse_request as webauthn_parse_request,
    perform_assertion as webauthn_perform_assertion, WebAuthnAssertion, WebAuthnError,
    WebAuthnRequest,
};
