//! Vault session: login, unlock, sync, decrypt, CRUD, clipboard.

mod clipboard;
mod decrypt;
mod domains;
mod error;
mod export;
mod fingerprint;
mod generator;
mod models;
mod paths;
mod pin;
mod policies;
mod reports;
mod secure_storage;
mod send_crypto;
mod session;
mod ssh_agent;
mod uri_match;
mod vault_cache;

pub use clipboard::ClipboardService;
pub use error::{Result, SessionError};
pub use export::{
    export_csv, export_encrypted_json, export_json, import_bitwarden_json, import_encrypted_json,
    EncryptedExport, ImportBundle,
};
pub use fingerprint::fingerprint_phrase_from_public_der;
pub use generator::{
    generate_passphrase, generate_passphrase_opts, generate_password, generate_password_checked,
    generate_username_catchall, generate_username_plus_address, generate_username_word,
    password_entropy_bits, password_entropy_for_string, password_strength_label, GeneratorOptions,
    PassphraseOptions,
};
pub use models::*;
pub use paths::{app_data_dir, ensure_dir, profile_dir, profiles_dir, profiles_file, write_atomic};
pub use pin::{
    clear_pin, pin_configured, random_numeric_pin, store_pin_wrapped_key, unlock_with_pin,
    MAX_PIN_FAILURES,
};
pub use domains::{parse_domains, VaultDomains};
pub use policies::{
    apply_generator_policy, generator_policy, parse_policies, send_policy, GeneratorPolicy, Policy,
    PolicyType, SendPolicy,
};
pub use reports::{
    build_health_report, find_duplicate_items, find_reused_passwords, find_unsecured_http,
    find_weak_passwords, hibp_password_pwned_count, DuplicateItemGroup, HibpError,
    ReusedPasswordGroup, UnsecuredHttpEntry, VaultHealthReport, WeakPasswordEntry,
};
pub use secure_storage::{
    with_refresh_token_store_for_tests, FailingRefreshTokenStore, MemoryRefreshTokenStore,
    RefreshTokenStore,
};
pub use send_crypto::{
    decode_send_key_material, derive_send_key, encode_send_key, encrypt_send_meta,
    encrypt_send_text, generate_send_key_material,
};
pub use session::{
    plaintext_token_allowed, totp_display_from_secret, totp_from_secret, LoginResult, Session,
    SessionStatus, TotpDisplay,
};
pub use ssh_agent::{
    add_keys_to_agent, agent_socket_path, default_agent_socket_hint, parse_ssh_key_item,
    start_agent_with_keys, ssh_add_instructions, ParsedSshKey, SshAgentHandle,
};
pub use uri_match::{
    item_matches_uri, item_matches_uri_decrypted, registrable_domain, uri_host, uri_matches,
    UriMatchType,
};
pub use vault_api::normalize_server_url;
