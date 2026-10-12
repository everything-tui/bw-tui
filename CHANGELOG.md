# Changelog

## Unreleased

### Security

- Removed leftover agent debug keystroke logger that could record master-password characters
- Fixed Argon2 `kdfMemory` unit (API MiB → Argon2 KiB) and enforced KDF min/max bounds
- Favorite toggles use `/ciphers/{id}/partial` to avoid wiping custom fields / history
- Login edits preserve raw cipher fields and append password history on password change
- Block edits of organization / item-key ciphers until org-key encrypt is supported
- Atomic `0600` writes for auth/cache/profiles; clipboard clear on lock; panic terminal restore

### Fixed

- `verify_reprompt` uses the account KDF (not default PBKDF2)
- Failed unlock no longer leaves a wrong master key in memory
- `register_finish` no longer treats "already/taken" as success
- `set_tokens(..., None)` clears the refresh token
- SSH key cipher model, EncString types 5/6, unicode subtitle truncation

### Added

- CI (fmt/clippy/test) and Vaultwarden integration workflow
- Offline vault cache improvements and profile auto-lock (prior work)
