# Security Policy

## Threat model

`bitwarden-tui` is a local terminal client for Vaultwarden / Bitwarden-compatible servers.

**In scope**

- Protecting master passwords and decrypted vault secrets in process memory for the session lifetime
- Protecting refresh tokens via OS secure storage when available
- Integrity of encrypted offline vault cache (`vault.cache`)
- Not logging secrets (passwords, TOTP seeds, refresh tokens) to disk or status chrome

**Out of scope**

- Compromised OS user account / malware with memory read access
- Malicious Vaultwarden administrators (they already hold ciphertext + can dictate weak KDF)
- Physical shoulder-surfing of an unlocked TUI

## Reporting

Please open a private security advisory on the repository or email the maintainers.
Do not file public issues that include secrets or exploit details.

## Hardening expectations

- Prefer HTTPS; warn on non-localhost HTTP
- File permissions `0600` for auth/cache metadata
- Clipboard auto-clear; clear on lock/quit when still holding the copied secret
- KDF parameter minimums enforced client-side
- Panic / suspend should restore the terminal and avoid leaving secrets in scrollback
