# Changelog

## Unreleased

### Changed

- Help overlay (`?`) groups shortcuts by context (Global, Login, 2FA, Vault, …) with `j`/`k` scroll
- TUI New Send is a Quick create overlay (content + optional password; `Enter` saves; auto name). Tab to **Advanced…** (or `a` before typing) for the full field list; edit (`e`) still opens the full form
- With the left sidebar focused, `s` opens Quick New Send; with items/detail focused, `s` still cycles sort

### Added

- Feature-gap roadmap P0–P5: themes/keybinds, Sends+receive, zxcvbn/health/revision sync, multi-format import/export, timeout/sleep lock + org policies, org share/bulk, 2FA picker + account tools, power-user TUI (QR/editor/autotype/toasts/watchtower/domain rules), CLI unlock daemon / serve / CRUD / completions
- Full Sends: file Sends (client-side encrypted upload via `POST /sends/file/v2`, direct + Azure upload types), password protection (PBKDF2-SHA256, 100k iterations, send key as salt), max access count, expiration/deletion dates (default deletion 7 days, max 31), hide email (respects org policy), disable, notes; TUI Send form + detail pane expanded; `Session::{create_send, create_file_send, update_send}`
- Receive a Send: `POST /sends/access/{id}` (+ file download endpoint), decrypt with the URL-fragment key (HKDF salt `bitwarden-send`); TUI "Open Send link" overlay (`O` / palette) and CLI `receive <url>` (works without a saved session)

## [0.1.0] - 2026-10-12

### Added

- Full Sends and receive (see Unreleased for continuing work)
- Sync includes equivalent/global domains (no `excludeDomains`); stored on `Session` for URI matching
- Org policies parsed on sync; generator clamping in TUI/CLI (`generate --apply-org-policy`); Send create blocked when disabled
- TUI generator: password / passphrase / username modes, strength meter, `avoid_ambiguous`, min numbers/special
- Health report opt-in HIBP counts (`h` in overlay; network only)
- CLI `get --uri`; git-credential uses full URI + equivalent domains
- Passkeys (FIDO2): `login.fido2Credentials` metadata (site, user, discoverable, created) shown in item detail; private key material is never decrypted; credentials are preserved verbatim on edit; clone warns that passkeys are not copied
- Password strength via `zxcvbn` (score 0–4, warnings) in health report weak-password detection and the generator meter; `generate_password_min_score`
- Health report: old passwords (>1 year), expired / expiring cards, inactive 2FA (built-in domain list + optional `2fa-directory.json` dataset in the data dir), opt-in HIBP email breach lookup (`BW_TUI_HIBP_API_KEY`)
- Faster sync: `GET /accounts/revision-date` probe (`Session::sync_if_changed`); TUI polls it every `[sync] revision_poll_seconds` (default 60) and only full-syncs on change. SignalR push not implemented (documented)
- Search operator `url: / `uri:`; default background sync interval 5 minutes

### Security

- Enforce master-password re-prompt before reveal / secret copy / edit when an item has `reprompt`
- Removed leftover agent debug keystroke logger that could record master-password characters
- Fixed Argon2 `kdfMemory` unit (API MiB → Argon2 KiB) and enforced KDF min/max bounds
- Favorite toggles use `/ciphers/{id}/partial` to avoid wiping custom fields / history
- Login edits preserve raw cipher fields and append password history on password change
- Org/login edits use resolved cipher keys when org keys are available (partial/metadata preserved)
- Atomic `0600` writes for auth/cache/profiles; clipboard clear on lock; panic terminal restore

### Fixed

- Send crypto matches official `makeSendKey` (HKDF salt `bitwarden-send`, info `send`, 16-byte material wrapped with user key)
- Encrypted JSON import (`import_encrypted_json` / CLI `import --password`)
- URI match type 4 (regex) implemented
- TOTP countdown uses real period/remaining; support `steam://` and `otpauth://` secrets
- `verify_reprompt` uses the account KDF (not default PBKDF2)
- Failed unlock no longer leaves a wrong master key in memory
- `register_finish` no longer treats "already/taken" as success
- `set_tokens(..., None)` clears the refresh token
- SSH key cipher model, EncString types 5/6, unicode subtitle truncation

### Added

#### Vault / session

- Custom fields + password history decrypt/display; full identity address fields
- URI match helpers (domain/host/startsWith/exact) and equivalent-domain grouping
- Vault health reports (reused / weak / http / duplicates; optional HIBP)
- Export JSON / CSV / encrypted JSON + Bitwarden JSON import
- Bitwarden Send crypto helpers + API create/update/delete/list models
- Attachment download URL helpers + typed `CipherAttachment`
- Policy parsing (`parse_policies`) for generator / send policies
- EFF large wordlist (7776) passphrase generator with capitalize / include-number
- Username generators (word, plus-address, catch-all)
- SSH agent (Unix): local `ssh-agent` socket under the profile dir, loads vault SSH keys via `ssh-add`; stop on lock
- Master password change (`POST /accounts/password`) with local re-wrap of the user key
- Account overlay: configure/clear PIN unlock, change master password form
- Configurable clipboard auto-clear (per profile)
- API-key login (`Session::login_api_key`) and email 2FA resend

#### TUI

- Master-password re-prompt overlay; reprompt toggle on login form
- New-item type picker (login / note); folder rename/delete when folders focused
- Passphrase mode in generator; API-key login fields; resend email 2FA
- Expanded detail view (card/identity/SSH) with more copy keys
- Command palette (`:` / Ctrl+k), password history (`H`), health report (`R`)
- Custom field copy `1`–`9`; nested folder sidebar labels; search operators
- OSC 52 clipboard fallback; `config.toml` (theme / generator defaults)
- 2FA remember-device checkbox; persisted device token in profile `auth.json`
- Sidebar: My vault, orgs, collections, Sends; org labels on items; org edit blocked message
- Attachment names in detail; download/upload/delete; download to profile `downloads/`
- Sends: edit/delete (`e`/`d`), copy share link (`L`); org login edit when key resolves
- Account overlay (`,`) — fingerprint, password hint, change master password, PIN set/clear, SSH agent toggle
- PIN unlock on lock screen (Tab/`p` when `pin.key` configured); lockout after failures
- macOS Touch ID quick unlock: not implemented; use PIN unlock for faster re-entry
- Status bar sync age (`Synced Nm ago`); optional background sync via `[sync] background_interval_minutes`
- Sends list + text Send create; card create form; expanded new-item picker; clone (`Shift+C`)
- Edit all personal cipher types (login/note/card/identity/SSH); multi-URI login form with match types
- Move to folder (`Shift+M`); session `update_*` APIs with raw cipher round-trip

#### CLI

- `--json`; `list --search/--folder/--type`; fuzzy `get` with ambiguous-match error
- `generate`, `totp`, `delete`, `export`, `import`, `git-credential`, `askpass`

- CI (fmt/clippy/test) and Vaultwarden integration workflow
- Offline vault cache improvements and profile auto-lock (prior work)
