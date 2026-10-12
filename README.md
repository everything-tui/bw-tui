# bitwarden-tui

Terminal UI client for [Vaultwarden](https://github.com/dani-garcia/vaultwarden) (Bitwarden-compatible password manager API). Browse vault items, copy credentials, and manage a local session from the terminal.

## Build

```bash
cargo build --release
```

Binary: `target/release/bitwarden-tui`

## Run against Vaultwarden

1. Point the client at your server (local Docker or self-hosted):

   ```bash
   # Example: local Vaultwarden from docker/compose.yml
   ./target/release/bitwarden-tui --server http://127.0.0.1:8080
   ```

2. Sign in with your Vaultwarden email and master password when prompted.

### Named profiles

Use named profiles (e.g. `work`, `home`) so each account has its own server, email, and remembered session:

```bash
./target/release/bitwarden-tui --profile work
./target/release/bitwarden-tui --list-profiles
```

In the TUI, press **Ctrl+p** to create, edit, delete, or switch profiles. On the unlock screen, **Ctrl+o** signs out of the current profile only (other profiles keep their saved sessions).

By default, switching profiles **keeps unlocked vaults in memory** (parked) so you can switch back without re-entering the master password. Auto-lock timers keep running on parked profiles. Press **`L`** in the profile manager to toggle **lock-on-switch** (when on, leaving a profile locks and drops its session).

Each profile has its own **auto-lock** idle timeout (default **15 minutes**). Press **`e`** in the profile manager to edit name, server URL, email, and auto-lock (`1`–`1440` minutes, or `off` / `0`). The vault status bar shows `lock MM:SS` or `lock off`. Open (parked or active) vaults show an **open** badge in the list.

Environment overrides:

| Variable | Purpose |
| --- | --- |
| `BW_SERVER` | Server base URL |
| `BW_EMAIL` | Account email |
| `BW_PROFILE` | Active profile id |
| `VAULTWARDEN_URL` | Used by E2E scripts (not the CLI); default `http://127.0.0.1:8080` |
| `E2E_EMAIL` / `E2E_PASSWORD` | Integration test credentials |

### On-disk layout

Under the app data directory (`~/Library/Application Support/com.bitwarden-tui.bitwarden-tui/` on macOS, `~/.local/share/bitwarden-tui/` on Linux):

```text
config.toml                   # theme, generator defaults, background sync interval, keybinding overrides (stub)
profiles.json                 # registry + active profile
profiles/<id>/auth.json       # profile auth metadata + cached KDF (refresh token prefers OS keychain)
profiles/<id>/vault.cache     # UserKey-encrypted last sync (offline unlock)
```

Older installs with a flat `login.json` / `auth.json` are migrated once into profile `default`.

## Keybindings (summary)

| Key | Action |
| --- | --- |
| `/` | Fuzzy search (`type:login`, `folder:work`, `name:foo`, `url:github.com`, …) |
| `:` / Ctrl+k | Command palette |
| `H` | Password history for selected item |
| `R` | Vault health report |
| `1`–`9` | Copy custom field (detail pane) |
| `j` / `k` or `↓` / `↑` | Move selection |
| `Tab` / `h` / `l` | Cycle pane focus |
| `c` / `y` / `t` / `u` | Copy password / username / TOTP / URI |
| `m` / `v` / `x` / `p` / `b` / `o` | Copy card # / CVC / expiry / SSH keys / notes (detail) |
| `n` | New item (login or secure note) |
| `e` / `d` (folders pane) | Rename / delete folder |
| `Ctrl+a` (login) | Toggle password vs API-key login |
| `m` (2FA) | Resend email verification code |
| `Space` (2FA) | Remember this device (skip 2FA next login when server allows) |
| `Tab` / `p` (unlock) | Toggle master password vs PIN unlock (when PIN configured) |
| `,` | Account settings (fingerprint, password hint, change-password stub) |
| `Shift+C` | Clone selected personal item |
| `n` (Sends filter) | New text Send |
| `r` | Reveal secrets in detail (15s) / restore from trash |
| `n` / `e` / `d` / `f` | New item (login, note, card, identity, SSH) / edit / delete / favorite |
| `Shift+M` | Move selected item to folder |
| `g` | Generator (password / passphrase / username; org policy clamps options) |
| `R` → `h` | Vault health; opt-in HIBP breach counts (network) |
| `Ctrl+s` | Sync vault (status bar shows sync age, e.g. `Synced 5m ago`) |
| `Ctrl+l` | Lock |
| `Ctrl+p` | Profile manager |
| `e` | Edit selected profile (in profile manager) |
| `L` | Toggle lock-on-switch (in profile manager) |
| `Ctrl+o` | Sign out current profile (unlock) |
| `Ctrl+n` | New folder |
| `Home` / `End` / `PgUp` / `PgDn` | Jump / page selection |
| `?` | Help |
| `q` | Quit |

Press `?` in the app for the full map. Use `--mock` for UI-only demos without a server.

### Scripting CLI

After signing in once via the TUI (so a profile session exists):

```bash
bitwarden-tui --profile work status
bitwarden-tui --json list --search github --type login
bitwarden-tui get "GitHub" --field password
bitwarden-tui get --uri https://github.com/login --field password
bitwarden-tui totp "GitHub"
bitwarden-tui generate --length 24
bitwarden-tui generate --apply-org-policy   # unlock + clamp to org generator policy
bitwarden-tui sync
bitwarden-tui export backup.json --format json
bitwarden-tui export encrypted.json --encrypted --password 'export-pass'
bitwarden-tui import backup.json
bitwarden-tui delete "Old item"
# git / SSH helpers (after unlock):
git -c credential.helper='!bitwarden-tui git-credential' clone …
BW_PASSWORD=… bitwarden-tui askpass --prompt 'user@host'
```

In the TUI, open **Account** (`,`) to set a PIN for quick unlock, change your master password, or start a profile-local **SSH agent** (Unix; requires `ssh-agent` / `ssh-add` on `PATH`). The agent stops when you lock the vault. Export `SSH_AUTH_SOCK` from the status line message for child shells.

Master password is read from stdin (or `BW_PASSWORD` — discouraged). Set `BW_ALLOW_PLAINTEXT_TOKEN=1` only if OS keychain is unavailable and you accept disk-backed refresh tokens.

While unlocked, the TUI runs **periodic background sync** (default every **5** minutes via `[sync] background_interval_minutes` in `config.toml`). Real-time SignalR push is not implemented; periodic sync is the supported live-update path.

## Security notes

- Master passwords and decrypted secrets stay in process memory only for the session; quit the app when finished.
- “Remember” stores the profile’s server URL and email in `profiles.json`, plus auth metadata in `profiles/<id>/auth.json`. The refresh token is stored in the **OS secure store** (macOS Keychain / Windows Credential Manager / Linux Secret Service) when available, with a plaintext disk fallback if secure storage fails—same model as the official Bitwarden desktop client. The master password is never written to disk.
- After a successful sync, the encrypted vault payload is cached in `profiles/<id>/vault.cache` (ciphertext only; encrypted with your UserKey). On later unlocks without network, the app can decrypt that last synced state with your master password. Offline mode is **read-only** (browse/copy); create/edit/delete/favorite require connectivity. Sign-out deletes the cache.
- Prefer HTTPS and a trusted Vaultwarden instance in production. The Docker Compose stack is **dev/test only** (`SIGNUPS_ALLOWED=true`, fixed `ADMIN_TOKEN`).
- Never commit `.env`, admin tokens, or vault data volumes.
- Clipboard copies may linger in the system clipboard; clear them after use if on a shared machine.

## Docker test environment

Local Vaultwarden for development and integration tests:

```bash
# Start Vaultwarden (port 8080)
docker compose -f docker/compose.yml up -d

# Wait until healthy /alive, print test credential hints
./scripts/e2e-setup.sh

# Start (if needed) + run cargo tests
./scripts/e2e-run.sh
```

| Setting | Value |
| --- | --- |
| URL | http://127.0.0.1:8080 |
| Admin token | `dev-only-admin-token` (dev only) |
| Test password | `TestPassword123!` (created dynamically per test run) |

**Registration (Vaultwarden ≥1.37):** `POST /identity/accounts/register/send-verification-email` then `POST /identity/accounts/register/finish` with encrypted keys. With SMTP verification off, the JWT is returned directly. Shell signup is impractical; Rust integration tests register via crypto.

Stop / reset:

```bash
docker compose -f docker/compose.yml down
# optional: wipe persisted vault data
docker volume rm bitwarden-tui-vw-data
```

## Workspace layout

| Crate | Role |
| --- | --- |
| `vault-crypto` | KDF, AES, key wrapping |
| `vault-api` | HTTP client / models |
| `vault-session` | Session & sync |
| `vault-tui` | Ratatui frontend (`bitwarden-tui` binary) |

## License

MIT
