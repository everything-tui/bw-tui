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
profiles.json                 # registry + active profile
profiles/<id>/auth.json       # profile auth metadata (refresh token prefers OS keychain)
```

Older installs with a flat `login.json` / `auth.json` are migrated once into profile `default`.

## Keybindings (summary)

| Key | Action |
| --- | --- |
| `/` | Fuzzy search |
| `j` / `k` or `↓` / `↑` | Move selection |
| `Tab` / `h` / `l` | Cycle pane focus |
| `c` / `y` / `t` / `u` | Copy password / username / TOTP / URI |
| `n` / `e` / `d` / `f` | New / edit / delete / favorite |
| `g` | Password generator |
| `Ctrl+s` | Sync vault |
| `Ctrl+l` | Lock |
| `Ctrl+p` | Profile manager |
| `e` | Edit selected profile (in profile manager) |
| `L` | Toggle lock-on-switch (in profile manager) |
| `Ctrl+o` | Sign out current profile (unlock) |
| `Ctrl+n` | New folder |
| `?` | Help |
| `q` | Quit |

Press `?` in the app for the full map. Use `--mock` for UI-only demos without a server.

## Security notes

- Master passwords and decrypted secrets stay in process memory only for the session; quit the app when finished.
- “Remember” stores the profile’s server URL and email in `profiles.json`, plus auth metadata in `profiles/<id>/auth.json`. The refresh token is stored in the **OS secure store** (macOS Keychain / Windows Credential Manager / Linux Secret Service) when available, with a plaintext disk fallback if secure storage fails—same model as the official Bitwarden desktop client. The master password is never written to disk.
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
