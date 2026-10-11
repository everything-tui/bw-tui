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

Environment overrides (when supported by the CLI):

| Variable | Purpose |
| --- | --- |
| `VAULTWARDEN_URL` | Server base URL (default for E2E: `http://127.0.0.1:8080`) |
| `E2E_EMAIL` / `E2E_PASSWORD` | Integration test credentials |

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
| `Ctrl+n` | New folder |
| `?` | Help |
| `q` | Quit |

Press `?` in the app for the full map. Use `--mock` for UI-only demos without a server.

## Security notes

- Master passwords and decrypted secrets stay in process memory only for the session; quit the app when finished.
- “Remember server & email” stores the server URL, email (`login.json`), and a refresh token (`auth.json`) so the next launch opens the unlock screen. The master password is never written to disk.
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
