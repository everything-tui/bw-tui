# bitwarden-tui

Terminal UI client for [Vaultwarden](https://github.com/dani-garcia/vaultwarden) (Bitwarden-compatible password manager API). Browse vault items, copy credentials, and manage a local session from the terminal.

## Install

### Prebuilt binaries

Download archives for Linux, macOS, and Windows from the [GitHub Releases](https://github.com/everything-tui/bw-tui/releases) page, or use an installer:

```bash
# Linux / macOS
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/everything-tui/bw-tui/releases/latest/download/vault-tui-installer.sh | sh
```

```powershell
# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -c "irm https://github.com/everything-tui/bw-tui/releases/latest/download/vault-tui-installer.ps1 | iex"
```

The installers place the `bitwarden-tui` binary on your `PATH` (under `CARGO_HOME` by default).

### Build from source

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
config.toml                   # theme, generator defaults, background sync interval, keybinding overrides
profiles.json                 # registry + active profile
profiles/<id>/auth.json       # profile auth metadata + cached KDF (refresh token prefers OS keychain)
profiles/<id>/vault.cache     # UserKey-encrypted last sync (offline unlock)
```

Older installs with a flat `login.json` / `auth.json` are migrated once into profile `default`.

## Keybindings

The vault browser follows a few rules so keys are guessable:

- **Lowercase = frequent, Shift = heavier variant, Ctrl = app-level.** `c` copies, `C` clones; `p` copies the SSH public key, `P` opens the generator.
- **One key, one meaning.** Copy keys work from any pane, and each field in the detail pane shows the key that copies it. `n` / `e` / `d` always mean new / edit / delete *the focused thing* (item, folder, or Send).
- **Enter goes in, Esc goes back.** Enter: folders → items → detail → edit. Esc: leave the pane → clear the search → clear marks.
- **Hints follow you.** The status bar shows the keys that matter for the current pane/view; `:` lists every command with its key; `?` shows the full map.

| Key | Action |
| --- | --- |
| `j` `k` / `↓` `↑` | Move (scrolls when the detail pane is focused) |
| `h` `l` / `←` `→` / `Tab` | Switch pane |
| `Ctrl+d` `Ctrl+u` / `PgDn` `PgUp` | Page |
| `g g` / `G` (also `Home` / `End`) | First / last |
| `g` then `a` `f` `l` `n` `c` `i` `k` `s` `t` | Go to All / Favorites / Logins / Notes / Cards / Identities / SSH keys / Sends / Trash (a popup lists the targets) |
| `/` | Search (`type:login`, `folder:work`, `name:foo`, `url:github.com`, …); `Ctrl+n` / `Ctrl+p` move through results, `Enter` keeps the filter |
| `c` `y` `t` `u` `o` | Copy password / username / TOTP / URI / notes |
| `m` `v` `x` · `p` `b` · `1`–`9` | Copy card number / CVC / expiry · SSH public / private key · custom field |
| `S` | Copy sequence: username → password → TOTP |
| `n` `e` `d` | New / edit / delete (folder when the Folders pane is focused, Send in the Sends view) |
| `f` `r` `Space` | Favorite / reveal secrets (15s) / mark for bulk delete or share |
| `C` `M` `O` | Clone / move to folder / share to organization |
| `U` | Undo last delete |
| `E` `F` `V` `A` `H` `Q` | Notes in `$EDITOR` / custom fields / attachments / upload attachment / password history / QR code |
| `a` `T` | Auto-type login / TOTP into the focused window |
| `s` | Cycle sort: name / recently used / modified |
| `r` `X` (Trash) | Restore / empty trash |
| `c` `o` (Sends) | Copy Send link / open a received Send link |
| `P` `R` `D` `,` | Generator / health report / domain rules / account settings |
| `Ctrl+t` | Change theme (live preview) |
| `Ctrl+s` `Ctrl+l` `Ctrl+n` `Ctrl+p` | Sync / lock / new folder / profiles |
| `:` or `Ctrl+k` | Command palette (every command, with its key) |
| `?` | Help |
| `q` | Quit (press twice while a live vault is unlocked) |

Login: `Ctrl+h` show password · `Ctrl+r` remember · `Ctrl+a` API-key login · `F1` help. Unlock: `Tab` PIN · `Ctrl+o` sign out. Forms: `Tab` fields · `Ctrl+s` save · `Ctrl+g` generate · `Ctrl+e` `$EDITOR` · `Esc` cancel.

### Rebinding keys

Vault-browser keys can be changed in `config.toml`. `keys` takes one or more keys separated by spaces, or `none` to unbind. A key you assign is taken away from whichever default had it:

```toml
[[keybindings.overrides]]
action = "open_generator"
keys = "g F2"            # the go-to prefix loses `g`

[[keybindings.overrides]]
action = "quit"
keys = "Ctrl+q"
```

Action names are the snake_case form of the palette entries (`copy_password`, `toggle_favorite`, `goto_prefix`, `receive_send`, …). Conflicts and unknown names are reported as warnings at startup.

## Themes

The interface is drawn in layers rather than boxes. The sidebar, header and status bar sit on the darkest tone, the item list on the middle tone, and the detail pane on the lightest. Popups float on a dimmed backdrop. Every color comes from the active theme.

**Switch live:** press `Ctrl+t` (or pick *Change theme* in the `:` palette). Moving through the list previews each theme immediately; `Enter` keeps it and saves it to `config.toml`, `Esc` reverts.

Built-in themes: `default` (violet), `catppuccin-mocha`, `catppuccin-latte`, `tokyo-night`, `rose-pine`, `gruvbox`, `dracula`, `nord`, `bitwarden`, `solarized`, `light`, `high-contrast`.

```toml
theme = "tokyo-night"
transparent_background = false   # true: let the terminal background show through the panes

[colors]                         # optional: override any token of the chosen theme
accent = "#ff79c6"
surface = "30, 32, 48"           # hex or "r, g, b"
```

Tokens you can set under `[colors]`:

| Group | Tokens |
| --- | --- |
| Surfaces (back → front) | `mantle`, `base`, `surface`, `overlay`, `backdrop` |
| Text | `text`, `subtext`, `muted` |
| Accent & selection | `accent`, `accent_fg`, `accent_dim`, `select_bg`, `select_bg_idle`, `border`, `border_focused` |
| Status | `danger`, `success`, `warning`, `info`, `favorite` |
| Item types | `login`, `note`, `card`, `identity`, `ssh` |
| Revealed passwords | `digit`, `symbol` |

Overrides and `transparent_background` stay applied when you switch themes. `NO_COLOR` gives a monochrome UI, and `BW_ASCII=1` swaps the Unicode glyphs for ASCII.

### Scripting CLI

Sign in once via the TUI or `login`, then use subcommands. Prefer the unlock daemon so other commands reuse the session without re-entering the master password:

```bash
# Account / daemon (like BW_SESSION)
bitwarden-tui login --email you@example.com --server https://vault.example.com
bitwarden-tui unlock          # prints: export BW_SESSION="…"
bitwarden-tui lock
bitwarden-tui logout
bitwarden-tui config server https://vault.example.com
bitwarden-tui encode 'hello' # base64 ( --decode reverses )
bitwarden-tui serve --port 8087   # localhost REST API; token printed or BW_SERVE_TOKEN

# Vault
bitwarden-tui --profile work status
bitwarden-tui --json list --search github --type login
bitwarden-tui list --format template --template '{name}\t{username}'   # fzf / rofi friendly
bitwarden-tui get "GitHub" --field password
bitwarden-tui get --uri https://github.com/login --field password
bitwarden-tui create item '{"type":1,"name":"Site","login":{"username":"u","password":"p"}}'
bitwarden-tui edit item Site '{"login":{"password":"new"}}'
bitwarden-tui restore "Old item"
bitwarden-tui move "Site" "Work"
bitwarden-tui share "Site" "My Org" --collection "Shared"
bitwarden-tui totp "GitHub"
bitwarden-tui generate --length 24
bitwarden-tui generate --apply-org-policy   # unlock + clamp to org generator policy
bitwarden-tui sync
bitwarden-tui export backup.json --format json
bitwarden-tui export vault.zip --format zip
bitwarden-tui export encrypted.json --encrypted --password 'export-pass'
bitwarden-tui import backup.json
bitwarden-tui import chrome.csv --format chrome-csv
bitwarden-tui delete "Old item"
# Sends (create/list need an unlocked session; receive needs no login at all):
bitwarden-tui send create "text body" --name Note --password pw --max-access 3 --delete-in 2d --hide-email
bitwarden-tui send create --file ./report.pdf --name Report --expires 12h
bitwarden-tui send list
bitwarden-tui receive 'https://vault.example.com/#/send/<id>/<key>' [--password pw] [-o dir-or-file]
# Shell integration
bitwarden-tui completions zsh > ~/.zfunc/_bitwarden-tui
bitwarden-tui man | mandoc -Tascii | less
# git / SSH helpers (after unlock):
git -c credential.helper='!bitwarden-tui git-credential' clone …
BW_PASSWORD=… bitwarden-tui askpass --prompt 'user@host'
```

In the TUI, open **Account** (`,`) to set a PIN for quick unlock, change your master password, or start a profile-local **SSH agent** (Unix; requires `ssh-agent` / `ssh-add` on `PATH`). The agent stops when you lock the vault. Export `SSH_AUTH_SOCK` from the status line message for child shells.

Master password is read from stdin (or `BW_PASSWORD` — discouraged). Set `BW_ALLOW_PLAINTEXT_TOKEN=1` only if OS keychain is unavailable and you accept disk-backed refresh tokens.

While unlocked, the TUI keeps the vault fresh in two layers (`[sync]` in `config.toml`):

- **Revision-date polling** (default every **60** s, `revision_poll_seconds`; `0` disables): `GET /accounts/revision-date` is a tiny request. A full `/sync` only runs when the server revision changed (e.g. you edited from the browser extension), so changes from other devices show up within one poll interval. It never resets the idle auto-lock timer when nothing changed.
- **Periodic full sync** (default every **5** minutes, `background_interval_minutes`): unconditional fallback.

Real-time SignalR/WebSocket push (`/notifications/hub`, MessagePack framing) is **not implemented**; revision polling is the supported live-update path. Manual sync (`Ctrl+s`, CLI `sync`) is always a full sync.

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
