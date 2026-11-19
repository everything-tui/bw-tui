# bw-tui

Terminal UI client for [Vaultwarden](https://github.com/dani-garcia/vaultwarden) (Bitwarden-compatible password manager API). Browse vault items, copy credentials, and manage a local session from the terminal.

## Install

### Homebrew (macOS / Linux)

```bash
brew install everything-tui/tap/bw-tui
```

Update later with `brew upgrade bw-tui`.

### Installer scripts

```bash
# Linux / macOS
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/everything-tui/bw-tui/releases/latest/download/bw-tui-installer.sh | sh
```

```powershell
# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -c "irm https://github.com/everything-tui/bw-tui/releases/latest/download/bw-tui-installer.ps1 | iex"
```

The installers place the `bw-tui` binary on your `PATH` (under `CARGO_HOME` by default).

### Prebuilt binaries

Every [GitHub Release](https://github.com/everything-tui/bw-tui/releases) has these archives. Each comes with a `.sha256` checksum:

| Platform | Archive |
|---|---|
| macOS, Apple Silicon | `bw-tui-aarch64-apple-darwin.tar.xz` |
| macOS, Intel | `bw-tui-x86_64-apple-darwin.tar.xz` |
| Linux x86_64 (glibc) | `bw-tui-x86_64-unknown-linux-gnu.tar.xz` |
| Linux arm64 (glibc) | `bw-tui-aarch64-unknown-linux-gnu.tar.xz` |
| Linux x86_64 (static, musl) | `bw-tui-x86_64-unknown-linux-musl.tar.xz` |
| Linux arm64 (static, musl) | `bw-tui-aarch64-unknown-linux-musl.tar.xz` |
| Windows x86_64 | `bw-tui-x86_64-pc-windows-msvc.zip` |
| Windows ARM64 | `bw-tui-aarch64-pc-windows-msvc.zip` |

The musl builds are fully static, so they run on any Linux distribution, including Alpine and old glibc systems. Pick them if the glibc build fails with a `GLIBC_x.y not found` error.

### Build from source

You need the stable Rust toolchain from [rustup](https://rustup.rs). Then, from the repository root:

```bash
cargo install --path crates/bw-tui --locked
```

That puts `bw-tui` in `~/.cargo/bin`. To get just the binary in `target/release/bw-tui` instead, run `cargo build --release`.

Prerequisites for each platform:

**macOS**

```bash
xcode-select --install
```

**Linux (Debian / Ubuntu)**

```bash
sudo apt install build-essential pkg-config libssl-dev
```

On Fedora: `sudo dnf install gcc pkgconf-pkg-config openssl-devel`. On Arch: `sudo pacman -S base-devel openssl`.
Auto-type also needs `xdotool` (X11) or `wtype` (Wayland) at runtime.

**Linux, static musl binary**

OpenSSL is compiled from source automatically, so you need `perl` and `make` but no `libssl-dev`:

```bash
sudo apt install musl-tools perl make
```

```bash
rustup target add x86_64-unknown-linux-musl
```

```bash
cargo build --release --target x86_64-unknown-linux-musl
```

Binary: `target/x86_64-unknown-linux-musl/release/bw-tui`. On arm64, use `aarch64-unknown-linux-musl`.

**Windows**

Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) and select the "Desktop development with C++" workload. Then run `cargo build --release` in PowerShell. Binary: `target\release\bw-tui.exe`.

To build for Windows ARM64, also install the "MSVC ARM64 build tools" component, then run:

```powershell
rustup target add aarch64-pc-windows-msvc
cargo build --release --target aarch64-pc-windows-msvc
```

### Platform support

The core TUI (browse, search, edit, copy, Sends) works on every platform. These features depend on the OS:

| Feature | macOS | Linux | Windows |
|---|---|---|---|
| Background agent (stays unlocked between runs) | ✅ | ✅ | ❌ |
| SSH agent integration | ✅ | ✅ | ❌ |
| Lock on system sleep | ✅ | ✅ (needs D-Bus) | ❌ |
| Auto-type | ✅ (`osascript`) | ✅ (`xdotool` / `wtype`) | ❌ |
| Biometric unlock (`biometric` feature) | ✅ | ❌ | ❌ |

## Run against Vaultwarden

1. Point the client at your server (local Docker or self-hosted):

   ```bash
   # Example: local Vaultwarden from docker/compose.yml
   ./target/release/bw-tui --server http://127.0.0.1:8080
   ```

2. Sign in with your Vaultwarden email and master password when prompted.

### Named profiles

Use named profiles (e.g. `work`, `home`) so each account has its own server, email, and remembered session:

```bash
./target/release/bw-tui --profile work
./target/release/bw-tui --list-profiles
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

Under the app data directory (`~/Library/Application Support/com.everything-tui.bw-tui/` on macOS, `~/.local/share/bw-tui/` on Linux):

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
bw-tui login --email you@example.com --server https://vault.example.com
bw-tui unlock          # prints: export BW_SESSION="…"
bw-tui lock
bw-tui logout
bw-tui config server https://vault.example.com
bw-tui encode 'hello' # base64 ( --decode reverses )
bw-tui serve --port 8087   # localhost REST API; token printed or BW_SERVE_TOKEN

# Vault
bw-tui --profile work status
bw-tui --json list --search github --type login
bw-tui list --format template --template '{name}\t{username}'   # fzf / rofi friendly
bw-tui get "GitHub" --field password
bw-tui get --uri https://github.com/login --field password
bw-tui create item '{"type":1,"name":"Site","login":{"username":"u","password":"p"}}'
bw-tui edit item Site '{"login":{"password":"new"}}'
bw-tui restore "Old item"
bw-tui move "Site" "Work"
bw-tui share "Site" "My Org" --collection "Shared"
bw-tui totp "GitHub"
bw-tui generate --length 24
bw-tui generate --apply-org-policy   # unlock + clamp to org generator policy
bw-tui sync
bw-tui export backup.json --format json
bw-tui export vault.zip --format zip
bw-tui export encrypted.json --encrypted --password 'export-pass'
bw-tui import backup.json
bw-tui import chrome.csv --format chrome-csv
bw-tui delete "Old item"
# Sends (create/list need an unlocked session; receive needs no login at all):
bw-tui send create "text body" --name Note --password pw --max-access 3 --delete-in 2d --hide-email
bw-tui send create --file ./report.pdf --name Report --expires 12h
bw-tui send list
bw-tui receive 'https://vault.example.com/#/send/<id>/<key>' [--password pw] [-o dir-or-file]
# Shell integration
bw-tui completions zsh > ~/.zfunc/_bw-tui
bw-tui man | mandoc -Tascii | less
# git / SSH helpers (after unlock):
git -c credential.helper='!bw-tui git-credential' clone …
BW_PASSWORD=… bw-tui askpass --prompt 'user@host'
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
docker volume rm bw-tui-vw-data
```

## Versioning & releases

The version lives in three places that must always match:

- the top heading of `CHANGELOG.md`: `## [X.Y.Z] - YYYY-MM-DD` (no `## Unreleased`)
- `[workspace.package] version` in `Cargo.toml` (all crates inherit it)
- the `bw-tui` entry in `Cargo.lock` (run `cargo update --workspace` after a bump)

Check them locally:

```bash
scripts/version.sh check
```

Versions stay on `0.x.y`: a fix-only batch bumps the patch, anything with new or changed behavior bumps the minor. Sections are `Added`, `Modified`, `Fixed`, `Removed` (and `Security`).

**Branches**

- `main`: day-to-day work. Every PR runs the `Validate Version` check above.
- `publish`: release branch. A PR into `publish` also fails if the version already has a release or isn't newer than the latest one.

**Cutting a release**

1. Make sure the top CHANGELOG entry and `Cargo.toml` have the new version (`scripts/version.sh check`).
2. Open a PR from `main` into `publish` and merge it.
3. `Create Release` runs on the push to `publish`, validates the version and starts `Release` with tag `vX.Y.Z`. If that version is already released, it does nothing.
4. `Release` (cargo-dist) builds all 8 targets, creates the tag and the GitHub Release with archives, checksums and installers, and pushes the Homebrew formula.
5. `Release notes` then rewrites the release page:
   - title: `X.Y.Z - YYYY-MM-DD`
   - every CHANGELOG entry since the previous release
   - install commands and a downloads table
   - a compare link and a link to the full CHANGELOG

Preview the release page text locally:

```bash
scripts/version.sh body
```

The release workflow (`.github/workflows/release.yml`) is generated by cargo-dist. Change `dist-workspace.toml` and run `dist generate` instead of editing it by hand.

## Workspace layout

| Crate | Role |
| --- | --- |
| `vault-crypto` | KDF, AES, key wrapping |
| `vault-api` | HTTP client / models |
| `vault-session` | Session & sync |
| `bw-tui` | Ratatui frontend (`bw-tui` binary) |

## License

MIT
