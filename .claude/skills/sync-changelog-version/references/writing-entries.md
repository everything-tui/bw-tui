# Writing Changelog Entries

The CHANGELOG is copied verbatim onto the GitHub Release page. Its readers are **people who use bw-tui**, not people who read its code. Write every bullet so a regular password-manager user understands it without knowing Rust, the Bitwarden API or cryptography.

**Goal:** a user skims the release notes and can tell in seconds whether the update affects how they use the app: a shortcut moved, a bug they hit is fixed, a feature they wanted exists now. Changed or removed shortcuts, commands and settings matter most: always say what the old behavior was and what to do now.

## The one test

Before writing a bullet, ask: **"Would a user notice this while using the app?"**

| Answer | What to do |
|---|---|
| Yes: they see, press, type or feel something different | Write a bullet in plain language (rules below) |
| No, but it protects them (security fix, data-loss fix) | Write a bullet that says what risk is gone, in plain words |
| No: refactor, internal API, code cleanup, test helpers | **Leave it out** |
| The whole batch is invisible | One bullet under `### Modified`: `- Behind-the-scenes improvements to reliability` (or `…to speed` if users would feel it) |

## How to write a bullet

1. **Describe what the user experiences, not what the code does.** "Search results now appear as you type" not "Debounced search query evaluation".
2. **Start with the thing they touch**: a screen, a key, a command, a setting. "The password generator…", "Pressing `P`…", "`bw-tui get`…".
3. **Fixed bullets describe the old problem from the user's side.** "Unlocking no longer fails on some self-hosted servers" not "Handle missing `kdfMemory` in prelogin response".
4. **One change per bullet, about 25 words max.** Split long bullets. Group 4+ related bullets under a short bold lead bullet with sub-bullets (as with a redesign).
5. **Present tense, plain verbs**: "now shows", "opens", "no longer crashes", "you can now…".
6. **Say why it matters when that isn't obvious**: "…so you don't lose unsaved changes".

## Keep vs. translate

**Keep** these. Users type or see them:

- Keys: `Ctrl+t`, `g g`, `Enter`, `Esc` (always in backticks)
- CLI commands and flags: `bw-tui receive <url>`, `--json`
- Settings in `config.toml`: `theme = "nord"`, `[sync] background_interval_minutes`
- Environment variables a user sets: `BW_TUI_HIBP_API_KEY`
- Product terms users already know: vault, item, folder, Send, organization, collection, two-step login, passkey, master password, PIN

**Translate or drop** these:

| Don't write | Write instead |
|---|---|
| Endpoint paths (`POST /sends/file/v2`) | "File Sends can now be created" |
| Function/type names (`Session::sync_if_changed`, `CipherAttachment`) | What the user notices: "Syncing is faster when nothing changed" |
| Crypto details (HKDF, PBKDF2 100k iterations, EncString types) | "Password-protected Sends", "Works with more encryption settings" |
| "cipher" | "item" |
| "KDF", "Argon2" | "your account's security settings" (or drop) |
| "hit-test", "re-derive layout", "token", "struct", "parse" | Describe the visible effect, or drop |
| File names, crate names, module paths | Drop |
| "Implemented", "refactored", "plumbed" | "Added", "now", "you can" |

## Examples

| Too technical | User friendly |
|---|---|
| Faster sync: `GET /accounts/revision-date` probe; only full-syncs on change | Syncing is faster: the vault is only re-downloaded when something actually changed |
| Fixed Argon2 `kdfMemory` unit (API MiB → Argon2 KiB) | Fixed: unlocking failed for accounts using Argon2 encryption settings |
| Mouse clicks hit-test against the last drawn frame | Mouse clicks now always land on what you see on screen |
| `[keybindings]` overrides were parsed but never applied | Fixed: custom shortcuts in `config.toml` were ignored. They now work everywhere |
| Removed leftover agent debug keystroke logger | Security: removed a debug log that could record parts of your master password |
| Favorite toggles use `/ciphers/{id}/partial` | Fixed: marking an item as favorite could erase its custom fields |
