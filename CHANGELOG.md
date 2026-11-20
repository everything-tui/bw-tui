# Changelog

## [0.2.1] - 2026-11-19

### Modified

- Behind-the-scenes improvements to reliability: updated the libraries bw-tui uses for encryption, networking and drawing the screen

## [0.2.0] - 2026-11-19

### Added

- **Sends are complete**:
  - Share files, not just text. Files are encrypted on your computer before they are uploaded
  - Protect a Send with a password, limit how many times it can be opened, and choose when it expires or is deleted (after 7 days by default, at most 31)
  - Hide your email address from recipients, turn a Send off, and add private notes
- **Open Sends that others share with you**: press `o` in the Sends view, or run `bw-tui receive <url>`. The command works without logging in
- Lock the vault automatically after a period of inactivity or when your computer goes to sleep. Your organization's policies are respected
- Import from and export to more password-manager formats
- Share items with an organization and act on several items at once
- Choose which two-step login method to use when signing in, plus more account tools
- Show a login as a QR code, edit notes in your own text editor, auto-type logins into other apps, and see short pop-up notifications
- Command line: stay unlocked between commands, create, edit and delete items, and use tab completion in your shell

### Modified

- **New look**: pane borders are gone. Each column has its own background shade, and a header bar shows where you are, sync status, the auto-lock timer and your profile. Also:
  - The status bar shows the current mode and the keys you can press
  - The item list has colored letter icons, an always-visible search bar and neatly aligned details
  - The detail pane shows each field's label above its value, with the key to copy it. Two-step login codes are grouped with a countdown
  - Dialogs float over a dimmed background, with filled input fields and ◉/○ toggles
  - The password generator colors the password and shows a strength meter. The health report shows summary tiles
  - Login, unlock and two-step login screens are centered
- **Themes**: choose from 12 built-in themes (default, Catppuccin Mocha/Latte, Tokyo Night, Rosé Pine, Gruvbox, Dracula, Nord, Bitwarden, Solarized, light, high-contrast):
  - `Ctrl+t` opens a picker that previews each theme live and remembers your choice
  - Change any single color under `[colors]` in `config.toml`
  - `transparent_background = true` lets your terminal's background show through
- Themes now color every screen. Before, changing `theme` only affected a few parts of the app
- Mouse clicks now always land on what you see on screen
- **New, more consistent shortcuts** (see README → Keybindings):
  - `g` starts a "go to" shortcut with a hint popup: `g g` top, `g f` favorites, `g t` trash, `g s` Sends. `G` jumps to the bottom. The password generator moved from `g` to `P`
  - `Enter` goes deeper (folders → items → details → edit) and `Esc` goes back. The detail pane scrolls with `j`/`k`
  - Copy shortcuts for cards, SSH keys, notes and custom fields (`m v x p b o 1–9`), plus `F` and `A`, now also work from the item list
  - Undo delete is now `U`, so `u` always copies the website. `s` always changes the sort order. Create a new Send with `n` in the Sends view or from the command palette
  - In the Sends view, `c` copies the link and `o` opens a link someone sent you. Before, the shortcut for opening a link didn't work
  - Attachments: press `V` to open the attachment list, then `d` to delete or `a` to upload. This replaces `Ctrl`+number shortcuts, which most terminals don't support
  - `q` now asks you to press it a second time to quit while your vault is unlocked, instead of refusing to quit
  - In search, `Ctrl+n` / `Ctrl+p` move through results and `Ctrl+u` clears what you typed
- The status bar shows the keys you can press on the current screen
- The command palette lists every action with its shortcut and runs it directly. Before, many entries only said "use the keyboard shortcut". You can also search it by key name, and it scrolls past the first page
- The help screen always matches your current shortcuts and shows the current screen's keys first
- Creating a Send is quicker: type the content, optionally add a password and press `Enter`. A name is filled in for you. Choose **Advanced…** (`Tab`, or `a` before typing) for all options. Editing a Send (`e`) still opens the full form

### Fixed

- Custom shortcuts under `[keybindings]` in `config.toml` were ignored. They now work everywhere: the vault, command palette, help screen and key hints. Upper and lower case are different keys (`c` is not `C`), and one action can have several keys

## [0.1.0] - 2026-10-12

### Added

- **Browsing your vault**:
  - The sidebar shows My vault, your organizations, collections and Sends, with nested folders. Items show which organization they belong to
  - See every detail of logins, secure notes, cards, identities (including the full address) and SSH keys, with custom fields and password history (`H`)
  - Create, edit and clone items (`Shift+C`) and move them to another folder (`Shift+M`). A login can have several websites, each with its own matching rule
  - Edit organization items you have access to. Items you can't edit tell you so
  - Rename and delete folders
  - See, download, upload and delete attachments. Downloads are saved in your profile's `downloads/` folder
  - Passkeys saved on a login appear in its details and are kept when you edit it. Cloning a login warns you that passkeys are not copied
- **Finding things**:
  - Search filters, including `url:` / `uri:` to find items by website
  - A command palette (`:` or `Ctrl+k`) to run any action by name
- **Copying**:
  - Copy custom fields with `1`–`9`, plus more copy keys for cards, identities and SSH keys
  - Copying also works when you use bw-tui on a remote machine, for example over SSH
  - The clipboard clears itself after a delay you choose, per profile
- **Password generator**:
  - Create passwords, passphrases (optionally capitalized and with a number) and usernames (random word, plus-address or catch-all email)
  - A strength meter with tips, an option to avoid look-alike characters, and minimum numbers and symbols
  - Set `generate_password_min_score` in `config.toml` to only accept strong generated passwords
  - Follows your organization's password rules. On the command line, use `generate --apply-org-policy`
- **Health report** (`R`):
  - Finds reused, weak, old (over a year) and duplicate passwords, and websites without HTTPS
  - Finds cards that have expired or expire soon, and websites where you could turn on two-step login
  - Optionally checks whether your passwords appeared in known data breaches (press `h`, needs internet)
  - Optionally checks whether your email appeared in data breaches (set `BW_TUI_HIBP_API_KEY`)
- **Sends**: create text Sends, edit (`e`) and delete (`d`) them, and copy the share link (`L`). Sends are blocked if your organization doesn't allow them
- **Signing in and unlocking**:
  - Log in with an API key, resend the two-step login email, and tick "remember this device" so you aren't asked for a code every time
  - Unlock with a PIN instead of your master password (`Tab` or `p` on the lock screen). Too many wrong PINs lock it
  - Turn on "master password re-prompt" for an item when editing it
  - Account screen (`,`): see your fingerprint phrase and password hint, change your master password, set or remove your PIN, and turn the SSH agent on or off
- **SSH agent** (macOS and Linux): use the SSH keys stored in your vault with `ssh`. The keys are removed when the vault locks
- **Syncing**:
  - The status bar shows when you last synced (for example `Synced 5m ago`)
  - The vault syncs in the background every 5 minutes. Change it with `[sync] background_interval_minutes`
  - Every minute, bw-tui checks whether anything changed and only downloads the vault when it did. Change it with `[sync] revision_poll_seconds`
- Websites that belong together count as one when matching logins, for example a google.com login also matches youtube.com
- **Import and export**: export to JSON, CSV or password-protected JSON. Import Bitwarden JSON files, including password-protected ones (`import --password`)
- **Command line**:
  - `--json` output for scripts
  - `list` with `--search`, `--folder` and `--type`
  - `get` finds items by approximate name, or by website with `--uri`. It tells you when several items match
  - `generate`, `totp`, `delete`, `export` and `import`
  - Use bw-tui as a Git credential helper (`git-credential`) and as a password prompt for other tools (`askpass`)
- Use your vault offline from a local copy. Each profile locks itself automatically
- Set your theme and generator defaults in `config.toml`

### Fixed

- Two-step login codes show the correct time left, and Steam Guard and `otpauth://` codes are supported
- Sends created in bw-tui now open correctly in the official Bitwarden apps
- Importing password-protected JSON exports now works
- Logins that use the "regular expression" website matching rule now match
- Master password re-prompt now works for accounts with non-default security settings
- A wrong master password no longer causes problems on the next unlock attempt
- Creating an account no longer reports success when the email address is already taken
- Signing out now fully forgets your login
- SSH key items, items saved in older formats, and long names with special characters now display correctly
- Marking an item as favorite no longer erases its custom fields or password history
- Editing a login keeps fields that bw-tui doesn't show, and changing a password saves the old one in password history
- Editing organization items no longer risks losing data
- If bw-tui crashes, your terminal goes back to normal

### Security

- Items with "master password re-prompt" now always ask for your master password before showing, copying or editing secrets
- Removed a leftover debug log that could record parts of your master password as you typed it
- Unlocking now works with Argon2 account security settings, and unsafe security settings sent by a server are rejected
- Saved login, cache and profile files can only be read by your user account, and are never left half-written
- The clipboard is cleared when the vault locks
