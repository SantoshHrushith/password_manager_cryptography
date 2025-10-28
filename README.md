# Secure Password Vault (local)

A small local password manager that stores encrypted credentials in `vault.json` using AES-GCM. The project derives a 32-byte key from your master password using PBKDF2-HMAC-SHA256 and protects integrity with a SHA-256 digest file.

## What's new in this version
- Unified, consistent terminal UI using `render_screen()` for all screens (Menu / Add / Search / Site view / Reveal / Change master).
- Add flow supports cancellation (`b`) and uses the same UI layout as the menu.
- Edit and Delete actions available after revealing a credential (requires re-entering the master password to reveal). Edits re-encrypt with the entered master; deletions remove the entry and clean up empty sites.
- Vault integrity: `vault.json.sha256` is kept in sync with the vault and verified on load.
- Atomic saves (write-to-temp + os.replace) to avoid partial writes.
- `.gitignore` added to avoid committing `vault.json`, `salt.bin`, `.venv`, etc.

## Files of interest
- `vault.py` — main program (CLI + interactive UI + crypto functions).
- `vault.json` — encrypted vault (do NOT commit).
- `vault.json.sha256` — SHA-256 digest used to verify vault integrity (do NOT commit).
- `salt.bin` — PBKDF2 salt (do NOT commit).
- `.gitignore` — ignores secrets and environment files.
- `requirements.txt` — Python dependency list (cryptography).

## Quick start (Windows PowerShell)
1. Create and activate a virtual environment (if you haven't already):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Run the interactive CLI:

```powershell
.\.venv\Scripts\python.exe vault.py cli
# or if your venv is active:
python vault.py cli
```

## CLI commands (non-interactive)
- `init` — initialize salt (creates `salt.bin`).
- `add` — non-interactive add (prompts for website, username, password).
- `view` — prompt for a site and show its credential (requires master password).
- `list` — list stored sites.
- `dump` — decrypt and print all credentials (confirmation required).
- `changepw` — change master password interactively (re-encrypts vault with new salt/key).
- `verify` — verify vault integrity (checks `vault.json.sha256`).
- `cli` — interactive UI (recommended for normal use).

## Interactive UI overview (states)
- Menu — unified UI header, commands row, numbered site list, and an instructions line.
- Add — consistent UI (title, instructions, no details area) and prompts (Website/Username/Password). You can cancel by typing `b` or leaving a field blank.
- Search — shows matching sites, select one or cancel.
- Site view — shows usernames for the site; select a username to reveal.
- Reveal — re-enter master password to reveal the credential, then choose `edit`, `delete` or `back`.
- Change master — unified UI for changing the master password; re-encrypts vault with a fresh salt.

## Security notes
- The master password is never stored; only the derived key (via PBKDF2 salt) is used to encrypt/decrypt.
- Use a strong master password. You can increase `ITERATIONS` in `vault.py` to harden against brute-force (tradeoff: unlock gets slower).
- Keep offline backups of `vault.json` and `salt.bin` (encrypted backup recommended). Do not commit them to git. The `.gitignore` added in this repo already prevents accidental commits.

## Troubleshooting
- If you get a vault integrity error, do not overwrite the vault file; restore from a backup if available.
- If you lose the master password, the vault cannot be recovered.

If you'd like, I can:
- Add a demo script that exercises the interactive states automatically.
- Add unit tests for encryption/decryption and vault IO.

Happy to adjust the UI wording, separators or add clipboard export for revealed passwords.

