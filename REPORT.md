Project Report — Secure Password Vault (local)

Date: 2025-10-28

This report summarizes the current implementation, recent changes, design choices, and suggested next steps for the local password vault project implemented in `vault.py`.

## High-level summary
- Purpose: a small, local-only password manager that encrypts credentials with AES-GCM and derives the encryption key from a user-provided master password using PBKDF2-HMAC-SHA256.
- Storage: encrypted credentials are stored in `vault.json`. An integrity file `vault.json.sha256` stores a SHA-256 digest to detect accidental or malicious changes. The PBKDF2 salt is persisted in `salt.bin`.

## What changed (recent updates)
- Unified terminal UI: implemented `render_screen()` + `clear_screen()` and replaced ad-hoc prints with consistent screens for Menu, Add, Search, Site view, Reveal, and Change-master screens. This gives a consistent title / commands / details / instructions layout.
- Add screen improvements: Add uses `render_screen()` and now supports cancellation (type `b` or leave the field blank to cancel). The details area is suppressed when not relevant.
- Edit & Delete actions: after revealing a credential (requires re-entering master password), the user can edit or delete the entry. Edits re-encrypt using the provided confirm key. Deletions remove the entry and the site key if it becomes empty.
- Atomic vault writes: `save_vault()` writes to a temporary file then `os.replace()` to avoid partial writes. The SHA-256 digest file is updated after successful saves.
- .gitignore: added to prevent committing `vault.json`, `salt.bin`, `.venv`, etc.

## Crypto & data model (concise)
- KDF: PBKDF2-HMAC-SHA256 with ITERATIONS = 200000 (set in `vault.py`). Salt is 16 bytes stored in `salt.bin`.
- Symmetric cipher: AES-256 in GCM mode (AES-GCM) — provides confidentiality and authentication via the GCM tag. Each encrypted blob stores base64-encoded iv (12 bytes), ciphertext, and tag.
- Vault JSON shape: top-level object mapping site -> list of entries. Each entry is {"username": <encrypted blob>, "password": <encrypted blob>}. Legacy single-entry objects are normalized on load.
- Integrity: `vault.json.sha256` stores the SHA-256 hex digest of the vault file. `load_vault()` verifies the digest unless disabled.

## CLI states and flows
The interactive UI implements a clear state machine. Key states:
- Main Menu — unified screen listing sites and top-level commands (+, ?, #, q) and instructions.
- Add — form screen (no details area) for Website/Username/Password; supports cancel.
- Search — shows matching sites and lets you select or cancel.
- Site view — lists usernames for a site; select a username to reveal.
- Reveal — re-enter master password to reveal the credential, then choose `edit`, `delete` or `back`.
- Change master — verifies current master, asks for new password twice, re-encrypts the vault with a new salt.

## Usage (quick)
1. Set up a virtualenv and install the dependency in `requirements.txt` (cryptography).
2. Run `python vault.py cli` for interactive mode. Other commands are available as described in README.

## Testing and verification performed
- Manual smoke-tested interactive flows: Menu → Add → Site → Reveal → Edit/Delete.
- Verified `py_compile` on `vault.py` (syntax OK in current workspace).

## Known limitations & risk
- If the master password is lost, the vault is irrecoverable.
- `ITERATIONS` is set to 200k — reasonable for now but can be increased (slow unlock tradeoff).
- The current UI prints to the terminal; clipboard integration and secure ephemeral display are not implemented.
- No automated unit tests yet for crypto functions or file IO.

## Next recommended steps
1. Add unit tests for encrypt/decrypt, KDF, and save/load (quick pytest suite).
2. Add an automated demo script to exercise major interactive states (could use pexpect or a headless mode).
3. Consider adding an optional encrypted backup export/import command.
4. Add a "quiet" or "no-clear" flag for environments that need scrollback instead of clearing the screen.
5. Optionally support copying a revealed password to the OS clipboard using a platform-safe library and clearing it after a timeout.

If you want, I can implement items 1 or 2 next. Tell me which one to start with and I will add the files and run tests locally.

---
Report generated from the current workspace state on 2025-10-28.
