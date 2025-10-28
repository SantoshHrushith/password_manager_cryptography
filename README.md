# Secure Password Vault — Local AES-encrypted password manager

This is a simple local password vault implemented in Python that derives an AES key from a master password (PBKDF2) and stores credentials encrypted with AES-GCM. The vault file has a SHA-256 hash stored alongside it to detect tampering.

Files created:
- `vault.py` — main CLI program (init, add, view, list, verify)
- `requirements.txt` — Python dependency list
- `README.md` — this file
- `REPORT.md` — final report for submission

Quick start
1. Create a virtual environment and install dependencies:

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2. Initialize salt (creates `salt.bin`):

```powershell
python vault.py init
```

3. Use the CLI:

Add credential:
```powershell
python vault.py add
```

View credential:
```powershell
python vault.py view
```

List sites:
```powershell
python vault.py list
```

Verify vault integrity:
```powershell
python vault.py verify
```

Notes
- The master password is never stored. If you forget it, stored credentials cannot be recovered.
- The vault is `vault.json` and its integrity hash is stored in `vault.json.sha256`.
