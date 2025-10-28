# Final Report — Secure Password Vault (Local AES Manager)

Project summary

This project implements a local password vault in Python. It derives an AES-256 key from a master password using PBKDF2-HMAC-SHA256 with a random salt and 200,000 iterations. Credentials (username/password) are encrypted using AES-GCM which provides confidentiality and authentication. All encrypted entries are stored in `vault.json`. A SHA-256 hash of `vault.json` is stored in `vault.json.sha256` to detect external tampering.

Design choices

- PBKDF2 with 200k iterations: balances CPU work for attackers and usability. Salt (16 bytes) prevents precomputed attacks.
- AES-GCM: provides both confidentiality and integrity (authentication tag). We use a 12-byte random IV per-encryption.
- Vault integrity: SHA-256 over the entire `vault.json` file, stored in `vault.json.sha256`. The application verifies the hash before loading the vault and after saving it.
- No external key managers: key material is derived from user-supplied master password only. Salt and vault files are stored locally.

Files

- `vault.py`: main program — supports `init`, `add`, `view`, `list`, `verify`.
- `vault.json`: created at runtime to hold encrypted credentials.
- `vault.json.sha256`: stores SHA-256 hex digest of `vault.json` for integrity checks.
- `salt.bin`: random salt used with PBKDF2.

How integrity verification works

1. After saving `vault.json`, the program computes sha256(vault.json) and writes the hex digest to `vault.json.sha256`.
2. On load, the program recomputes sha256(vault.json) and compares to the stored digest. If they differ, the program refuses to load the vault and warns the user.

Viva questions (short answers)

- Why PBKDF2? — To derive a cryptographic key from a potentially weak password while slowing brute-force attempts via iterations and using a salt to avoid rainbow tables.
- Why AES-GCM? — GCM provides authenticated encryption: both confidentiality and integrity (via the authentication tag) in a single primitive.
- What if the vault file is tampered with? — The SHA-256 digest check will detect tampering. Additionally, AES-GCM will fail decryption with an authentication tag mismatch if ciphertext or metadata changed.
- Can an attacker recover the vault if the master password is lost? — No. The key is derived from the master password and is not stored; without it the ciphertext cannot be decrypted.

How to run tests (manual quick test)

1. Add an entry
   - `python vault.py add` — provide site, username, password and master password
2. List entries
   - `python vault.py list`
3. View entry
   - `python vault.py view` — provide same master password
4. Verify integrity
   - `python vault.py verify`

Security notes & next steps

- Consider using a KDF with memory-hard properties (Argon2) for stronger resistance to GPU/ASIC attacks.
- Consider encrypting salt and hash files if storing them on untrusted media, or using file system protections.
- Add secure clipboard wiping when copying passwords to clipboard.
