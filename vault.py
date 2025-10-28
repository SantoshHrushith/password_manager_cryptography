import os
import json
import base64
import hashlib
import argparse
from getpass import getpass
from typing import Dict, Any

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# Files and constants
SALT_FILE = "salt.bin"
VAULT_FILE = "vault.json"
VAULT_HASH_FILE = VAULT_FILE + ".sha256"
ITERATIONS = 200000


def clear_screen() -> None:
    """Clear the console screen for better UI transitions."""
    try:
        if os.name == "nt":
            os.system("cls")
        else:
            os.system("clear")
    except Exception:
        # best-effort; ignore failures
        pass


def render_screen(
    title: str,
    instructions: str | None = None,
    details: list[str] | None = None,
    commands: str | None = None,
) -> None:
    """Clear the screen and render a consistent UI screen.

    Layout produced:
      separator
      title
      separator
      commands (single-line)
      separator
      details (each on its own line)
      separator
      instructions
      hyphen-line

    All widths are computed from the longest provided element.
    """
    clear_screen()

    # leave details as None when caller didn't provide it so callers can
    # suppress the details area (useful for forms like Add where no list is shown)
    # determine width from title, commands, details and instructions
    candidates = [title]
    if commands:
        candidates.append(commands)
    if instructions:
        candidates.append(instructions)
    if details:
        candidates.extend(details)
    width = max(20, max((len(x) for x in candidates), default=20) + 4)
    sep = "=" * width

    print(sep)
    print(title)
    print(sep)

    # print details only when explicitly provided. If caller passed an empty
    # list we show a placeholder; if caller passed None, the details area is
    # omitted (useful for form screens like Add).
    if details is not None:
        if details:
            for d in details:
                print(d)
        else:
            # keep a placeholder line so layout is consistent when caller
            # intentionally passed an empty list
            print("(no items)")
    print(sep)
    if commands:
        print(commands)
    print("-" * width)

    if instructions:
        # print instructions exactly as provided
        print(instructions)
    # trailing hyphen line to visually separate from input prompt
    print("-" * width)


def generate_key(master_password: str) -> bytes:
    """Derive a 32-byte AES key from the master password using PBKDF2-HMAC-SHA256.

    Salt is stored in `salt.bin` next to the vault. If salt doesn't exist it is
    created with os.urandom(16).
    """
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
    else:
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(master_password.encode())


def encrypt_data(key: bytes, plaintext: str) -> Dict[str, str]:
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv), backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return {
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(encryptor.tag).decode(),
    }


def decrypt_data(key: bytes, data: Dict[str, str]) -> str:
    iv = base64.b64decode(data["iv"])
    ciphertext = base64.b64decode(data["ciphertext"])
    tag = base64.b64decode(data["tag"])
    decryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()
    ).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()


def compute_hash(filename: str) -> str:
    if not os.path.exists(filename):
        return ""
    sha256 = hashlib.sha256()
    with open(filename, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


def save_hash(filename: str, hash_hex: str) -> None:
    with open(filename, "w") as f:
        f.write(hash_hex)


def load_hash(filename: str) -> str:
    if not os.path.exists(filename):
        return ""
    with open(filename, "r") as f:
        return f.read().strip()


def verify_vault_hash() -> bool:
    """Return True if stored hash matches computed hash of the vault file."""
    if not os.path.exists(VAULT_FILE):
        # Nothing to verify
        return True
    computed = compute_hash(VAULT_FILE)
    stored = load_hash(VAULT_HASH_FILE)
    return stored != "" and stored == computed


def load_vault(verify: bool = True) -> Dict[str, Any]:
    if not os.path.exists(VAULT_FILE):
        return {}
    if verify and not verify_vault_hash():
        raise RuntimeError(
            "Vault integrity check failed: the stored hash does not match the vault file."
        )
    with open(VAULT_FILE, "r", encoding="utf-8") as f:
        raw = json.load(f)

    # Normalize vault format: ensure each site maps to a list of entries
    normalized: Dict[str, Any] = {}
    for site, value in raw.items():
        if isinstance(value, dict) and "username" in value:
            # old single-entry format -> convert to list
            normalized[site] = [value]
        else:
            normalized[site] = value
    return normalized


def save_vault(vault: Dict[str, Any]) -> None:
    # Atomic write: write to temporary file then replace
    tmp = VAULT_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(vault, f, indent=4)
    os.replace(tmp, VAULT_FILE)
    # Update hash after successful save
    h = compute_hash(VAULT_FILE)
    save_hash(VAULT_HASH_FILE, h)


def add_credential(key: bytes) -> None:
    # Render consistent add screen then prompt for fields
        # Render consistent Add screen
    render_screen(
        title="[+] ADD",
        instructions="Enter Website, Username and Password.[b] to cancel.",
        details=None,
        commands="[Enter details to save]",
    )
    site = input("Website (or [b]): ").strip()
    if site.lower() == "b" or site == "":
        print("Add cancelled.")
        return
    username = input("Username (or 'b' to cancel): ").strip()
    if username.lower() == "b" or username == "":
        print("Add cancelled.")
        return
    password = getpass("Password (leave blank to cancel): ")
    if password == "":
        print("Add cancelled.")
        return
    encrypted_user = encrypt_data(key, username)
    encrypted_pass = encrypt_data(key, password)
    vault = load_vault()
    # Ensure vault stores a list of entries per site
    if site in vault:
        entries = vault[site]
        # older format migration: single dict -> list
        if isinstance(entries, dict) and "username" in entries:
            entries = [entries]
        entries.append({"username": encrypted_user, "password": encrypted_pass})
        vault[site] = entries
    else:
        vault[site] = [{"username": encrypted_user, "password": encrypted_pass}]
    save_vault(vault)
    print(f"Credential for {site} saved securely.")


def view_credential(key: bytes) -> None:
    site = input("Enter website to view: ").strip()
    vault = load_vault()
    if site not in vault:
        print("❌ No such entry.")
        return
    encrypted_data = vault[site]
    try:
        username = decrypt_data(key, encrypted_data["username"])
        password = decrypt_data(key, encrypted_data["password"])
    except InvalidTag:
        print("❌ Decryption failed: authentication tag mismatch. Possibly wrong master password or tampered data.")
        return
    print(f"🔹 Username: {username}")
    print(f"🔹 Password: {password}")


def list_sites() -> None:
    vault = load_vault()
    if not vault:
        print("Vault is empty.")
        return
    print("Stored sites:")
    for site in vault.keys():
        print(f" - {site}")


def dump_all_credentials(key: bytes) -> None:
    """Decrypt and print all credentials after a confirmation prompt."""
    confirm = input("This will print all passwords to the terminal. Continue? (yes/no): ").strip().lower()
    if confirm not in ("y", "yes"):
        print("Aborted.")
        return
    vault = load_vault()
    if not vault:
        print("Vault is empty.")
        return
    print("All stored credentials:")
    for site, data in vault.items():
        try:
            username = decrypt_data(key, data["username"])
            password = decrypt_data(key, data["password"])
        except InvalidTag:
            print(f" - {site}: [decryption failed: wrong password or tampered data]")
            continue
        print(f" - {site}\n    Username: {username}\n    Password: {password}")


def delete_entry(site: str, index: int) -> None:
    """Delete the entry at index (0-based) for site and save vault."""
    vault = load_vault()
    entries = vault.get(site, [])
    if not entries or index < 0 or index >= len(entries):
        print("Invalid entry selection — cannot delete.")
        return
    # remove entry
    entries.pop(index)
    if not entries:
        # remove site if no entries left
        vault.pop(site, None)
    else:
        vault[site] = entries
    save_vault(vault)
    print("Entry deleted.")


def edit_entry(site: str, index: int, key: bytes) -> None:
    """Edit username/password for an entry; key is the encryption key to use.

    The function will decrypt the existing values, prompt for new values
    (blank = keep current), then re-encrypt and save.
    """
    vault = load_vault()
    entries = vault.get(site, [])
    if not entries or index < 0 or index >= len(entries):
        print("Invalid entry selection — cannot edit.")
        return
    entry = entries[index]
    try:
        cur_user = decrypt_data(key, entry["username"])
        cur_pass = decrypt_data(key, entry["password"])
    except Exception:
        print("Cannot decrypt entry with provided key. Edit aborted.")
        return

    print(f"Current username: {cur_user}")
    new_user = input("New username (leave blank to keep): ").strip()
    if new_user == "":
        new_user = cur_user
    new_pass = getpass("New password (leave blank to keep): ")
    if new_pass == "":
        new_pass = cur_pass

    # re-encrypt
    entries[index] = {
        "username": encrypt_data(key, new_user),
        "password": encrypt_data(key, new_pass),
    }
    vault[site] = entries
    save_vault(vault)
    print("Entry updated.")


def init_salt() -> None:
    if os.path.exists(SALT_FILE):
        print("Salt already exists. Initialization skipped.")
        return
    with open(SALT_FILE, "wb") as f:
        f.write(os.urandom(16))
    print("Salt generated and saved to disk.")


def verify_command() -> None:
    ok = verify_vault_hash()
    if ok:
        print("Vault integrity OK.")
    else:
        print("Vault integrity FAILED. Stored hash does not match vault file.")


def change_master_password_interactive() -> None:
    """Interactively change the master password and re-encrypt the vault."""
    if not os.path.exists(SALT_FILE):
        print("No master password/salt found. Use 'init' to create one first.")
        return

    # Render a consistent Change Master UI first
    render_screen(
        "# CHANGE MASTER KEY",
        instructions="You will be asked to enter the current master password, then a new one.",
        details=None,
        commands=None,
    )

    # Verify current password
    old_master = getpass("Enter current master password: ")
    old_key = generate_key(old_master)
    # Try decrypting one item (if any) to validate password
    vault = load_vault()
    sample_ok = True
    for site, entries in vault.items():
        if not entries:
            continue
        try:
            # entries may be list
            sample = entries[0]
            decrypt_data(old_key, sample["username"])
        except Exception:
            sample_ok = False
        break
    if not sample_ok and vault:
        print("Current master password seems incorrect. Aborting.")
        return

    # Get new password
    new_master = getpass("Enter new master password: ")
    new_master2 = getpass("Confirm new master password: ")
    if new_master != new_master2:
        print("Passwords do not match. Aborting.")
        return

    # Decrypt all entries with old_key
    decrypted: Dict[str, Any] = {}
    for site, entries in vault.items():
        decrypted[site] = []
        for entry in entries:
            try:
                u = decrypt_data(old_key, entry["username"])
                p = decrypt_data(old_key, entry["password"])
            except Exception:
                print(f"Failed to decrypt entry for {site}. Aborting to avoid data loss.")
                return
            decrypted[site].append({"username": u, "password": p})

    # Write new salt
    with open(SALT_FILE, "wb") as f:
        f.write(os.urandom(16))

    # Derive new key and re-encrypt
    new_key = generate_key(new_master)
    new_vault: Dict[str, Any] = {}
    for site, entries in decrypted.items():
        new_vault[site] = []
        for e in entries:
            new_vault[site].append({
                "username": encrypt_data(new_key, e["username"]),
                "password": encrypt_data(new_key, e["password"]),
            })

    save_vault(new_vault)
    print("Master password changed and vault re-encrypted.")


def interactive_cli(initial_key: bytes) -> None:
    """Interactive CLI per user's spec.

    - If master key was just provided (initial_key), it is used and validated.
    - Menu shows header and a single-line command row (+, ?, #, q) and a numbered site list.
    - User selects a site by serial number; '+' adds, '?' searches, '#' changes master password, 'q' quits.
    """
    # Cleaned single-flow interactive CLI implementation
    key = initial_key
    try:
        vault = load_vault()
    except RuntimeError as e:
        print(f"ERROR: {e}")
        return

    # If vault has entries, validate provided key against a sample (allow up to 3 attempts)
    if vault:
        sample_entry = None
        for _, entries in vault.items():
            if entries:
                sample_entry = entries[0]
                break
        if sample_entry is not None:
            for attempt in range(3):
                try:
                    _ = decrypt_data(key, sample_entry["username"])
                    break
                except Exception:
                    if attempt == 2:
                        print("Master password appears incorrect. Aborting interactive CLI.")
                        return
                    print("Master password validation failed. Please re-enter your master password.")
                    new_master = getpass("Enter master password: ")
                    key = generate_key(new_master)

    # Main interactive loop
    while True:
        vault = load_vault()
        sites = list(vault.keys())

        # Render consistent menu screen: title, commands, site list, and instructions
        details = [f"{i}. {s}" for i, s in enumerate(sites, start=1)]
        render_screen(
            "Menu",
            instructions=("Choose an Action ( [Sno] / [+] / [?] / [#] / [q] ):"),
            details=details,
            commands="Options: [Sno]SELECT [+]ADD   [?]SEARCH   [#]CHANGE_MASTER_KEY   [q]QUIT",
        )

        choice = input("> ").strip()
        if not choice:
            print("Invalid selection")
            continue

        # Options handling
        if choice == "+":
            add_credential(key)
            continue

        if choice == "?":
            term = input("Search term: ").strip().lower()
            matches = [s for s in sites if term in s.lower()]
            if not matches:
                print("No matching sites.")
                continue
            # Render search results with unified UI
            details = [f"{i}. {s}" for i, s in enumerate(matches, start=1)]
            render_screen(
                "Search results",
                instructions="Enter serial number of matching site to select or 'b' to cancel:",
                details=details,
                commands=None,
            )
            sel = input("> ").strip()
            if sel.lower() == "b":
                continue
            try:
                midx = int(sel) - 1
                site = matches[midx]
            except Exception:
                print("Invalid selection")
                continue
            entries = vault.get(site, [])
        elif choice == "#":
            change_master_password_interactive()
            new_master = getpass("Enter master password to continue: ")
            key = generate_key(new_master)
            continue
        elif choice.lower() in ("q", "quit"):
            break
        else:
            # numeric selection
            try:
                sel = int(choice) - 1
            except ValueError:
                print("Invalid selection")
                continue
            if sel < 0 or sel >= len(sites):
                print("Invalid selection")
                continue
            site = sites[sel]
            entries = vault.get(site, [])

        # Normalize older single-entry case
        if isinstance(entries, dict) and "username" in entries:
            entries = [entries]
        

        # Site-specific loop: list usernames and allow viewing (requires re-entry of master)
        while True:
            if not entries:
                print("No usernames for this site.")
                break

            # Render site view using the unified screen renderer
            usernames = []
            for j, e in enumerate(entries, start=1):
                try:
                    uname = decrypt_data(key, e["username"])
                except Exception:
                    uname = "[locked: incorrect master key]"
                usernames.append(f"{j}. {uname}")

            render_screen(
                f"Site: {site}",
                instructions="Choose an Action ( [Sno] / [b] ):",
                details=usernames,
                commands="Options: [Sno]SELECT [b]BACK",
            )
            sub = input("> ").strip()
            if sub.lower() == "b":
                # go back to main menu
                break

            try:
                sidx = int(sub) - 1
                if sidx < 0 or sidx >= len(entries):
                    print("Invalid selection")
                    continue
            except ValueError:
                print("Invalid selection")
                continue

            confirm_pwd = getpass("Re-enter master password to reveal password: ")
            confirm_key = generate_key(confirm_pwd)
            entry = entries[sidx]
            try:
                password = decrypt_data(confirm_key, entry["password"])
                username = decrypt_data(confirm_key, entry["username"])
            except Exception:
                print("Decryption failed: wrong master password or tampered data.")
                continue
            # Show revealed credentials and offer actions: edit / delete / back
            while True:
                # render revealed entry with consistent UI
                details = [f"Username: {username}", f"Password: {password}"]
                render_screen(
                    f"Site: {site}",
                    instructions="Choose an Action ( [e] / [d] / [b]):",
                    details=details,
                    commands="Options: [e]EDIT  [d]DELETE  [b]BACK",
                )
                action = input("> ").strip().lower()
                if action == "" or action == "b":
                    # go back to usernames list
                    break
                elif action in ("e", "edit"):
                    # edit using the confirm_key as encryption key
                    edit_entry(site, sidx, confirm_key)
                    # reload entries for site
                    vault = load_vault()
                    entries = vault.get(site, [])
                    if not entries or sidx >= len(entries):
                        # entry removed or index out of range -> return to site list
                        break
                    # re-decrypt updated entry to show new values
                    try:
                        username = decrypt_data(confirm_key, entries[sidx]["username"])
                        password = decrypt_data(confirm_key, entries[sidx]["password"])
                    except Exception:
                        print("Updated entry cannot be decrypted with provided key. Returning to site list.")
                        break
                    # loop to show updated entry and options again
                    continue
                elif action in ("d", "delete"):
                    confirm = input("Delete this entry? (yes/no): ").strip().lower()
                    if confirm in ("y", "yes"):
                        delete_entry(site, sidx)
                        # reload vault and entries
                        vault = load_vault()
                        entries = vault.get(site, [])
                        # after deletion return to site list
                        break
                    else:
                        continue
                else:
                    print("Invalid option — choose e, d or b.")



def parse_args():
    p = argparse.ArgumentParser(description="Secure Password Vault CLI")
    p.add_argument(
        "command",
        choices=["init", "add", "view", "list", "verify", "dump", "cli", "changepw"],
        help="Command to run",
    )
    return p.parse_args()


def main():
    args = parse_args()
    cmd = args.command
    if cmd == "init":
        init_salt()
        return

    # Special handling for interactive CLI: create master if missing, otherwise ask for it
    if cmd == "cli":
        # If salt (master) not present, prompt to create one
        if not os.path.exists(SALT_FILE):
            print("No master key found. Create a new master password.")
            while True:
                m1 = getpass("Enter new master password: ")
                m2 = getpass("Confirm new master password: ")
                if m1 != m2:
                    print("Passwords do not match. Try again.")
                    continue
                if m1.strip() == "":
                    print("Password cannot be empty. Try again.")
                    continue
                # create salt and derive key
                with open(SALT_FILE, "wb") as f:
                    f.write(os.urandom(16))
                key = generate_key(m1)
                # ensure vault exists
                if not os.path.exists(VAULT_FILE):
                    save_vault({})
                break
        else:
            # Ask for existing master password
            master_pwd = getpass("Enter master password: ")
            key = generate_key(master_pwd)

        try:
            interactive_cli(key)
        except RuntimeError as e:
            print(f"ERROR: {e}")
        return

    # For other operations that use the vault, require master password
    master_pwd = getpass("Enter master password: ")
    key = generate_key(master_pwd)

    try:
        if cmd == "add":
            add_credential(key)
        elif cmd == "view":
            view_credential(key)
        elif cmd == "list":
            list_sites()
        elif cmd == "dump":
            dump_all_credentials(key)
        elif cmd == "changepw":
            change_master_password_interactive()
        elif cmd == "verify":
            verify_command()
    except RuntimeError as e:
        print(f"ERROR: {e}")


if __name__ == "__main__":
    main()
