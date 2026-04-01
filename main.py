import json
import os
import base64
import secrets
import string
import getpass
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.style import Style

console = Console()

FILE = "data.json"
KEY_FILE = ".key"
MASTER_PASSWORD_HASH = None
SESSION_ACTIVE = False


# Generate a key from master password using PBKDF2
def derive_key(password: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


# Initialize or load encryption key
def init_encryption():
    global MASTER_PASSWORD_HASH

    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            data = json.load(f)
            salt = base64.b64decode(data["salt"])
            MASTER_PASSWORD_HASH = data["hash"]
            return derive_key_from_salt(salt)
    else:
        return None


def derive_key_from_salt(salt: bytes) -> bytes:
    password = getpass.getpass("Enter master password: ")
    key = derive_key(password, salt)

    from cryptography.hazmat.primitives import hashes
    stored_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    stored_hash.update(key)
    computed_hash = base64.b64encode(stored_hash.finalize()).decode()

    if computed_hash != MASTER_PASSWORD_HASH:
        console.print("[red]Invalid master password![/red]")
        return None
    return key


def setup_encryption():
    password = getpass.getpass("Set master password: ")
    confirm = getpass.getpass("Confirm master password: ")

    if password != confirm:
        console.print("[red]Passwords do not match![/red]")
        return None

    salt = os.urandom(16)
    key = derive_key(password, salt)

    from cryptography.hazmat.primitives import hashes
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(key)
    password_hash = base64.b64encode(hasher.finalize()).decode()

    with open(KEY_FILE, "w") as f:
        json.dump({
            "salt": base64.b64encode(salt).decode(),
            "hash": password_hash
        }, f)

    console.print("[green]Master password set![/green]")
    return key


# AES Encryption
def encrypt_password(password: str, key: bytes) -> str:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(password.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode()


def decrypt_password(encoded: str, key: bytes) -> str:
    data = base64.b64decode(encoded)
    iv = data[:16]
    encrypted = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    return decrypted.decode()


# Load and save data
def load_data():
    if not os.path.exists(FILE):
        return []
    try:
        with open(FILE, "r") as f:
            return json.load(f)
    except:
        return []


def save_data(data):
    with open(FILE, "w") as f:
        json.dump(data, f, indent=4)


# Password generator
def generate_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-="
    password = ''.join(secrets.choice(chars) for _ in range(length))
    return password


def generate_and_show():
    length = Prompt.ask("Password length", default="16")
    try:
        length = int(length)
        if length < 8:
            console.print("[red]Password length must be at least 8[/red]")
            return
    except ValueError:
        console.print("[red]Invalid length[/red]")
        return

    password = generate_password(length)
    console.print(Panel(f"[bold green]{password}[/bold green]", title="Generated Password"))


# Add credential
def add_password(key: bytes):
    site = Prompt.ask("Enter website")
    user = Prompt.ask("Enter username")

    gen = Confirm.ask("Generate strong password?")
    if gen:
        pwd = generate_password()
        console.print(f"Generated: [green]{pwd}[/green]")
    else:
        pwd = getpass.getpass("Enter password: ")

    data = load_data()
    encrypted_pwd = encrypt_password(pwd, key)

    data.append({
        "site": site,
        "username": user,
        "password": encrypted_pwd,
        "created": datetime.now().isoformat()
    })

    save_data(data)
    console.print("[green]Saved successfully![/green]")


# View credentials
def view_passwords(key: bytes):
    data = load_data()

    if not data:
        console.print("[yellow]No data found![/yellow]")
        return

    table = Table(title="Stored Passwords", style="cyan")
    table.add_column("#", style="dim")
    table.add_column("Site", style="green")
    table.add_column("Username", style="blue")
    table.add_column("Password", style="yellow")
    table.add_column("Created", style="dim")

    for i, entry in enumerate(data, 1):
        pwd = decrypt_password(entry["password"], key)
        masked_pwd = "*" * min(len(pwd), 12)
        created = entry.get("created", "N/A")[:10]
        table.add_row(str(i), entry["site"], entry["username"], masked_pwd, created)

    console.print(table)

    show = Prompt.ask("\nShow specific password? (number or 'n')", default="n")
    if show.lower() != "n":
        try:
            idx = int(show) - 1
            if 0 <= idx < len(data):
                pwd = decrypt_password(data[idx]["password"], key)
                console.print(Panel(
                    f"[bold]Site:[/bold] {data[idx]['site']}\n"
                    f"[bold]Username:[/bold] {data[idx]['username']}\n"
                    f"[bold]Password:[/bold] [green]{pwd}[/green]",
                    title="Credential Details"
                ))
        except ValueError:
            pass


# Search passwords
def search_passwords(key: bytes):
    query = Prompt.ask("Search for (site name)").lower()
    data = load_data()

    results = [e for e in data if query in e["site"].lower()]

    if not results:
        console.print("[red]No matches found[/red]")
        return

    table = Table(title=f"Search Results: '{query}'", style="cyan")
    table.add_column("Site", style="green")
    table.add_column("Username", style="blue")
    table.add_column("Password", style="yellow")

    for entry in results:
        pwd = decrypt_password(entry["password"], key)
        table.add_row(entry["site"], entry["username"], "*" * min(len(pwd), 12))

    console.print(table)


# Edit password
def edit_password(key: bytes):
    view_passwords(key)
    num = Prompt.ask("Enter number to edit (or 'n' to cancel)")

    try:
        idx = int(num) - 1
        data = load_data()

        if not (0 <= idx < len(data)):
            console.print("[red]Invalid number[/red]")
            return

        entry = data[idx]
        console.print(f"\nEditing: [green]{entry['site']}[/green]")

        new_site = Prompt.ask("New site name", default=entry["site"])
        new_user = Prompt.ask("New username", default=entry["username"])
        new_pwd = Prompt.ask("New password (leave empty to keep)", default="", password=True)

        data[idx]["site"] = new_site
        data[idx]["username"] = new_user
        if new_pwd:
            data[idx]["password"] = encrypt_password(new_pwd, key)
        data[idx]["updated"] = datetime.now().isoformat()

        save_data(data)
        console.print("[green]Updated successfully![/green]")

    except ValueError:
        console.print("[yellow]Cancelled[/yellow]")


# Delete password
def delete_password():
    data = load_data()

    if not data:
        console.print("[yellow]No data to delete[/yellow]")
        return

    table = Table(title="Stored Passwords", style="cyan")
    table.add_column("#", style="dim")
    table.add_column("Site", style="green")
    table.add_column("Username", style="blue")

    for i, entry in enumerate(data, 1):
        table.add_row(str(i), entry["site"], entry["username"])

    console.print(table)

    num = Prompt.ask("Enter number to delete (or 'n' to cancel)")

    try:
        idx = int(num) - 1
        if 0 <= idx < len(data):
            if Confirm.ask(f"Delete {data[idx]['site']}?"):
                data.pop(idx)
                save_data(data)
                console.print("[green]Deleted![/green]")
    except ValueError:
        console.print("[yellow]Cancelled[/yellow]")


# Main menu
def show_menu():
    console.print(Panel.fit(
        "[bold blue]Password Manager[/bold blue]\n"
        "1. Add Password\n"
        "2. View Passwords\n"
        "3. Search\n"
        "4. Generate Password\n"
        "5. Edit Password\n"
        "6. Delete Password\n"
        "7. Exit",
        style="bold green"
    ))


def main():
    global SESSION_ACTIVE

    console.print(Panel.fit("[bold]Welcome to Password Manager[/bold]"))

    key = init_encryption()

    if key is None:
        console.print("[yellow]No vault found. Creating new one...[/yellow]")
        key = setup_encryption()
        if key is None:
            return

    SESSION_ACTIVE = True
    console.print("[green]Vault unlocked![/green]\n")

    while SESSION_ACTIVE:
        show_menu()
        choice = Prompt.ask("Choose", choices=["1", "2", "3", "4", "5", "6", "7"], default="7")

        if choice == "1":
            add_password(key)
        elif choice == "2":
            view_passwords(key)
        elif choice == "3":
            search_passwords(key)
        elif choice == "4":
            generate_and_show()
        elif choice == "5":
            edit_password(key)
        elif choice == "6":
            delete_password()
        elif choice == "7":
            console.print("[yellow]Goodbye![/yellow]")
            break


if __name__ == "__main__":
    main()
