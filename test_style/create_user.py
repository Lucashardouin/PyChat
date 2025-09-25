import json
from pathlib import Path
from getpass import getpass
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

USERS_FILE = Path("users.json")
ph = PasswordHasher()

def load_users():
    if not USERS_FILE.exists():
        return {}
    return json.loads(USERS_FILE.read_text(encoding="utf-8"))

def save_users(users):
    USERS_FILE.write_text(json.dumps(users, indent=2), encoding="utf-8")

def create_user(username, password, role):
    users = load_users()
    if username in users:
        raise RuntimeError("username already exists")
    users[username] = {
        "scheme": "argon2",
        "hash": ph.hash(password),
        "role": role,
        # add other metadata if needed, e.g. role/joined
    }
    save_users(users)
    print(f"User {username} created.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 2:
        username = sys.argv[1]
    else:
        username = input("Username: ").strip()
    # use getpass so password is not shown
    pw = getpass("Password: ")
    pw2 = getpass("Confirm Password: ")
    if pw != pw2:
        print("Passwords don't match. Aborting.")
        raise SystemExit(1)
    if len(pw) < 8:
        print("Warning: password shorter than 8 chars.")
    role = input("Role: ")
    create_user(username, pw, role)