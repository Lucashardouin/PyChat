# create_basecamp.py - admin helper to add basecamp codes
import json
from pathlib import Path
from getpass import getpass
from argon2 import PasswordHasher

USERS_FILE = Path("basecamps.json")
ph = PasswordHasher()

def load():
    if not USERS_FILE.exists():
        return {}
    return json.loads(USERS_FILE.read_text(encoding="utf-8"))

def save(data):
    USERS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")

def create(id, name, code):
    data = load()
    if id in data:
        raise SystemExit("id already exists")
    data[id] = {"name": name, "scheme": "argon2", "hash": ph.hash(code)}
    save(data)
    print("Created basecamp", id)

if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 3:
        id = sys.argv[1]
        name = sys.argv[2]
        code = None
        if len(sys.argv) >= 4:
            code = sys.argv[3]
    else:
        id = input("basecamp id (short): ").strip()
        name = input("display name: ").strip()
    if not code:
        code = getpass("secret basecamp code (shown hidden): ")
    create(id, name, code)
