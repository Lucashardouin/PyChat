
# lan_chat_server.py (secure chat_id)
from flask import Flask, request, render_template, redirect, url_for, session, jsonify, flash
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
import sqlite3, hashlib, json, time, base64, os, secrets
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from nacl import secret, utils

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "messagerie.db")

app = Flask(__name__, template_folder="templates", static_folder="static", static_url_path="/static")
_secret_file = os.path.join(APP_DIR, ".flask_secret")
if os.path.exists(_secret_file):
    app.secret_key = open(_secret_file, "rb").read()
else:
    sk = utils.random(secret.SecretBox.KEY_SIZE)
    with open(_secret_file, "wb") as f: f.write(sk)
    app.secret_key = sk

CORS(app, resources={r"/api/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*")

@app.context_processor
def inject_current_user():
    return {"current_username": session.get("username")}

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        pubkey_b64 TEXT,
        enc_priv_b64 TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS user_codes (
        user_id INTEGER UNIQUE,
        code_hash_sha256_hex TEXT,
        code_hash_b64 TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id TEXT UNIQUE,
        user1_id INTEGER,
        user2_id INTEGER,
        active BOOLEAN,
        codes_json TEXT
    )""")
    try:
        c.execute("SELECT chat_id FROM sessions LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE sessions ADD COLUMN chat_id TEXT")
    c.execute("""CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        session_key TEXT NOT NULL,
        content TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_messages_session_ts ON messages(session_key, timestamp)")
    conn.commit(); conn.close()

def authenticate_user(username, password):
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT id, password_hash FROM users WHERE username=?", (username,))
    row = c.fetchone(); conn.close()
    if row and row["password_hash"] == hashlib.sha256(password.encode()).hexdigest():
        return row["id"]
    return None

def verify_user_code(user_id, code_plain):
    if not code_plain: return False
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT code_hash_sha256_hex, code_hash_b64 FROM user_codes WHERE user_id=?", (user_id,))
    row = c.fetchone(); conn.close()
    if not row: return False
    want_hex = hashlib.sha256(code_plain.encode()).hexdigest()
    want_b64 = base64.b64encode(hashlib.sha256(("code-namespace:" + code_plain).encode()).digest()).decode()
    return (row["code_hash_sha256_hex"] == want_hex) or (row["code_hash_b64"] == want_b64)

def upsert_user_code(user_id, code_plain):
    if not code_plain: return
    hexv = hashlib.sha256(code_plain.encode()).hexdigest()
    b64v = base64.b64encode(hashlib.sha256(("code-namespace:" + code_plain).encode()).digest()).decode()
    conn = get_db(); c = conn.cursor()
    c.execute("INSERT INTO user_codes (user_id, code_hash_sha256_hex, code_hash_b64) VALUES (?,?,?) "
              "ON CONFLICT(user_id) DO UPDATE SET code_hash_sha256_hex=excluded.code_hash_sha256_hex, code_hash_b64=excluded.code_hash_b64",
              (user_id, hexv, b64v))
    conn.commit(); conn.close()

def add_message(sender_id, receiver_id, message):
    key = "-".join(map(str, sorted([sender_id, receiver_id])))
    conn = get_db(); c = conn.cursor()
    c.execute("INSERT INTO messages (sender_id, receiver_id, session_key, content) VALUES (?,?,?,?)",
              (int(sender_id), int(receiver_id), key, message))
    conn.commit(); conn.close()

def generate_chat_id(nbytes: int = 16) -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(nbytes)).decode().rstrip('=')

def get_session_by_chat_id(chat_id):
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT id, chat_id, user1_id, user2_id, active FROM sessions WHERE chat_id=?", (chat_id,))
    row = c.fetchone(); conn.close()
    return row

def ensure_pair_session(user1_id, user2_id, user1_code, user2_code):
    a, b = sorted([int(user1_id), int(user2_id)])
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT chat_id FROM sessions WHERE user1_id=? AND user2_id=?", (a, b))
    row = c.fetchone()
    if row and row["chat_id"]:
        chat_id = row["chat_id"]
    else:
        chat_id = generate_chat_id()
        codes_json = json.dumps({str(a): user1_code, str(b): user2_code})
        c.execute("INSERT INTO sessions (chat_id, user1_id, user2_id, active, codes_json) VALUES (?,?,?,?,?)",
                  (chat_id, a, b, 1, codes_json))
        conn.commit()
    conn.close()
    return chat_id

def _chat_serializer():
    return URLSafeTimedSerializer(app.secret_key, salt="chat-token")

def issue_chat_token(user_id, chat_id):
    s = _chat_serializer()
    return s.dumps({"uid": int(user_id), "chat_id": chat_id})

def verify_chat_token(token, max_age=3600):
    s = _chat_serializer()
    return s.loads(token, max_age=max_age)

def current_user_from_token_or_session(expected_chat_id=None):
    token = (request.headers.get("X-Chat-Token")
             or request.args.get("token")
             or request.form.get("token"))
    if token:
        try:
            data = verify_chat_token(token)
            if expected_chat_id is None or data.get("chat_id") == expected_chat_id:
                return int(data["uid"])
        except (BadSignature, SignatureExpired, KeyError, ValueError):
            return None
    return session.get("user_id")

@app.get("/")
def index_page():
    return render_template("login.html")

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        uid = authenticate_user(username, password)
        if uid:
            session["user_id"] = uid
            session["username"] = username
            return redirect(url_for("code_page"))
        flash("Incorrect username or password.", "error")
        return render_template("login.html"), 401
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register_page():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        confirm  = (request.form.get("confirm")
                    or request.form.get("confirm_password")
                    or request.form.get("password2")
                    or "").strip()
        code_plain = (request.form.get("code")
                      or request.form.get("user_code")
                      or request.form.get("secret_code")
                      or "").strip()

        if not username or not password or not confirm or not code_plain:
            flash("Please fill in all fields, including password confirmation.", "error")
            return render_template("register.html"), 400
        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("register.html"), 400

        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        conn = get_db(); c = conn.cursor()
        c.execute("SELECT 1 FROM users WHERE username=?", (username,))
        if c.fetchone():
            conn.close()
            flash("Username is already taken.", "error")
            return render_template("register.html"), 409

        c.execute("INSERT INTO users (username, password_hash) VALUES (?,?)", (username, pwd_hash))
        uid = c.lastrowid
        conn.commit(); conn.close()

        upsert_user_code(uid, code_plain)
        return redirect(url_for("login_page"))
    return render_template("register.html")

@app.route("/code", methods=["GET", "POST"])
def code_page():
    if "user_id" not in session:
        return redirect(url_for("login_page"))
    if request.method == "POST":
        peer_username = request.form["peer"]
        user_code = request.form.get("user_code") or request.form.get("code") or ""
        peer_code = request.form.get("peer_code") or ""
        conn = get_db(); c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username=?", (peer_username,))
        row = c.fetchone(); conn.close()
        if not row:
            flash("Peer user not found.", "error")
            return render_template("code.html"), 404
        peer_id = row["id"]
        if not verify_user_code(session["user_id"], user_code):
            flash("Your code is invalid.", "error")
            return render_template("code.html"), 401
        if not verify_user_code(peer_id, peer_code):
            flash("Peer code is invalid.", "error")
            return render_template("code.html"), 401
        chat_id = ensure_pair_session(session["user_id"], peer_id, user_code, peer_code)
        return redirect(url_for("chat_page", chat_id=chat_id))
    return render_template("code.html")

@app.route("/chat/<chat_id>")
def chat_page(chat_id):
    if "user_id" not in session:
        return redirect(url_for("login_page"))
    row = get_session_by_chat_id(chat_id)
    if not row:
        return "Chat not found", 404
    user_id = int(session["user_id"])
    u1, u2 = int(row["user1_id"]), int(row["user2_id"])
    if user_id not in (u1, u2):
        return "Forbidden", 403
    peer_id = u2 if user_id == u1 else u1
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT username FROM users WHERE id=?", (peer_id,))
    res = c.fetchone()
    peer_name = res["username"] if res else "Unknown"
    conn.close()
    chat_token = issue_chat_token(user_id, chat_id)
    return render_template("messagerie.html",
                           chat_id=chat_id,
                           peer_id=peer_id,
                           current_user_id=user_id,
                           peer_name=peer_name,
                           current_username=session.get("username","Me"),
                           chat_token=chat_token)

@app.post("/send_message/<chat_id>")
def send_message(chat_id):
    row = get_session_by_chat_id(chat_id)
    if not row: return jsonify({"error":"no such chat"}), 404
    user_id = current_user_from_token_or_session(expected_chat_id=chat_id)
    if not user_id: return jsonify({"error":"not logged in"}), 403
    u1, u2 = int(row["user1_id"]), int(row["user2_id"])
    if int(user_id) not in (u1, u2): return jsonify({"error":"forbidden"}), 403
    peer_id = u2 if int(user_id) == u1 else u1
    msg = request.form.get("message","")
    if not msg: return jsonify({"error":"empty"}), 400
    add_message(user_id, peer_id, msg)
    return jsonify({"status":"ok"})

@app.get("/get_messages/<chat_id>")
def get_messages(chat_id):
    row = get_session_by_chat_id(chat_id)
    if not row: return jsonify([]), 404
    current_user = current_user_from_token_or_session(expected_chat_id=chat_id)
    if not current_user: return jsonify([]), 403
    u1, u2 = int(row["user1_id"]), int(row["user2_id"])
    if int(current_user) not in (u1, u2): return jsonify([]), 403
    peer_id = u2 if int(current_user) == u1 else u1
    key = "-".join(map(str, sorted([current_user, peer_id])))
    conn = get_db(); c = conn.cursor()
    c.execute("""SELECT sender_id AS 'from', content AS msg
                 FROM messages WHERE session_key=? ORDER BY timestamp ASC, id ASC""", (key,))
    rows = [dict(r) for r in c.fetchall()]; conn.close()
    return jsonify(rows)

@app.get("/healthz")
def healthz():
    return {"ok": True}

def main():
    init_db()
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)

if __name__ == "__main__":
    main()
