# lan_chat_server.py
from flask import Flask, request, render_template, redirect, url_for, session, jsonify, flash
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
import sqlite3, hashlib, json, time, base64, os
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
        user1_id INTEGER,
        user2_id INTEGER,
        active BOOLEAN,
        codes_json TEXT
    )""")
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

def create_session(user1_id, user2_id, user1_code, user2_code):
    key = tuple(sorted([user1_id, user2_id]))
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT id FROM sessions WHERE user1_id=? AND user2_id=?", key)
    if not c.fetchone():
        codes_json = json.dumps({str(user1_id): user1_code, str(user2_id): user2_code})
        c.execute("INSERT INTO sessions (user1_id, user2_id, active, codes_json) VALUES (?,?,?,?)",
                  (key[0], key[1], 1, codes_json))
        conn.commit()
    conn.close()

def add_message(sender_id, receiver_id, message):
    key = "-".join(map(str, sorted([sender_id, receiver_id])))
    conn = get_db(); c = conn.cursor()
    c.execute("INSERT INTO messages (sender_id, receiver_id, session_key, content) VALUES (?,?,?,?)",
              (int(sender_id), int(receiver_id), key, message))
    conn.commit(); conn.close()

def _chat_serializer():
    return URLSafeTimedSerializer(app.secret_key, salt="chat-token")

def issue_chat_token(user_id, peer_id):
    s = _chat_serializer()
    return s.dumps({"uid": int(user_id), "peer_id": int(peer_id)})

def verify_chat_token(token, max_age=3600):
    s = _chat_serializer()
    return s.loads(token, max_age=max_age)

def current_user_from_token_or_session(expected_peer_id=None):
    token = (request.headers.get("X-Chat-Token")
             or request.args.get("token")
             or request.form.get("token"))
    if token:
        try:
            data = verify_chat_token(token)
            if expected_peer_id is None or int(data["peer_id"]) == int(expected_peer_id):
                return int(data["uid"])
        except (BadSignature, SignatureExpired):
            return None
    return session.get("user_id")

# ---------- Pages ----------
@app.get("/")
def index_page():
    return render_template("login.html")


#    except Exception:
#        return ('<h2>Welcome</h2><p><a href="/login">Login</a> or <a href="/register">Register</a></p>')

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
        try:
            flash("Mot de passe incorrect", "error")
            return render_template("login.html"), 401
        except Exception:
            return "Mot de passe incorrect", 401
    try:
        return render_template("login.html")
    except Exception:
        return ('<form method="POST">'
                '<input name="username" placeholder="Username"><br>'
                '<input name="password" type="password" placeholder="Password"><br>'
                '<button>Login</button></form>')


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

        # Require confirmation and match
        if not username or not password or not confirm or not code_plain:
            try:
                flash("Merci de remplir tous les champs, y compris la confirmation du mot de passe.", "error")
                return render_template("register.html"), 400
            except Exception:
                return "Missing fields (need username, password, confirm, code)", 400

        if password != confirm:
            try:
                flash("Les mots de passe ne correspondent pas.", "error")
                return render_template("register.html"), 400
            except Exception:
                return "Passwords do not match", 400

        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        conn = get_db(); c = conn.cursor()
        c.execute("SELECT 1 FROM users WHERE username=?", (username,))
        if c.fetchone():
            conn.close()
            try:
                flash("Nom d'utilisateur déjà pris.", "error")
                return render_template("register.html"), 409
            except Exception:
                return "Username exists", 409

        c.execute("INSERT INTO users (username, password_hash) VALUES (?,?)", (username, pwd_hash))
        uid = c.lastrowid
        conn.commit(); conn.close()

        upsert_user_code(uid, code_plain)

        return redirect(url_for("login_page"))

    try:
        return render_template("register.html")
    except Exception:
        # Minimal fallback page with confirmation
        return ('<h3>Register</h3>'
                '<form method="POST">'
                '<input name="username" placeholder="Username"><br>'
                '<input name="password" type="password" placeholder="Password"><br>'
                '<input name="confirm" type="password" placeholder="Confirm password"><br>'
                '<input name="code" placeholder="Your secret code"><br>'
                '<button>Create account</button></form>')


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
        if not row: return "Utilisateur pair non trouvé", 404
        peer_id = row["id"]
        if verify_user_code(session["user_id"], user_code) and verify_user_code(peer_id, peer_code):
            create_session(session["user_id"], peer_id, user_code, peer_code)
            return redirect(url_for("chat_page", peer_id=peer_id))
        return "Codes invalides", 401
    return render_template("code.html")

@app.route("/chat/<int:peer_id>")
def chat_page(peer_id):
    if "user_id" not in session:
        return redirect(url_for("login_page"))
    user_id = session["user_id"]
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT username FROM users WHERE id=?", (peer_id,))
    row = c.fetchone(); conn.close()
    peer_name = row["username"] if row else "Inconnu"
    chat_token = issue_chat_token(user_id, peer_id)
    return render_template("messagerie.html",
                           peer_id=peer_id,
                           current_user_id=user_id,
                           peer_name=peer_name,
                           current_username=session.get("username","Moi"),
                           chat_token=chat_token)

@app.post("/send_message/<int:peer_id>")
def send_message(peer_id):
    user_id = current_user_from_token_or_session(expected_peer_id=peer_id)
    if not user_id: return jsonify({"error":"not logged in"}), 403
    msg = request.form.get("message","")
    if not msg: return jsonify({"error":"empty"}), 400
    add_message(user_id, peer_id, msg)
    return jsonify({"status":"ok"})

@app.get("/get_messages/<int:peer_id>")
def get_messages(peer_id):
    current_user = current_user_from_token_or_session(expected_peer_id=peer_id)
    if not current_user: return jsonify([])
    key = "-".join(map(str, sorted([current_user, peer_id])))
    conn = get_db(); c = conn.cursor()
    c.execute("""SELECT sender_id AS 'from', content AS msg
                 FROM messages WHERE session_key=? ORDER BY timestamp ASC, id ASC""", (key,))
    rows = [dict(r) for r in c.fetchall()]; conn.close()
    return jsonify(rows)

# ---------- JSON API ----------
@app.post("/api/register")
def api_register():
    data = request.get_json(force=True, silent=False) or {}
    u = (data.get("username") or "").strip()
    p = data.get("password") or ""
    pub = data.get("public_key")
    encp = data.get("enc_private")
    code_hash_b64 = data.get("code_hash")
    if not (u and p and pub and encp and code_hash_b64):
        return jsonify({"error":"missing fields"}), 400
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE username=?", (u,))
    if c.fetchone(): conn.close(); return jsonify({"error":"username exists"}), 409
    c.execute("SELECT 1 FROM user_codes WHERE code_hash_b64=?", (code_hash_b64,))
    if c.fetchone(): conn.close(); return jsonify({"error":"secret key already used"}), 409
    pwd_hash = hashlib.sha256(p.encode()).hexdigest()
    c.execute("INSERT INTO users (username, password_hash, pubkey_b64, enc_priv_b64) VALUES (?,?,?,?)",
              (u, pwd_hash, pub, encp))
    uid = c.lastrowid
    c.execute("INSERT INTO user_codes (user_id, code_hash_b64) VALUES (?,?)", (uid, code_hash_b64))
    conn.commit(); conn.close()
    return jsonify({"ok": True})

@app.post("/api/login")
def api_login():
    data = request.get_json(force=True, silent=False) or {}
    u = (data.get("username") or "").strip()
    p = data.get("password") or ""
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT password_hash, pubkey_b64, enc_priv_b64 FROM users WHERE username=?", (u,))
    row = c.fetchone()
    if not row: conn.close(); return jsonify({"error":"no such user"}), 404
    if row["password_hash"] != hashlib.sha256(p.encode()).hexdigest():
        conn.close(); return jsonify({"error":"invalid credentials"}), 401
    resp = {"ok": True, "public_key": row["pubkey_b64"], "enc_private": row["enc_priv_b64"]}
    conn.close(); return jsonify(resp)

@app.post("/api/lookup_by_code")
def api_lookup_by_code():
    data = request.get_json(force=True, silent=False) or {}
    code_hash_b64 = data.get("code_hash","")
    conn = get_db(); c = conn.cursor()
    c.execute("""SELECT u.username, u.pubkey_b64
                 FROM user_codes uc JOIN users u ON u.id = uc.user_id
                 WHERE uc.code_hash_b64 = ?""", (code_hash_b64,))
    row = c.fetchone(); conn.close()
    if not row: return jsonify({"ok": False})
    return jsonify({"ok": True, "username": row["username"], "public_key": row["pubkey_b64"]})

# ---------- Socket.IO ----------
ROOMS = {}

@socketio.on("join_room")
def on_join(data):
    r = data.get("room"); u = data.get("username")
    if not r or not u: return
    join_room(r)
    room = ROOMS.setdefault(r, {"created": time.time(), "members": set()})
    room["members"].add(u)
    emit("presence", {"room": r, "members": sorted(room["members"])}, room=r)

@socketio.on("leave_room")
def on_leave(data):
    r = data.get("room"); u = data.get("username")
    if not r or not u: return
    try:
        leave_room(r)
        ROOMS[r]["members"].discard(u)
        emit("presence", {"room": r, "members": sorted(ROOMS[r]["members"])}, room=r)
        if not ROOMS[r]["members"]:
            ROOMS.pop(r, None)
    except KeyError:
        pass

@socketio.on("signal")
def on_signal(data):
    if not data or not data.get("room"): return
    emit("signal", data, room=data["room"], include_self=False)

@socketio.on("relay_send")
def on_relay_send(data):
    r = data.get("room")
    if not r: return
    emit("relay_recv", data, room=r, include_self=False)

@socketio.on("end_chat")
def on_end_chat(data):
    r = data.get("room")
    if not r: return
    emit("chat_ended", {"room": r}, room=r)

@app.get("/healthz")
def healthz():
    return {"ok": True}

def main():
    init_db()
    socketio.run(app, host="0.0.0.0", port=5000)

if __name__ == "__main__":
    main()
