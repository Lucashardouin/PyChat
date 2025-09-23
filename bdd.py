from flask import Flask, request, render_template, redirect, url_for, session, jsonify, make_response
import sqlite3
import hashlib
from nacl import secret, utils
import json
from datetime import datetime, timedelta

# -----------------------------
# -- Initialisation Flask
# -----------------------------
app = Flask(__name__)
app.secret_key = utils.random(secret.SecretBox.KEY_SIZE)

# Cookie de session non permanent → disparaît à la fermeture de l’onglet
app.config["SESSION_PERMANENT"] = False

# Timeout d’inactivité (ex: 10 min)
SESSION_TIMEOUT = timedelta(minutes=10)
INACTIVITY_TIMEOUT = 10 

# Chemin vers la base SQLite
DB_PATH = "messagerie.db"

# -----------------------------
# -- Fonctions utilitaires
# -----------------------------
def get_db():
    connexion = sqlite3.connect(DB_PATH)
    connexion.row_factory = sqlite3.Row
    return connexion

def authenticate_user(username, password):
    connexion = get_db()
    cursor = connexion.cursor()
    cursor.execute("SELECT id, password_hash FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    connexion.close()
    if row and row["password_hash"] == hashlib.sha256(password.encode()).hexdigest():
        return row["id"]
    return None

def verify_user_code(user_id, code):
    connexion = get_db()
    cursor = connexion.cursor()
    cursor.execute("SELECT code_hash FROM user_codes WHERE user_id=?", (user_id,))
    row = cursor.fetchone()
    connexion.close()
    if row and row["code_hash"] == hashlib.sha256(code.encode()).hexdigest():
        return True
    return False

def create_session(user1_id, user2_id, user1_code, user2_code):
    connexion = get_db()
    cursor = connexion.cursor()
    key = tuple(sorted([user1_id, user2_id]))
    cursor.execute("SELECT id FROM sessions WHERE user1_id=? AND user2_id=?", key)
    if not cursor.fetchone():
        codes_json = json.dumps({str(user1_id): user1_code, str(user2_id): user2_code})
        cursor.execute(
            "INSERT INTO sessions (user1_id, user2_id, active, codes_json) VALUES (?, ?, ?, ?)",
            (key[0], key[1], 1, codes_json)
        )
    connexion.commit()
    connexion.close()

def add_message(sender_id, receiver_id, message):
    key = "-".join(map(str, sorted([sender_id, receiver_id])))
    connexion = get_db()
    cursor = connexion.cursor()
    cursor.execute(
        "INSERT INTO messages (sender_id, receiver_id, session_key, content) VALUES (?, ?, ?, ?)",
        (int(sender_id), int(receiver_id), key, message)
    )
    connexion.commit()
    connexion.close()

# -----------------------------
# -- Vérification timeout session
# -----------------------------
# @app.before_request
# def check_session_timeout():
#     if "user_id" in session:
#         now = datetime.utcnow()
#         last_activity = session.get("last_activity")
#         if last_activity:
#             last_activity = datetime.fromisoformat(last_activity)
#             if now - last_activity > SESSION_TIMEOUT:
#                 session.clear()
#                 return redirect(url_for("login"))
#         session["last_activity"] = now.isoformat()

# Middleware: vérifie avant chaque requête
@app.before_request
def check_activity():
    if "user_id" in session:
        last = session.get("last_activity")
        now = datetime.utcnow().timestamp()
        if last and (now - last > INACTIVITY_TIMEOUT):
            # Trop d'inactivité → déconnexion
            session.clear()
            return render_template("login.html", error="Session expirée pour cause d'inactivité")

# Route appelée par le front pour signaler une activité
@app.route("/activity", methods=["POST"])
def update_activity():
    if "user_id" not in session:
        return jsonify({"status": "not_logged"}), 401

    # Met à jour la dernière activité dans la session
    session["last_activity"] = datetime.utcnow().timestamp()
    return jsonify({"status": "ok"}), 200

# -----------------------------
# -- Routes Flask
# -----------------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user_id = authenticate_user(username, password)
        if user_id:
            session["user_id"] = user_id
            session["username"] = username
            session["last_activity"] = datetime.utcnow().timestamp()
            return redirect(url_for("code_page"))
        else:
            return render_template("login.html", error="Mot de passe incorrect")
    return render_template("login.html")

@app.route("/code", methods=["GET", "POST"])
def code_page():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        peer_username = request.form["peer"]
        user_code = request.form["user_code"]
        peer_code = request.form["peer_code"]

        connexion = get_db()
        cursor = connexion.cursor()
        cursor.execute("SELECT id FROM users WHERE username=?", (peer_username,))
        row = cursor.fetchone()
        connexion.close()

        if not row:
            return "Utilisateur pair non trouvé"
        peer_id = row["id"]

        if verify_user_code(session["user_id"], user_code) and verify_user_code(peer_id, peer_code):
            create_session(session["user_id"], peer_id, user_code, peer_code)
            return redirect(url_for("chat_page", peer_id=peer_id))
        else:
            return "Codes invalides"

    return render_template("code.html")

@app.route("/chat/<int:peer_id>")
def chat_page(peer_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    user_id = session["user_id"]
    # Récupère le nom du pair
    connexion = get_db()
    cur = connexion.cursor()
    cur.execute("SELECT username FROM users WHERE id=?", (peer_id,))
    row = cur.fetchone()
    connexion.close()
    peer_name = row["username"] if row else "Inconnu"

    return render_template(
        "messagerie.html",
        peer_id=peer_id,
        current_user_id=user_id,
        # Récuperer le nom d'utilisateur
        peer_name=peer_name,
        current_username=session.get("username", "Moi")
    )

# Route pour envoyer un message
@app.route("/send_message/<int:peer_id>", methods=["POST"])
def send_message(peer_id):
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "not logged in"}), 403
    msg = request.form["message"]
    add_message(user_id, peer_id, msg)
    return jsonify({"status": "ok"})



# Route pour recuperer les messages ephemeres en JSON
@app.route("/get_messages/<int:peer_id>")
def get_messages(peer_id):
    current_user = session.get("user_id")
    if not current_user:
        return jsonify([])

    key = "-".join(map(str, sorted([current_user, peer_id])))

    connexion = get_db()
    cursor = connexion.cursor()
    cursor.execute(
        "SELECT sender_id AS 'from', content AS msg FROM messages WHERE session_key=? ORDER BY timestamp ASC, id ASC",
        (key,)
    )
    rows = cursor.fetchall()
    connexion.close()

    return jsonify([dict(r) for r in rows])

@app.route("/logout")
def logout():
    session.clear()
    resp = make_response(redirect(url_for("login")))
    resp.set_cookie("session", "", expires=0)  # force la suppression du cookie
    return resp

# -----------------------------
# -- Initialisation base SQLite
# -----------------------------
def init_db():
    connexion = get_db()
    cursor = connexion.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        encryption_key BLOB
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_codes (
        user_id INTEGER UNIQUE,
        code_hash TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user1_id INTEGER,
        user2_id INTEGER,
        active BOOLEAN,
        codes_json TEXT,
        FOREIGN KEY(user1_id) REFERENCES users(id),
        FOREIGN KEY(user2_id) REFERENCES users(id)
    )
    """)

    # Creation table messages
    cursor.execute(""" CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id INTEGER NOT NULL,
                    receiver_id INTEGER NOT NULL,
                    session_key TEXT NOT NULL,            -- clé triée "minId-maxId"
                    content TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(sender_id) REFERENCES users(id),
                    FOREIGN KEY(receiver_id) REFERENCES users(id))""")
    
    # Index utile pour les lectures
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_messages_session_ts ON messages(session_key, timestamp)")

    # Insertion de 4 utilisateurs test
    users_list = [
        ("Alice", "mdp123", "123456"),
        ("Bob", "mdp456", "456798"),
        ("Charlie", "mdp789", "789000"),
        ("David", "mdp000", "000123")
    ]

    for username, password, code in users_list:
        cursor.execute("SELECT id FROM users WHERE username=?", (username,))
        if cursor.fetchone():
            continue
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        encryption_key = utils.random(secret.SecretBox.KEY_SIZE)
        cursor.execute(
            "INSERT INTO users (username, password_hash, encryption_key) VALUES (?, ?, ?)",
            (username, password_hash, encryption_key)
        )
        user_id = cursor.lastrowid
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        cursor.execute("INSERT INTO user_codes (user_id, code_hash) VALUES (?, ?)", (user_id, code_hash))

    connexion.commit()
    connexion.close()

# -----------------------------
# -- Lancement du serveur
# -----------------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
