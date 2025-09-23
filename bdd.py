from flask import Flask, request, render_template, redirect, url_for, session, jsonify
import sqlite3
import hashlib
from nacl import secret, utils
import json

# -----------------------------
# -- Initialisation Flask
# -----------------------------
app = Flask(__name__)

# Cle secrete Flask pour les sessions
app.secret_key = utils.random(secret.SecretBox.KEY_SIZE)

# Chemin vers la base SQLite
DB_PATH = "messagerie.db"


# -----------------------------
# -- Fonctions utiles
# -----------------------------

# Fonction pour obtenir la connexion a la base SQLite
def get_db():
    connexion = sqlite3.connect(DB_PATH)  
    connexion.row_factory = sqlite3.Row  # permet d’acceder aux colonnes par nom
    return connexion


# Authentifie un utilisateur par username et mot de passe
def authenticate_user(username, password):
    connexion = get_db()
    cursor = connexion.cursor()
    cursor.execute("SELECT id, password_hash FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    connexion.close()
    # Verifie si le hash du mot de passe correspond
    if row and row["password_hash"] == hashlib.sha256(password.encode()).hexdigest():
        return row["id"]  # retourne l'ID utilisateur
    return None


# Verifie si le code saisi correspond au code de l'utilisateur
def verify_user_code(user_id, code):
    connexion = get_db()
    cursor = connexion.cursor()
    cursor.execute("SELECT code_hash FROM user_codes WHERE user_id=?", (user_id,))
    row = cursor.fetchone()
    connexion.close()
    if row and row["code_hash"] == hashlib.sha256(code.encode()).hexdigest():
        return True
    return False


# Cree une session éphémère entre 2 utilisateurs
def create_session(user1_id, user2_id, user1_code, user2_code):
    connexion = get_db()
    cursor = connexion.cursor()
    # Tri des ID pour avoir une cle unique (peu importe l'ordre)
    key = tuple(sorted([user1_id, user2_id]))
    # Verifie si la session existe déjà
    cursor.execute("SELECT id FROM sessions WHERE user1_id=? AND user2_id=?", key)
    if not cursor.fetchone():
        # Stocke les codes saisis dans un JSON
        codes_json = json.dumps({str(user1_id): user1_code, str(user2_id): user2_code})
        cursor.execute("INSERT INTO sessions (user1_id, user2_id, active, codes_json) VALUES (?, ?, ?, ?)",
                       (key[0], key[1], 1, codes_json))
    connexion.commit()
    connexion.close()


# (
# -----------------------------
# -- Flask
# -----------------------------

# Page de login 
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user_id = authenticate_user(username, password)
        if user_id:
            # Sauvegarde info utilisateur dans session Flask
            session["user_id"] = user_id
            session["username"] = username
            return redirect(url_for("code_page"))
        else:
            return "Mot de passe incorrect"
    return render_template("login.html")  # formulaire HTML -- A MODIFIER

# Page pour saisir les codes pour activer la session de chat
@app.route("/code", methods=["GET", "POST"])
def code_page():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        peer_username = request.form["peer"]        # nom du pair
        user_code = request.form["user_code"]       # code de l'utilisateur
        peer_code = request.form["peer_code"]       # code du pair

        # Recupere l'ID du pair dans la base
        connexion = get_db()
        cursor = connexion.cursor()
        cursor.execute("SELECT id FROM users WHERE username=?", (peer_username,))
        row = cursor.fetchone()
        connexion.close()
        if not row:
            return "Utilisateur pair non trouvé"
        peer_id = row["id"]

        # Verifie les deux codes
        if verify_user_code(session["user_id"], user_code) and verify_user_code(peer_id, peer_code):
            # Cree la session ephemere active
            create_session(session["user_id"], peer_id, user_code, peer_code)
            return "Session activée ! Vous pouvez commencer à discuter."
        else:
            return "Codes invalides"

    return render_template("code.html")  # formulaire HTML pour codes -- A MODIFIER

# )




# -----------------------------
# -- Initialisation de la base
# -----------------------------

def init_db():
    # Connexion a SQLite
    connexion = get_db()
    cursor = connexion.cursor()

    # Creation table utilisateurs
    cursor.execute("CREATE TABLE IF NOT EXISTS users ("
                   "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                   "username TEXT UNIQUE,"
                   "password_hash TEXT,"
                   "encryption_key BLOB)")

    # Creation table codes secrets
    cursor.execute("CREATE TABLE IF NOT EXISTS user_codes ("
                   "user_id INTEGER UNIQUE,"
                   "code_hash TEXT,"
                   "FOREIGN KEY(user_id) REFERENCES users(id))")

    # Creation table sessions ephemeres
    cursor.execute("CREATE TABLE IF NOT EXISTS sessions ("
                   "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                   "user1_id INTEGER,"
                   "user2_id INTEGER,"
                   "active BOOLEAN,"
                   "codes_json TEXT,"
                   "FOREIGN KEY(user1_id) REFERENCES users(id),"
                   "FOREIGN KEY(user2_id) REFERENCES users(id))")




    # -----------------------------
    # -- Insertion de 4 utilisateurs test
    # -----------------------------
    users_list = [
        ("Alice", "mdp123", "123456"),
        ("Bob", "mdp456", "456798"),
        ("Charlie", "mdp789", "789000"),
        ("David", "mdp000", "000123")
    ]


    for username, password, code in users_list:
        # Verifie si l'utilisateur existe deja
        cursor.execute("SELECT id FROM users WHERE username=?", (username,))
        if cursor.fetchone():
            continue  # utilisateur deja présent

        # Hash du mot de passe
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        encryption_key = utils.random(secret.SecretBox.KEY_SIZE)

        # Insere l'utilisateur
        cursor.execute("INSERT INTO users (username, password_hash, encryption_key) VALUES (?, ?, ?)",
                       (username, password_hash, encryption_key))
        user_id = cursor.lastrowid

        # Insere son code secret
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        cursor.execute("INSERT INTO user_codes (user_id, code_hash) VALUES (?, ?)", (user_id, code_hash))

    connexion.commit()
    connexion.close()




# (

# -----------------------------
# -- Lancer le site
# -----------------------------

if __name__ == "__main__":
    init_db()       # initialise la base et cree les utilisateurs test
    app.run(debug=True)

# )
