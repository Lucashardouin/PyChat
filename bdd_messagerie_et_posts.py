from flask import Flask, request, render_template, redirect, url_for, session, jsonify
import sqlite3
import hashlib
from nacl import secret, utils
import json
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired  # utile pour les tockens


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


# Cree une session ephemere entre 2 utilisateurs
def create_session(user1_id, user2_id, user1_code, user2_code):
    connexion = get_db()
    cursor = connexion.cursor()
    
    # Tri des ID pour avoir une cle unique (peu importe l'ordre)
    key = tuple(sorted([user1_id, user2_id]))
    
    # Clé messages (même format que la table messages)
    session_key = f"{min(user1_id, user2_id)}-{max(user1_id, user2_id)}"
    cursor.execute("DELETE FROM messages WHERE session_key=?", (session_key,))  

    
    # Verifie si la session existe deja
    cursor.execute("SELECT id FROM sessions WHERE user1_id=? AND user2_id=?", key)
    if not cursor.fetchone():
        # Stocke les codes saisis dans un JSON
        codes_json = json.dumps({str(user1_id): user1_code, str(user2_id): user2_code})
        cursor.execute("INSERT INTO sessions (user1_id, user2_id, active, codes_json) VALUES (?, ?, ?, ?)",
                       (key[0], key[1], 1, codes_json))
    connexion.commit()
    connexion.close()



# Dictionnaire global pour stocker les messages éphémères
# La clé est un tuple (user1_id, user2_id), les valeurs sont des listes de messages


# Fonction pour ajouter un message à une session éphémère
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




# ------------- FONCTIONS TOKEN UTILISATEURS  -----------------------------------------------------------

# Cree le sérialiseur qui signe/verifie les jetons datés avec la cle secrete Flask (salt = type de jeton)
def _chat_serializer():  
    return URLSafeTimedSerializer(app.secret_key, salt="chat-token")  


# Cree un jeton de chat pour l’onglet (contient uid + peer_id)
def issue_chat_token(user_id, peer_id):  
    s = _chat_serializer()
    return s.dumps({"uid": int(user_id), "peer_id": int(peer_id)})  


# Verifie signature + expiration et renvoie le payload
def verify_chat_token(token, max_age=3600):  
    s = _chat_serializer()
    return s.loads(token, max_age=max_age)  



# Renvoie l’ID user depuis le token si present, sinon depuis la session
def current_user_from_token_or_session(expected_peer_id=None):  
    
    # Recupere le token envoyé par le front (header / query / form)
    token = (request.headers.get("X-Chat-Token")                 
             or request.args.get("token")                        
             or request.form.get("token"))                       
    if token:                                                    
        try:                                                     
            data = verify_chat_token(token)    

            # Si un pair est attendu, vérifier que le token correspond                  
            if expected_peer_id is None or int(data["peer_id"]) == int(expected_peer_id):  
                return int(data["uid"])                          
        except (BadSignature, SignatureExpired):                 
            return None   
    # Fallback : cookie Flask                                        
    return session.get("user_id")                                


# Ajoute un post
def add_public_post(author_id: int, title: str, content: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO posts (author_id, title, content) VALUES (?, ?, ?)",
        (int(author_id), (title or "").strip(), content.strip())
    )
    conn.commit()
    conn.close()

# Récupère les derniers posts pour l'accueil
def fetch_public_posts(limit=50):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT p.id, p.title, p.content, p.created_at,
               u.username AS author
        FROM posts p
        LEFT JOIN users u ON u.id = p.author_id
        ORDER BY p.created_at DESC, p.id DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows



# --- TOKENS POSTS ------------------------------------------------------------

def _post_serializer():  
    return URLSafeTimedSerializer(app.secret_key, salt="post-token") 

def issue_post_token(user_id: int):  
    s = _post_serializer()
    return s.dumps({"uid": int(user_id)})  

def verify_post_token(token: str, max_age=3600): 
    s = _post_serializer()
    return s.loads(token, max_age=max_age)  # peut lever BadSignature/SignatureExpired



# (
# -----------------------------
# -- Flask 
# -----------------------------

# Page d'authentification : login.html
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
    return render_template("login.html")  # formulaire HTML d'authentification


# Page pour saisir les codes pour activer la session de chat : code.html
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
            # Renvoie la page avec la liste des posts
            posts = fetch_public_posts()
            return render_template(                     
                "code.html",
                posts=posts,
                error="Utilisateur pair non trouvé",
                current_username=session.get("username"),
                post_token=issue_post_token(session["user_id"])  # TOKEN POST
            )
        peer_id = row["id"]


        # Verifie les deux codes
        if verify_user_code(session["user_id"], user_code) and verify_user_code(peer_id, peer_code):
            # Cree la session ephemere active
            create_session(session["user_id"], peer_id, user_code, peer_code)
            return redirect(url_for("chat_page", peer_id=peer_id))  # redirection vers page de chat 
        else:
            # Renvoie la page avec la liste des posts
            posts = fetch_public_posts()
            return render_template("code.html",                            
                                   posts=posts,                            
                                   error="Codes invalides",
                                   #current_username=session.get("username"),                 (pas obligatoire mais utile)
                                   post_token=issue_post_token(session["user_id"]) 
                                   ) 

    # Renvoie la page avec les posts
    posts = fetch_public_posts() 
     # formulaire HTML pour codes incluant le token
    return render_template(                           
        "code.html",
        posts=posts,
        current_username=session.get("username"),
        post_token=issue_post_token(session["user_id"])  # TOKEN POSTS
    )




# Page de messagerie : messagerie.html
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

    # TOCKEN
    chat_token = issue_chat_token(user_id, peer_id) ##

    return render_template(
        "messagerie.html",
        peer_id=peer_id,
        current_user_id=user_id,
        # Récuperer le nom d'utilisateur
        peer_name=peer_name,
        current_username=session.get("username", "Moi"),
        # TOCKEN
        chat_token=chat_token, #
    )


# Route pour envoyer un message
@app.route("/send_message/<int:peer_id>", methods=["POST"])
def send_message(peer_id):
    #user_id = session.get("user_id")   - TOCKEN
    user_id = current_user_from_token_or_session(expected_peer_id=peer_id) #

    if not user_id:
        return jsonify({"error": "not logged in"}), 403
    msg = request.form["message"]
    add_message(user_id, peer_id, msg)
    return jsonify({"status": "ok"})



# Route pour recuperer les messages ephemeres en JSON
@app.route("/get_messages/<int:peer_id>")
def get_messages(peer_id):
    # current_user = session.get("user_id") - TOCKEN
    current_user = current_user_from_token_or_session(expected_peer_id=peer_id) #

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



# Route pour publier un post
@app.post("/add_post")
def add_post_route():
    # Lire/Vérifier le jeton d'auteur fourni par l'onglet
    token = (request.form.get("post_token") or "").strip()
    try:
        data = verify_post_token(token)               # -> {'uid': ...}
        author_id = int(data["uid"])
    except (BadSignature, SignatureExpired, KeyError):
        return redirect(url_for("login"))

    title   = (request.form.get("title")   or "").strip()
    content = (request.form.get("content") or "").strip()

    if not content:
        posts = fetch_public_posts()
        return render_template(
            "code.html",
            posts=posts,
            error="Le contenu du post est vide.",
            current_username=session.get("username"),
            post_token=issue_post_token(author_id)     # renvoyer un nouveau jeton
        )

    add_public_post(author_id, title, content)        # <- signature à 3 params
    return redirect(url_for("code_page"))





# --- API JSON: liste des posts (lecture seule) -------------------------------
@app.get("/api/posts")
def api_posts():
    if "user_id" not in session:
        # les utilisateurs connectés uniquement peuvent s'y connecter
        return jsonify([]), 403
    return jsonify(fetch_public_posts())  # liste de dicts {id,title,content,created_at,author}



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



    # Creation table posts
    cursor.execute("""CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                author_id INTEGER NOT NULL,
                title TEXT,                 -- NEW: titre
                content TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(author_id) REFERENCES users(id))""")

        # Si la BDD existe déjà sans 'title', on l'ajoute (SQLite autorise ADD COLUMN)
    try:
        cursor.execute("ALTER TABLE posts ADD COLUMN title TEXT")
    except sqlite3.OperationalError:
        pass  # colonne déjà présente, on ignore



    # -----------------------------
    # -- Insertion de 4 utilisateurs test
    # -----------------------------
    # utilisateur, mot de passe, code secret
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
            continue  # utilisateur deja present

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

#if __name__ == "__main__":
#    init_db()       # initialise la base et cree les utilisateurs test
#    app.run(debug=True)


#if __name__ == "__main__":
#    init_db()
#    app.run(debug=True, threaded=True)

if __name__ == "__main__":
    init_db()
    app.run(debug=True, use_reloader=False)


# )
