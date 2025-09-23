# signaling_server.py
from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
from argon2 import PasswordHasher
from argon2.low_level import hash_secret, Type
import time, os, base64, secrets
from flask_cors import CORS

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["SECRET_KEY"] = "replace-with-random-secret"

# Allow cross-origin requests from the Streamlit UI to /api/*
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=False)

# Socket.IO already allows cross-origin websockets:
socketio = SocketIO(app, cors_allowed_origins="*")

ph = PasswordHasher()

# In-memory "db" for demo. Replace with sqlite if you like.
USERS = {}  # username -> {pwd_hash, pubkey_b64, enc_priv_b64, k_salt_b64, created}
CODES = {}  # code_hash (str) -> username
ROOMS = {}  # room -> {created, members:set}
RELAY = {}  # room -> [ciphertext packets]

@app.get("/")
def home():
    return "Signaling + API server up. Static assets at /static/"

# ---------- REST: Accounts ----------

def argon2id_hash_bytes(data: bytes, salt: bytes) -> str:
    # Strong Argon2id (server-side) for "secret connect key" hashing
    h = hash_secret(
        secret=data,
        salt=salt,
        time_cost=3,
        memory_cost=64*1024,
        parallelism=2,
        hash_len=32,
        type=Type.ID
    )
    # return as urlsafe base64 for compact db key
    return base64.urlsafe_b64encode(h).decode()

@app.post("/api/register")
def api_register():
    """
    Expects JSON:
    {
      "username": "...",
      "password": "...",              # plaintext to hash server-side (or send hash if you prefer)
      "public_key": "base64",
      "enc_private": "base64",        # client-side encrypted with password-derived key
      "code_hash": "string",          # Argon2id hash (urlsafe b64) of the Secret Connect Key (client never sends plaintext)
    }
    """
    data = request.get_json(force=True)
    u = data.get("username","").strip()
    p = data.get("password","")
    pub = data.get("public_key")
    encp = data.get("enc_private")
    code_hash = data.get("code_hash")

    if not (u and p and pub and encp and code_hash):
        return jsonify({"error":"missing fields"}), 400
    if u in USERS:
        return jsonify({"error":"username exists"}), 409
    if code_hash in CODES:
        return jsonify({"error":"secret key already used"}), 409

    pwd_hash = ph.hash(p)
    USERS[u] = {
        "pwd_hash": pwd_hash,
        "pubkey_b64": pub,
        "enc_priv_b64": encp,
        "created": time.time()
    }
    CODES[code_hash] = u
    return jsonify({"ok": True})

@app.post("/api/login")
def api_login():
    """
    Expects JSON: {"username":"...", "password":"..."}
    Returns encrypted private key blob (base64) and your public key.
    """
    data = request.get_json(force=True)
    u = data.get("username","").strip()
    p = data.get("password","")
    if u not in USERS:
        return jsonify({"error":"no such user"}), 404
    try:
        ph.verify(USERS[u]["pwd_hash"], p)
    except Exception:
        return jsonify({"error":"invalid credentials"}), 401
    return jsonify({
        "ok": True,
        "public_key": USERS[u]["pubkey_b64"],
        "enc_private": USERS[u]["enc_priv_b64"]
    })

@app.post("/api/lookup_by_code")
def api_lookup_by_code():
    """
    Expects JSON: {"code_hash":"..."}   # Argon2id hash (urlsafe b64) the client computed for the peer's Secret Connect Key
    Returns: {"ok":True, "username": "...", "public_key":"base64"} if found
    """
    data = request.get_json(force=True)
    code_hash = data.get("code_hash","")
    u = CODES.get(code_hash)
    if not u:
        return jsonify({"ok": False})
    return jsonify({"ok": True, "username": u, "public_key": USERS[u]["pubkey_b64"]})

# ---------- Socket.IO: presence / signaling / relay ----------

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
            ROOMS.pop(r, None); RELAY.pop(r, None)
    except KeyError:
        pass

@socketio.on("signal")
def on_signal(data):
    # {room, from, type:"offer"/"answer"/"ice", payload}
    if not data or not data.get("room"): return
    emit("signal", data, room=data["room"], include_self=False)

@socketio.on("relay_send")
def on_relay_send(data):
    r = data.get("room")
    if not r: return
    RELAY.setdefault(r, []).append(data)
    emit("relay_recv", data, room=r, include_self=False)

@socketio.on("end_chat")
def on_end_chat(data):
    r = data.get("room")
    if not r: return
    RELAY.pop(r, None)
    emit("chat_ended", {"room": r}, room=r)

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)
