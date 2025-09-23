# streamlit_app.py
import streamlit as st
import streamlit.components.v1 as components
import json, html

st.set_page_config(page_title="LAN Secure Chat", page_icon="🔐", layout="centered")
st.title("🔐 LAN Secure Chat (accounts + Secret Connect Key)")

sig_url = st.text_input(
    "Signaling/API server URL",
    value="http://10.0.0.1:5000",
    help="Your Pi's Flask server (same one that serves /socket.io/socket.io.js)"
)

tabs = st.tabs(["Register", "Login", "Chat"])

# ------------ HTML blocks as PLAIN strings (NOT f-strings). ------------
REGISTER_HTML = r"""
<!doctype html>
<html><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<script src="__SOCK__/socket.io/socket.io.js"></script>
<style> body{font-family:system-ui,sans-serif;margin:0}.wrap{padding:12px} </style>
</head>
<body><div class="wrap"><div id="out">Working…</div></div>
<script>
(async () => {
  // STREAMLIT injects this value via .replace
  const CFG = __CFG__;

  // ---------- helpers ----------
  const enc = new TextEncoder();
  const b64 = a => btoa(String.fromCharCode(...new Uint8Array(a)));
  const api = (p, body) =>
    fetch(CFG.api + p, {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(body)})
      .then(r=>r.json());

  async function sha256(bytes){ return await crypto.subtle.digest("SHA-256", bytes); }

  async function deriveWrapKey(password, salt){
    const baseKey = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    return await crypto.subtle.deriveKey(
      {name:"PBKDF2", hash:"SHA-256", salt, iterations: 200_000},
      baseKey,
      {name:"AES-GCM", length:256},
      false,
      ["encrypt","decrypt"]
    );
  }

  // 1) ECDH P-256 keypair
  const kp = await crypto.subtle.generateKey(
    {name:"ECDH", namedCurve:"P-256"},
    true, ["deriveBits","deriveKey"]
  );
  const pub_spki   = await crypto.subtle.exportKey("spki",  kp.publicKey);
  const priv_pkcs8 = await crypto.subtle.exportKey("pkcs8", kp.privateKey);

  // 2) Human-friendly Secret Connect Key
  const raw = crypto.getRandomValues(new Uint8Array(10));
  const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
  let bits=0, acc=0, out=[];
  for (let i=0;i<raw.length;i++){ acc=(acc<<8)|raw[i]; bits+=8; while(bits>=5){bits-=5; out.push((acc>>bits)&31);} }
  while(out.length<16) out.push(0);
  const SECRET = [0,4,8,12].map(i=> out.slice(i,i+4).map(j=>alphabet[j]).join("")).join("-");

  // 3) code_hash = base64(SHA256("code-namespace:"+SECRET))
  const code_hash = b64(await sha256(new TextEncoder().encode("code-namespace:" + SECRET)));

  // 4) Encrypt private key with password-derived AES-GCM
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const wrapKey = await deriveWrapKey(CFG.password, salt);
  const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv}, wrapKey, priv_pkcs8);
  const enc_blob = new Uint8Array([...salt, ...iv, ...new Uint8Array(ct)]); // pack

  // 5) Register
  const resp = await api("/api/register", {
    username:   CFG.username,
    password:   CFG.password,
    public_key: b64(pub_spki),       // SPKI form
    enc_private: b64(enc_blob),      // [salt||iv||ciphertext]
    code_hash
  });
  if (!resp.ok){
    document.getElementById("out").textContent = "Error: " + (resp.error || "register failed");
    return;
  }

  // 6) Show the secret once
  alert("Your Secret Connect Key (save this):\n\n" + SECRET + "\n\nShown once; not stored in plaintext.");
  document.getElementById("out").innerHTML = "✅ Account created. Secret key shown in popup.";
})();
</script>
</body></html>
"""

LOGIN_HTML = r"""
<!doctype html>
<html><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<script src="__SOCK__/socket.io/socket.io.js"></script>
<style> body{font-family:system-ui,sans-serif;margin:0}.wrap{padding:12px} </style>
</head>
<body><div class="wrap"><div id="out">Logging in…</div></div>
<script>
(async () => {
  const CFG = __CFG__;

  const enc = new TextEncoder();
  const fromB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const api = (p, body) =>
    fetch(CFG.api + p, {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(body)})
      .then(r=>r.json());

  async function deriveWrapKey(password, salt){
    const baseKey = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    return await crypto.subtle.deriveKey(
      {name:"PBKDF2", hash:"SHA-256", salt, iterations: 200_000},
      baseKey,
      {name:"AES-GCM", length:256},
      false,
      ["encrypt","decrypt"]
    );
  }

  const resp = await api("/api/login", {username: CFG.username, password: CFG.password});
  if (!resp.ok){
    document.getElementById("out").textContent = "Error: " + (resp.error || "login failed");
    return;
  }

  // Unpack enc_private: [salt(16) || iv(12) || ciphertext]
  const blob = fromB64(resp.enc_private);
  const salt = blob.slice(0,16);
  const iv   = blob.slice(16, 28);
  const ct   = blob.slice(28);

  const wrapKey = await deriveWrapKey(CFG.password, salt);
  let priv_pkcs8;
  try {
    priv_pkcs8 = await crypto.subtle.decrypt({name:"AES-GCM", iv}, wrapKey, ct);
  } catch(e){
    document.getElementById("out").textContent = "Error: wrong password (cannot decrypt)";
    return;
  }

  // Import keys for use in Chat tab
  const pubKey  = await crypto.subtle.importKey(
    "spki",
    Uint8Array.from(atob(resp.public_key), c=>c.charCodeAt(0)),
    {name:"ECDH", namedCurve:"P-256"},
    true, []
  );
  const privKey = await crypto.subtle.importKey(
    "pkcs8",
    priv_pkcs8,
    {name:"ECDH", namedCurve:"P-256"},
    true, ["deriveBits","deriveKey"]
  );

  // Stash in this iframe (optional)
    window.ME = { username: CFG.username, pubKey, privKey, unlocked: !!resp.unlocked };

    // Also persist across iframes in THIS browser tab.
    // Store the raw key material so another iframe can import it.
    const priv_pkcs8_b64 = btoa(String.fromCharCode(...new Uint8Array(priv_pkcs8))); // we still have priv_pkcs8 (ArrayBuffer)
    const payload = {
    username: CFG.username,
    // we already got public_key from the server; keep the same base64
    pub_spki_b64: resp.public_key,
    priv_pkcs8_b64: priv_pkcs8_b64,
    unlocked: !!resp.unlocked
    };
    sessionStorage.setItem("lanchat_me", JSON.stringify(payload));

    document.getElementById("out").innerHTML =
    "✅ Logged in as <b>"+CFG.username+"</b> — Unlocked: <b>"+(resp.unlocked?"Yes":"No")+"</b>";

})();
</script>
</body></html>
"""

CHAT_HTML = r"""
<!doctype html>
<html><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<script src="__SOCK__/socket.io/socket.io.js"></script>
<style>
 body{font-family:system-ui,sans-serif;margin:0}.wrap{padding:12px}
 .row{display:grid;gap:8px;grid-template-columns:1fr 1fr}
 input,button{padding:.6rem;border-radius:10px;border:1px solid #ccc}
 #msgs{height:260px;overflow:auto;padding:10px;border:1px dashed #ddd;border-radius:10px;background:#fafafa}
 .me{background:#e9f5ff;padding:.3rem .5rem;border-radius:10px;margin:.2rem 0}
 .peer{background:#f3f3f3;padding:.3rem .5rem;border-radius:10px;margin:.2rem 0}
 .lock{color:#666}
</style>
</head>
<body><div class="wrap">
  <div id="status">Loading…</div>
  <div id="who" style="font-family:ui-monospace, Menlo, monospace; margin:6px 0;"></div>
  <div id="msgs"></div>
  <div class="row" style="margin-top:8px;">
    <input id="msg" placeholder="Type message…"/><button id="send">Send</button>
  </div>
  <div style="margin-top:8px;">
    <button id="end">End & Wipe</button>
  </div>
</div>
<script>
(async () => {
  const CFG = __CFG__;

  const $ = id => document.getElementById(id);
  const enc = new TextEncoder(), dec = new TextDecoder();
  const b64 = a => btoa(String.fromCharCode(...new Uint8Array(a)));
  const fromB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const api = (p, body) =>
    fetch(CFG.api + p, {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(body)})
      .then(r=>r.json());

  const saved = sessionStorage.getItem("lanchat_me");
    if (!saved) { $("status").textContent = "❌ You must Login first (Tab 2)."; return; }
    const savedME = JSON.parse(saved);

    // Import keys from storage
    const pubKey = await crypto.subtle.importKey(
    "spki",
    Uint8Array.from(atob(savedME.pub_spki_b64), c => c.charCodeAt(0)),
    {name:"ECDH", namedCurve:"P-256"},
    true, []
    );
    const privKey = await crypto.subtle.importKey(
    "pkcs8",
    Uint8Array.from(atob(savedME.priv_pkcs8_b64), c => c.charCodeAt(0)),
    {name:"ECDH", namedCurve:"P-256"},
    true, ["deriveBits","deriveKey"]
    );

    const ME = { username: savedME.username, pubKey, privKey, unlocked: !!savedME.unlocked };
    $("who").textContent = `You: ${ME.username} | Unlocked: ${ME.unlocked ? "Yes" : "No"}`;

  // Discover peer by Secret Connect Key (base64(SHA256("code-namespace:"+secret)))
  const peerSecret = (CFG.peer_secret || "").trim(); // keep dashes exactly as shown at register

  if (!peerSecret){ $("status").textContent = "❌ Enter peer secret."; return; }
  const code_hash = b64(await crypto.subtle.digest("SHA-256", enc.encode("code-namespace:" + peerSecret)));
  const lookup = await api("/api/lookup_by_code", {code_hash});
  if (!lookup.ok){ $("status").textContent = "❌ Peer not found for that secret."; return; }
  $("who").textContent += " | Peer: " + lookup.username;

  // Import peer public key (SPKI)
  const peerPubKey = await crypto.subtle.importKey(
    "spki",
    Uint8Array.from(atob(lookup.public_key), c=>c.charCodeAt(0)),
    {name:"ECDH", namedCurve:"P-256"},
    true, []
  );

  // ECDH -> HKDF -> AES-GCM session key
  const sharedBits = await crypto.subtle.deriveBits({name:"ECDH", public: peerPubKey}, ME.privKey, 256);
  const hkdfKey = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  const sessionKey = await crypto.subtle.deriveKey(
    {name:"HKDF", hash:"SHA-256", salt: enc.encode("room:"+CFG.room), info: enc.encode("lan-chat")},
    hkdfKey,
    {name:"AES-GCM", length:256},
    false,
    ["encrypt","decrypt"]
  );

  // short fingerprint for comparison
  const fpTest = await crypto.subtle.encrypt({name:"AES-GCM", iv: new Uint8Array(12)}, sessionKey, new Uint8Array(0));
  const fpBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", fpTest)).slice(0,6);
  const fp = Array.from(fpBytes).map(b=>b.toString(16).padStart(2,"0")).join(":");
  $("who").textContent += " | FP: " + fp;

  async function encryptText(text){
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv}, sessionKey, enc.encode(text));
    return { iv: b64(iv), c: b64(ct) };
  }
  async function decryptText(iv_b64, c_b64){
    const iv = fromB64(iv_b64);
    const pt = await crypto.subtle.decrypt({name:"AES-GCM", iv}, sessionKey, fromB64(c_b64));
    return dec.decode(pt);
  }

  // Socket.IO signaling + optional relay
  const socket = io(CFG.api); // allow polling fallback
  const rtcCfg = { iceServers: [] };
  let pc = null, dc = null;
  socket.on("connect", () => status("Connected to signaling server"));
  socket.on("connect_error", (err) => status("Socket connect_error: " + err.message));
  socket.on("error", (err) => status("Socket error: " + err));


  function add(me, txt, locked=false){
    const d = document.createElement("div");
    d.className = me ? "me" : "peer";
    d.textContent = locked ? "🔒 Encrypted (enter Unlock Code)" : txt;
    if (locked) d.classList.add("lock");
    $("msgs").appendChild(d); $("msgs").scrollTop = $("msgs").scrollHeight;
  }

  function sendPacket(obj){
    if (dc && dc.readyState === "open"){
      dc.send(JSON.stringify(obj));
    } else if (!CFG.p2p_only){
      socket.emit("relay_send", {
        room: CFG.room, from: ME.username, to: lookup.username,
        ciphertext_b64: b64(new TextEncoder().encode(JSON.stringify(obj)))
      });
    } else {
      alert("P2P not ready and relay disabled.");
    }
  }

  function onData(ev){
    try {
      const obj = JSON.parse(ev.data);
      if (obj.t === "msg"){
        if (!ME.unlocked) add(false, "", true);
        else decryptText(obj.i, obj.c).then(txt => add(false, txt, false));
      }
    } catch(e){}
  }

  socket.on("relay_recv", (pkt) => {
    try {
      const obj = JSON.parse(new TextDecoder().decode(fromB64(pkt.ciphertext_b64)));
      if (obj.t === "msg"){
        if (!ME.unlocked) add(false, "", true);
        else decryptText(obj.i, obj.c).then(txt => add(false, txt, false));
      }
    } catch(e){}
  });

  async function start(isCaller){
    pc = new RTCPeerConnection(rtcCfg);
    pc.onconnectionstatechange = () => $("status").textContent = "WebRTC: " + pc.connectionState;
    pc.onicecandidate = (e) => e.candidate && socket.emit("signal", {room: CFG.room, from: ME.username, type:"ice", payload: e.candidate});
    pc.ondatachannel = (e) => { dc = e.channel; dc.onopen = () => $("status").textContent = "P2P channel open"; dc.onmessage = onData; };
    if (isCaller){
      dc = pc.createDataChannel("chat");
      dc.onopen = () => $("status").textContent = "P2P channel open";
      dc.onmessage = onData;
      const offer = await pc.createOffer(); await pc.setLocalDescription(offer);
      socket.emit("signal", {room: CFG.room, from: ME.username, type:"offer", payload: offer});
    }
  }

  socket.on("connect", () => socket.emit("join_room", {room: CFG.room, username: ME.username}));
  socket.on("presence", (p) => { $("status").textContent = "Room: "+CFG.room+" | Members: "+p.members.join(", "); if (!pc) start(p.members.length>1); });
  socket.on("signal", async (sig) => {
    if (!pc) start(false);
    if (sig.type === "offer"){
      await pc.setRemoteDescription(new RTCSessionDescription(sig.payload));
      const answer = await pc.createAnswer(); await pc.setLocalDescription(answer);
      socket.emit("signal", {room: CFG.room, from: ME.username, type:"answer", payload: answer});
    } else if (sig.type === "answer"){
      await pc.setRemoteDescription(new RTCSessionDescription(sig.payload));
    } else if (sig.type === "ice"){
      try { await pc.addIceCandidate(new RTCIceCandidate(sig.payload)); } catch(e){}
    }
  });

  document.getElementById("send").onclick = async () => {
    const t = document.getElementById("msg").value.trim(); if (!t) return;
    const p = await encryptText(t);
    sendPacket({t:"msg", i:p.iv, c:p.c});
    if (!ME.unlocked) add(true, "", true); else add(true, t, false);
    document.getElementById("msg").value = "";
  };
  document.getElementById("end").onclick = () => {
    socket.emit("end_chat", {room: CFG.room});
    try { if (dc) dc.close(); if (pc) pc.close(); } catch(e){}
    $("status").textContent = "Chat ended.";
  };
})();
</script>
</body></html>
"""

# ----------------------- TAB 1: Register -----------------------
with tabs[0]:
    st.markdown("Create an account. You'll get a **Secret Connect Key** — shown once — to share with contacts.")
    col1, col2 = st.columns(2)
    with col1:
        r_user = st.text_input("Username", key="r_user", value="alice")
    with col2:
        r_pass = st.text_input("Password", key="r_pass", type="password")

    if st.button("Create account"):
        cfg = {"api": sig_url.rstrip("/"), "username": r_user, "password": r_pass}
        html_app = REGISTER_HTML.replace("__SOCK__", html.escape(sig_url.rstrip("/"))) \
                                .replace("__CFG__", json.dumps(cfg))
        components.html(html_app, height=260, scrolling=False)

# ----------------------- TAB 2: Login --------------------------
with tabs[1]:
    st.markdown("Login to decrypt your private key **locally** (stays in this browser memory).")
    col1, col2 = st.columns(2)
    with col1:
        l_user = st.text_input("Username", key="l_user", value="alice")
    with col2:
        l_pass = st.text_input("Password", key="l_pass", type="password")

    if st.button("Login"):
        cfg = {"api": sig_url.rstrip("/"), "username": l_user, "password": l_pass}
        html_app = LOGIN_HTML.replace("__SOCK__", html.escape(sig_url.rstrip("/"))) \
                             .replace("__CFG__", json.dumps(cfg))
        components.html(html_app, height=200, scrolling=False)

# ----------------------- TAB 3: Chat ---------------------------
with tabs[2]:
    st.markdown("Enter the **other person's Secret Connect Key** to fetch their public key and start an E2E chat.")
    c_user = st.text_input("Your username (must be logged in above)", key="c_user", value="alice")
    c_room = st.text_input("Room name (anything both sides agree on)", key="c_room", value="room-1")
    c_secret = st.text_input("Peer's Secret Connect Key (e.g., K7F3-WQ2M-9JH4-ABCD)", key="c_secret")
    p2p_only = st.checkbox("Enforce P2P only (disable relay fallback)", value=False)

    if st.button("Start chat"):
        cfg = {
            "api": sig_url.rstrip("/"),
            "username": c_user,
            "room": c_room,
            "peer_secret": c_secret,
            "p2p_only": p2p_only
        }
        html_app = CHAT_HTML.replace("__SOCK__", html.escape(sig_url.rstrip("/"))) \
                            .replace("__CFG__", json.dumps(cfg))
        components.html(html_app, height=640, scrolling=True)
