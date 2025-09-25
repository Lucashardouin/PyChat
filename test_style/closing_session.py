from flask import Flask, request, render_template, redirect, url_for, session, jsonify, make_response, flash, get_flashed_messages
import sqlite3
import hashlib
from nacl import secret, utils
import json
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired  # utile pour les tockens
from datetime import datetime, timedelta
from flask.sessions import SecureCookieSessionInterface
import db
import app


app.config["SESSION_PERMANENT"] = False

# Timeout d’inactivité (ex: 10 min)

INACTIVITY_TIMEOUT = 15 


app.secret_key = utils.random(secret.SecretBox.KEY_SIZE)


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
