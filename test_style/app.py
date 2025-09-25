from flask import Flask, render_template, request, jsonify, session, make_response, redirect, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room, rooms
import json
import hashlib
from datetime import datetime
import db
import closing_session

app = Flask(__name__)
app.config['SECRET_KEY'] = 'nexus_terminal_2087_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Base camp codes (expandable for multiple camps)
BASE_CAMP_CODES = {
    'ALPHA-47X9': 'Alpha Base Camp - Sector 7'
}

# Initialize database
db.init_db()


def verify_user(username, password):
    """Verify user credentials"""
    try:
        with open('users.json', 'r') as f:
            users = json.load(f)

        if username in users:
            # Hash the provided password and compare
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            return users[username]['password'] == hashed_password
        return False
    except FileNotFoundError:
        return False


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=["GET","POST"])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if verify_user(username, password):
        session['username'] = username
        session['authenticated'] = True
        session["last_activity"] = datetime.utcnow().timestamp()
        return jsonify({'success': True, 'message': f'Welcome back, {username}'})
    else:
        return jsonify({'success': False, 'message': 'Invalid credentials. Access denied.'})


@app.route('/verify_basecamp', methods=['POST'])
def verify_basecamp():
    if not session.get('authenticated'):
        return jsonify({'success': False, 'message': 'Authentication required'})

    data = request.get_json()
    basecamp_code = data.get('basecamp_code', '').upper()

    if basecamp_code in BASE_CAMP_CODES:
        session['basecamp'] = basecamp_code
        session['basecamp_name'] = BASE_CAMP_CODES[basecamp_code]
        return jsonify({
            'success': True,
            'message': f'Access granted to {BASE_CAMP_CODES[basecamp_code]}',
            'basecamp_name': BASE_CAMP_CODES[basecamp_code]
        })
    else:
        return jsonify({'success': False, 'message': 'Invalid base camp code. Access denied.'})


@app.route('/basecamp')
def basecamp():
    if not session.get('authenticated') or not session.get('basecamp'):
        return render_template('index.html')

    return render_template('basecamp.html',
                           username=session.get('username'),
                           basecamp_name=session.get('basecamp_name'),
                           basecamp_code=session.get('basecamp'))


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    resp = make_response(redirect(url_for("login")))
    resp.set_cookie("session", "", expires=0)
    return jsonify({'success': True, 'message': 'Disconnected from network'})


@app.route('/end_chat', methods=['POST'])
def end_chat():
    session.pop('basecamp', None)
    session.pop('basecamp_name', None)
    return jsonify({'success': True, 'message': 'Chat session terminated'})


# Socket.IO events for real-time chat
@socketio.on('connect')
def on_connect():
    if session.get('authenticated') and session.get('basecamp'):
        username = session.get('username')
        basecamp = session.get('basecamp')
        join_room(basecamp)

        # Store user info in database
        db.add_user_session(username, basecamp)

        # Notify others in the same basecamp
        emit('user_joined', {
            'username': username,
            'message': f'{username} has connected to the network',
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }, room=basecamp, include_self=False)

        # Send system message to user
        emit('system_message', {
            'message': f'Connected to {session.get("basecamp_name")}. Communication channel open.',
            'timestamp': datetime.now().strftime('%H:%M:%S')
        })


@socketio.on('disconnect')
def on_disconnect():
    if session.get('authenticated') and session.get('basecamp'):
        username = session.get('username')
        basecamp = session.get('basecamp')

        # Remove user session from database
        db.remove_user_session(username, basecamp)

        # Notify others
        emit('user_left', {
            'username': username,
            'message': f'{username} has disconnected from the network',
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }, room=basecamp, include_self=False)

        leave_room(basecamp)


@socketio.on('send_message')
def handle_message(data):
    if session.get('authenticated') and session.get('basecamp'):
        username = session.get('username')
        basecamp = session.get('basecamp')
        message = data.get('message', '').strip()

        if message:
            # Store message in database
            db.add_message(username, basecamp, message)

            # Broadcast to all users in the same basecamp
            emit('new_message', {
                'username': username,
                'message': message,
                'timestamp': datetime.now().strftime('%H:%M:%S')
            }, room=basecamp)


@socketio.on('get_online_users')
def get_online_users():
    if session.get('authenticated') and session.get('basecamp'):
        basecamp = session.get('basecamp')
        users = db.get_online_users(basecamp)
        emit('online_users_update', {'users': users})


if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)