import sqlite3
import threading
from datetime import datetime

# Thread-local storage for database connections
local = threading.local()


def get_db():
    """Get database connection for current thread"""
    if not hasattr(local, 'connection'):
        local.connection = sqlite3.connect('nexus_terminal.db', check_same_thread=False)
        local.connection.row_factory = sqlite3.Row
    return local.connection


def init_db():
    """Initialize database with required tables"""
    conn = get_db()
    cursor = conn.cursor()

    # Create messages table
    cursor.execute('''
                   CREATE TABLE IF NOT EXISTS messages
                   (
                       id
                       INTEGER
                       PRIMARY
                       KEY
                       AUTOINCREMENT,
                       username
                       TEXT
                       NOT
                       NULL,
                       basecamp
                       TEXT
                       NOT
                       NULL,
                       message
                       TEXT
                       NOT
                       NULL,
                       timestamp
                       DATETIME
                       DEFAULT
                       CURRENT_TIMESTAMP
                   )
                   ''')

    # Create user_sessions table (for tracking online users)
    cursor.execute('''
                   CREATE TABLE IF NOT EXISTS user_sessions
                   (
                       id
                       INTEGER
                       PRIMARY
                       KEY
                       AUTOINCREMENT,
                       username
                       TEXT
                       NOT
                       NULL,
                       basecamp
                       TEXT
                       NOT
                       NULL,
                       connected_at
                       DATETIME
                       DEFAULT
                       CURRENT_TIMESTAMP,
                       UNIQUE
                   (
                       username,
                       basecamp
                   )
                       )
                   ''')

    # Create basecamps table
    cursor.execute('''
                   CREATE TABLE IF NOT EXISTS basecamps
                   (
                       id
                       INTEGER
                       PRIMARY
                       KEY
                       AUTOINCREMENT,
                       code
                       TEXT
                       UNIQUE
                       NOT
                       NULL,
                       name
                       TEXT
                       NOT
                       NULL,
                       created_at
                       DATETIME
                       DEFAULT
                       CURRENT_TIMESTAMP
                   )
                   ''')

    # Insert default basecamp
    cursor.execute('''
                   INSERT
                   OR IGNORE INTO basecamps (code, name) 
        VALUES (?, ?)
                   ''', ('ALPHA-47X9', 'Alpha Base Camp - Sector 7'))

    conn.commit()


def add_message(username, basecamp, message):
    """Add a new message to the database"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
                   INSERT INTO messages (username, basecamp, message)
                   VALUES (?, ?, ?)
                   ''', (username, basecamp, message))

    conn.commit()


def get_recent_messages(basecamp, limit=50):
    """Get recent messages for a basecamp"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
                   SELECT username, message, timestamp
                   FROM messages
                   WHERE basecamp = ?
                   ORDER BY timestamp DESC
                       LIMIT ?
                   ''', (basecamp, limit))

    messages = cursor.fetchall()
    return [dict(row) for row in reversed(messages)]


def add_user_session(username, basecamp):
    """Add or update user session"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT OR REPLACE INTO user_sessions (username, basecamp, connected_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
    ''', (username, basecamp))

    conn.commit()


def remove_user_session(username, basecamp):
    """Remove user session"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
                   DELETE
                   FROM user_sessions
                   WHERE username = ?
                     AND basecamp = ?
                   ''', (username, basecamp))

    conn.commit()


def get_online_users(basecamp):
    """Get list of online users in a basecamp"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
                   SELECT username, connected_at
                   FROM user_sessions
                   WHERE basecamp = ?
                   ORDER BY connected_at ASC
                   ''', (basecamp,))

    users = cursor.fetchall()
    return [dict(row) for row in users]


def cleanup_old_sessions():
    """Clean up old sessions (can be called periodically)"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
                   DELETE
                   FROM user_sessions
                   WHERE connected_at < datetime('now', '-1 hour')
                   ''')

    conn.commit()


def get_message_count(basecamp):
    """Get total message count for a basecamp"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
                   SELECT COUNT(*) as count
                   FROM messages
                   WHERE basecamp = ?
                   ''', (basecamp,))

    result = cursor.fetchone()
    return result['count'] if result else 0