from flask import Flask, render_template, request, jsonify, session, g
import json
import os
import base64
import secrets
import string
import sqlite3
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pyotp
import qrcode
import io
import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Database and log files
DB_FILE = "vault.db"
LOG_FILE = "audit.log"

# Session timeout (15 minutes)
SESSION_TIMEOUT = timedelta(minutes=15)

# Setup logging
def setup_logging():
    handler = RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5)
    handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    return app.logger

logger = setup_logging()

# Rate limiter setup
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["100 per hour"],
    storage_uri="memory://"
)

# Global key for session
encryption_key = None


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_FILE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """Initialize the SQLite database with all tables"""
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT FALSE,
            two_fa_secret TEXT,
            two_fa_enabled BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            site TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            category TEXT DEFAULT 'uncategorized',
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used TIMESTAMP,
            expiry_days INTEGER DEFAULT 90,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            password_id INTEGER,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (password_id) REFERENCES passwords(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS secure_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            category TEXT DEFAULT 'personal',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_passwords_user ON passwords(user_id);
        CREATE INDEX IF NOT EXISTS idx_passwords_site ON passwords(site);
        CREATE INDEX IF NOT EXISTS idx_passwords_category ON passwords(category);
        CREATE INDEX IF NOT EXISTS idx_notes_user ON secure_notes(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
    ''')
    db.commit()


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def get_user_by_username(username: str):
    """Get user from database by username"""
    db = get_db()
    cursor = db.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()


def create_user(username: str, password: str, is_admin: bool = False):
    """Create a new user in the database"""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(key)
    password_hash = base64.b64encode(hasher.finalize()).decode()
    totp_secret = pyotp.random_base32()

    db = get_db()
    db.execute(
        "INSERT INTO users (username, password_hash, salt, is_admin, two_fa_secret) VALUES (?, ?, ?, ?, ?)",
        (username, password_hash, base64.b64encode(salt).decode(), is_admin, totp_secret)
    )
    db.commit()

    return key, totp_secret


def verify_user_password(password: str, salt_b64: str, stored_hash: str) -> bytes:
    """Verify user password and return derived key"""
    salt = base64.b64decode(salt_b64)
    key = derive_key(password, salt)
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(key)
    computed_hash = base64.b64encode(hasher.finalize()).decode()

    if computed_hash == stored_hash:
        return key
    return None


def encrypt_password(password: str, key: bytes) -> str:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(password.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode()


def decrypt_password(encoded: str, key: bytes) -> str:
    data = base64.b64decode(encoded)
    iv = data[:16]
    encrypted = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    return decrypted.decode()


def generate_password(length=16, use_symbols=True):
    chars = string.ascii_letters + string.digits
    if use_symbols:
        chars += "!@#$%^&*()_+-="
    return ''.join(secrets.choice(chars) for _ in range(length))


def check_password_strength(password: str) -> dict:
    """Check password strength and return detailed analysis"""
    score = 0
    feedback = []

    if len(password) >= 8:
        score += 1
    elif len(password) >= 12:
        score += 2
    elif len(password) >= 16:
        score += 3

    if any(c.isupper() for c in password) and any(c.islower() for c in password):
        score += 1
        feedback.append("Good: Uses mixed case")

    if any(c.isdigit() for c in password):
        score += 1
        feedback.append("Good: Contains numbers")

    if any(c in "!@#$%^&*()_+-=" for c in password):
        score += 1
        feedback.append("Good: Contains symbols")

    if len(password) < 12:
        feedback.append("Consider using 12+ characters")

    strength = "weak"
    if score >= 5:
        strength = "strong"
    elif score >= 3:
        strength = "medium"

    return {
        "score": score,
        "strength": strength,
        "feedback": feedback
    }


def check_password_pwned(password: str) -> bool:
    """Check if password appears in known breaches using SHA1 hash"""
    import urllib.request
    import ssl

    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    try:
        context = ssl.create_default_context()
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        with urllib.request.urlopen(url, context=context, timeout=5) as response:
            data = response.read().decode()
            for line in data.split('\n'):
                if ':' in line:
                    hash_suffix, count = line.strip().split(':')
                    if hash_suffix == suffix:
                        return True
    except Exception:
        pass  # Silently fail if API unavailable
    return False


def log_audit(action: str, details: str = "", ip: str = None):
    """Log an audit event to database and file"""
    try:
        db = get_db()
        db.execute(
            "INSERT INTO audit_log (action, username, details, ip_address) VALUES (?, ?, ?, ?)",
            (action, session.get('username', 'system'), details, ip or request.remote_addr)
        )
        db.commit()
        logger.info(f"AUDIT: {action} - {details} by {session.get('username', 'system')}")
    except Exception as e:
        logger.error(f"Failed to log audit: {e}")


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return jsonify({'error': 'Not authenticated'}), 401

        # Check session timeout
        last_activity = session.get('last_activity')
        if last_activity:
            last_dt = datetime.fromisoformat(last_activity)
            if datetime.now() - last_dt > SESSION_TIMEOUT:
                session.clear()
                return jsonify({'error': 'Session expired'}), 401

        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/init', methods=['GET'])
def check_init():
    # Check if any users exist in the database
    try:
        db = get_db()
        cursor = db.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        return jsonify({'exists': user_count > 0, 'multi_user': True})
    except:
        init_db()
        return jsonify({'exists': False, 'multi_user': True})


@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    global encryption_key
    data = request.json
    username = data.get('username', '')
    password = data.get('password', '')
    totp_code = data.get('totp_code', '')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    db = get_db()
    cursor = db.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if not user:
        log_audit("LOGIN_FAILED", f"Unknown user: {username}")
        return jsonify({'error': 'Invalid credentials'}), 401

    derived_key = verify_user_password(password, user['salt'], user['password_hash'])
    if not derived_key:
        log_audit("LOGIN_FAILED", f"Invalid password for user: {username}")
        return jsonify({'error': 'Invalid credentials'}), 401

    # Check 2FA if enabled
    if user['two_fa_enabled']:
        if not totp_code:
            return jsonify({'error': '2FA code required', '2fa_required': True}), 401
        totp = pyotp.TOTP(user['two_fa_secret'])
        if not totp.verify(totp_code):
            log_audit("LOGIN_FAILED", f"Invalid 2FA code for user: {username}")
            return jsonify({'error': 'Invalid 2FA code'}), 401

    encryption_key = derived_key
    session['logged_in'] = True
    session['last_activity'] = datetime.now().isoformat()
    session['username'] = username
    session['user_id'] = user['id']
    session['is_admin'] = user['is_admin']

    log_audit("LOGIN_SUCCESS", f"User {username} logged in")
    return jsonify({'success': True, 'username': username, 'is_admin': user['is_admin'], '2fa_enabled': user['two_fa_enabled']})


@app.route('/api/register', methods=['POST'])
@limiter.limit("3 per hour")
def register():
    global encryption_key
    data = request.json
    username = data.get('username', '')
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400

    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    db = get_db()

    # Check if username already exists
    cursor = db.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        return jsonify({'error': 'Username already exists'}), 400

    # Generate salt and hash
    salt = os.urandom(16)
    key = derive_key(password, salt)
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(key)
    password_hash = base64.b64encode(hasher.finalize()).decode()

    totp_secret = pyotp.random_base32()

    # Check if this is the first user (make them admin)
    is_first_user = db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0

    # Create user in database
    db.execute('''
        INSERT INTO users (username, password_hash, salt, is_admin, two_fa_secret, two_fa_enabled)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (username, password_hash, base64.b64encode(salt).decode(), is_first_user, totp_secret, False))
    db.commit()

    encryption_key = key
    session['logged_in'] = True
    session['last_activity'] = datetime.now().isoformat()
    session['username'] = username
    session['user_id'] = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    session['is_admin'] = is_first_user

    # Generate QR code for 2FA setup
    qr_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
        name=username,
        issuer_name="SecureVault"
    )

    # Generate QR code image as base64
    qr = qrcode.make(qr_uri)
    buffered = io.BytesIO()
    qr.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode()

    log_audit("USER_REGISTERED", f"New user registered: {username}")
    return jsonify({
        'success': True,
        'username': username,
        'totp_secret': totp_secret,
        'qr_code': qr_base64
    })


@app.route('/api/verify-2fa', methods=['POST'])
@login_required
def verify_2fa():
    data = request.json
    totp_code = data.get('totp_code', '')

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    totp_secret = user['two_fa_secret']
    totp = pyotp.TOTP(totp_secret)

    if totp.verify(totp_code):
        db.execute("UPDATE users SET two_fa_enabled = TRUE WHERE id = ?", (session['user_id'],))
        db.commit()
        log_audit("2FA_ENABLED", f"Two-factor authentication enabled by user {session['username']}")
        return jsonify({'success': True})

    return jsonify({'error': 'Invalid 2FA code'}), 400


@app.route('/api/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    data = request.json
    password = data.get('password', '')

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()

    if not verify_user_password(password, user['salt'], user['password_hash']):
        return jsonify({'error': 'Invalid password'}), 401

    db.execute("UPDATE users SET two_fa_enabled = FALSE WHERE id = ?", (session['user_id'],))
    db.commit()

    log_audit("2FA_DISABLED", f"Two-factor authentication disabled by user {session['username']}")
    return jsonify({'success': True})


@app.route('/api/passwords', methods=['GET'])
@login_required
def get_passwords():
    db = get_db()
    cursor = db.execute("SELECT * FROM passwords WHERE user_id = ? ORDER BY updated_at DESC", (session['user_id'],))
    entries = cursor.fetchall()

    result = []
    for entry in entries:
        result.append({
            'id': entry['id'],
            'site': entry['site'],
            'username': entry['username'],
            'password': decrypt_password(entry['password'], encryption_key),
            'category': entry['category'],
            'notes': entry['notes'],
            'created': entry['created_at'][:10] if entry['created_at'] else '',
            'updated': entry['updated_at'][:10] if entry['updated_at'] else '',
            'last_used': entry['last_used'][:10] if entry['last_used'] else '',
            'expiry_days': entry['expiry_days']
        })
    return jsonify(result)


@app.route('/api/passwords', methods=['POST'])
@login_required
def add_password():
    data = request.json
    site = data.get('site', '')
    username = data.get('username', '')
    password = data.get('password', '')
    category = data.get('category', 'uncategorized')
    notes = data.get('notes', '')
    expiry_days = data.get('expiry_days', 90)

    if not site or not username or not password:
        return jsonify({'error': 'Site, username, and password required'}), 400

    encrypted_pwd = encrypt_password(password, encryption_key)

    db = get_db()
    db.execute('''
        INSERT INTO passwords (user_id, site, username, password, category, notes, expiry_days)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (session['user_id'], site, username, encrypted_pwd, category, notes, expiry_days))
    db.commit()

    log_audit("PASSWORD_ADDED", f"Added password for {site} by user {session['username']}")
    return jsonify({'success': True})


@app.route('/api/passwords/<int:pwd_id>', methods=['PUT'])
@login_required
def update_password(pwd_id):
    db = get_db()
    cursor = db.execute("SELECT * FROM passwords WHERE id = ? AND user_id = ?", (pwd_id, session['user_id']))
    entry = cursor.fetchone()

    if not entry:
        return jsonify({'error': 'Not found'}), 404

    data = request.json

    # Save old password to history before updating
    if data.get('password'):
        db.execute('''
            INSERT INTO password_history (user_id, password_id, password)
            VALUES (?, ?, ?)
        ''', (session['user_id'], pwd_id, entry['password']))

    updates = []
    values = []

    if 'site' in data:
        updates.append("site = ?")
        values.append(data['site'])
    if 'username' in data:
        updates.append("username = ?")
        values.append(data['username'])
    if 'password' in data:
        updates.append("password = ?")
        values.append(encrypt_password(data['password'], encryption_key))
    if 'category' in data:
        updates.append("category = ?")
        values.append(data['category'])
    if 'notes' in data:
        updates.append("notes = ?")
        values.append(data['notes'])
    if 'expiry_days' in data:
        updates.append("expiry_days = ?")
        values.append(data['expiry_days'])

    updates.append("updated_at = ?")
    values.append(datetime.now().isoformat())
    values.append(pwd_id)

    db.execute(f"UPDATE passwords SET {', '.join(updates)} WHERE id = ?", values)
    db.commit()

    log_audit("PASSWORD_UPDATED", f"Updated password for {entry['site']} by user {session['username']}")
    return jsonify({'success': True})


@app.route('/api/passwords/<int:pwd_id>', methods=['DELETE'])
@login_required
def delete_password(pwd_id):
    db = get_db()
    cursor = db.execute("SELECT site FROM passwords WHERE id = ? AND user_id = ?", (pwd_id, session['user_id']))
    entry = cursor.fetchone()

    if not entry:
        return jsonify({'error': 'Not found'}), 404

    db.execute("DELETE FROM passwords WHERE id = ?", (pwd_id,))
    db.commit()

    log_audit("PASSWORD_DELETED", f"Deleted password for {entry['site']} by user {session['username']}")
    return jsonify({'success': True})


@app.route('/api/passwords/<int:pwd_id>/use', methods=['POST'])
@login_required
def mark_password_used(pwd_id):
    db = get_db()
    db.execute("UPDATE passwords SET last_used = ? WHERE id = ?",
              (datetime.now().isoformat(), pwd_id))
    db.commit()
    return jsonify({'success': True})


@app.route('/api/generate', methods=['GET'])
@login_required
def gen_pwd():
    length = request.args.get('length', 16, type=int)
    use_symbols = request.args.get('symbols', 'true').lower() == 'true'
    return jsonify({'password': generate_password(max(8, min(length, 64)), use_symbols)})


@app.route('/api/check-strength', methods=['POST'])
@login_required
def check_strength():
    data = request.json
    password = data.get('password', '')
    return jsonify(check_password_strength(password))


@app.route('/api/check-pwned', methods=['POST'])
@login_required
def check_pwned():
    data = request.json
    password = data.get('password', '')
    is_pwned = check_password_pwned(password)
    return jsonify({'pwned': is_pwned})


@app.route('/api/search', methods=['GET'])
@login_required
def search():
    query = request.args.get('q', '').lower()
    category = request.args.get('category', '')

    db = get_db()
    if category:
        cursor = db.execute(
            "SELECT * FROM passwords WHERE user_id = ? AND (LOWER(site) LIKE ? OR LOWER(username) LIKE ?) AND category = ? ORDER BY site",
            (session['user_id'], f'%{query}%', f'%{query}%', category)
        )
    else:
        cursor = db.execute(
            "SELECT * FROM passwords WHERE user_id = ? AND (LOWER(site) LIKE ? OR LOWER(username) LIKE ?) ORDER BY site",
            (session['user_id'], f'%{query}%', f'%{query}%')
        )

    entries = cursor.fetchall()
    results = []
    for entry in entries:
        results.append({
            'id': entry['id'],
            'site': entry['site'],
            'username': entry['username'],
            'password': decrypt_password(entry['password'], encryption_key),
            'category': entry['category'],
            'created': entry['created_at'][:10] if entry['created_at'] else ''
        })
    return jsonify(results)


@app.route('/api/audit', methods=['GET'])
@login_required
def get_audit():
    db = get_db()

    # Weak passwords (short or simple) - filtered by user
    cursor = db.execute("SELECT id, site, username, password FROM passwords WHERE user_id = ?", (session['user_id'],))
    all_passwords = cursor.fetchall()

    weak = []
    reused = {}
    old = []
    expiring = []

    now = datetime.now()

    for entry in all_passwords:
        decrypted = decrypt_password(entry['password'], encryption_key)
        strength = check_password_strength(decrypted)

        if strength['strength'] == 'weak':
            weak.append({'id': entry['id'], 'site': entry['site'], 'reason': 'Weak password'})

        # Track for duplicates (store id and site)
        if decrypted in reused:
            reused[decrypted].append({'id': entry['id'], 'site': entry['site']})
        else:
            reused[decrypted] = [{'id': entry['id'], 'site': entry['site']}]

        # Check age
        if entry.get('created_at'):
            created = datetime.fromisoformat(entry['created_at'])
            age_days = (now - created).days
            if age_days > 180:
                old.append({'id': entry['id'], 'site': entry['site'], 'age_days': age_days})

        # Check expiry
        if entry.get('expiry_days') and entry.get('updated_at'):
            updated = datetime.fromisoformat(entry['updated_at'])
            days_since_update = (now - updated).days
            if days_since_update >= entry['expiry_days'] - 7:
                expiring.append({
                    'id': entry['id'],
                    'site': entry['site'],
                    'days_overdue': days_since_update - entry['expiry_days']
                })

    # Find reused passwords (include IDs for fixing)
    reused_list = []
    for pwd, items in reused.items():
        if len(items) > 1:
            reused_list.append({
                'password': pwd,
                'items': items
            })

    # Get recent activity (global for admin, user-specific for others)
    if session.get('is_admin'):
        cursor = db.execute(
            "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 50"
        )
    else:
        cursor = db.execute(
            "SELECT * FROM audit_log WHERE user_id = ? OR username = ? ORDER BY created_at DESC LIMIT 50",
            (session['user_id'], session['username'])
        )
    recent_activity = [dict(row) for row in cursor.fetchall()]

    return jsonify({
        'weak': weak,
        'reused': reused_list,
        'old': old,
        'expiring': expiring,
        'recent_activity': recent_activity
    })


@app.route('/api/notes', methods=['GET'])
@login_required
def get_notes():
    db = get_db()
    cursor = db.execute("SELECT * FROM secure_notes WHERE user_id = ? ORDER BY updated_at DESC", (session['user_id'],))
    notes = []
    for row in cursor.fetchall():
        note = dict(row)
        note['content'] = decrypt_password(note['content'], encryption_key)
        notes.append(note)
    return jsonify(notes)


@app.route('/api/notes', methods=['POST'])
@login_required
def add_note():
    data = request.json
    title = data.get('title', '')
    content = data.get('content', '')
    category = data.get('category', 'personal')

    if not title or not content:
        return jsonify({'error': 'Title and content required'}), 400

    encrypted_content = encrypt_password(content, encryption_key)
    db = get_db()
    db.execute(
        "INSERT INTO secure_notes (user_id, title, content, category) VALUES (?, ?, ?, ?)",
        (session['user_id'], title, encrypted_content, category)
    )
    db.commit()

    log_audit("NOTE_ADDED", f"Added note: {title} by user {session['username']}")
    return jsonify({'success': True})


@app.route('/api/notes/<int:note_id>', methods=['PUT', 'DELETE'])
@login_required
def manage_note(note_id):
    db = get_db()
    if request.method == 'DELETE':
        db.execute("DELETE FROM secure_notes WHERE id = ? AND user_id = ?", (note_id, session['user_id']))
        db.commit()
        log_audit("NOTE_DELETED", f"Deleted note #{note_id} by user {session['username']}")
        return jsonify({'success': True})

    # Verify ownership first
    cursor = db.execute("SELECT * FROM secure_notes WHERE id = ? AND user_id = ?", (note_id, session['user_id']))
    if not cursor.fetchone():
        return jsonify({'error': 'Not found'}), 404

    data = request.json
    if 'title' in data and 'content' in data:
        encrypted_content = encrypt_password(data['content'], encryption_key)
        db.execute(
            "UPDATE secure_notes SET title = ?, content = ?, category = ?, updated_at = ? WHERE id = ?",
            (data['title'], encrypted_content, data.get('category', 'personal'), datetime.now().isoformat(), note_id)
        )
        db.commit()
        log_audit("NOTE_UPDATED", f"Updated note #{note_id} by user {session['username']}")
        return jsonify({'success': True})

    return jsonify({'error': 'Invalid request'}), 400


@app.route('/api/export', methods=['POST'])
@login_required
def export_data():
    data = request.json
    export_password = data.get('export_password', '')

    if len(export_password) < 8:
        return jsonify({'error': 'Export password must be at least 8 characters'}), 400

    # Derive a key for export encryption
    export_salt = os.urandom(16)
    export_key = derive_key(export_password, export_salt)

    db = get_db()

    # Export passwords (user-specific)
    cursor = db.execute("SELECT site, username, password, category, notes FROM passwords WHERE user_id = ?", (session['user_id'],))
    passwords = []
    for row in cursor.fetchall():
        passwords.append({
            'site': row['site'],
            'username': row['username'],
            'password': decrypt_password(row['password'], encryption_key),
            'category': row['category'],
            'notes': row['notes'] or ''
        })

    # Export notes (user-specific)
    cursor = db.execute("SELECT title, content, category FROM secure_notes WHERE user_id = ?", (session['user_id'],))
    notes = []
    for row in cursor.fetchall():
        notes.append({
            'title': row['title'],
            'content': decrypt_password(row['content'], encryption_key),
            'category': row['category']
        })

    export_data = {
        'version': 1,
        'exported_at': datetime.now().isoformat(),
        'passwords': passwords,
        'notes': notes
    }

    # Encrypt the export
    encrypted_export = encrypt_password(json.dumps(export_data), export_key)

    return jsonify({
        'data': encrypted_export,
        'salt': base64.b64encode(export_salt).decode()
    })


@app.route('/api/import', methods=['POST'])
@login_required
def import_data():
    data = request.json
    import_password = data.get('import_password', '')
    encrypted_data = data.get('data', '')
    salt = base64.b64decode(data.get('salt', ''))

    try:
        import_key = derive_key(import_password, salt)
        decrypted_json = decrypt_password(encrypted_data, import_key)
        imported = json.loads(decrypted_json)

        db = get_db()
        imported_count = 0

        for pwd in imported.get('passwords', []):
            encrypted = encrypt_password(pwd['password'], encryption_key)
            db.execute(
                "INSERT INTO passwords (user_id, site, username, password, category, notes) VALUES (?, ?, ?, ?, ?, ?)",
                (session['user_id'], pwd['site'], pwd['username'], encrypted, pwd.get('category', 'uncategorized'), pwd.get('notes', ''))
            )
            imported_count += 1

        db.commit()
        log_audit("DATA_IMPORTED", f"Imported {imported_count} passwords")
        return jsonify({'success': True, 'count': imported_count})
    except Exception as e:
        return jsonify({'error': f'Import failed: {str(e)}'}), 400


@app.route('/api/categories', methods=['GET'])
@login_required
def get_categories():
    db = get_db()
    cursor = db.execute("""
        SELECT DISTINCT category FROM passwords WHERE user_id = ?
        UNION
        SELECT DISTINCT category FROM secure_notes WHERE user_id = ?
    """, (session['user_id'], session['user_id']))
    categories = [row[0] for row in cursor.fetchall()]
    return jsonify(categories)


@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    """Get all users (admin only)"""
    db = get_db()
    user = db.execute("SELECT is_admin FROM users WHERE id = ?", (session['user_id'],)).fetchone()

    if not user['is_admin']:
        return jsonify({'error': 'Admin access required'}), 403

    cursor = db.execute("SELECT id, username, is_admin, created_at FROM users ORDER BY created_at")
    users = [dict(row) for row in cursor.fetchall()]
    return jsonify(users)


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    """Delete a user (admin only)"""
    db = get_db()

    # Verify admin status
    current_user = db.execute("SELECT is_admin FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    if not current_user['is_admin']:
        return jsonify({'error': 'Admin access required'}), 403

    # Cannot delete yourself
    if user_id == session['user_id']:
        return jsonify({'error': 'Cannot delete your own account'}), 400

    # Get username for audit
    user_to_delete = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user_to_delete:
        return jsonify({'error': 'User not found'}), 404

    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()

    log_audit("USER_DELETED", f"User {user_to_delete['username']} deleted by admin {session['username']}")
    return jsonify({'success': True})


@app.route('/api/logout', methods=['POST'])
def logout():
    global encryption_key
    if session.get('username'):
        log_audit("LOGOUT", f"User {session.get('username')} logged out")
    encryption_key = None
    session.clear()
    return jsonify({'success': True})


@app.route('/api/change-password', methods=['POST'])
@login_required
def change_master_password():
    global encryption_key
    data = request.json
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')

    if len(new_password) < 8:
        return jsonify({'error': 'New password must be at least 8 characters'}), 400

    # Get current user from database
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()

    if not verify_user_password(current_password, user['salt'], user['password_hash']):
        return jsonify({'error': 'Current password is incorrect'}), 401

    # Load all existing passwords for this user
    cursor = db.execute("SELECT * FROM passwords WHERE user_id = ?", (session['user_id'],))
    entries = cursor.fetchall()

    decrypted_passwords = []
    for entry in entries:
        decrypted_passwords.append({
            'id': entry['id'],
            'password': decrypt_password(entry['password'], encryption_key)
        })

    # Load secure notes for this user
    cursor = db.execute("SELECT id, content FROM secure_notes WHERE user_id = ?", (session['user_id'],))
    secure_notes = []
    for row in cursor.fetchall():
        secure_notes.append({
            'id': row['id'],
            'content': decrypt_password(row['content'], encryption_key)
        })

    # Generate new salt and hash
    new_salt = os.urandom(16)
    new_key = derive_key(new_password, new_salt)
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(new_key)
    new_hash = base64.b64encode(hasher.finalize()).decode()

    # Update user in database
    db.execute(
        "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
        (new_hash, base64.b64encode(new_salt).decode(), session['user_id'])
    )

    # Re-encrypt all passwords with new key
    for p in decrypted_passwords:
        new_encrypted = encrypt_password(p['password'], new_key)
        db.execute("UPDATE passwords SET password = ? WHERE id = ?", (new_encrypted, p['id']))

    # Also update secure notes
    for note in secure_notes:
        new_encrypted_note = encrypt_password(note['content'], new_key)
        db.execute("UPDATE secure_notes SET content = ? WHERE id = ?", (new_encrypted_note, note['id']))

    db.commit()
    encryption_key = new_key

    log_audit("MASTER_PASSWORD_CHANGED", f"Master password changed by user {session['username']}")
    return jsonify({'success': True})


if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True, port=5000)
