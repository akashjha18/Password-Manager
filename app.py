from flask import Flask, render_template, request, jsonify, session
import json
import os
import base64
import secrets
import string
from datetime import datetime
from functools import wraps
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

FILE = "data.json"
KEY_FILE = ".key"

# Global key for session
encryption_key = None


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def init_encryption():
    global encryption_key
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            data = json.load(f)
            salt = base64.b64decode(data["salt"])
            return salt, data["hash"]
    return None, None


def verify_password(password: str, salt: bytes, stored_hash: str) -> bool:
    key = derive_key(password, salt)
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(key)
    computed_hash = base64.b64encode(hasher.finalize()).decode()
    return computed_hash == stored_hash


def setup_encryption(password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(key)
    password_hash = base64.b64encode(hasher.finalize()).decode()

    with open(KEY_FILE, "w") as f:
        json.dump({
            "salt": base64.b64encode(salt).decode(),
            "hash": password_hash
        }, f)
    return key


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


def load_data():
    if not os.path.exists(FILE):
        return []
    try:
        with open(FILE, "r") as f:
            return json.load(f)
    except:
        return []


def save_data(data):
    with open(FILE, "w") as f:
        json.dump(data, f, indent=4)


def generate_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-="
    return ''.join(secrets.choice(chars) for _ in range(length))


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return jsonify({'error': 'Not authenticated'}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/init', methods=['GET'])
def check_init():
    salt, hash_val = init_encryption()
    if salt and hash_val:
        return jsonify({'exists': True})
    return jsonify({'exists': False})


@app.route('/api/login', methods=['POST'])
def login():
    global encryption_key
    data = request.json
    password = data.get('password', '')

    salt, stored_hash = init_encryption()
    if not salt or not stored_hash:
        return jsonify({'error': 'No vault exists'}), 400

    if verify_password(password, salt, stored_hash):
        encryption_key = derive_key(password, salt)
        session['logged_in'] = True
        return jsonify({'success': True})
    return jsonify({'error': 'Invalid password'}), 401


@app.route('/api/setup', methods=['POST'])
def setup():
    global encryption_key
    data = request.json
    password = data.get('password', '')

    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    encryption_key = setup_encryption(password)
    session['logged_in'] = True
    return jsonify({'success': True})


@app.route('/api/passwords', methods=['GET'])
@login_required
def get_passwords():
    data = load_data()
    result = []
    for entry in data:
        result.append({
            'site': entry['site'],
            'username': entry['username'],
            'password': decrypt_password(entry['password'], encryption_key),
            'created': entry.get('created', '')[:10],
            'updated': entry.get('updated', '')[:10]
        })
    return jsonify(result)


@app.route('/api/passwords', methods=['POST'])
@login_required
def add_password():
    data = request.json
    site = data.get('site', '')
    username = data.get('username', '')
    password = data.get('password', '')

    if not site or not username or not password:
        return jsonify({'error': 'All fields required'}), 400

    entries = load_data()
    entries.append({
        'site': site,
        'username': username,
        'password': encrypt_password(password, encryption_key),
        'created': datetime.now().isoformat()
    })
    save_data(entries)
    return jsonify({'success': True})


@app.route('/api/passwords/<int:index>', methods=['PUT'])
@login_required
def update_password(index):
    data = request.json
    entries = load_data()

    if not (0 <= index < len(entries)):
        return jsonify({'error': 'Not found'}), 404

    if data.get('site'):
        entries[index]['site'] = data['site']
    if data.get('username'):
        entries[index]['username'] = data['username']
    if data.get('password'):
        entries[index]['password'] = encrypt_password(data['password'], encryption_key)
    entries[index]['updated'] = datetime.now().isoformat()

    save_data(entries)
    return jsonify({'success': True})


@app.route('/api/passwords/<int:index>', methods=['DELETE'])
@login_required
def delete_password(index):
    entries = load_data()

    if not (0 <= index < len(entries)):
        return jsonify({'error': 'Not found'}), 404

    entries.pop(index)
    save_data(entries)
    return jsonify({'success': True})


@app.route('/api/generate', methods=['GET'])
@login_required
def gen_pwd():
    length = request.args.get('length', 16, type=int)
    return jsonify({'password': generate_password(max(8, min(length, 64)))})


@app.route('/api/search', methods=['GET'])
@login_required
def search():
    query = request.args.get('q', '').lower()
    data = load_data()
    results = []
    for entry in data:
        if query in entry['site'].lower() or query in entry['username'].lower():
            results.append({
                'site': entry['site'],
                'username': entry['username'],
                'password': decrypt_password(entry['password'], encryption_key),
                'created': entry.get('created', '')[:10]
            })
    return jsonify(results)


@app.route('/api/logout', methods=['POST'])
def logout():
    global encryption_key
    encryption_key = None
    session.clear()
    return jsonify({'success': True})


@app.route('/api/change-password', methods=['POST'])
@login_required
def change_password():
    global encryption_key
    data = request.json
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')

    if len(new_password) < 8:
        return jsonify({'error': 'New password must be at least 8 characters'}), 400

    # Verify current password
    salt, stored_hash = init_encryption()
    if not verify_password(current_password, salt, stored_hash):
        return jsonify({'error': 'Current password is incorrect'}), 401

    # Load all existing passwords with current key
    entries = load_data()
    decrypted_passwords = []
    for entry in entries:
        try:
            decrypted_passwords.append({
                'site': entry['site'],
                'username': entry['username'],
                'password': decrypt_password(entry['password'], encryption_key)
            })
        except Exception as e:
            return jsonify({'error': f'Failed to decrypt: {str(e)}'}), 500

    # Generate new salt and hash
    new_salt = os.urandom(16)
    new_key = derive_key(new_password, new_salt)
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(new_key)
    new_hash = base64.b64encode(hasher.finalize()).decode()

    # Save new key file
    with open(KEY_FILE, "w") as f:
        json.dump({
            "salt": base64.b64encode(new_salt).decode(),
            "hash": new_hash
        }, f)

    # Re-encrypt all passwords with new key
    new_entries = []
    for p in decrypted_passwords:
        new_entries.append({
            'site': p['site'],
            'username': p['username'],
            'password': encrypt_password(p['password'], new_key),
            'created': datetime.now().isoformat()
        })

    save_data(new_entries)
    encryption_key = new_key

    return jsonify({'success': True})


if __name__ == '__main__':
    app.run(debug=True, port=5000)
