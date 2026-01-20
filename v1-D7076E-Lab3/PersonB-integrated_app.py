"""
Integrated Flask Application with MFA Support
Person B - Integration of TOTP, HOTP, and WebAuthn with Person A's API
"""

from flask import Flask, request, jsonify
import sqlite3
import hashlib
import bcrypt
import secrets
import hmac
from argon2 import PasswordHasher as Argon2PasswordHasher
import pyotp
import json
from datetime import datetime

app = Flask(__name__)
PEPPER = b"system_pepper_secret_key"

def init_db():
    """Initialize database with MFA support"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Users table with MFA columns
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY,
                  salt BLOB,
                  hash BLOB,
                  hash_type TEXT,
                  mfa_enabled INTEGER DEFAULT 0,
                  mfa_type TEXT,
                  totp_secret TEXT,
                  hotp_secret TEXT,
                  hotp_counter INTEGER DEFAULT 0,
                  webauthn_credentials TEXT)''')
    
    # MFA logs table
    c.execute('''CREATE TABLE IF NOT EXISTS mfa_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT,
                  timestamp TEXT,
                  mfa_type TEXT,
                  success INTEGER,
                  details TEXT)''')
    
    conn.commit()
    conn.close()

class PasswordHasher:
    """Password hashing from Person A"""
    def hash_sha256(self, password, salt, rounds=100):
        hash_input = password.encode() + salt + PEPPER
        for _ in range(rounds):
            hash_input = hashlib.sha256(hash_input).digest()
        return hash_input
    
    def hash_bcrypt(self, password):
        return bcrypt.hashpw(password.encode() + PEPPER, bcrypt.gensalt(rounds=8))
    
    def verify_password(self, password, stored_hash, salt, hash_type):
        """Verify password against stored hash"""
        if hash_type == 'sha256':
            test_hash = self.hash_sha256(password, salt)
            return hmac.compare_digest(test_hash, stored_hash)
        elif hash_type == 'bcrypt':
            return bcrypt.checkpw(password.encode() + PEPPER, stored_hash)
        return False

hasher = PasswordHasher()

def add_hmac(response):
    """Add HMAC from Person A"""
    mac = hmac.new(b'secret_key', str(response).encode(), hashlib.sha256).hexdigest()
    response['mac'] = mac
    return response

def log_mfa_attempt(username, mfa_type, success, details=""):
    """Log MFA verification attempts"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("INSERT INTO mfa_logs VALUES (NULL, ?, ?, ?, ?, ?)",
              (username, datetime.now().isoformat(), mfa_type, 1 if success else 0, details))
    conn.commit()
    conn.close()

@app.route('/register', methods=['POST'])
def register():
    """User registration endpoint"""
    data = request.get_json()
    username = data['username']
    password = data['password']
    hash_type = data.get('hash_type', 'bcrypt')
    
    salt = secrets.token_bytes(32)
    
    if hash_type == 'sha256':
        password_hash = hasher.hash_sha256(password, salt)
    else:
        password_hash = hasher.hash_bcrypt(password)
        salt = b''
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, salt, hash, hash_type) VALUES (?, ?, ?, ?)",
                  (username, salt, password_hash, hash_type))
        conn.commit()
        response = {'status': 'success', 'username': username, 'hash_type': hash_type}
    except sqlite3.IntegrityError:
        response = {'status': 'error', 'message': 'User already exists'}
    conn.close()
    
    return jsonify(add_hmac(response))

@app.route('/login', methods=['POST'])
def login():
    """Enhanced login with password verification"""
    data = request.get_json()
    username = data['username']
    password = data['password']
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT salt, hash, hash_type, mfa_enabled, mfa_type FROM users WHERE username=?",
              (username,))
    result = c.fetchone()
    conn.close()
    
    if not result:
        response = {'status': 'error', 'message': 'User not found'}
        return jsonify(add_hmac(response))
    
    salt, stored_hash, hash_type, mfa_enabled, mfa_type = result
    
    if hasher.verify_password(password, stored_hash, salt if salt else b'', hash_type):
        if mfa_enabled:
            session_token = secrets.token_hex(32)
            response = {'status': 'mfa_required', 'mfa_type': mfa_type, 'session_token': session_token}
        else:
            response = {'status': 'success', 'message': 'Login successful', 'username': username}
    else:
        response = {'status': 'error', 'message': 'Invalid credentials'}
    
    return jsonify(add_hmac(response))

@app.route('/mfa/enroll/totp', methods=['POST'])
def enroll_totp():
    """Enroll user for TOTP"""
    data = request.get_json()
    username = data['username']
    
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=username, issuer_name='SecureAuthApp')
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("UPDATE users SET mfa_enabled=1, mfa_type='totp', totp_secret=? WHERE username=?",
              (secret, username))
    conn.commit()
    conn.close()
    
    response = {'status': 'success', 'mfa_type': 'totp', 'secret': secret, 'provisioning_uri': provisioning_uri}
    return jsonify(add_hmac(response))

@app.route('/mfa/verify', methods=['POST'])
def verify_mfa():
    """Verify TOTP or HOTP token"""
    data = request.get_json()
    username = data['username']
    token = data['token']
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT mfa_type, totp_secret FROM users WHERE username=?", (username,))
    result = c.fetchone()
    
    if not result:
        conn.close()
        response = {'status': 'error', 'message': 'User not found'}
        return jsonify(add_hmac(response))
    
    mfa_type, totp_secret = result
    
    if mfa_type == 'totp':
        totp = pyotp.TOTP(totp_secret)
        is_valid = totp.verify(token, valid_window=1)
        log_mfa_attempt(username, 'totp', is_valid)
        
        if is_valid:
            response = {'status': 'success', 'message': 'TOTP verified'}
        else:
            response = {'status': 'error', 'message': 'Invalid TOTP token'}
    else:
        response = {'status': 'error', 'message': 'MFA not configured'}
    
    conn.close()
    return jsonify(add_hmac(response))

@app.route('/mfa/stats', methods=['GET'])
def mfa_stats():
    """Get MFA statistics"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM mfa_logs ORDER BY timestamp DESC LIMIT 100")
    logs = c.fetchall()
    conn.close()
    
    total = len(logs)
    successful = sum(1 for log in logs if log[4] == 1)
    
    response = {
        'total_attempts': total,
        'successful': successful,
        'failed': total - successful,
        'success_rate': f"{(successful/total*100) if total > 0 else 0:.2f}%"
    }
    
    return jsonify(add_hmac(response))

if __name__ == '__main__':
    print("=== Integrated Authentication API with MFA ===")
    init_db()
    print("Starting server on port 5000...")
    app.run(debug=True, port=5000)
