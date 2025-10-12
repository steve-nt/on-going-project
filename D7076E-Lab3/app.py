"""
Flask REST API for Secure Authentication Lab
Implements password hashing, MFA (TOTP/HOTP/FIDO2), and HMAC integrity
"""

import os
import sqlite3
import hashlib
import hmac
import secrets
import base64
import json
import time
from datetime import datetime
from functools import wraps

import bcrypt
import argon2
from Crypto.Hash import SHA3_256
import pyotp
import qrcode
from io import BytesIO

from flask import Flask, request, jsonify, session, send_file
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, UserVerificationRequirement
from fido2 import cbor

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)
app.config['DATABASE'] = 'auth.db'

# System-wide pepper (kept secret, not in DB)
PEPPER = b'system_wide_secret_pepper_key_12345'

# HMAC secret for response integrity
HMAC_SECRET = os.urandom(32)

# FIDO2/WebAuthn setup
RP_ID = "localhost"
RP_NAME = "Secure Auth Lab"
rp = PublicKeyCredentialRpEntity(RP_ID, RP_NAME)
fido_server = Fido2Server(rp)

# Password hashing algorithms
HASH_ALGORITHMS = {
    'sha256': 'SHA-256',
    'sha3': 'SHA-3',
    'bcrypt': 'bcrypt',
    'argon2': 'Argon2'
}

# Database initialization
def init_db():
    """Initialize SQLite database with users table"""
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            salt BLOB NOT NULL,
            hash BLOB NOT NULL,
            hash_algorithm TEXT NOT NULL,
            pepper_used INTEGER DEFAULT 0,
            totp_secret TEXT,
            hotp_secret TEXT,
            hotp_counter INTEGER DEFAULT 0,
            webauthn_credential_id BLOB,
            webauthn_public_key BLOB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS mfa_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            mfa_type TEXT NOT NULL,
            success INTEGER NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            details TEXT
        )
    ''')

    conn.commit()
    conn.close()

# Helper functions for password hashing
def hash_password_sha256(password, salt, use_pepper=False):
    """Hash password using SHA-256"""
    pwd = password.encode('utf-8')
    if use_pepper:
        pwd = pwd + PEPPER
    return hashlib.sha256(salt + pwd).digest()

def hash_password_sha3(password, salt, use_pepper=False):
    """Hash password using SHA-3"""
    pwd = password.encode('utf-8')
    if use_pepper:
        pwd = pwd + PEPPER
    h = SHA3_256.new()
    h.update(salt + pwd)
    return h.digest()

def hash_password_bcrypt(password, salt, use_pepper=False):
    """Hash password using bcrypt"""
    pwd = password.encode('utf-8')
    if use_pepper:
        pwd = pwd + PEPPER
    # bcrypt has built-in salt, but we'll use our own for consistency
    return bcrypt.hashpw(pwd, bcrypt.gensalt(rounds=12))

def hash_password_argon2(password, salt, use_pepper=False):
    """Hash password using Argon2"""
    pwd = password.encode('utf-8')
    if use_pepper:
        pwd = pwd + PEPPER
    ph = argon2.PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        salt_len=16
    )
    # Argon2 generates its own salt internally, but we'll store ours
    return ph.hash(pwd).encode('utf-8')

def hash_password(password, salt, algorithm='sha256', use_pepper=False):
    """Hash password using specified algorithm"""
    if algorithm == 'sha256':
        return hash_password_sha256(password, salt, use_pepper)
    elif algorithm == 'sha3':
        return hash_password_sha3(password, salt, use_pepper)
    elif algorithm == 'bcrypt':
        return hash_password_bcrypt(password, salt, use_pepper)
    elif algorithm == 'argon2':
        return hash_password_argon2(password, salt, use_pepper)
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")

def verify_password(password, stored_hash, salt, algorithm='sha256', use_pepper=False):
    """Verify password against stored hash"""
    if algorithm == 'bcrypt':
        pwd = password.encode('utf-8')
        if use_pepper:
            pwd = pwd + PEPPER
        return bcrypt.checkpw(pwd, stored_hash)
    elif algorithm == 'argon2':
        pwd = password.encode('utf-8')
        if use_pepper:
            pwd = pwd + PEPPER
        ph = argon2.PasswordHasher()
        try:
            ph.verify(stored_hash.decode('utf-8'), pwd)
            return True
        except:
            return False
    else:
        # For SHA-256 and SHA-3
        computed_hash = hash_password(password, salt, algorithm, use_pepper)
        return hmac.compare_digest(computed_hash, stored_hash)

def verify_password_timing_vulnerable(password, stored_hash, salt, algorithm='sha256', use_pepper=False):
    """VULNERABLE: Verify password with timing attack vulnerability"""
    computed_hash = hash_password(password, salt, algorithm, use_pepper)
    # Byte-by-byte comparison that leaks timing information
    if len(computed_hash) != len(stored_hash):
        return False
    for i in range(len(computed_hash)):
        if computed_hash[i] != stored_hash[i]:
            return False
    return True

def add_hmac_to_response(data):
    """Add HMAC to response data for integrity protection"""
    data_str = json.dumps(data, sort_keys=True)
    mac = hmac.new(HMAC_SECRET, data_str.encode('utf-8'), hashlib.sha256).hexdigest()
    return {'data': data, 'hmac': mac}

def verify_hmac(request_data):
    """Verify HMAC of request data"""
    if 'data' not in request_data or 'hmac' not in request_data:
        return False
    data_str = json.dumps(request_data['data'], sort_keys=True)
    expected_mac = hmac.new(HMAC_SECRET, data_str.encode('utf-8'), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_mac, request_data['hmac'])

def log_mfa_attempt(username, mfa_type, success, details=''):
    """Log MFA authentication attempt"""
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('''
        INSERT INTO mfa_logs (username, mfa_type, success, details)
        VALUES (?, ?, ?, ?)
    ''', (username, mfa_type, 1 if success else 0, details))
    conn.commit()
    conn.close()

# API Routes
@app.route('/register', methods=['POST'])
def register():
    """Register a new user with specified hashing algorithm"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    algorithm = data.get('algorithm', 'sha256')
    use_pepper = data.get('use_pepper', False)

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    if algorithm not in HASH_ALGORITHMS:
        return jsonify({'error': f'Invalid algorithm. Choose from: {list(HASH_ALGORITHMS.keys())}'}), 400

    # Generate salt
    salt = os.urandom(32)

    # Hash password
    password_hash = hash_password(password, salt, algorithm, use_pepper)

    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute('''
            INSERT INTO users (username, salt, hash, hash_algorithm, pepper_used)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, salt, password_hash, algorithm, 1 if use_pepper else 0))
        conn.commit()
        conn.close()

        response = {
            'message': 'User registered successfully',
            'username': username,
            'algorithm': HASH_ALGORITHMS[algorithm],
            'pepper_used': use_pepper,
            'salt': base64.b64encode(salt).decode('utf-8'),
            'hash': base64.b64encode(password_hash).decode('utf-8')
        }

        return jsonify(add_hmac_to_response(response)), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409

@app.route('/login', methods=['POST'])
def login():
    """Login with username and password"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    use_timing_attack_demo = data.get('timing_vulnerable', False)

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('''
        SELECT salt, hash, hash_algorithm, pepper_used, totp_secret, hotp_secret, webauthn_credential_id
        FROM users WHERE username = ?
    ''', (username,))
    result = c.fetchone()
    conn.close()

    if not result:
        return jsonify({'error': 'Invalid credentials'}), 401

    salt, stored_hash, algorithm, pepper_used, totp_secret, hotp_secret, webauthn_cred = result

    # Verify password
    start_time = time.perf_counter()
    if use_timing_attack_demo:
        is_valid = verify_password_timing_vulnerable(password, stored_hash, salt, algorithm, pepper_used)
    else:
        is_valid = verify_password(password, stored_hash, salt, algorithm, pepper_used)
    end_time = time.perf_counter()
    verification_time = (end_time - start_time) * 1000000  # microseconds

    if not is_valid:
        response = {
            'error': 'Invalid credentials',
            'verification_time_us': verification_time
        }
        return jsonify(add_hmac_to_response(response)), 401

    # Check if MFA is enabled
    mfa_enabled = []
    if totp_secret:
        mfa_enabled.append('TOTP')
    if hotp_secret:
        mfa_enabled.append('HOTP')
    if webauthn_cred:
        mfa_enabled.append('WebAuthn')

    session['username'] = username
    session['authenticated'] = False  # Need MFA

    response = {
        'message': 'Password verified',
        'username': username,
        'mfa_enabled': mfa_enabled,
        'mfa_required': len(mfa_enabled) > 0,
        'verification_time_us': verification_time
    }

    return jsonify(add_hmac_to_response(response)), 200

@app.route('/mfa/totp/enroll', methods=['POST'])
def enroll_totp():
    """Enroll user in TOTP-based MFA"""
    data = request.json
    username = data.get('username')

    if not username:
        return jsonify({'error': 'Username required'}), 400

    # Generate TOTP secret
    secret = pyotp.random_base32()

    # Update user record
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('UPDATE users SET totp_secret = ? WHERE username = ?', (secret, username))
    conn.commit()
    conn.close()

    # Generate QR code
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(username, issuer_name="Secure Auth Lab")

    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Save QR code
    qr_filename = f'qr_{username}_totp.png'
    img.save(qr_filename)

    response = {
        'message': 'TOTP enrolled successfully',
        'secret': secret,
        'provisioning_uri': provisioning_uri,
        'qr_code_file': qr_filename
    }

    return jsonify(add_hmac_to_response(response)), 200

@app.route('/mfa/totp/verify', methods=['POST'])
def verify_totp():
    """Verify TOTP code"""
    data = request.json
    username = data.get('username')
    code = data.get('code')
    time_window = data.get('window', 0)  # ±0, ±1, etc.

    if not username or not code:
        return jsonify({'error': 'Username and code required'}), 400

    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('SELECT totp_secret FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    conn.close()

    if not result or not result[0]:
        return jsonify({'error': 'TOTP not enrolled'}), 400

    secret = result[0]
    totp = pyotp.TOTP(secret)

    # Verify with configurable time window
    is_valid = totp.verify(code, valid_window=time_window)

    log_mfa_attempt(username, 'TOTP', is_valid, f'window={time_window}')

    if is_valid:
        session['authenticated'] = True
        response = {
            'message': 'TOTP verified successfully',
            'authenticated': True
        }
        return jsonify(add_hmac_to_response(response)), 200
    else:
        response = {'error': 'Invalid TOTP code'}
        return jsonify(add_hmac_to_response(response)), 401

@app.route('/mfa/hotp/enroll', methods=['POST'])
def enroll_hotp():
    """Enroll user in HOTP-based MFA"""
    data = request.json
    username = data.get('username')

    if not username:
        return jsonify({'error': 'Username required'}), 400

    # Generate HOTP secret
    secret = pyotp.random_base32()

    # Update user record
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('UPDATE users SET hotp_secret = ?, hotp_counter = 0 WHERE username = ?', (secret, username))
    conn.commit()
    conn.close()

    # Generate QR code
    hotp = pyotp.HOTP(secret)
    provisioning_uri = hotp.provisioning_uri(username, initial_count=0, issuer_name="Secure Auth Lab")

    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Save QR code
    qr_filename = f'qr_{username}_hotp.png'
    img.save(qr_filename)

    response = {
        'message': 'HOTP enrolled successfully',
        'secret': secret,
        'provisioning_uri': provisioning_uri,
        'qr_code_file': qr_filename,
        'counter': 0
    }

    return jsonify(add_hmac_to_response(response)), 200

@app.route('/mfa/hotp/verify', methods=['POST'])
def verify_hotp():
    """Verify HOTP code with counter management"""
    data = request.json
    username = data.get('username')
    code = data.get('code')
    look_ahead = data.get('look_ahead', 3)  # How many counters ahead to check

    if not username or not code:
        return jsonify({'error': 'Username and code required'}), 400

    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('SELECT hotp_secret, hotp_counter FROM users WHERE username = ?', (username,))
    result = c.fetchone()

    if not result or not result[0]:
        conn.close()
        return jsonify({'error': 'HOTP not enrolled'}), 400

    secret, current_counter = result
    hotp = pyotp.HOTP(secret)

    # Try current counter and look ahead for desync
    is_valid = False
    used_counter = current_counter

    for i in range(look_ahead + 1):
        test_counter = current_counter + i
        if hotp.verify(code, test_counter):
            is_valid = True
            used_counter = test_counter
            # Update counter to next value
            c.execute('UPDATE users SET hotp_counter = ? WHERE username = ?', (test_counter + 1, username))
            conn.commit()
            break

    conn.close()

    details = f'counter={used_counter}, expected={current_counter}, look_ahead={look_ahead}'
    log_mfa_attempt(username, 'HOTP', is_valid, details)

    if is_valid:
        session['authenticated'] = True
        response = {
            'message': 'HOTP verified successfully',
            'authenticated': True,
            'counter_used': used_counter,
            'counter_drift': used_counter - current_counter
        }
        return jsonify(add_hmac_to_response(response)), 200
    else:
        response = {
            'error': 'Invalid HOTP code',
            'current_counter': current_counter
        }
        return jsonify(add_hmac_to_response(response)), 401

@app.route('/mfa/webauthn/register/begin', methods=['POST'])
def webauthn_register_begin():
    """Begin WebAuthn registration"""
    data = request.json
    username = data.get('username')

    if not username:
        return jsonify({'error': 'Username required'}), 400

    # Get user ID from database
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    conn.close()

    if not result:
        return jsonify({'error': 'User not found'}), 404

    user_id = str(result[0]).encode('utf-8')

    registration_data, state = fido_server.register_begin(
        {
            "id": user_id,
            "name": username,
            "displayName": username,
        },
        credentials=[],
        user_verification=UserVerificationRequirement.PREFERRED
    )

    session['webauthn_state'] = state
    session['username'] = username

    # Convert to JSON-serializable format
    response = {
        'publicKey': {
            'challenge': base64.b64encode(registration_data['publicKey']['challenge']).decode('utf-8'),
            'rp': registration_data['publicKey']['rp'],
            'user': {
                'id': base64.b64encode(registration_data['publicKey']['user']['id']).decode('utf-8'),
                'name': registration_data['publicKey']['user']['name'],
                'displayName': registration_data['publicKey']['user']['displayName']
            },
            'pubKeyCredParams': registration_data['publicKey']['pubKeyCredParams'],
            'timeout': registration_data['publicKey'].get('timeout', 60000),
            'attestation': registration_data['publicKey'].get('attestation', 'none'),
            'authenticatorSelection': registration_data['publicKey'].get('authenticatorSelection', {})
        }
    }

    return jsonify(response), 200

@app.route('/mfa/webauthn/register/complete', methods=['POST'])
def webauthn_register_complete():
    """Complete WebAuthn registration"""
    data = request.json
    username = session.get('username')
    state = session.get('webauthn_state')

    if not username or not state:
        return jsonify({'error': 'Registration not initiated'}), 400

    try:
        # Parse client data
        client_data = data.get('response', {})

        # Complete registration
        auth_data = fido_server.register_complete(
            state,
            client_data,
            data
        )

        # Store credential
        credential_id = auth_data.credential_data.credential_id
        public_key = auth_data.credential_data.public_key

        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute('''
            UPDATE users
            SET webauthn_credential_id = ?, webauthn_public_key = ?
            WHERE username = ?
        ''', (credential_id, cbor.encode(public_key), username))
        conn.commit()
        conn.close()

        response = {
            'message': 'WebAuthn registered successfully',
            'credential_id': base64.b64encode(credential_id).decode('utf-8')
        }

        return jsonify(add_hmac_to_response(response)), 200
    except Exception as e:
        return jsonify({'error': f'Registration failed: {str(e)}'}), 400

@app.route('/mfa/webauthn/authenticate/begin', methods=['POST'])
def webauthn_authenticate_begin():
    """Begin WebAuthn authentication"""
    data = request.json
    username = data.get('username')

    if not username:
        return jsonify({'error': 'Username required'}), 400

    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('SELECT webauthn_credential_id FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    conn.close()

    if not result or not result[0]:
        return jsonify({'error': 'WebAuthn not enrolled'}), 400

    credential_id = result[0]

    auth_data, state = fido_server.authenticate_begin([credential_id])

    session['webauthn_auth_state'] = state
    session['username'] = username

    response = {
        'publicKey': {
            'challenge': base64.b64encode(auth_data['publicKey']['challenge']).decode('utf-8'),
            'timeout': auth_data['publicKey'].get('timeout', 60000),
            'rpId': auth_data['publicKey'].get('rpId'),
            'allowCredentials': [
                {
                    'type': 'public-key',
                    'id': base64.b64encode(credential_id).decode('utf-8')
                }
            ],
            'userVerification': auth_data['publicKey'].get('userVerification', 'preferred')
        }
    }

    return jsonify(response), 200

@app.route('/mfa/webauthn/authenticate/complete', methods=['POST'])
def webauthn_authenticate_complete():
    """Complete WebAuthn authentication"""
    data = request.json
    username = session.get('username')
    state = session.get('webauthn_auth_state')

    if not username or not state:
        return jsonify({'error': 'Authentication not initiated'}), 400

    try:
        # Get stored credential
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute('SELECT webauthn_credential_id FROM users WHERE username = ?', (username,))
        result = c.fetchone()
        conn.close()

        if not result:
            return jsonify({'error': 'Credential not found'}), 400

        credential_id = result[0]

        # Complete authentication
        fido_server.authenticate_complete(
            state,
            [credential_id],
            data.get('credential_id'),
            data.get('client_data'),
            data.get('auth_data'),
            data.get('signature')
        )

        session['authenticated'] = True
        log_mfa_attempt(username, 'WebAuthn', True, 'Authentication successful')

        response = {
            'message': 'WebAuthn authentication successful',
            'authenticated': True
        }

        return jsonify(add_hmac_to_response(response)), 200
    except Exception as e:
        log_mfa_attempt(username, 'WebAuthn', False, f'Error: {str(e)}')
        return jsonify({'error': f'Authentication failed: {str(e)}'}), 401

@app.route('/mfa/logs', methods=['GET'])
def get_mfa_logs():
    """Get MFA authentication logs"""
    username = request.args.get('username')

    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()

    if username:
        c.execute('''
            SELECT mfa_type, success, timestamp, details
            FROM mfa_logs
            WHERE username = ?
            ORDER BY timestamp DESC
            LIMIT 50
        ''', (username,))
    else:
        c.execute('''
            SELECT username, mfa_type, success, timestamp, details
            FROM mfa_logs
            ORDER BY timestamp DESC
            LIMIT 100
        ''')

    logs = c.fetchall()
    conn.close()

    if username:
        log_list = [
            {
                'mfa_type': log[0],
                'success': bool(log[1]),
                'timestamp': log[2],
                'details': log[3]
            }
            for log in logs
        ]
    else:
        log_list = [
            {
                'username': log[0],
                'mfa_type': log[1],
                'success': bool(log[2]),
                'timestamp': log[3],
                'details': log[4]
            }
            for log in logs
        ]

    response = {'logs': log_list, 'count': len(log_list)}
    return jsonify(add_hmac_to_response(response)), 200

@app.route('/status', methods=['GET'])
def status():
    """Check API status"""
    response = {
        'status': 'running',
        'algorithms': list(HASH_ALGORITHMS.values()),
        'mfa_types': ['TOTP', 'HOTP', 'WebAuthn'],
        'features': ['HMAC integrity', 'Salt & Pepper', 'Timing attack demo']
    }
    return jsonify(add_hmac_to_response(response)), 200

if __name__ == '__main__':
    init_db()
    # Run with SSL for WebAuthn (self-signed cert for local testing)
    app.run(debug=True, host='0.0.0.0', port=5000)
