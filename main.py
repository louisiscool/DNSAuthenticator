
#!/usr/bin/env python3
"""
Flask web authenticator (single-user). Features:
- Web UI that looks like Google Authenticator (list of accounts, big code, countdown).
- Add accounts via manual otpauth URI or Base32 secret.
- Import via scanning QR in-browser (webcam + jsQR library in client-side JS).
- Server-side encrypted vault: vault is stored on disk encrypted with Fernet; master password is asked each session and used to derive the key (scrypt).
- TOTP generation performed server-side for simplicity (pyotp).

Notes:
- This is a single-user demo. Do NOT expose to the public internet without HTTPS and hardening.
- Run locally and open on your phone (same LAN) for mobile-like use.
"""

from flask import Flask, render_template, request, redirect, url_for, jsonify, send_from_directory
import os, json, time, uuid
from dataclasses import dataclass, asdict
from typing import List, Optional
import base64
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet, InvalidToken
import pyotp

APP_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(APP_DIR, 'data')
VAULT_PATH = os.path.join(DATA_DIR, 'vault.json.enc')
SALT_PATH = os.path.join(DATA_DIR, 'salt.bin')

os.makedirs(DATA_DIR, exist_ok=True)

app = Flask(__name__, static_folder='static', template_folder='templates')

@dataclass
class Account:
    id: str
    issuer: Optional[str]
    label: str
    secret_base32: str
    digits: int = 6
    period: int = 30
    algorithm: str = 'SHA1'
    added_at: float = time.time()

# --- crypto helpers ---
def load_salt():
    if os.path.exists(SALT_PATH):
        return open(SALT_PATH, 'rb').read()
    s = os.urandom(16)
    open(SALT_PATH, 'wb').write(s)
    return s

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    key = kdf.derive(password.encode('utf-8'))
    return base64.urlsafe_b64encode(key)

def encrypt_vault(data: dict, fernet: Fernet):
    plain = json.dumps(data, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    return fernet.encrypt(plain)

def decrypt_vault(blob: bytes, fernet: Fernet):
    plain = fernet.decrypt(blob)
    return json.loads(plain.decode('utf-8'))

# --- vault helpers ---

def vault_exists():
    return os.path.exists(VAULT_PATH)

def write_encrypted_vault(obj: dict, fernet: Fernet):
    open(VAULT_PATH, 'wb').write(encrypt_vault(obj, fernet))

def read_encrypted_vault(fernet: Fernet) -> dict:
    if not os.path.exists(VAULT_PATH):
        return {'accounts': []}
    blob = open(VAULT_PATH, 'rb').read()
    return decrypt_vault(blob, fernet)

# --- flask routes ---
@app.route('/')
def index():
    # web UI. Client will ask /api/status and /api/accounts
    return render_template('index.html')

@app.route('/api/status')
def api_status():
    return jsonify({'vault_exists': vault_exists()})

@app.route('/api/init', methods=['POST'])
def api_init():
    # create empty vault encrypted with provided password
    payload = request.json or {}
    pw = payload.get('password')
    if not pw:
        return jsonify({'ok': False, 'error': 'missing password'}), 400
    salt = load_salt()
    key = derive_key(pw, salt)
    f = Fernet(key)
    write_encrypted_vault({'accounts': []}, f)
    return jsonify({'ok': True})

@app.route('/api/unlock', methods=['POST'])
def api_unlock():
    payload = request.json or {}
    pw = payload.get('password')
    if not pw:
        return jsonify({'ok': False, 'error': 'missing password'}), 400
    salt = load_salt()
    key = derive_key(pw, salt)
    f = Fernet(key)
    try:
        vault = read_encrypted_vault(f)
    except InvalidToken:
        return jsonify({'ok': False, 'error': 'wrong password'}), 403
    # return accounts (no secrets stripped) - client trusts server session
    return jsonify({'ok': True, 'accounts': vault.get('accounts', [])})

@app.route('/api/add', methods=['POST'])
def api_add():
    payload = request.json or {}
    pw = payload.get('password')
    data = payload.get('account')
    if not pw or not data:
        return jsonify({'ok': False, 'error': 'missing'}), 400
    salt = load_salt()
    key = derive_key(pw, salt)
    f = Fernet(key)
    try:
        vault = read_encrypted_vault(f)
    except InvalidToken:
        return jsonify({'ok': False, 'error': 'wrong password'}), 403
    # normalize
    acc = Account(
        id=str(uuid.uuid4()),
        issuer=data.get('issuer'),
        label=data.get('label') or 'Account',
        secret_base32=(data.get('secret') or '').replace(' ', '').upper(),
        digits=int(data.get('digits') or 6),
        period=int(data.get('period') or 30),
        algorithm=(data.get('algorithm') or 'SHA1').upper(),
        added_at=time.time(),
    )
    # validate code generation
    try:
        _ = pyotp.TOTP(acc.secret_base32, digits=acc.digits, interval=acc.period).now()
    except Exception as e:
        return jsonify({'ok': False, 'error': f'invalid secret: {e}'}), 400
    vault.setdefault('accounts', []).append(asdict(acc))
    write_encrypted_vault(vault, f)
    return jsonify({'ok': True, 'account': asdict(acc)})

@app.route('/api/remove', methods=['POST'])
def api_remove():
    payload = request.json or {}
    pw = payload.get('password')
    aid = payload.get('id')
    if not pw or not aid:
        return jsonify({'ok': False, 'error': 'missing'}), 400
    salt = load_salt()
    key = derive_key(pw, salt)
    f = Fernet(key)
    try:
        vault = read_encrypted_vault(f)
    except InvalidToken:
        return jsonify({'ok': False, 'error': 'wrong password'}), 403
    before = len(vault.get('accounts', []))
    vault['accounts'] = [a for a in vault.get('accounts', []) if a['id'] != aid]
    write_encrypted_vault(vault, f)
    after = len(vault.get('accounts', []))
    return jsonify({'ok': True, 'removed': before-after})

@app.route('/api/code', methods=['POST'])
def api_code():
    payload = request.json or {}
    pw = payload.get('password')
    aid = payload.get('id')
    if not pw or not aid:
        return jsonify({'ok': False, 'error': 'missing'}), 400
    salt = load_salt()
    key = derive_key(pw, salt)
    f = Fernet(key)
    try:
        vault = read_encrypted_vault(f)
    except InvalidToken:
        return jsonify({'ok': False, 'error': 'wrong password'}), 403
    acc = next((a for a in vault.get('accounts', []) if a['id'] == aid), None)
    if not acc:
        return jsonify({'ok': False, 'error': 'not found'}), 404
    code = pyotp.TOTP(acc['secret_base32'], digits=acc['digits'], interval=acc['period']).now()
    remaining = acc['period'] - (int(time.time()) % acc['period'])
    return jsonify({'ok': True, 'code': code, 'remaining': remaining})

# static files are served automatically by Flask from /static

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)



