
from flask import Flask, jsonify, request, abort
import sqlite3
import jwt
import datetime
import os
import uuid
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa
from argon2 import PasswordHasher
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
SECRET = "your-secret-key"
ALGORITHM = "RS256"
DATABASE = 'totally_not_my_privateKeys.db'
AES_KEY = os.getenv('NOT_MY_KEY', 'ThisIsADefaultKey1234567890123456')[:32].encode()
backend = default_backend()
ph = PasswordHasher()

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["5 per minute"]
)

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS auth_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

def encrypt_data(plaintext):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt_data(ciphertext):
    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode()

def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode('utf-8')

def save_key(key, exp):
    encrypted_key = encrypt_data(key)
    with get_db() as conn:
        conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_key, exp))

def generate_jwt(payload, private_key, kid):
    headers = {"kid": str(kid)}
    return jwt.encode(payload, private_key, algorithm=ALGORITHM, headers=headers)

@app.route('/auth', methods=['POST'])
def auth():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    with get_db() as conn:
        c = conn.cursor()
        user = c.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,)).fetchone()
        if user:
            user_id, password_hash = user
            try:
                ph.verify(password_hash, password)
                c.execute("INSERT INTO auth_logs(request_ip, user_id) VALUES (?, ?)", (request.remote_addr, user_id))
                conn.commit()
            except Exception:
                abort(401, description="Invalid credentials.")
        else:
            abort(404, description="User not found.")

    expired = request.args.get("expired")
    now = int(datetime.datetime.now().timestamp())

    with get_db() as conn:
        if expired:
            row = conn.execute("SELECT * FROM keys WHERE exp < ?", (now,)).fetchone()
        else:
            row = conn.execute("SELECT * FROM keys WHERE exp > ?", (now,)).fetchone()

    if not row:
        abort(404, description="No appropriate key found")

    private_key = decrypt_data(row['key'])

    payload = {
        "user": username,
        "iat": now,
        "exp": row['exp']
    }
    token = generate_jwt(payload, private_key, row['kid'])
    return jsonify(token=token)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = str(uuid.uuid4())
    password_hash = ph.hash(password)

    with get_db() as conn:
        try:
            conn.execute("INSERT INTO users(username, password_hash, email) VALUES (?, ?, ?)", (username, password_hash, email))
            conn.commit()
        except sqlite3.IntegrityError:
            abort(409, description="Username or email already exists.")

    return jsonify({"password": password}), 201

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    now = int(datetime.datetime.now().timestamp())
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM keys WHERE exp > ?", (now,)).fetchall()

    keys = []
    for row in rows:
        public_key = serialization.load_pem_private_key(
            decrypt_data(row["key"]).encode('utf-8'),
            password=None,
            backend=default_backend()
        ).public_key()

        keys.append({
            "kid": str(row["kid"]),
            "kty": "RSA",
            "use": "sig",
            "alg": ALGORITHM,
            "n": jwt.utils.base64url_encode(public_key.public_numbers().n.to_bytes(256, 'big')).decode('utf-8'),
            "e": jwt.utils.base64url_encode(public_key.public_numbers().e.to_bytes(3, 'big')).decode('utf-8')
        })

    return jsonify({"keys": keys})

if __name__ == '__main__':
    init_db()
    save_key(generate_private_key(), int((datetime.datetime.now() - datetime.timedelta(hours=1)).timestamp()))
    save_key(generate_private_key(), int((datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp()))
    app.run(port=8080)
