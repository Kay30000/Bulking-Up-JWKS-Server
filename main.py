from http.server import BaseHTTPRequestHandler, HTTPServer ##Backup: merge2.py
from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse, parse_qs
import base64
import os
import json
import jwt
from datetime import datetime, timezone, timedelta
import sqlite3
import uuid
from argon2 import PasswordHasher
from collections import deque

# Load environment variables
load_dotenv()

hostName = "localhost"
serverPort = 8080

# Generate RSA keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

ph = PasswordHasher()

# In-memory rate limiting dictionary (for POST /auth endpoint)
rate_limiter = {}

def db_connection():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    conn.execute('PRAGMA journal_mode=WAL;')
    return conn

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')  # removes trailing '='
    return encoded.decode('utf-8')

def encrypt_data(data):
    """Encrypt data using AES (CBC mode with a random IV)"""
    aes_key = os.getenv("NOT_MY_KEY")
    if not aes_key:
        raise ValueError("Environment variable NOT_MY_KEY is not set or is empty.")

    aes_key = aes_key.encode('utf-8')
    if len(aes_key) not in [16, 24, 32]:
        raise ValueError("AES_KEY must be 16, 24, or 32 bytes in length.")

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = data + ' ' * (16 - len(data) % 16)
    encrypted_data = encryptor.update(padded_data.encode()) + encryptor.finalize()

    return base64.b64encode(iv + encrypted_data).decode('utf-8')

def log_auth_request(request_ip, user_id):
    """Log the authentication request in the auth_logs table."""
    try:
        print(f"Logging request - IP: {request_ip}, User ID: {user_id}")  # Debugging log
        conn = db_connection()
        cursor = conn.cursor()
        timestamp = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            "INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)",
            (request_ip, timestamp, user_id)
        )
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()

class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        parsed_path = urlparse(self.path)

        if parsed_path.path == "/register":
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            user_data = json.loads(body)

            username = user_data.get("username")
            email = user_data.get("email")

            if not username or not email:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(bytes(json.dumps({"error": "Username and email are required."}), "utf-8"))
                return

            password = str(uuid.uuid4())
            hashed_password = ph.hash(password)

            conn = db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                (username, hashed_password, email)
            )
            conn.commit()
            conn.close()

            self.send_response(201)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(bytes(json.dumps({"password": password}), "utf-8"))
            return

        if parsed_path.path == "/auth":
            # Rate limiter check
            request_ip = self.client_address[0]
            now = datetime.now(timezone.utc)
            window_start = now - timedelta(seconds=1)

            if request_ip not in rate_limiter:
                rate_limiter[request_ip] = deque()

            # Remove timestamps older than 1 second from the queue
            while rate_limiter[request_ip] and rate_limiter[request_ip][0] < window_start:
                rate_limiter[request_ip].popleft()

            # Check if there are more than 10 requests in the last second
            if len(rate_limiter[request_ip]) >= 10:
                self.send_response(429)
                self.end_headers()
                self.wfile.write(bytes(json.dumps({"error": "Too many requests. Please try again later."}), "utf-8"))
                return

            # Log the request time
            rate_limiter[request_ip].append(now)

            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')

            if not body:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(bytes(json.dumps({"error": "Empty request body"}), "utf-8"))
                return

            try:
                auth_data = json.loads(body)
            except json.JSONDecodeError:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(bytes(json.dumps({"error": "Invalid JSON in request body"}), "utf-8"))
                return

            username = auth_data.get("username")
            timestamp = auth_data.get("timestamp")

            if not username or not timestamp:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(bytes(json.dumps({"error": "Missing required fields: username and timestamp."}), "utf-8"))
                return

            try:
                datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(bytes(json.dumps({"error": "Invalid timestamp format. Must be ISO 8601."}), "utf-8"))
                return

            # Get the request IP
            request_ip = self.client_address[0]

            # Check user exists
            # Check user exists
            conn = db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            conn.close()

            if user:
                user_id = user[0]
                print(f"User ID found: {user_id}")  # Debugging log
            else:
                user_id = None
                print("User not found in database.")  # Debugging log

            if not user_id:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(bytes(json.dumps({"error": "User not found"}), "utf-8"))
                return


            headers = {"kid": "goodKID"}
            token_payload = {
                "user": username,
                "exp": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
            }
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            encrypted_jwt = encrypt_data(encoded_jwt)

            try:
                log_auth_request(request_ip, user_id)
            except sqlite3.OperationalError as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(bytes(json.dumps({"error": "Database error: " + str(e)}), "utf-8"))
                return

            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encrypted_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        parsed_path = urlparse(self.path)

        if parsed_path.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(private_key.private_numbers().public_numbers.n),
                        "e": int_to_base64(private_key.private_numbers().public_numbers.e),
                    },
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "expiredKID",
                        "n": int_to_base64(expired_key.private_numbers().public_numbers.n),
                        "e": int_to_base64(expired_key.private_numbers().public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()

if __name__ == "__main__":
    print("Starting the server...")
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
       webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")
