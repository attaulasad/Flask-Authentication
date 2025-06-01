from cryptography.fernet import Fernet
import sqlite3
import json
from datetime import datetime
from log_utils import log_action
import os

# Load or generate encryption key
try:
    with open("secret.key", "rb") as f:
        key = f.read()
except FileNotFoundError:
    key = Fernet.generate_key()
    with open("secret.key", "wb") as f:
        f.write(key)

cipher = Fernet(key)

# Database path
DB_PATH = os.getenv("DB_PATH", "users.db")

def get_db_connection():
    """Get a database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def encrypt_data(data: dict) -> str:
    """Encrypt user data into a token."""
    json_data = json.dumps(data)
    token = cipher.encrypt(json_data.encode())
    log_action("encrypted data", data, f"token: {token.decode()[:8]}...")
    return token.decode()

def decrypt_data(token: str) -> dict:
    """Decrypt token into user data."""
    try:
        decrypted = cipher.decrypt(token.encode())
        return json.loads(decrypted.decode())
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")

def encrypt_user_acc_data(data: str) -> str:
    """Encrypt username or password for accounts table."""
    if not isinstance(data, str) or not data:
        raise ValueError("Data must be a non-empty string")
    encrypted = cipher.encrypt(data.encode('utf-8'))
    return encrypted.decode('utf-8')

def decrypt_user_acc_data(encrypted_data: str) -> str:
    """Decrypt username or password from accounts table."""
    try:
        decrypted = cipher.decrypt(encrypted_data.encode('utf-8'))
        return decrypted.decode('utf-8')
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")