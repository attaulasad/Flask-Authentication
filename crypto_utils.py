import sqlite3
import json
from cryptography.fernet import Fernet
from log_utils import log_action
import os
import hashlib

# Load or generate encryption key
try:
    with open("fernet.key", "rb") as f:
        key = f.read()
    log_action("fernet_key_loaded", {}, "Key loaded successfully")
except FileNotFoundError:
    key = Fernet.generate_key()
    with open("fernet.key", "wb") as f:
        f.write(key)
    log_action("fernet_key_generated", {}, "New key generated")

cipher = Fernet(key)

# Database path
DB_PATH = os.getenv("DB_PATH", "database.db")

def get_db_connection():
    """Get a database connection. Caller must close it."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_user_acc_data(data: str) -> str:
    """Hash user account data (username/email) for storage."""
    return hashlib.sha256(data.lower().encode('utf-8')).hexdigest()

def encrypt_data(data: dict) -> str:
    """Encrypt user data into a token."""
    json_data = json.dumps(data)
    token = cipher.encrypt(json_data.encode())
    log_action("encrypted_data", data, f"token: {token.decode()[:8]}...")
    return token.decode()

def decrypt_data(token: str) -> dict:
    """Decrypt token into user data."""
    try:
        decrypted = cipher.decrypt(token.encode())
        data = json.loads(decrypted.decode())
        log_action("decrypted_data", {}, f"token: {token[:8]}...")
        return data
    except Exception as e:
        log_action("decryption_failed", {"error": str(e)}, f"token: {token[:8]}...")
        raise ValueError(f"Decryption failed: {str(e)}") from e

def decrypt_user_acc_data(hashed_data: str) -> str:
    """Retrieve original username by matching hashed data."""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT username FROM accounts WHERE username = ?", (hashed_data,))
            row = c.fetchone()
            if not row:
                raise ValueError("No matching username found")
            
            # Get the latest token for the user
            c.execute("""
                SELECT token FROM user_tokens 
                WHERE account_id = (SELECT id FROM accounts WHERE username = ?)
                ORDER BY id DESC LIMIT 1
            """, (hashed_data,))
            token_data = c.fetchone()
            
            if token_data:
                user_data = decrypt_data(token_data["token"])
                return user_data["username"]
            return hashed_data  # Return hashed data if no token found
    except Exception as e:
        log_action("account_decryption_failed", {"error": str(e)}, f"hashed_data: {hashed_data[:8]}...")
        return hashed_data  # Return hashed data on error
