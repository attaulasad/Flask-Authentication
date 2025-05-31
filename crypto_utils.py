from cryptography.fernet import Fernet
import sqlite3
import json
from datetime import datetime, timedelta
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

def init_db():
    """Initialize the database with revoked_tokens table."""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                token TEXT PRIMARY KEY,
                revoked_at TEXT
            )
        """)
        conn.commit()

# Initialize database
init_db()

def get_db_connection():
    """Get a database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def is_token_revoked(token: str) -> bool:
    """Check if token is revoked."""
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT token FROM revoked_tokens WHERE token = ?", (token,))
        return c.fetchone() is not None

def revoke_token(token: str):
    """Revoke a token by adding it to the database."""
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO revoked_tokens (token, revoked_at) VALUES (?, ?)",
                  (token, datetime.now().isoformat()))
        conn.commit()

def encrypt_data(data: dict) -> str:
    """Encrypt user data into a token."""
    json_data = json.dumps(data)
    token = cipher.encrypt(json_data.encode())
    log_action("encrypted data", data, f"token: {token.decode()[:20]}...")
    return token.decode()

def decrypt_data(token: str) -> dict:
    """Decrypt token into user data, checking revocation."""
    if is_token_revoked(token):
        log_action("attempted decrypt with revoked token", {"token": token[:20] + "..."})
        raise Exception("Token has been revoked")
    try:
        decrypted = cipher.decrypt(token.encode())
        return json.loads(decrypted.decode())
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")

def validate_and_update_token(token: str) -> tuple:
    """Validate token, check expiry/credits/deleted, decrement credits, return updated data."""
    try:
        if is_token_revoked(token):
            return None, "Token revoked"

        user_data = decrypt_data(token)
        if user_data.get("deleted", False):
            return None, "User is deleted"

        expiry_time = datetime.fromisoformat(user_data["expiry"])
        if datetime.now() > expiry_time:
            return None, "Access expired"

        if user_data["credits"] <= 0:
            return None, "No credits left"

        user_data["credits"] -= 1
        updated_token = encrypt_data(user_data)
        return (user_data, updated_token), None
    except Exception as e:
        return None, f"Invalid token or decryption failed: {str(e)}"

def delete_user_and_get_token(token: str) -> tuple:
    """Revoke token without decrypting."""
    try:
        if not is_token_revoked(token):
            revoke_token(token)
        return "User deleted successfully", None
    except Exception as e:
        return None, f"Deletion failed: {str(e)}"