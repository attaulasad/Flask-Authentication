from cryptography.fernet import Fernet
import json
from datetime import datetime, timedelta
from log_utils import log_action

# Load or generate encryption key
try:
    with open("secret.key", "rb") as f:
        key = f.read()
except FileNotFoundError:
    key = Fernet.generate_key()
    with open("secret.key", "wb") as f:
        f.write(key)

cipher = Fernet(key)

# File-based revocation list
REVOKED_FILE = "revoked_tokens.txt"

def load_revoked_tokens():
    """Load revoked tokens from file."""
    try:
        with open(REVOKED_FILE, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        return set()

def save_revoked_token(token: str):
    """Save a revoked token to file."""
    with open(REVOKED_FILE, "a") as f:
        f.write(token + "\n")

# Initialize revoked tokens
revoked_tokens = load_revoked_tokens()

def encrypt_data(data: dict) -> str:
    """Encrypt user data into a token."""
    log_action("encrypting data", data, f"data: {data}")
    json_data = json.dumps(data)
    token = cipher.encrypt(json_data.encode())
    return token.decode()

def decrypt_data(token: str) -> dict:
    """Decrypt token into user data, checking revocation first."""
    if token in revoked_tokens:
        log_action("attempted decrypt with revoked token", {"token": token})
        raise Exception("Token has been revoked")
    decrypted = cipher.decrypt(token.encode())
    return json.loads(decrypted.decode())

def validate_and_update_token(token: str) -> tuple:
    """
    Validate the token, check expiry, credits, and deleted status,
    decrement credits, return updated user_data and new token.
    """
    try:
        if token in revoked_tokens:
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
    """
    Revoke token without decrypting. Returns success message.
    """
    try:
        if token not in revoked_tokens:
            revoked_tokens.add(token)
            save_revoked_token(token)
        return "User deleted successfully", None
    except Exception as e:
        return None, f"Deletion failed: {str(e)}"