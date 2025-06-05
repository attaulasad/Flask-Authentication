from flask import Flask, request, jsonify, flash, render_template, redirect, url_for, session, abort
from crypto_utils import encrypt_data, decrypt_data, get_db_connection, encrypt_user_acc_data, decrypt_user_acc_data
from log_utils import log_action
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import hashlib
import re
from dotenv import load_dotenv
import sqlite3
from cryptography.fernet import Fernet

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# Generate and save key securely
if not os.path.exists("fernet.key"):
    with open("fernet.key", "wb") as f:
        f.write(Fernet.generate_key())

with open("fernet.key", "rb") as f:
    key = f.read()
cipher = Fernet(key)

if not app.secret_key:
    raise ValueError("FLASK_SECRET_KEY environment variable must be set")

# Set session timeout to 15 minutes
app.permanent_session_lifetime = timedelta(minutes=15)

# Admin credentials
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
if not ADMIN_USERNAME or not ADMIN_PASSWORD:
    raise ValueError("ADMIN_USERNAME and ADMIN_PASSWORD environment variables must be set")
ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD)

# Admin API key
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")
if not ADMIN_API_KEY:
    raise ValueError("ADMIN_API_KEY environment variable must be set")

# Register SQLite datetime adapter to handle datetime objects
def adapt_datetime(dt):
    return dt.isoformat()

sqlite3.register_adapter(datetime, adapt_datetime)

# Initialize database
def init_db():
    with get_db_connection() as conn:
        c = conn.cursor()
        # Create accounts table
        c.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL
            )
        """)
        # Create api_keys table
        c.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key TEXT NOT NULL UNIQUE,
                account_id INTEGER NOT NULL UNIQUE,
                created_at TIMESTAMP NOT NULL,
                FOREIGN KEY (account_id) REFERENCES accounts(id)
            )
        """)
        # Create user_tokens table
        c.execute("""
            CREATE TABLE IF NOT EXISTS user_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL,
                token TEXT NOT NULL,
                credits INTEGER NOT NULL,
                expiry TEXT NOT NULL,  -- Stores ISO datetime
                FOREIGN KEY (account_id) REFERENCES accounts(id)
            )
        """)
        conn.commit()

init_db()

# Generate static API key
def generate_api_key(username):
    return hashlib.sha256(username.encode('utf-8')).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash("Please log in to access the admin dashboard.", "danger")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Validate email format
def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['logged_in'] = True
            session.permanent = True
            flash("Logged in successfully!", "success")
            next_url = request.args.get('next') or url_for('admin_dashboard')
            return redirect(next_url)
        else:
            flash("Invalid username or password.", "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))

# === User API Routes ===

@app.route('/encrypt', methods=['POST'])
def encrypt_route():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    credits = int(data.get("credits", 10))
    expiry_value = data.get("expiry_value", 365)
    expiry_unit = data.get("expiry_unit", "Days")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if not is_valid_email(username):
        return jsonify({"error": "Invalid email format"}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        encrypted_username = encrypt_user_acc_data(username)
        c.execute("SELECT id FROM accounts WHERE username = ?", (encrypted_username,))
        if c.fetchone():
            return jsonify({"error": "Email already exists"}), 400

    try:
        expiry_value = int(expiry_value)
        if expiry_value <= 0:
            raise ValueError
        if expiry_unit == "Minutes":
            expiry = (datetime.now() + timedelta(minutes=expiry_value)).isoformat()
        elif expiry_unit == "Days":
            expiry = (datetime.now() + timedelta(days=expiry_value)).isoformat()
        elif expiry_unit == "Months":
            expiry = (datetime.now() + timedelta(days=expiry_value * 30)).isoformat()
        else:
            return jsonify({"error": "Invalid expiry unit"}), 400
    except ValueError:
        return jsonify({"error": "Invalid expiry value"}), 400

    user_data = {
        "username": username,
        "credits": credits,
        "expiry": expiry,
        "deleted": False
    }
    token = encrypt_data(user_data)

    with get_db_connection() as conn:
        c = conn.cursor()
        try:
            encrypted_password = encrypt_user_acc_data(password)
            c.execute("INSERT INTO accounts (username, password, created_at) VALUES (?, ?, ?)",
                      (encrypted_username, encrypted_password, datetime.now()))
            account_id = c.lastrowid
            c.execute("DELETE FROM user_tokens WHERE account_id = ?", (account_id,))
            c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry) VALUES (?, ?, ?, ?)",
                      (account_id, token, credits, expiry))
            conn.commit()
            log_action("user created", user_data, f"token: {token[:8]}...")
            return jsonify({"message": "User created", "token": token})
        except sqlite3.IntegrityError:
            conn.rollback()
            return jsonify({"error": "Database error"}), 400

@app.route('/decrypt', methods=['POST'])
def decrypt_route():
    token = request.json.get("token")
    try:
        user_data = decrypt_data(token)
        if user_data.get("deleted"):
            return jsonify({"error": "User is deleted"}), 403
        expiry_time = datetime.fromisoformat(user_data["expiry"])
        if datetime.now() > expiry_time:
            return jsonify({"error": "Token expired"}), 403
        if user_data["credits"] <= 0:
            return jsonify({"error": "No credits left"}), 403
        user_data["credits"] -= 1
        new_token = encrypt_data(user_data)
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT account_id FROM user_tokens WHERE token = ?", (token,))
            account_row = c.fetchone()
            if not account_row:
                return jsonify({"error": "Token not found"}), 404
            account_id = account_row["account_id"]
            c.execute("DELETE FROM user_tokens WHERE account_id = ?", (account_id,))
            c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry) VALUES (?, ?, ?, ?)",
                      (account_id, new_token, user_data["credits"], user_data["expiry"]))
            conn.commit()
        log_action("accessed /decrypt", user_data, f"new_token: {new_token[:8]}...")
        return jsonify({
            "message": "Access granted",
            "user_data": user_data,
            "new_token": new_token
        })
    except Exception as e:
        return jsonify({"error": f"Invalid token: {str(e)}"}), 400

@app.route('/status', methods=['POST'])
def status_route():
    token = request.json.get("token")
    try:
        user_data = decrypt_data(token)
        if user_data.get("deleted"):
            return jsonify({"status": "deleted", "message": "User has been deleted"}), 403
        expiry_time = datetime.fromisoformat(user_data["expiry"])
        status = "active" if datetime.now() < expiry_time else "expired"
        return jsonify({
            "status": status,
            "credits": user_data["credits"],
            "expiry": user_data["expiry"]
        })
    except Exception as e:
        return jsonify({"error": f"Invalid token: {str(e)}"}), 400

@app.route('/delete_user', methods=['POST'])
def delete_user():
    api_key = request.headers.get("Authorization")
    if not api_key:
        return jsonify({"error": "API key missing"}), 400
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT account_id FROM api_keys WHERE api_key = ?", (api_key,))
        account_row = c.fetchone()
        if not account_row:
            return jsonify({"error": "Invalid API key"}), 401
        account_id = account_row["account_id"]
        c.execute("DELETE FROM user_tokens WHERE account_id = ?", (account_id,))
        c.execute("DELETE FROM api_keys WHERE account_id = ?", (account_id,))
        c.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        c.execute("DELETE FROM sqlite_sequence WHERE name IN ('user_tokens', 'accounts', 'api_keys')")
        conn.commit()
        log_action("user deleted via API", {"api_key": api_key[:8] + "..."})
        return jsonify({"message": "User and associated data deleted successfully"}), 200

# === Admin API Routes ===

def check_admin():
    key = request.headers.get("x-api-key")
    if key != ADMIN_API_KEY:
        abort(403, "Forbidden: Invalid Admin Key")

@app.route('/admin/create_user', methods=['POST'])
def admin_create_user():
    check_admin()
    data = request.json
    username = data.get("username")
    password = data.get("password")
    credits = int(data.get("credits", 10))
    expiry_value = data.get("expiry_value", 365)
    expiry_unit = data.get("expiry_unit", "Days")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if not is_valid_email(username):
        return jsonify({"error": "Invalid email format"}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        encrypted_username = encrypt_user_acc_data(username)
        c.execute("SELECT id FROM accounts WHERE username = ?", (encrypted_username,))
        if c.fetchone():
            return jsonify({"error": "Email already exists"}), 400

    try:
        expiry_value = int(expiry_value)
        if expiry_value <= 0:
            raise ValueError
        if expiry_unit == "Minutes":
            expiry = (datetime.now() + timedelta(minutes=expiry_value)).isoformat()
        elif expiry_unit == "Days":
            expiry = (datetime.now() + timedelta(days=expiry_value)).isoformat()
        elif expiry_unit == "Months":
            expiry = (datetime.now() + timedelta(days=expiry_value * 30)).isoformat()
        else:
            return jsonify({"error": "Invalid expiry unit"}), 400
    except ValueError:
        return jsonify({"error": "Invalid expiry value"}), 400

    user_data = {
        "username": username,
        "credits": credits,
        "expiry": expiry,
        "deleted": False
    }
    token = encrypt_data(user_data)

    with get_db_connection() as conn:
        c = conn.cursor()
        try:
            encrypted_password = encrypt_user_acc_data(password)
            c.execute("INSERT INTO accounts (username, password, created_at) VALUES (?, ?, ?)",
                      (encrypted_username, encrypted_password, datetime.now()))
            account_id = c.lastrowid
            c.execute("DELETE FROM user_tokens WHERE account_id = ?", (account_id,))
            c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry) VALUES (?, ?, ?, ?)",
                      (account_id, token, credits, expiry))
            conn.commit()
            log_action("admin created user", user_data, f"token: {token[:8]}...")
            return jsonify({"message": "User created", "token": token})
        except sqlite3.IntegrityError:
            conn.rollback()
            return jsonify({"error": "Database error"}), 400

@app.route('/admin/refill_credits', methods=['POST'])
def admin_refill_credits():
    check_admin()
    account_id = int(request.json.get("account_id", 0))
    add_credits = int(request.json.get("add_credits", 0))

    if add_credits <= 0 or account_id <= 0:
        return jsonify({"error": "Invalid account_id or add_credits must be positive"}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM accounts WHERE id = ?", (account_id,))
        if not c.fetchone():
            return jsonify({"error": "Account not found"}), 404
        c.execute("SELECT token, credits, expiry FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (account_id,))
        token_data = c.fetchone()
        if not token_data:
            return jsonify({"error": "No tokens found for this account"}), 404

        user_data = decrypt_data(token_data["token"])
        if user_data.get("deleted"):
            return jsonify({"error": "Cannot add credits. User is deleted."}), 403

        old_credits = user_data["credits"]
        user_data["credits"] += add_credits
        new_token = encrypt_data(user_data)
        c.execute("DELETE FROM user_tokens WHERE account_id = ?", (account_id,))
        c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry) VALUES (?, ?, ?, ?)",
                  (account_id, new_token, user_data["credits"], user_data["expiry"]))
        conn.commit()
        log_action(f"credits refilled (+{add_credits}) from {old_credits} to {user_data['credits']}", user_data, f"new_token: {new_token[:8]}...")
        return jsonify({"message": "Credits added", "new_token": new_token, "user_data": user_data})

@app.route('/admin/extend_time', methods=['POST'])
def admin_extend_time():
    check_admin()
    account_id = int(request.json.get("account_id", 0))
    add_value = int(request.json.get("add_value", 30))
    add_unit = request.json.get("add_unit", "Minutes")

    if add_value <= 0 or account_id <= 0:
        return jsonify({"error": "Invalid account_id or add value must be positive"}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM accounts WHERE id = ?", (account_id,))
        if not c.fetchone():
            return jsonify({"error": "Account not found"}), 404
        c.execute("SELECT token, credits, expiry FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (account_id,))
        token_data = c.fetchone()
        if not token_data:
            return jsonify({"error": "No tokens found for this account"}), 404

        user_data = decrypt_data(token_data["token"])
        if user_data.get("deleted"):
            return jsonify({"error": "Cannot extend time. User is deleted."}), 403

        expiry = datetime.fromisoformat(user_data["expiry"])
        if add_unit == "Minutes":
            new_expiry = expiry + timedelta(minutes=add_value)
        elif add_unit == "Days":
            new_expiry = expiry + timedelta(days=add_value)
        elif add_unit == "Months":
            new_expiry = expiry + timedelta(days=add_value * 30)
        else:
            return jsonify({"error": "Invalid time unit"}), 400

        user_data["expiry"] = new_expiry.isoformat()
        new_token = encrypt_data(user_data)
        c.execute("DELETE FROM user_tokens WHERE account_id = ?", (account_id,))
        c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry) VALUES (?, ?, ?, ?)",
                  (account_id, new_token, user_data["credits"], new_expiry))
        conn.commit()
        log_action(f"expiry extended (+{add_value} {add_unit})", user_data, f"new_token: {new_token[:8]}...")
        return jsonify({"message": "Time extended", "new_token": new_token, "user_data": user_data})

# === Admin Dashboard GUI ===

@app.route('/admin')
@login_required
def admin_dashboard():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT 
                    ak.id AS api_key_id,
                    ak.api_key, 
                    ak.account_id, 
                    a.username,
                    ut.credits, 
                    ut.expiry, 
                    ut.token
                FROM accounts a
                LEFT JOIN api_keys ak ON ak.account_id = a.id
                LEFT JOIN user_tokens ut ON a.id = ut.account_id
                WHERE ut.id = (
                    SELECT MAX(id) FROM user_tokens WHERE account_id = a.id
                ) OR ut.id IS NULL
            """)
            active_api_keys = [
                {
                    "api_key_id": row["api_key_id"],
                    "api_key": row["api_key"] or "No API Key",
                    "username": decrypt_user_acc_data(row["username"]),
                    "credits": row["credits"] or 0,
                    "expiry": row["expiry"] or "N/A",
                    "token": row["token"] or "No Token"
                } for row in c.fetchall()
            ]
            c.execute("SELECT id, username FROM accounts")
            users = [
                {
                    "id": row["id"],
                    "username": decrypt_user_acc_data(row["username"])
                } for row in c.fetchall()
            ]
        return render_template('admin_dashboard.html', active_api_keys=active_api_keys, users=users)
    except Exception as e:
        print(e)
        flash(f"Error loading dashboard: {str(e)}", "danger")
        return redirect(url_for('login'))

@app.route('/admin/create_user_form', methods=['POST'])
@login_required
def create_user_form():
    username = request.form.get('username')
    password = request.form.get('password')
    credits = int(request.form.get('credits', 10))
    expiry_value = request.form.get('expiry_value', 365)
    expiry_unit = request.form.get('expiry_unit', "Days")

    if not username or not password:
        flash("Email and password are required.", "danger")
        return redirect(url_for('admin_dashboard'))

    if not is_valid_email(username):
        flash("Invalid email format.", "danger")
        return redirect(url_for('admin_dashboard'))

    with get_db_connection() as conn:
        c = conn.cursor()
        encrypted_username = encrypt_user_acc_data(username)
        c.execute("SELECT id FROM accounts WHERE username = ?", (encrypted_username,))
        if c.fetchone():
            flash("Error: Email already exists.", "danger")
            return redirect(url_for('admin_dashboard'))

    try:
        expiry_value = int(expiry_value)
        if expiry_value <= 0:
            raise ValueError
        if expiry_unit == "Minutes":
            expiry = (datetime.now() + timedelta(minutes=expiry_value)).isoformat()
        elif expiry_unit == "Days":
            expiry = (datetime.now() + timedelta(days=expiry_value)).isoformat()
        elif expiry_unit == "Months":
            expiry = (datetime.now() + timedelta(days=expiry_value * 30)).isoformat()
        else:
            flash("Invalid expiry unit.", "danger")
            return redirect(url_for('admin_dashboard'))
    except ValueError:
        flash("Invalid expiry value.", "danger")
        return redirect(url_for('admin_dashboard'))

    user_data = {
        "username": username,
        "credits": credits,
        "expiry": expiry,
        "deleted": False
    }
    token = encrypt_data(user_data)

    with get_db_connection() as conn:
        c = conn.cursor()
        try:
            encrypted_password = encrypt_user_acc_data(password)
            c.execute("INSERT INTO accounts (username, password, created_at) VALUES (?, ?, ?)",
                      (encrypted_username, encrypted_password, datetime.now()))
            account_id = c.lastrowid
            c.execute("DELETE FROM user_tokens WHERE account_id = ?", (account_id,))
            c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry) VALUES (?, ?, ?, ?)",
                      (account_id, token, credits, expiry))
            conn.commit()
            log_action("admin created user via form", user_data, f"token: {token[:8]}...")
            flash(f"User {username} created successfully.", "success")
            return redirect(url_for('admin_dashboard'))
        except sqlite3.IntegrityError as e:
            conn.rollback()
            flash(f"Error: Database error: {str(e)}", "danger")
            return redirect(url_for('admin_dashboard'))

@app.route('/admin/generate_api_key_form', methods=['POST'])
@login_required
def generate_api_key_form():
    account_id = int(request.form.get('account_id', 0))

    if not account_id:
        flash("User is required.", "danger")
        return redirect(url_for('admin_dashboard'))

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT username FROM accounts WHERE id = ?", (account_id,))
        account = c.fetchone()
        if not account:
            flash("User not found.", "danger")
            return redirect(url_for('admin_dashboard'))

        username = decrypt_user_acc_data(account["username"])

        c.execute("SELECT id FROM api_keys WHERE account_id = ?", (account_id,))
        if c.fetchone():
            flash("Error: User already has an API key. Delete the existing key first.", "danger")
            return redirect(url_for('admin_dashboard'))

        api_key = generate_api_key(username)
        try:
            c.execute("INSERT INTO api_keys (api_key, account_id, created_at) VALUES (?, ?, ?)",
                      (api_key, account_id, datetime.now()))
            conn.commit()
            log_action("api_key generated", {"username": username}, f"api_key: {api_key[:8]}...")
            flash(f"API key generated for {username}.", "success")
            return redirect(url_for('admin_dashboard'))
        except sqlite3.IntegrityError as e:
            conn.rollback()
            flash(f"Error: Database error: {str(e)}", "danger")
            return redirect(url_for('admin_dashboard'))

@app.route('/admin/refill_credits_form', methods=['POST'])
@login_required
def refill_credits_form():
    account_id = int(request.form.get('account_id', 0))
    add_credits = int(request.form.get('add_credits', 0))

    if add_credits <= 0 or account_id <= 0:
        flash("Invalid user or add credits must be positive.", "danger")
        return redirect(url_for('admin_dashboard'))

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM accounts WHERE id = ?", (account_id,))
        if not c.fetchone():
            flash("User not found.", "danger")
            return redirect(url_for('admin_dashboard'))

        c.execute("SELECT token, credits, expiry FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (account_id,))
        token_data = c.fetchone()
        if not token_data:
            flash("No tokens found for this user.", "danger")
            return redirect(url_for('admin_dashboard'))

        user_data = decrypt_data(token_data["token"])
        if user_data.get("deleted"):
            flash("Cannot add credits. User is deleted.", "danger")
            return redirect(url_for('admin_dashboard'))

        old_credits = user_data["credits"]
        user_data["credits"] += add_credits
        new_token = encrypt_data(user_data)
        c.execute("DELETE FROM user_tokens WHERE account_id = ?", (account_id,))
        c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry) VALUES (?, ?, ?, ?)",
                  (account_id, new_token, user_data["credits"], user_data["expiry"]))
        conn.commit()
        log_action(f"credits refilled via form (+{add_credits}) from {old_credits} to {user_data['credits']}", user_data, f"new_token: {new_token[:8]}...")
        flash(f"Credits added for {user_data['username']}. New credits: {user_data['credits']}.", "success")
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/extend_time_form', methods=['POST'])
@login_required
def extend_time_form():
    account_id = int(request.form.get('account_id', 0))
    add_value = int(request.form.get('add_minutes', 30))  # Changed to add_value
    add_unit = request.form.get('add_unit', "Minutes")

    if add_value <= 0 or account_id <= 0:
        flash("Invalid user or add value must be positive.", "danger")
        return redirect(url_for('admin_dashboard'))

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM accounts WHERE id = ?", (account_id,))
        if not c.fetchone():
            flash("User not found.", "danger")
            return redirect(url_for('admin_dashboard'))

        c.execute("SELECT token, credits, expiry FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (account_id,))
        token_data = c.fetchone()
        if not token_data:
            flash("No tokens found for this user.", "danger")
            return redirect(url_for('admin_dashboard'))

        user_data = decrypt_data(token_data["token"])
        if user_data.get("deleted"):
            flash("Cannot extend time. User is deleted.", "danger")
            return redirect(url_for('admin_dashboard'))

        expiry = datetime.fromisoformat(user_data["expiry"])
        if add_unit == "Minutes":
            new_expiry = expiry + timedelta(minutes=add_value)
        elif add_unit == "Days":
            new_expiry = expiry + timedelta(days=add_value)
        elif add_unit == "Months":
            new_expiry = expiry + timedelta(days=add_value * 30)
        else:
            flash("Invalid time unit.", "danger")
            return redirect(url_for('admin_dashboard'))

        user_data["expiry"] = new_expiry.isoformat()
        new_token = encrypt_data(user_data)
        c.execute("DELETE FROM user_tokens WHERE account_id = ?", (account_id,))
        c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry) VALUES (?, ?, ?, ?)",
                  (account_id, new_token, user_data["credits"], new_expiry))
        conn.commit()
        log_action(f"extended time via form (+{add_value} {add_unit})", user_data, f"new_token: {new_token[:8]}...")
        flash(f"Time extended for {user_data['username']}.", "success")
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/check_user_status_form', methods=['POST'])
@login_required
def check_user_status_form():
    account_id = int(request.form.get('account_id', 0))
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM accounts WHERE id = ?", (account_id,))
        if not c.fetchone():
            flash("User not found.", "danger")
            return redirect(url_for('admin_dashboard'))

        c.execute("SELECT token FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (account_id,))
        token_data = c.fetchone()
        if not token_data:
            flash("No tokens found for this user.", "danger")
            return redirect(url_for('admin_dashboard'))

        user_data = decrypt_data(token_data["token"])
        if user_data.get("deleted"):
            flash("User is deleted.", "info")
            return redirect(url_for('admin_dashboard'))

        expiry = user_data["expiry"]
        expiry_time = datetime.fromisoformat(expiry)
        status = "active" if datetime.now() < expiry_time else "expired"
        formatted_expiry = expiry_time.strftime("%B %d, %Y, %I:%M %p")
        message = (
            f"Username: {user_data['username']}<br>"
            f"Credits Left: {user_data['credits']}<br>"
            f"Expiry: {formatted_expiry}<br>"
            f"Status: {status}"
        )
        flash(message, "info")
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user_form', methods=['POST'])
@login_required
def delete_user_form():
    account_id = request.form.get('account_id')
    if account_id == 'delete_all':
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("DELETE FROM user_tokens")
            c.execute("DELETE FROM api_keys")
            c.execute("DELETE FROM accounts")
            c.execute("DELETE FROM sqlite_sequence WHERE name IN ('user_tokens', 'accounts', 'api_keys')")
            conn.commit()
            log_action("all users deleted via admin form", {"action": "delete_all"})
            flash("All users and associated data deleted successfully.", "success")
        return redirect(url_for('admin_dashboard'))
    else:
        account_id = int(account_id)
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT id, username FROM accounts WHERE id = ?", (account_id,))
            account = c.fetchone()
            if not account:
                flash("User not found.", "danger")
                return redirect(url_for('admin_dashboard'))
            username = decrypt_user_acc_data(account[1])
            c.execute("DELETE FROM user_tokens WHERE account_id = ?", (account_id,))
            c.execute("DELETE FROM api_keys WHERE account_id = ?", (account_id,))
            c.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
            c.execute("DELETE FROM sqlite_sequence WHERE name IN ('user_tokens', 'accounts', 'api_keys')")
            conn.commit()
            log_action("user deleted via admin form", {"username": username})
            flash(f"User {username} deleted successfully.", "success")
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_api_key_form', methods=['POST'])
@login_required
def delete_api_key_form():
    api_key_id = int(request.form.get('api_key_id', 0))
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT ak.api_key, a.username, ak.account_id FROM api_keys ak JOIN accounts a ON a.id = ak.account_id WHERE ak.id = ?", (api_key_id,))
        api_key_row = c.fetchone()
        if not api_key_row:
            flash("API key not found.", "danger")
            return redirect(url_for('admin_dashboard'))
        username = decrypt_user_acc_data(api_key_row[1])
        api_key = api_key_row[0]
        account_id = api_key_row[2]
        c.execute("DELETE FROM api_keys WHERE id = ?", (api_key_id,))
        c.execute("DELETE FROM user_tokens WHERE account_id = ?", (account_id,))
        conn.commit()
        log_action("api_key and token deleted via admin form", {"username": username, "api_key": f"{api_key[:8]}..."})
        flash(f"API key and token deleted for {username} successfully.", "success")
        return redirect(url_for('admin_dashboard'))

if __name__ == "__main__":
    app.run()