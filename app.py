from flask import Flask, request, jsonify, abort, render_template, redirect, url_for, flash, session
from crypto_utils import encrypt_data, decrypt_data, get_db_connection, encrypt_user_acc_data, decrypt_user_acc_data
from datetime import datetime, timedelta
from log_utils import log_action
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import hashlib
from dotenv import load_dotenv
import sqlite3

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")
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

# Initialize and migrate database
def init_db():
    with get_db_connection() as conn:
        c = conn.cursor()
        # Create accounts table
        c.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                created_at TIMESTAMP
            )
        """)
        # Create or migrate api_keys
        c.execute("PRAGMA table_info(api_keys)")
        columns = [row['name'] for row in c.fetchall()]
        has_username = 'username' in columns
        has_account_id = 'account_id' in columns

        if not has_username and has_account_id:
            # api_keys schema is correct
            pass
        elif has_username and not has_account_id:
            # Migrate old api_keys
            print("Migrating api_keys table...")
            c.execute("SELECT api_key, username, created_at FROM api_keys")
            api_keys = c.fetchall()
            c.execute("""
                CREATE TABLE api_keys_new (
                    api_key TEXT PRIMARY KEY,
                    account_id INTEGER NOT NULL,
                    created_at TIMESTAMP,
                    FOREIGN KEY (account_id) REFERENCES accounts(id)
                )
            """)
            for row in api_keys:
                api_key = row['api_key']
                username = row['username']
                created_at = row['created_at']
                encrypted_username = encrypt_user_acc_data(username)
                encrypted_password = encrypt_user_acc_data('migrated_password')
                c.execute("INSERT OR IGNORE INTO accounts (username, password, created_at) VALUES (?, ?, ?)",
                          (encrypted_username, encrypted_password, created_at))
                c.execute("SELECT id FROM accounts WHERE username = ?", (encrypted_username,))
                account_id = c.fetchone()['id']
                c.execute("INSERT INTO api_keys_new (api_key, account_id, created_at) VALUES (?, ?, ?)",
                          (api_key, account_id, created_at))
            c.execute("DROP TABLE api_keys")
            c.execute("ALTER TABLE api_keys_new RENAME TO api_keys")
            print("Migration complete.")
        else:
            # Create api_keys with correct schema
            c.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    api_key TEXT PRIMARY KEY,
                    account_id INTEGER NOT NULL,
                    created_at TIMESTAMP,
                    FOREIGN KEY (account_id) REFERENCES accounts(id)
                )
            """)

        # Create or migrate user_tokens
        c.execute("PRAGMA table_info(user_tokens)")
        columns = [row['name'] for row in c.fetchall()]
        has_api_key = 'api_key' in columns
        has_account_id = 'account_id' in columns

        if not has_api_key and has_account_id:
            # user_tokens schema is correct
            pass
        elif has_api_key and not has_account_id:
            # Migrate user_tokens
            print("Migrating user_tokens table...")
            c.execute("""
                SELECT ut.id, ut.api_key, ut.token, ut.credits, ut.expiry, ak.account_id
                FROM user_tokens ut
                JOIN api_keys ak ON ut.api_key = ak.api_key
            """)
            tokens = c.fetchall()
            c.execute("""
                CREATE TABLE user_tokens_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id INTEGER NOT NULL,
                    token TEXT NOT NULL,
                    credits INTEGER NOT NULL,
                    expiry TIMESTAMP NOT NULL,
                    FOREIGN KEY (account_id) REFERENCES accounts(id)
                )
            """)
            for row in tokens:
                c.execute("""
                    INSERT INTO user_tokens_new (id, account_id, token, credits, expiry)
                    VALUES (?, ?, ?, ?, ?)
                """, (row['id'], row['account_id'], row['token'], row['credits'], row['expiry']))
            c.execute("DROP TABLE user_tokens")
            c.execute("ALTER TABLE user_tokens_new RENAME TO user_tokens")
            print("Migration complete.")
        else:
            # Create user_tokens with correct schema
            c.execute("""
                CREATE TABLE IF NOT EXISTS user_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id INTEGER NOT NULL,
                    token TEXT NOT NULL,
                    credits INTEGER NOT NULL,
                    expiry TIMESTAMP NOT NULL,
                    FOREIGN KEY (account_id) REFERENCES accounts(id)
                )
            """)

        conn.commit()

init_db()

# Generate static API key
def generate_api_key(username, password):
    combined = f"{username}:{password}".encode('utf-8')
    return hashlib.sha256(combined).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash("Please log in to access the admin dashboard.", "danger")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

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
    expiry_minutes = int(data.get("expiry_minutes", 60))

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    api_key = generate_api_key(username, password)
    user_data = {
        "username": username,
        "credits": credits,
        "expiry": (datetime.now() + timedelta(minutes=expiry_minutes)).isoformat(),
        "deleted": False
    }
    token = encrypt_data(user_data)

    with get_db_connection() as conn:
        c = conn.cursor()
        try:
            encrypted_username = encrypt_user_acc_data(username)
            encrypted_password = encrypt_user_acc_data(password)
            c.execute("SELECT id FROM accounts WHERE username = ?", (encrypted_username,))
            if c.fetchone():
                return jsonify({"error": "Username already exists"}), 400
            c.execute("INSERT INTO accounts (username, password, created_at) VALUES (?, ?, ?)",
                      (encrypted_username, encrypted_password, datetime.now()))
            account_id = c.lastrowid
            c.execute("DELETE FROM user_tokens WHERE account_id = ?", (account_id,))
            c.execute("INSERT INTO api_keys (api_key, account_id, created_at) VALUES (?, ?, ?)",
                      (api_key, account_id, datetime.now()))
            c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry) VALUES (?, ?, ?, ?)",
                      (account_id, token, credits, datetime.now() + timedelta(minutes=expiry_minutes)))
            conn.commit()
            log_action("user created", user_data, f"api_key: {api_key[:8]}..., token: {token[:8]}...")
            return jsonify({"api_key": api_key, "token": token})
        except sqlite3.IntegrityError:
            conn.rollback()
            return jsonify({"error": "API key already exists"}), 400

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
            c.execute("""
                SELECT ut.account_id
                FROM user_tokens ut
                WHERE ut.token = ?
            """, (token,))
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
        c.execute("DELETE FROM api_keys WHERE api_key = ?", (api_key,))
        c.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        c.execute("DELETE FROM sqlite_sequence WHERE name IN ('user_tokens', 'accounts')")
        conn.commit()
        log_action("user deleted via API", {"api_key": api_key[:8] + "..."})
        return jsonify({"message": "User and associated tokens deleted"}), 200

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
    expiry_minutes = int(data.get("expiry_minutes", 60))

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    api_key = generate_api_key(username, password)
    user_data = {
        "username": username,
        "credits": credits,
        "expiry": (datetime.now() + timedelta(minutes=expiry_minutes)).isoformat(),
        "deleted": False
    }
    token = encrypt_data(user_data)

    with get_db_connection() as conn:
        c = conn.cursor()
        try:
            encrypted_username = encrypt_user_acc_data(username)
            encrypted_password = encrypt_user_acc_data(password)
            c.execute("SELECT id FROM accounts WHERE username = ?", (encrypted_username,))
            if c.fetchone():
                return jsonify({"error": "Username already exists"}), 400
            c.execute("INSERT INTO accounts (username, password, created_at) VALUES (?, ?, ?)",
                      (encrypted_username, encrypted_password, datetime.now()))
            account_id = c.lastrowid
            c.execute("DELETE FROM user_tokens WHERE account_id = ?", (account_id,))
            c.execute("INSERT INTO api_keys (api_key, account_id, created_at) VALUES (?, ?, ?)",
                      (api_key, account_id, datetime.now()))
            c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry) VALUES (?, ?, ?, ?)",
                      (account_id, token, credits, datetime.now() + timedelta(minutes=expiry_minutes)))
            conn.commit()
            log_action("admin created user", user_data, f"api_key: {api_key[:8]}..., token: {token[:8]}...")
            return jsonify({"message": "User created", "api_key": api_key, "token": token})
        except sqlite3.IntegrityError:
            conn.rollback()
            return jsonify({"error": "API key already exists"}), 400

@app.route('/admin/refill_credits', methods=['POST'])
def admin_refill_credits():
    check_admin()
    api_key = request.json.get("api_key")
    add_credits = int(request.json.get("add_credits", 0))

    if add_credits <= 0:
        return jsonify({"error": "add_credits must be positive"}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT account_id FROM api_keys WHERE api_key = ?", (api_key,))
        account_row = c.fetchone()
        if not account_row:
            return jsonify({"error": "API key not found"}), 404
        account_id = account_row["account_id"]
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
        log_action(f"credits refilled (+{add_credits}) from {old_credits} to {user_data['credits']}", user_data, f"api_key: {api_key[:8]}..., new_token: {new_token[:8]}...")
        return jsonify({"message": "Credits added", "new_token": new_token, "user_data": user_data})

@app.route('/admin/extend_time', methods=['POST'])
def admin_extend_time():
    check_admin()
    api_key = request.json.get("api_key")
    add_minutes = int(request.json.get("add_minutes", 30))

    if add_minutes <= 0:
        return jsonify({"error": "add_minutes must be positive"}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT account_id FROM api_keys WHERE api_key = ?", (api_key,))
        account_row = c.fetchone()
        if not account_row:
            return jsonify({"error": "API key not found"}), 404
        account_id = account_row["account_id"]
        c.execute("SELECT token, credits, expiry FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (account_id,))
        token_data = c.fetchone()
        if not token_data:
            return jsonify({"error": "No tokens found for this account"}), 404

        user_data = decrypt_data(token_data["token"])
        if user_data.get("deleted"):
            return jsonify({"error": "Cannot extend time. User is deleted."}), 403

        expiry = datetime.fromisoformat(user_data["expiry"])
        new_expiry = expiry + timedelta(minutes=add_minutes)
        user_data["expiry"] = new_expiry.isoformat()
        new_token = encrypt_data(user_data)
        c.execute("DELETE FROM user_tokens WHERE account_id = ?", (account_id,))
        c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry) VALUES (?, ?, ?, ?)",
                  (account_id, new_token, user_data["credits"], new_expiry))
        conn.commit()
        log_action(f"expiry extended (+{add_minutes} mins)", user_data, f"api_key: {api_key[:8]}..., new_token: {new_token[:8]}...")
        return jsonify({"message": "Time extended", "new_token": new_token, "user_data": user_data})

# === Admin Dashboard GUI ===

@app.route('/admin')
@login_required
def admin_dashboard():
    new_api_key = request.args.get('new_api_key', '')
    new_token = request.args.get('new_token', '')
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT 
                    ak.api_key, 
                    ak.account_id, 
                    a.username,
                    ut.credits, 
                    ut.expiry, 
                    ut.token
                FROM api_keys ak
                JOIN accounts a ON ak.account_id = a.id
                JOIN user_tokens ut ON ak.account_id = ut.account_id
                WHERE ut.id = (
                    SELECT MAX(id) FROM user_tokens WHERE account_id = ak.account_id
                )
            """)
            active_api_keys = [
                {
                    "api_key": row["api_key"],
                    "username": decrypt_user_acc_data(row["username"]),
                    "credits": row["credits"],
                    "expiry": row["expiry"],
                    "token": row["token"]
                } for row in c.fetchall()
            ]
        return render_template('admin_dashboard.html', new_api_key=new_api_key, new_token=new_token, active_api_keys=active_api_keys)
    except Exception as e:
        flash(f"Error loading dashboard: {str(e)}", "danger")
        return redirect(url_for('login'))

@app.route('/admin/create_user_form', methods=['POST'])
@login_required
def create_user_form():
    username = request.form.get('username')
    password = request.form.get('password')
    credits = int(request.form.get('credits', 10))
    expiry_minutes = int(request.form.get('expiry_minutes', 60))

    if not username or not password:
        flash("Username and password are required.", "danger")
        return redirect(url_for('admin_dashboard'))

    api_key = generate_api_key(username, password)
    user_data = {
        "username": username,
        "credits": credits,
        "expiry": (datetime.now() + timedelta(minutes=expiry_minutes)).isoformat(),
        "deleted": False
    }
    token = encrypt_data(user_data)

    with get_db_connection() as conn:
        c = conn.cursor()
        try:
            encrypted_username = encrypt_user_acc_data(username)
            encrypted_password = encrypt_user_acc_data(password)
            c.execute("SELECT id FROM accounts WHERE username = ?", (encrypted_username,))
            if c.fetchone():
                flash("Error: Username already exists.", "danger")
                return redirect(url_for('admin_dashboard'))
            c.execute("INSERT INTO accounts (username, password, created_at) VALUES (?, ?, ?)",
                      (encrypted_username, encrypted_password, datetime.now()))
            account_id = c.lastrowid
            c.execute("DELETE FROM user_tokens WHERE account_id = ?", (account_id,))
            c.execute("INSERT INTO api_keys (api_key, account_id, created_at) VALUES (?, ?, ?)",
                      (api_key, account_id, datetime.now()))
            c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry) VALUES (?, ?, ?, ?)",
                      (account_id, token, credits, datetime.now() + timedelta(minutes=expiry_minutes)))
            conn.commit()
            log_action("admin created user via form", user_data, f"api_key: {api_key[:8]}..., token: {token[:8]}...")
            flash(f"User created! API key: {api_key[:8]}... Copy the API key and token from the 'New API Key' section below.", "success")
            return redirect(url_for('admin_dashboard', new_api_key=api_key, new_token=token))
        except sqlite3.IntegrityError:
            conn.rollback()
            flash("Error: API key already exists.", "danger")
            return redirect(url_for('admin_dashboard'))

@app.route('/admin/refill_credits_form', methods=['POST'])
@login_required
def refill_credits_form():
    api_key = request.form.get('api_key')
    add_credits = int(request.form.get('add_credits', 0))

    if add_credits <= 0:
        flash("Add credits must be positive.", "danger")
        return redirect(url_for('admin_dashboard'))

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT account_id FROM api_keys WHERE api_key = ?", (api_key,))
        account_row = c.fetchone()
        if not account_row:
            flash("API key not found.", "danger")
            return redirect(url_for('admin_dashboard'))
        account_id = account_row["account_id"]
        c.execute("SELECT token, credits, expiry FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (account_id,))
        token_data = c.fetchone()
        if not token_data:
            flash("No tokens found for this account.", "danger")
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
        log_action(f"credits refilled via form (+{add_credits}) from {old_credits} to {user_data['credits']}", user_data, f"api_key: {api_key[:8]}..., new_token: {new_token[:8]}...")
        flash(f"Credits added! New credits: {user_data['credits']}. Copy the new token from the 'New API Key' section below.", "success")
        return redirect(url_for('admin_dashboard', new_api_key=api_key, new_token=new_token))

@app.route('/admin/extend_time_form', methods=['POST'])
@login_required
def extend_time_form():
    api_key = request.form.get('api_key')
    add_minutes = int(request.form.get('add_minutes', 30))

    if add_minutes <= 0:
        flash("Add minutes must be positive.", "danger")
        return redirect(url_for('admin_dashboard'))

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT account_id FROM api_keys WHERE api_key = ?", (api_key,))
        account_row = c.fetchone()
        if not account_row:
            flash("API key not found.", "danger")
            return redirect(url_for('admin_dashboard'))
        account_id = account_row["account_id"]
        c.execute("SELECT token, credits, expiry FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (account_id,))
        token_data = c.fetchone()
        if not token_data:
            flash("No tokens found for this account.", "danger")
            return redirect(url_for('admin_dashboard'))

        user_data = decrypt_data(token_data["token"])
        if user_data.get("deleted"):
            flash("Cannot extend time. User is deleted.", "danger")
            return redirect(url_for('admin_dashboard'))

        expiry = datetime.fromisoformat(user_data["expiry"])
        new_expiry = expiry + timedelta(minutes=add_minutes)
        user_data["expiry"] = new_expiry.isoformat()
        new_token = encrypt_data(user_data)
        c.execute("DELETE FROM user_tokens WHERE account_id = ?", (account_id,))
        c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry) VALUES (?, ?, ?, ?)",
                  (account_id, new_token, user_data["credits"], new_expiry))
        conn.commit()
        log_action(f"expiry extended via form (+{add_minutes} mins)", user_data, f"api_key: {api_key[:8]}..., new_token: {new_token[:8]}...")
        flash(f"Time extended! Copy the new token from the 'New API Key' section below.", "success")
        return redirect(url_for('admin_dashboard', new_api_key=api_key, new_token=new_token))

@app.route('/admin/check_user_status_form', methods=['POST'])
@login_required
def check_user_status_form():
    api_key = request.form.get('api_key')
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT account_id FROM api_keys WHERE api_key = ?", (api_key,))
        account_row = c.fetchone()
        if not account_row:
            flash("API key not found.", "danger")
            return redirect(url_for('admin_dashboard'))
        account_id = account_row["account_id"]
        c.execute("SELECT token, credits, expiry FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (account_id,))
        token_data = c.fetchone()
        if not token_data:
            flash("No tokens found for this account.", "danger")
            return redirect(url_for('admin_dashboard'))

        user_data = decrypt_data(token_data["token"])
        if user_data.get("deleted"):
            flash("User is deleted.", "info")
            return redirect(url_for('admin_dashboard'))

        expiry_time = datetime.fromisoformat(user_data["expiry"])
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
    api_key = request.form.get('api_key')
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT account_id FROM api_keys WHERE api_key = ?", (api_key,))
        account_row = c.fetchone()
        if not account_row:
            flash("API key not found.", "danger")
            return redirect(url_for('admin_dashboard'))
        account_id = account_row["account_id"]
        c.execute("DELETE FROM user_tokens WHERE account_id = ?", (account_id,))
        c.execute("DELETE FROM api_keys WHERE api_key = ?", (api_key,))
        c.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        c.execute("DELETE FROM sqlite_sequence WHERE name IN ('user_tokens', 'accounts')")
        conn.commit()
        log_action("user deleted via admin form", {"api_key": api_key[:8] + "..."})
        flash("User and associated tokens deleted successfully.", "success")
        return redirect(url_for('admin_dashboard'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)