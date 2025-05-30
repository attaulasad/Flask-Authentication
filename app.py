from flask import Flask, request, jsonify, abort, render_template, redirect, url_for, flash, session
from crypto_utils import encrypt_data, decrypt_data, get_db_connection
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

# Initialize database
def init_db():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                api_key TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                created_at TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS user_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key TEXT NOT NULL,
                token TEXT NOT NULL,
                credits INTEGER NOT NULL,
                expiry TIMESTAMP NOT NULL,
                FOREIGN KEY (api_key) REFERENCES api_keys(api_key)
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
            c.execute("INSERT INTO api_keys (api_key, username, created_at) VALUES (?, ?, ?)",
                      (api_key, username, datetime.now()))
            c.execute("INSERT INTO user_tokens (api_key, token, credits, expiry) VALUES (?, ?, ?, ?)",
                      (api_key, token, credits, datetime.now() + timedelta(minutes=expiry_minutes)))
            conn.commit()
            log_action("user created", user_data, f"api_key: {api_key[:8]}..., token: {token[:8]}...")
            return jsonify({"api_key": api_key, "token": token})
        except sqlite3.IntegrityError:
            conn.rollback()
            return jsonify({"error": "API key already exists for this username"}), 400

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
            c.execute("UPDATE user_tokens SET token = ?, credits = ?, expiry = ? WHERE token = ?",
                      (new_token, user_data["credits"], user_data["expiry"], token))
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
        c.execute("SELECT api_key FROM api_keys WHERE api_key = ?", (api_key,))
        if not c.fetchone():
            return jsonify({"error": "Invalid API key"}), 401
        c.execute("DELETE FROM user_tokens WHERE api_key = ?", (api_key,))
        c.execute("DELETE FROM api_keys WHERE api_key = ?", (api_key,))
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
            c.execute("INSERT INTO api_keys (api_key, username, created_at) VALUES (?, ?, ?)",
                      (api_key, username, datetime.now()))
            c.execute("INSERT INTO user_tokens (api_key, token, credits, expiry) VALUES (?, ?, ?, ?)",
                      (api_key, token, credits, datetime.now() + timedelta(minutes=expiry_minutes)))
            conn.commit()
            log_action("admin created user", user_data, f"api_key: {api_key[:8]}..., token: {token[:8]}...")
            return jsonify({"message": "User created", "api_key": api_key, "token": token})
        except sqlite3.IntegrityError:
            conn.rollback()
            return jsonify({"error": "API key already exists for this username"}), 400

@app.route('/admin/refill_credits', methods=['POST'])
def admin_refill_credits():
    check_admin()
    api_key = request.json.get("api_key")
    add_credits = int(request.json.get("add_credits", 0))

    if add_credits <= 0:
        return jsonify({"error": "add_credits must be positive"}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT token, credits, expiry FROM user_tokens WHERE api_key = ? ORDER BY id DESC LIMIT 1", (api_key,))
        token_data = c.fetchone()
        if not token_data:
            return jsonify({"error": "API key not found"}), 404

        user_data = decrypt_data(token_data["token"])
        if user_data.get("deleted"):
            return jsonify({"error": "Cannot add credits. User is deleted."}), 403

        old_credits = user_data["credits"]
        user_data["credits"] += add_credits
        new_token = encrypt_data(user_data)
        c.execute("INSERT INTO user_tokens (api_key, token, credits, expiry) VALUES (?, ?, ?, ?)",
                  (api_key, new_token, user_data["credits"], user_data["expiry"]))
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
        c.execute("SELECT token, credits, expiry FROM user_tokens WHERE api_key = ? ORDER BY id DESC LIMIT 1", (api_key,))
        token_data = c.fetchone()
        if not token_data:
            return jsonify({"error": "API key not found"}), 404

        user_data = decrypt_data(token_data["token"])
        if user_data.get("deleted"):
            return jsonify({"error": "Cannot extend time. User is deleted."}), 403

        expiry = datetime.fromisoformat(user_data["expiry"])
        new_expiry = expiry + timedelta(minutes=add_minutes)
        user_data["expiry"] = new_expiry.isoformat()
        new_token = encrypt_data(user_data)
        c.execute("INSERT INTO user_tokens (api_key, token, credits, expiry) VALUES (?, ?, ?, ?)",
                  (api_key, new_token, user_data["credits"], new_expiry))
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
                SELECT ak.api_key, ak.username, ut.credits, ut.expiry, ut.token
                FROM api_keys ak
                JOIN user_tokens ut ON ak.api_key = ut.api_key
                WHERE ut.id = (SELECT MAX(id) FROM user_tokens WHERE api_key = ak.api_key)
            """)
            active_api_keys = [
                {
                    "api_key": row["api_key"],
                    "username": row["username"],
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
            c.execute("INSERT INTO api_keys (api_key, username, created_at) VALUES (?, ?, ?)",
                      (api_key, username, datetime.now()))
            c.execute("INSERT INTO user_tokens (api_key, token, credits, expiry) VALUES (?, ?, ?, ?)",
                      (api_key, token, credits, datetime.now() + timedelta(minutes=expiry_minutes)))
            conn.commit()
            log_action("admin created user via form", user_data, f"api_key: {api_key[:8]}..., token: {token[:8]}...")
            flash(f"User created! API key: {api_key[:8]}... Copy the API key and token from the 'New API Key' section below.", "success")
            return redirect(url_for('admin_dashboard', new_api_key=api_key, new_token=token))
        except sqlite3.IntegrityError:
            conn.rollback()
            flash("Error: API key already exists for this username.", "danger")
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
        c.execute("SELECT token, credits, expiry FROM user_tokens WHERE api_key = ? ORDER BY id DESC LIMIT 1", (api_key,))
        token_data = c.fetchone()
        if not token_data:
            flash("API key not found.", "danger")
            return redirect(url_for('admin_dashboard'))

        user_data = decrypt_data(token_data["token"])
        if user_data.get("deleted"):
            flash("Cannot add credits. User is deleted.", "danger")
            return redirect(url_for('admin_dashboard'))

        old_credits = user_data["credits"]
        user_data["credits"] += add_credits
        new_token = encrypt_data(user_data)
        c.execute("INSERT INTO user_tokens (api_key, token, credits, expiry) VALUES (?, ?, ?, ?)",
                  (api_key, new_token, user_data["credits"], user_data["expiry"]))
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
        c.execute("SELECT token, credits, expiry FROM user_tokens WHERE api_key = ? ORDER BY id DESC LIMIT 1", (api_key,))
        token_data = c.fetchone()
        if not token_data:
            flash("API key not found.", "danger")
            return redirect(url_for('admin_dashboard'))

        user_data = decrypt_data(token_data["token"])
        if user_data.get("deleted"):
            flash("Cannot extend time. User is deleted.", "danger")
            return redirect(url_for('admin_dashboard'))

        expiry = datetime.fromisoformat(user_data["expiry"])
        new_expiry = expiry + timedelta(minutes=add_minutes)
        user_data["expiry"] = new_expiry.isoformat()
        new_token = encrypt_data(user_data)
        c.execute("INSERT INTO user_tokens (api_key, token, credits, expiry) VALUES (?, ?, ?, ?)",
                  (api_key, new_token, user_data["credits"], new_expiry))
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
        c.execute("SELECT token, credits, expiry FROM user_tokens WHERE api_key = ? ORDER BY id DESC LIMIT 1", (api_key,))
        token_data = c.fetchone()
        if not token_data:
            flash("API key not found.", "danger")
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
        c.execute("SELECT api_key FROM api_keys WHERE api_key = ?", (api_key,))
        if not c.fetchone():
            flash("API key not found.", "danger")
            return redirect(url_for('admin_dashboard'))
        c.execute("DELETE FROM user_tokens WHERE api_key = ?", (api_key,))
        c.execute("DELETE FROM api_keys WHERE api_key = ?", (api_key,))
        conn.commit()
        log_action("user deleted via admin form", {"api_key": api_key[:8] + "..."})
        flash("User and associated tokens deleted successfully.", "success")
        return redirect(url_for('admin_dashboard'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)