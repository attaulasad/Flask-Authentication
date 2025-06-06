from flask import Flask, request, jsonify, flash, render_template, redirect, url_for, session, abort
from crypto_utils import encrypt_data, decrypt_data, get_db_connection, hash_user_acc_data, decrypt_user_acc_data
from log_utils import log_action
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import hashlib
import re
from dotenv import load_dotenv
import sqlite3

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# Validate environment variables
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

# Register SQLite datetime adapter
def adapt_datetime(dt):
    return dt.isoformat()

sqlite3.register_adapter(datetime, adapt_datetime)

# Initialize database
def init_db():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    api_key TEXT NOT NULL UNIQUE,
                    account_id INTEGER NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (account_id) REFERENCES accounts(id)
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS user_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id INTEGER NOT NULL,
                    token TEXT NOT NULL,
                    credits INTEGER NOT NULL,
                    expiry_date TEXT NOT NULL,
                    FOREIGN KEY (account_id) REFERENCES accounts(id)
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS request_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id INTEGER NOT NULL,
                    request_type TEXT NOT NULL,
                    credits INTEGER NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    FOREIGN KEY (account_id) REFERENCES accounts(id)
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            # Ensure BONUS_CREDITS exists
            c.execute("SELECT value FROM settings WHERE key = 'BONUS_CREDITS'")
            if c.fetchone() is None:
                c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('BONUS_CREDITS', '10')")
            conn.commit()
            log_action("database_initialized", {"action": "Tables created or verified"}, "Success")
    except Exception as e:
        log_action("database_init_failed", {"error": str(e)}, "Initialization error")
        raise ValueError(f"Database initialization failed: {str(e)}")

try:
    init_db()
except Exception as e:
    print(f"Error initializing database: {str(e)}")
    raise

# Generate static API key
def generate_api_key(username):
    return hashlib.sha256(username.lower().encode('utf-8')).hexdigest()

# Decorators
def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash("Please log in as admin to access this page.", "danger")
            return redirect(url_for('admin_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def user_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_logged_in'):
            flash("Please log in to access your dashboard.", "danger")
            return redirect(url_for('user_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get("Authorization")
        if not api_key or not api_key.startswith("Bearer "):
            return jsonify({"error": "API key missing or invalid"}), 400
        api_key = api_key.replace("Bearer ", "")
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT account_id FROM api_keys WHERE api_key = ?", (api_key,))
            account = c.fetchone()
            if not account:
                return jsonify({"error": "Invalid API key"}), 401
            request.account_id = account["account_id"]
        return f(*args, **kwargs)
    return decorated_function

# Validate email format
def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Get BONUS_CREDITS from settings
def get_bonus_credits():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT value FROM settings WHERE key = 'BONUS_CREDITS'")
            result = c.fetchone()
            return int(result['value']) if result else 10
    except Exception as e:
        log_action("get_bonus_credits_failed", {"error": str(e)}, "Using default 10")
        print(f"Error fetching bonus credits: {str(e)}")
        return 10

# === Admin Routes ===
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    try:
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            if not username or not password:
                flash("Username and password are required.", "danger")
                return redirect(url_for('login'))
            if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
                session['admin_logged_in'] = True
                session.permanent = True
                flash("Logged in successfully!", "success")
                log_action("admin_login", {"username": username, "action": "login_success"}, "Success")
                next_url = request.args.get('next') or url_for('admin_dashboard')
                return redirect(next_url)
            else:
                flash("Invalid username or password.", "danger")
                log_action("admin_login_failed", {"username": username, "action": "invalid_credentials"}, "Invalid credentials")
                return redirect(url_for('login'))
        return render_template('login.html')
    except Exception as e:
        log_action("admin_login_error", {"error": str(e)}, "Unexpected error")
        print(f"Error in admin_login: {str(e)}")
        return abort(500, description=f"Internal Server Error: {str(e)}")

@app.route('/admin/logout')
@admin_login_required
def admin_logout():
    session.pop('admin_logged_in', None)
    flash("Logged out successfully.", "success")
    log_action("admin_logout", {"action": "logout_success"}, "Success")
    return redirect(url_for('admin_login'))

@app.route('/admin')
@admin_login_required
def admin_dashboard():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT 
                    a.id AS account_id,
                    ak.id AS api_key_id,
                    ak.api_key, 
                    a.username,
                    ut.credits, 
                    ut.expiry_date, 
                    ut.token
                FROM accounts a
                LEFT JOIN api_keys ak ON ak.account_id = a.id
                LEFT JOIN (
                    SELECT account_id, MAX(id) AS max_id
                    FROM user_tokens
                    GROUP BY account_id
                ) latest_ut ON a.id = latest_ut.account_id
                LEFT JOIN user_tokens ut ON ut.id = latest_ut.max_id
            """)
            active_api_keys = []
            for row in c.fetchall():
                try:
                    username = decrypt_user_acc_data(row['username'])
                except:
                    username = "Decryption Error"
                active_api_keys.append({
                    "account_id": row['account_id'],
                    "api_key_id": row['api_key_id'],
                    "api_key": row['api_key'] if row['api_key'] else "No API Key",
                    "username": username,
                    "credits": row['credits'] if row['credits'] else 0,
                    "expiry": row['expiry_date'] if row['expiry_date'] else "N/A",
                    "token": row['token'][:10] + "..." if row['token'] else "No Token"
                })
                
            c.execute("SELECT id, username FROM accounts")
            users = []
            for row in c.fetchall():
                try:
                    username = decrypt_user_acc_data(row['username'])
                except:
                    username = "Decryption Error"
                users.append({
                    "id": row['id'],
                    "username": username
                })
                
            bonus_credits = get_bonus_credits()
            
        return render_template('admin_dashboard.html', 
                               active_api_keys=active_api_keys, 
                               users=users, 
                               bonus_credits=bonus_credits)
    except Exception as e:
        log_action("admin_dashboard_error", {"error": str(e)}, "Failed to load dashboard")
        print(f"Error in admin_dashboard: {str(e)}")
        flash(f"Error loading dashboard: {str(e)}", "danger")
        return redirect(url_for('admin_login'))

@app.route('/admin/update_bonus', methods=['POST'])
@admin_login_required
def update_bonus():
    try:
        bonus_credits = int(request.form.get('bonus_credits'))
        if bonus_credits < 0:
            raise ValueError("Bonus credits cannot be negative")
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('BONUS_CREDITS', ?)", (str(bonus_credits),))
            conn.commit()
            log_action("bonus_updated", {"username": "admin", "action": "bonus_credits_updated", "new_value": bonus_credits}, "Success")
            flash("Bonus credits updated", "success")
        return redirect(url_for('admin_dashboard'))
    except ValueError as e:
        flash(f"Invalid bonus credits value: {e}", "danger")
        log_action("update_bonus_failed", {"username": "admin", "action": "update_bonus_credits", "error": str(e)}, "Invalid input")
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        log_action("update_bonus_error", {"username": "admin", "action": "update_bonus", "error": str(e)}, "Unexpected error")
        flash("Error updating bonus credits.", "danger")
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/create_user_form', methods=['POST'])
@admin_login_required
def create_user_form():
    try:
        username = request.form.get('username').lower()
        password = request.form.get('password')
        credits = int(request.form.get('credits', get_bonus_credits()))

        if not username or not password:
            flash("Email and password are required.", "danger")
            return redirect(url_for('admin_dashboard'))

        if not is_valid_email(username):
            flash("Invalid email format.", "danger")
            return redirect(url_for('admin_dashboard'))

        with get_db_connection() as conn:
            c = conn.cursor()
            hashed_username = hash_user_acc_data(username)
            c.execute("SELECT id FROM accounts WHERE username = ?", (hashed_username,))
            if c.fetchone():
                flash("Error: Email already exists.", "danger")
                return redirect(url_for('admin_dashboard'))

        expiry = (datetime.now() + timedelta(days=365)).isoformat()
        user_data = {
            "username": username,
            "credits": credits,
            "expiry": expiry,
            "deleted": False
        }
        token = encrypt_data(user_data)

        with get_db_connection() as conn:
            c = conn.cursor()
            hashed_username = hash_user_acc_data(username)
            encrypted_password = generate_password_hash(password)
            c.execute("INSERT INTO accounts (username, password, created_at) VALUES (?, ?, ?)",
                      (hashed_username, encrypted_password, datetime.now().isoformat()))
            account_id = c.lastrowid
            c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry_date) VALUES (?, ?, ?, ?)",
                      (account_id, token, credits, expiry))
            conn.commit()
            log_action("admin_user_created", {"username": username, "action": "Account created", "credits": credits}, f"account_id: {account_id}")
            flash(f"User {username} created successfully.", "success")
            return redirect(url_for('admin_dashboard'))
    except sqlite3.IntegrityError:
        log_action("create_user_failed", {"username": username, "action": "Duplicate email"}, "Duplicate email")
        flash("Error: Email already exists.", "danger")
        return redirect(url_for('admin_dashboard'))
    except ValueError as e:
        log_action("create_user_failed", {"error": str(e), "username": username}, "Invalid input")
        flash(f"Invalid input: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        log_action("create_user_failed", {"error": str(e), "username": username}, "Failed to create account")
        print(f"Error in create_user_form: {str(e)}")
        flash(f"Failed to create account: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/generate_api_key_form', methods=['POST'])
@admin_login_required
def generate_api_key_form():
    try:
        account_id = int(request.form.get('account_id'))
        expiry_value = int(request.form.get('expiry_value', 365))
        expiry_unit = request.form.get('expiry_unit', "Days")

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

            username = decrypt_user_acc_data(account["username"]).lower()

            c.execute("SELECT id FROM api_keys WHERE account_id = ?", (account_id,))
            if c.fetchone():
                flash("Error: User already has an API key. Delete the existing key first.", "danger")
                return redirect(url_for('admin_dashboard'))

            if expiry_value <= 0:
                raise ValueError("Expiry value must be positive")
                
            if expiry_unit == "Minutes":
                expiry = datetime.now() + timedelta(minutes=expiry_value)
            elif expiry_unit == "Days":
                expiry = datetime.now() + timedelta(days=expiry_value)
            elif expiry_unit == "Months":
                expiry = datetime.now() + timedelta(days=expiry_value * 30)
            else:
                raise ValueError("Invalid expiry unit")

            expiry_iso = expiry.isoformat()
            api_key = generate_api_key(username)

            c.execute("INSERT INTO api_keys (api_key, account_id, created_at) VALUES (?, ?, ?)", 
                      (api_key, account_id, datetime.now().isoformat()))
            
            # Get current token or create new
            c.execute("SELECT token, credits FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (account_id,))
            token_data = c.fetchone()
            
            if token_data:
                user_data = decrypt_data(token_data["token"])
                credits = user_data["credits"]
            else:
                credits = get_bonus_credits()
                user_data = {
                    "username": username,
                    "credits": credits,
                    "expiry": expiry_iso,
                    "deleted": False
                }
            
            user_data["expiry"] = expiry_iso
            new_token = encrypt_data(user_data)
            
            c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry_date) VALUES (?, ?, ?, ?)",
                      (account_id, new_token, credits, expiry_iso))
            
            conn.commit()
            log_action("api_key_generated", {"username": username, "action": "API key generated"}, f"API key: {api_key[:8]}...")
            flash(f"API key generated for user with expiry {expiry_value} {expiry_unit}.", "success")
            return redirect(url_for('admin_dashboard'))
    except ValueError as e:
        log_action("generate_api_key_failed", {"error": str(e), "account_id": account_id}, "Invalid input")
        flash(f"Invalid input: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))
    except sqlite3.IntegrityError:
        log_action("generate_api_key_failed", {"error": "Database integrity error", "account_id": account_id}, "Database error")
        flash("Error: Database error.", "danger")
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        log_action("generate_api_key_error", {"error": str(e), "account_id": account_id}, "Unexpected error")
        print(f"Error in generate_api_key_form: {str(e)}")
        flash(f"Failed to generate API key: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/refill_credits_form', methods=['POST'])
@admin_login_required
def refill_credits_form():
    try:
        account_id = int(request.form.get('account_id'))
        add_credits = int(request.form.get('add_credits'))
        if add_credits <= 0:
            raise ValueError("Credits to add must be positive")
            
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT token, credits FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (account_id,))
            token_data = c.fetchone()
            if not token_data:
                flash("User not found or no token exists.", "danger")
                return redirect(url_for('admin_dashboard'))
                
            username = decrypt_user_acc_data(c.execute("SELECT username FROM accounts WHERE id = ?", (account_id,)).fetchone()[0])
            user_data = decrypt_data(token_data["token"])
            user_data["credits"] += add_credits
            new_token = encrypt_data(user_data)
            
            c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry_date) VALUES (?, ?, ?, ?)",
                      (account_id, new_token, user_data["credits"], user_data["expiry"]))
            
            c.execute("INSERT INTO request_history (account_id, request_type, credits, timestamp) VALUES (?, ?, ?, ?)",
                      (account_id, "credits_refill", add_credits, datetime.now()))
            
            conn.commit()
            log_action("credits_refilled", {"username": username, "action": "Credits added", "credits_added": add_credits}, f"new_credits: {user_data['credits']}")
            flash(f"Added {add_credits} credits to user.", "success")
            return redirect(url_for('admin_dashboard'))
    except ValueError as e:
        log_action("refill_credits_failed", {"error": str(e), "account_id": account_id}, "Invalid input")
        flash(f"Invalid input: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        log_action("refill_credits_error", {"error": str(e), "account_id": account_id}, "Unexpected error")
        print(f"Error in refill_credits_form: {str(e)}")
        flash(f"Error refilling credits: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/extend_time_form', methods=['POST'])
@admin_login_required
def extend_time_form():
    try:
        account_id = int(request.form.get('account_id'))
        add_value = int(request.form.get('add_value'))
        add_unit = request.form.get('add_unit', 'Days')
        if add_value <= 0:
            flash("Time to add must be positive.", "danger")
            return redirect(url_for('admin_dashboard'))
            
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT token, expiry_date FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (account_id,))
            token_data = c.fetchone()
            if not token_data:
                flash("User not found or no token exists.", "danger")
                return redirect(url_for('admin_dashboard'))
                
            username = decrypt_user_acc_data(c.execute("SELECT username FROM accounts WHERE id = ?", (account_id,)).fetchone()[0])
            user_data = decrypt_data(token_data["token"])
            expiry_time = datetime.fromisoformat(user_data["expiry"])
            
            if add_unit == "Minutes":
                new_expiry = expiry_time + timedelta(minutes=add_value)
            elif add_unit == "Days":
                new_expiry = expiry_time + timedelta(days=add_value)
            elif add_unit == "Months":
                new_expiry = expiry_time + timedelta(days=add_value * 30)
            else:
                flash("Invalid time unit.", "danger")
                return redirect(url_for('admin_dashboard'))
                
            user_data["expiry"] = new_expiry.isoformat()
            new_token = encrypt_data(user_data)
            
            c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry_date) VALUES (?, ?, ?, ?)",
                      (account_id, new_token, user_data["credits"], user_data["expiry"]))
            
            c.execute("INSERT INTO request_history (account_id, request_type, credits, timestamp) VALUES (?, ?, ?, ?)",
                      (account_id, "time_extension", 0, datetime.now()))
            
            conn.commit()
            log_action("time_extended", {"username": username, "action": "time extended", "new_expiry": new_expiry.isoformat()},
                      f"extended_by: {add_value} {add_unit}")
            flash(f"Extended time for user by {add_value} {add_unit}.", "success")
            return redirect(url_for('admin_dashboard'))
    except ValueError as e:
        log_action("extend_time_failed", {"error": str(e)}, "Invalid input")
        flash(f"Invalid Input: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        log_action("extend_time_error", {"error": str(e), "account_id": account_id}, "Unexpected error")
        print(f"Error: {str(e)}")
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/check_user_status_form', methods=['POST'])
@admin_login_required
def check_user_status_form():
    try:
        account_id = int(request.form.get('account_id'))
        if not account_id:
            flash("User is required.", "danger")
            return redirect(url_for('admin_dashboard'))
            
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT token FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (account_id,))
            token_data = c.fetchone()
            if not token_data:
                log_action("user_status_failed", {"error": "User not found"}, "User not found or no token")
                flash("User not found or no token exists.", "danger")
                return redirect(url_for('admin_dashboard'))
                
            username = decrypt_user_acc_data(c.execute("SELECT username FROM accounts WHERE id = ?", (account_id,)).fetchone()[0])
            user_data = decrypt_data(token_data["token"])
            status = {
                "username": username,
                "credits": user_data["credits"],
                "expiry": user_data["expiry"]
            }
            log_action("user_status_checked", {"username": username, "action": "Status checked"}, "Success")
            flash(f"User Status: {username}, Credits: {status['credits']}, Expiry: {status['expiry']}", "success")
            return redirect(url_for('admin_dashboard'))
    except Exception as e:
        log_action("check_user_error", {"error": str(e)}, "Unexpected error")
        print(f"Error: {str(e)}")
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user_form', methods=['POST'])
@admin_login_required
def delete_user_form():
    try:
        account_id = request.form.get('account_id')
        if account_id == "delete_all":
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("DELETE FROM user_tokens")
                c.execute("DELETE FROM api_keys")
                c.execute("DELETE FROM accounts")
                c.execute("DELETE FROM request_history")
                conn.commit()
                log_action("all_users_deleted", {"action": "All users deleted"}, "Success")
                flash("All users deleted", "success")
                return redirect(url_for('admin_dashboard'))
        else:
            account_id = int(account_id)
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT username FROM accounts WHERE id = ?", (account_id,))
                account = c.fetchone()
                if not account:
                    flash("User not found", "danger")
                    return redirect(url_for('admin_dashboard'))
                    
                username = decrypt_user_acc_data(account["username"]).lower()
                
                # Mark as deleted in token
                c.execute("SELECT token FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (account_id,))
                token_data = c.fetchone()
                if token_data:
                    user_data = decrypt_data(token_data["token"])
                    user_data["deleted"] = True
                    new_token = encrypt_data(user_data)
                    c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry_date) VALUES (?, ?, ?, ?)",
                              (account_id, new_token, user_data["credits"], user_data["expiry"]))
                
                # Delete related records
                c.execute("DELETE FROM api_keys WHERE account_id = ?", (account_id,))
                c.execute("DELETE FROM user_tokens WHERE account_id = ?", (account_id,))
                c.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
                c.execute("DELETE FROM request_history WHERE account_id = ?", (account_id,))
                
                conn.commit()
                log_action("user_deleted", {"username": username, "action": "User deleted"}, f"account_id: {account_id}")
                flash(f"User {username} deleted successfully.", "success")
                return redirect(url_for('admin_dashboard'))
    except Exception as e:
        log_action("delete_user_error", {"error": str(e), "account_id": account_id}, "Unexpected error")
        print(f"Error in delete_user_form: {str(e)}")
        flash(f"Error deleting user: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_api_key_form', methods=['POST'])
@admin_login_required
def delete_api_key_form():
    api_key_id = None
    try:
        api_key_id = request.form.get('api_key_id')
        if not api_key_id:
            flash("API key ID is required.", "danger")
            return redirect(url_for('admin_dashboard'))
            
        api_key_id = int(api_key_id)
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT api_key, account_id FROM api_keys WHERE id = ?", (api_key_id,))
            api_key_row = c.fetchone()
            if not api_key_row:
                flash("API key not found.", "danger")
                return redirect(url_for('admin_dashboard'))
                
            api_key = api_key_row["api_key"]
            account_id = api_key_row["account_id"]
            
            # Get username
            c.execute("SELECT username FROM accounts WHERE id = ?", (account_id,))
            account = c.fetchone()
            if not account:
                flash("User not found.", "danger")
                return redirect(url_for('admin_dashboard'))
                
            username = decrypt_user_acc_data(account["username"])
            
            c.execute("DELETE FROM api_keys WHERE id = ?", (api_key_id,))
            c.execute("INSERT INTO request_history (account_id, request_type, credits, timestamp) VALUES (?, ?, ?, ?)",
                      (account_id, "api_key_deletion", 0, datetime.now()))
            conn.commit()
            
            log_action("api_key_deleted", {"username": username, "action": "API key deleted"}, f"api_key: {api_key[:8]}...")
            flash("API key deleted successfully.", "success")
            return redirect(url_for('admin_dashboard'))
    except ValueError:
        log_action("delete_api_key_error", {"error": "Invalid API key ID", "api_key_id": api_key_id}, "Invalid input")
        flash("Invalid API key ID.", "danger")
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        log_action("delete_api_key_error", {"error": str(e), "api_key_id": api_key_id}, "Unexpected error")
        print(f"Error in delete_api_key: {str(e)}")
        flash(f"Error deleting API key: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))

# === User Routes ===
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    try:
        if request.method == 'POST':
            username = request.form.get('username').lower()
            password = request.form.get('password')

            if not username or not password:
                flash("Email and password are required.", "danger")
                log_action("signup_failed", {"username": username, "action": "Invalid input"}, "Missing email or password")
                return redirect(url_for('signup'))

            if not is_valid_email(username):
                flash("Invalid email format.", "danger")
                log_action("signup_failed", {"username": username, "action": "Invalid email"}, "Invalid email format")
                return redirect(url_for('signup'))

            with get_db_connection() as conn:
                c = conn.cursor()
                hashed_username = hash_user_acc_data(username)
                c.execute("SELECT id FROM accounts WHERE username = ?", (hashed_username,))
                if c.fetchone():
                    flash("Error: Email already exists. Please log in.", "danger")
                    log_action("signup_redirected", {"username": username, "action": "Email exists"}, "Redirect to login")
                    return redirect(url_for('user_login'))

            expiry = (datetime.now() + timedelta(days=365)).isoformat()
            credits = get_bonus_credits()
            user_data = {
                "username": username,
                "credits": credits,
                "expiry": expiry,
                "deleted": False
            }
            token = encrypt_data(user_data)

            with get_db_connection() as conn:
                c = conn.cursor()
                hashed_username = hash_user_acc_data(username)
                encrypted_password = generate_password_hash(password)
                c.execute("INSERT INTO accounts (username, password, created_at) VALUES (?, ?, ?)",
                          (hashed_username, encrypted_password, datetime.now().isoformat()))
                account_id = c.lastrowid
                c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry_date) VALUES (?, ?, ?, ?)",
                          (account_id, token, credits, expiry))
                c.execute("INSERT INTO request_history (account_id, request_type, credits, timestamp) VALUES (?, ?, ?, ?)",
                          (account_id, "signup", 0, datetime.now()))
                conn.commit()
                log_action("user_signup", {"username": username, "action": "Account created", "credits": credits}, f"account_id: {account_id}")
                flash("Account created successfully. Please log in.", "success")
                return redirect(url_for('user_login'))

        return render_template('user_signup.html')
    except sqlite3.IntegrityError:
        log_action("signup_failed", {"username": username, "action": "Duplicate email"}, "Duplicate email")
        flash("Error: Email already exists. Please log in.", "danger")
        return redirect(url_for('user_login'))
    except ValueError as e:
        log_action("signup_failed", {"error": str(e), "username": username}, "Invalid input")
        flash(f"Invalid input: {str(e)}", "danger")
        return redirect(url_for('signup'))
    except Exception as e:
        log_action("signup_error", {"error": str(e), "username": username}, "Unexpected error")
        print(f"Error in signup: {str(e)}")
        flash(f"Error creating account: {str(e)}", "danger")
        return redirect(url_for('signup'))

@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    try:
        if request.method == 'POST':
            username = request.form.get('username').lower()
            password = request.form.get('password')
            with get_db_connection() as conn:
                c = conn.cursor()
                hashed_username = hash_user_acc_data(username)
                c.execute("SELECT id, password FROM accounts WHERE username = ?", (hashed_username,))
                account = c.fetchone()
                if account:
                    password_valid = check_password_hash(account['password'], password)
                    if password_valid:
                        session['user_logged_in'] = True
                        session['user_id'] = account['id']
                        session.permanent = True
                        flash("Logged in successfully!", "success")
                        log_action("user_login", {"username": username, "action": "Login success"}, "Success")
                        next_url = request.args.get('next') or url_for('user_dashboard')
                        return redirect(next_url)
                flash("Invalid email or password.", "danger")
                log_action("login_failed", {"username": username, "action": "Invalid credentials"}, "Invalid email or password")
                return redirect(url_for('user_login'))
        return render_template('user_login.html')
    except Exception as e:
        log_action("login_error", {"error": str(e), "username": username}, "Unexpected error")
        print(f"Error in user_login: {str(e)}")
        flash(f"Error logging in: {str(e)}", "danger")
        return redirect(url_for('user_login'))

@app.route('/user_logout')
def user_logout():
    session.pop('user_logged_in', None)
    session.pop('user_id', None)
    flash("Logged out successfully.", "success")
    log_action("user_logout", {"action": "Logout success"}, "Success")
    return redirect(url_for('user_login'))

@app.route('/user_dashboard')
@user_login_required
def user_dashboard():
    try:
        user_id = session.get('user_id')
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT a.username, ut.credits, ut.expiry_date, ut.token, ak.api_key
                FROM accounts a
                LEFT JOIN (
                    SELECT account_id, MAX(id) AS max_id
                    FROM user_tokens
                    GROUP BY account_id
                ) latest_ut ON a.id = latest_ut.account_id
                LEFT JOIN user_tokens ut ON ut.id = latest_ut.max_id
                LEFT JOIN api_keys ak ON a.id = ak.account_id
                WHERE a.id = ?
            """, (user_id,))
            user_data = c.fetchone()
            
            if not user_data:
                flash("User not found.", "danger")
                return redirect(url_for('user_login'))

            try:
                username = decrypt_user_acc_data(user_data["username"])
            except Exception as e:
                username = "Decryption Error"
                log_action("username_decryption_failed", {"error": str(e)}, "Failed to decrypt username")

            c.execute("""
                SELECT request_type, credits, timestamp 
                FROM request_history 
                WHERE account_id = ? 
                ORDER BY timestamp DESC LIMIT 50
            """, (user_id,))
            
            request_history = [
                {
                    "request_type": row["request_type"],
                    "credits": row["credits"],
                    "timestamp": row["timestamp"]
                } for row in c.fetchall()
            ]

            user_info = {
                "username": username,
                "credits": user_data["credits"] if user_data["credits"] else 0,
                "expiry": user_data["expiry_date"] if user_data["expiry_date"] else "N/A",
                "api_key": user_data["api_key"] if user_data["api_key"] else None
            }
            
            return render_template('user_dashboard.html', 
                                user=user_info, 
                                request_history=request_history)
    except Exception as e:
        log_action("user_dashboard_error", {"error": str(e)}, "Failed to load dashboard")
        flash(f"Error retrieving dashboard: {str(e)}", "danger")
        return redirect(url_for('user_login'))

@app.route('/user_generate_api_key', methods=['POST'])
@user_login_required
def user_generate_api_key():
    try:
        user_id = session.get('user_id')
        expiry_value = int(request.form.get('expiry_value', 365))
        expiry_unit = request.form.get('expiry_unit', "Days")

        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT username FROM accounts WHERE id = ?", (user_id,))
            account = c.fetchone()
            if not account:
                flash("User not found.", "danger")
                return redirect(url_for('user_dashboard'))
                
            username = decrypt_user_acc_data(account["username"]).lower()

            c.execute("SELECT id FROM api_keys WHERE account_id = ?", (user_id,))
            if c.fetchone():
                flash("Error: You already have an API key.", "danger")
                return redirect(url_for('user_dashboard'))

            if expiry_value <= 0:
                flash("Invalid expiry value.", "danger")
                return redirect(url_for('user_dashboard'))
                
            if expiry_unit == "Minutes":
                expiry = datetime.now() + timedelta(minutes=expiry_value)
            elif expiry_unit == "Days":
                expiry = datetime.now() + timedelta(days=expiry_value)
            elif expiry_unit == "Months":
                expiry = datetime.now() + timedelta(days=expiry_value * 30)
            else:
                flash("Invalid expiry unit.", "danger")
                return redirect(url_for('user_dashboard'))
                
            expiry_iso = expiry.isoformat()
            api_key = generate_api_key(username)

            c.execute("INSERT INTO api_keys (api_key, account_id, created_at) VALUES (?, ?, ?)",
                      (api_key, user_id, datetime.now().isoformat()))
            
            # Get current token
            c.execute("SELECT token, credits FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (user_id,))
            token_data = c.fetchone()
            
            if token_data:
                user_data = decrypt_data(token_data["token"])
                credits = user_data["credits"]
            else:
                credits = get_bonus_credits()
                user_data = {
                    "username": username,
                    "credits": credits,
                    "expiry": expiry_iso,
                    "deleted": False
                }
            
            user_data["expiry"] = expiry_iso
            new_token = encrypt_data(user_data)
            
            c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry_date) VALUES (?, ?, ?, ?)",
                      (user_id, new_token, credits, expiry_iso))
            
            c.execute("INSERT INTO request_history (account_id, request_type, credits, timestamp) VALUES (?, ?, ?, ?)",
                      (user_id, "api_key_generation", 0, datetime.now()))
            
            conn.commit()
            flash("API key generated successfully.", "success")
            log_action("user_api_key_generated", {"username": username, "action": "API key generated"}, "Success")
            return redirect(url_for('user_dashboard'))
    except ValueError as e:
        flash(f"Invalid input: {str(e)}", "danger")
        return redirect(url_for('user_dashboard'))
    except Exception as e:
        print(f"Error generating API key: {str(e)}")
        flash(f"Error generating API key: {str(e)}", "danger")
        return redirect(url_for('user_dashboard'))

@app.route('/user_delete_api_key', methods=['POST'])
@user_login_required
def user_delete_api_key():
    try:
        user_id = session.get('user_id')
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT api_key FROM api_keys WHERE account_id = ?", (user_id,))
            api_key_row = c.fetchone()
            if not api_key_row:
                flash("No API key found.", "danger")
                return redirect(url_for('user_dashboard'))
                
            c.execute("DELETE FROM api_keys WHERE account_id = ?", (user_id,))
            c.execute("INSERT INTO request_history (account_id, request_type, credits, timestamp) VALUES (?, ?, ?, ?)",
                      (user_id, "api_key_deletion", 0, datetime.now()))
            conn.commit()
            
            flash("API key deleted successfully.", "success")
            log_action("user_api_key_deleted", {"user_id": user_id, "action": "API key deleted"}, "Success")
            return redirect(url_for('user_dashboard'))
    except Exception as e:
        print(f"Error deleting API key: {str(e)}")
        flash(f"Error deleting API key: {str(e)}", "danger")
        return redirect(url_for('user_dashboard'))

# === API Endpoints ===
@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    try:
        data = request.get_json()
        username = data.get('username', '').lower()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400

        if not is_valid_email(username):
            return jsonify({"error": "Invalid email format"}), 400

        with get_db_connection() as conn:
            c = conn.cursor()
            hashed_username = hash_user_acc_data(username)
            c.execute("SELECT id FROM accounts WHERE username = ?", (hashed_username,))
            if c.fetchone():
                return jsonify({"error": "Email already exists"}), 409

        expiry = (datetime.now() + timedelta(days=365)).isoformat()
        credits = get_bonus_credits()
        user_data = {
            "username": username,
            "credits": credits,
            "expiry": expiry,
            "deleted": False
        }
        token = encrypt_data(user_data)

        with get_db_connection() as conn:
            c = conn.cursor()
            hashed_username = hash_user_acc_data(username)
            encrypted_password = generate_password_hash(password)
            c.execute("INSERT INTO accounts (username, password, created_at) VALUES (?, ?, ?)",
                      (hashed_username, encrypted_password, datetime.now().isoformat()))
            account_id = c.lastrowid
            c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry_date) VALUES (?, ?, ?, ?)",
                      (account_id, token, credits, expiry))
            c.execute("INSERT INTO request_history (account_id, request_type, credits, timestamp) VALUES (?, ?, ?, ?)",
                      (account_id, "api_signup", 0, datetime.now()))
            conn.commit()
            
        return jsonify({
            "message": "User created successfully",
            "token": token,
            "credits": credits,
            "expiry": expiry
        }), 201
        
    except sqlite3.IntegrityError:
        return jsonify({"error": "Email already exists"}), 409
    except Exception as e:
        print(f"API encrypt error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/generate', methods=['POST'])
@api_key_required
def api_generate():
    try:
        account_id = request.account_id
        credits_cost = 2  # 2 credits per image generation
        
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT token, credits FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (account_id,))
            token_data = c.fetchone()
            if not token_data:
                return jsonify({"error": "User token not found"}), 404
                
            user_data = decrypt_data(token_data["token"])
            if user_data.get("deleted", False):
                return jsonify({"error": "Account disabled"}), 403
                
            expiry_time = datetime.fromisoformat(user_data["expiry"])
            if datetime.now() > expiry_time:
                return jsonify({"error": "Token expired"}), 403
                
            if user_data["credits"] < credits_cost:
                return jsonify({"error": "Insufficient credits"}), 403

            # Deduct credits
            user_data["credits"] -= credits_cost
            new_token = encrypt_data(user_data)
            
            # Create new token record
            c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry_date) VALUES (?, ?, ?, ?)",
                      (account_id, new_token, user_data["credits"], user_data["expiry"]))
            
            # Log request
            c.execute("INSERT INTO request_history (account_id, request_type, credits, timestamp) VALUES (?, ?, ?, ?)",
                      (account_id, "image_generation", credits_cost, datetime.now()))
            
            conn.commit()
            
            return jsonify({
                "status": "success",
                "message": "Image generated",
                "credits_remaining": user_data["credits"]
            })
            
    except Exception as e:
        print(f"API generate error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# === Template Filters ===
@app.template_filter('datetimeformat')
def datetimeformat(value):
    try:
        dt = datetime.fromisoformat(value)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return str(value)

# === Error Handling ===
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Add session timeout warning
@app.before_request
def before_request():
    if session.get('user_logged_in') or session.get('admin_logged_in'):
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.now() - last_activity > timedelta(minutes=14):
                flash("Your session will expire in 1 minute. Please save your work.", "warning")
        session['last_activity'] = datetime.now().isoformat()

if __name__ == '__main__':
    app.run(debug=True)