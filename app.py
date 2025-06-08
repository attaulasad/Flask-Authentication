# Import required Flask modules and utilities
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

# Load environment variables from .env file
load_dotenv()

# Initialize Flask application
app = Flask(__name__)
# Set secret key for session management
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# Validate that FLASK_SECRET_KEY is set
if not app.secret_key:
    raise ValueError("FLASK_SECRET_KEY environment variable must be set")

# Set session timeout to 15 minutes
app.permanent_session_lifetime = timedelta(minutes=15)

# Load admin credentials from environment variables
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
# Validate that admin credentials are set
if not ADMIN_USERNAME or not ADMIN_PASSWORD:
    raise ValueError("ADMIN_USERNAME and ADMIN_PASSWORD environment variables must be set")
# Hash admin password for secure storage
ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD)

# Load admin API key from environment variables
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")
# Validate that admin API key is set
if not ADMIN_API_KEY:
    raise ValueError("ADMIN_API_KEY environment variable must be set")

# Register SQLite datetime adapter to handle datetime objects
def adapt_datetime(dt):
    # Convert datetime object to ISO format string for SQLite storage
    return dt.isoformat()

sqlite3.register_adapter(datetime, adapt_datetime)

# Initialize database with required tables
def init_db():
    """
    Initializes the SQLite database by creating necessary tables if they don't exist.
    Handles accounts, API keys, user tokens, request history, and settings.
    Logs success or failure and ensures BONUS_CREDITS setting is set.
    """
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            # Create accounts table for user credentials
            c.execute("""
                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            # Create api_keys table for API key management
            c.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    api_key TEXT NOT NULL UNIQUE,
                    account_id INTEGER NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (account_id) REFERENCES accounts(id)
                )
            """)
            # Create user_tokens table for user authentication tokens
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
            # Create request_history table for tracking user actions
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
            # Create settings table for application settings
            c.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            # Ensure BONUS_CREDITS setting exists with default value
            c.execute("SELECT value FROM settings WHERE key = 'BONUS_CREDITS'")
            if c.fetchone() is None:
                c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('BONUS_CREDITS', '10')")
            conn.commit()
            # Log successful database initialization
            log_action("database_initialized", {"action": "Tables created or verified"}, "Success")
    except Exception as e:
        # Log database initialization failure
        log_action("database_init_failed", {"error": str(e)}, "Initialization error")
        raise ValueError(f"Database initialization failed: {str(e)}")

# Attempt to initialize database and handle errors
try:
    init_db()
except Exception as e:
    print(f"Error initializing database: {str(e)}")
    raise

# Generate static API key based on username
def generate_api_key(username):
    """
    Generates a static API key by hashing the username.
    Args:
        username (str): The username to generate the API key for.
    Returns:
        str: A SHA-256 hash of the lowercase username.
    """
    # Convert username to lowercase and encode to UTF-8
    # Generate SHA-256 hash and return hexadecimal representation
    return hashlib.sha256(username.lower().encode('utf-8')).hexdigest()

# Decorator to require admin login
def admin_login_required(f):
    """
    Decorator to ensure the user is logged in as an admin.
    Redirects to admin login page if not authenticated.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if admin is logged in
        if not session.get('admin_logged_in'):
            # Flash error message and redirect to admin login
            flash("Please log in as admin to access this page.", "danger")
            return redirect(url_for('admin_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Decorator to require user login
def user_login_required(f):
    """
    Decorator to ensure the user is logged in.
    Redirects to user login page if not authenticated.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is logged in
        if not session.get('user_logged_in'):
            # Flash error message and redirect to user login
            flash("Please log in to access your dashboard.", "danger")
            return redirect(url_for('user_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Decorator to require valid API key
def api_key_required(f):
    """
    Decorator to validate API key in request headers.
    Attaches account_id to request if valid, else returns error.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get API key from Authorization header
        api_key = request.headers.get("Authorization")
        # Check if API key is present and starts with "Bearer "
        if not api_key or not api_key.startswith("Bearer "):
            return jsonify({"error": "API key missing or invalid"}), 400
        # Extract API key value
        api_key = api_key.replace("Bearer ", "")
        with get_db_connection() as conn:
            c = conn.cursor()
            # Query api_keys table for matching API key
            c.execute("SELECT account_id FROM api_keys WHERE api_key = ?", (api_key,))
            account = c.fetchone()
            # Return error if API key is invalid
            if not account:
                return jsonify({"error": "Invalid API key"}), 401
            # Attach account_id to request
            request.account_id = account["account_id"]
        return f(*args, **kwargs)
    return decorated_function

# Validate email format
def is_valid_email(email):
    """
    Validates email format using a regular expression.
    Args:
        email (str): The email address to validate.
    Returns:
        bool: True if email is valid, False otherwise.
    """
    # Define regex pattern for email validation
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    # Return True if email matches pattern
    return re.match(pattern, email) is not None

# Get BONUS_CREDITS from settings
def get_bonus_credits():
    """
    Retrieves the BONUS_CREDITS value from the settings table.
    Returns default value of 10 if retrieval fails.
    Returns:
        int: The number of bonus credits.
    """
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            # Query settings table for BONUS_CREDITS
            c.execute("SELECT value FROM settings WHERE key = 'BONUS_CREDITS'")
            result = c.fetchone()
            # Return integer value or default to 10
            return int(result['value']) if result else 10
    except Exception as e:
        # Log error and return default value
        log_action("get_bonus_credits_failed", {"error": str(e)}, "Using default 10")
        print(f"Error fetching bonus credits: {str(e)}")
        return 10

# === Root Route ===
@app.route('/')
def root():
    """
    Redirects to the user login page.
    Returns:
        Response: Redirect to user_login endpoint.
    """
    return redirect(url_for('user_login'))

# === Admin Routes ===
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """
    Handles admin login functionality.
    GET: Renders login template.
    POST: Validates admin credentials and logs in if correct.
    Returns:
        Response: Renders login template or redirects to dashboard.
    """
    try:
        if request.method == 'POST':
            # Get username and password from form
            username = request.form.get('username')
            password = request.form.get('password')
            # Validate input
            if not username or not password:
                flash("Username and password are required.", "danger")
                return render_template('login.html')
            # Check credentials against admin credentials
            if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
                # Set session variables for admin login
                session['admin_logged_in'] = True
                session.permanent = True
                flash("Logged in successfully!", "success")
                # Log successful login
                log_action("admin_login", {"username": username, "action": "login_success"}, "Success")
                # Redirect to next URL or admin dashboard
                next_url = request.args.get('next') or url_for('admin_dashboard')
                return redirect(next_url)
            else:
                # Flash error for invalid credentials
                flash("Invalid username or password.", "danger")
                # Log failed login attempt
                log_action("admin_login_failed", {"username": username, "action": "invalid_credentials"}, "Invalid credentials")
                return render_template('login.html')
        return render_template('login.html')
    except Exception as e:
        # Log unexpected error
        log_action("admin_login_error", {"error": str(e)}, "Unexpected error")
        print(f"Error in admin_login: {str(e)}")
        flash("An error occurred during login. Please try again.", "danger")
        return render_template('login.html')

@app.route('/admin/logout')
@admin_login_required
def admin_logout():
    """
    Logs out the admin user by clearing session data.
    Returns:
        Response: Redirects to admin login page.
    """
    # Remove admin login session
    session.pop('admin_logged_in', None)
    flash("Logged out successfully.", "success")
    # Log successful logout
    log_action("admin_logout", {"action": "logout_success"}, "Success")
    return redirect(url_for('admin_login'))

@app.route('/admin')
@admin_login_required
def admin_dashboard():
    """
    Displays the admin dashboard with user and API key information.
    Retrieves active API keys, user list, and bonus credits.
    Returns:
        Response: Renders admin dashboard template.
    """
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            # Query to get account, API key, and latest token data
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
                    # Decrypt username
                    username = decrypt_user_acc_data(row['username'])
                except:
                    username = "Decryption Error"
                # Append API key and user data to list
                active_api_keys.append({
                    "account_id": row['account_id'],
                    "api_key_id": row['api_key_id'],
                    "api_key": row['api_key'] if row['api_key'] else "No API Key",
                    "username": username,
                    "credits": row['credits'] if row['credits'] else 0,
                    "expiry": row['expiry_date'] if row['expiry_date'] else "N/A",
                    "token": row['token'][:10] + "..." if row['token'] else "No Token"
                })
                
            # Query all accounts for user list
            c.execute("SELECT id, username FROM accounts")
            users = []
            for row in c.fetchall():
                try:
                    # Decrypt username
                    username = decrypt_user_acc_data(row['username'])
                except:
                    username = "Decryption Error"
                # Append user data to list
                users.append({
                    "id": row['id'],
                    "username": username
                })
                
            # Get bonus credits value
            bonus_credits = get_bonus_credits()
            
        return render_template('admin_dashboard.html', 
                               active_api_keys=active_api_keys, 
                               users=users, 
                               bonus_credits=bonus_credits)
    except Exception as e:
        # Log dashboard loading error
        log_action("admin_dashboard_error", {"error": str(e)}, "Failed to load dashboard")
        print(f"Error in admin_dashboard: {str(e)}")
        flash(f"Error loading dashboard: {str(e)}", "danger")
        return redirect(url_for('admin_login'))

@app.route('/admin/update_bonus', methods=['POST'])
@admin_login_required
def update_bonus():
    """
    Updates the BONUS_CREDITS setting in the database.
    Validates input and logs the action.
    Returns:
        Response: Redirects to admin dashboard.
    """
    try:
        # Get bonus credits from form
        bonus_credits = int(request.form.get('bonus_credits'))
        # Validate non-negative value
        if bonus_credits < 0:
            raise ValueError("Bonus credits cannot be negative")
        with get_db_connection() as conn:
            c = conn.cursor()
            # Update or insert BONUS_CREDITS setting
            c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('BONUS_CREDITS', ?)", (str(bonus_credits),))
            conn.commit()
            # Log successful update
            log_action("bonus_updated", {"username": "admin", "action": "bonus_credits_updated", "new_value": bonus_credits}, "Success")
            flash("Bonus credits updated", "success")
        return redirect(url_for('admin_dashboard'))
    except ValueError as e:
        # Log invalid input error
        flash(f"Invalid bonus credits value: {e}", "danger")
        log_action("update_bonus_failed", {"username": "admin", "action": "update_bonus_credits", "error": str(e)}, "Invalid input")
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        # Log unexpected error
        log_action("update_bonus_error", {"username": "admin", "action": "update_bonus", "error": str(e)}, "Unexpected error")
        flash("Error updating bonus credits.", "danger")
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/create_user_form', methods=['POST'])
@admin_login_required
def create_user_form():
    """
    Creates a new user account via admin form.
    Validates input, creates account, token, and logs history.
    Returns:
        Response: Redirects to admin dashboard.
    """
    try:
        # Get form data
        username = request.form.get('username').lower()
        password = request.form.get('password')
        credits = int(request.form.get('credits', get_bonus_credits()))

        # Validate required fields
        if not username or not password:
            flash("Email and password are required.", "danger")
            return redirect(url_for('admin_dashboard'))

        # Validate email format
        if not is_valid_email(username):
            flash("Invalid email format.", "danger")
            return redirect(url_for('admin_dashboard'))

        with get_db_connection() as conn:
            c = conn.cursor()
            # Check for existing username
            hashed_username = hash_user_acc_data(username)
            c.execute("SELECT id FROM accounts WHERE username = ?", (hashed_username,))
            if c.fetchone():
                flash("Error: Email already exists.", "danger")
                return redirect(url_for('admin_dashboard'))

        # Set expiry date to one year from now
        expiry = (datetime.now() + timedelta(days=365)).isoformat()
        # Create user data dictionary
        user_data = {
            "username": username,
            "credits": credits,
            "expiry": expiry,
            "deleted": False
        }
        # Encrypt user data to create token
        token = encrypt_data(user_data)

        with get_db_connection() as conn:
            c = conn.cursor()
            # Insert new account
            hashed_username = hash_user_acc_data(username)
            encrypted_password = generate_password_hash(password)
            c.execute("INSERT INTO accounts (username, password, created_at) VALUES (?, ?, ?)",
                      (hashed_username, encrypted_password, datetime.now().isoformat()))
            account_id = c.lastrowid
            # Insert user token
            c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry_date) VALUES (?, ?, ?, ?)",
                      (account_id, token, credits, expiry))
            # Log signup in request history
            c.execute("INSERT INTO request_history (account_id, request_type, credits, timestamp) VALUES (?, ?, ?, ?)",
                      (account_id, "signup", credits, datetime.now()))
            conn.commit()
            # Log successful user creation
            log_action("admin_user_created", {"username": username, "action": "Account created", "credits": credits}, f"account_id: {account_id}")
            flash(f"User {username} created successfully.", "success")
            return redirect(url_for('admin_dashboard'))
    except sqlite3.IntegrityError:
        # Log duplicate email error
        log_action("create_user_failed", {"username": username, "action": "Duplicate email"}, "Duplicate email")
        flash("Error: Email already exists.", "danger")
        return redirect(url_for('admin_dashboard'))
    except ValueError as e:
        # Log invalid input error
        log_action("create_user_failed", {"error": str(e), "username": username}, "Invalid input")
        flash(f"Invalid input: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        # Log unexpected error
        log_action("create_user_failed", {"error": str(e), "username": username}, "Failed to create account")
        print(f"Error in create_user_form: {str(e)}")
        flash(f"Failed to create account: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/generate_api_key_form', methods=['POST'])
@admin_login_required
def generate_api_key_form():
    """
    Generates an API key for a user via admin form.
    Validates input, creates API key, updates token, and logs history.
    Returns:
        Response: Redirects to admin dashboard.
    """
    try:
        # Get form data
        account_id = int(request.form.get('account_id'))
        expiry_value = int(request.form.get('expiry_value', 365))
        expiry_unit = request.form.get('expiry_unit', "Days")

        # Validate account ID
        if not account_id:
            flash("User is required.", "danger")
            return redirect(url_for('admin_dashboard'))

        with get_db_connection() as conn:
            c = conn.cursor()
            # Get username for account
            c.execute("SELECT username FROM accounts WHERE id = ?", (account_id,))
            account = c.fetchone()
            if not account:
                flash("User not found.", "danger")
                return redirect(url_for('admin_dashboard'))

            # Decrypt username
            username = decrypt_user_acc_data(account["username"]).lower()

            # Check for existing API key
            c.execute("SELECT id FROM api_keys WHERE account_id = ?", (account_id,))
            if c.fetchone():
                flash("Error: User already has an API key. Delete the existing key first.", "danger")
                return redirect(url_for('admin_dashboard'))

            # Validate expiry value
            if expiry_value <= 0:
                raise ValueError("Expiry value must be positive")
                
            # Calculate expiry date based on unit
            if expiry_unit == "Minutes":
                expiry = datetime.now() + timedelta(minutes=expiry_value)
            elif expiry_unit == "Days":
                expiry = datetime.now() + timedelta(days=expiry_value)
            elif expiry_unit == "Months":
                expiry = datetime.now() + timedelta(days=expiry_value * 30)
            else:
                raise ValueError("Invalid expiry unit")

            expiry_iso = expiry.isoformat()
            # Generate API key
            api_key = generate_api_key(username)

            # Insert API key
            c.execute("INSERT INTO api_keys (api_key, account_id, created_at) VALUES (?, ?, ?)", 
                      (api_key, account_id, datetime.now().isoformat()))
            
            # Get current token data
            c.execute("SELECT token, credits FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (account_id,))
            token_data = c.fetchone()
            
            if token_data:
                # Decrypt existing token
                user_data = decrypt_data(token_data["token"])
                credits = user_data["credits"]
            else:
                # Create new user data if no token exists
                credits = get_bonus_credits()
                user_data = {
                    "username": username,
                    "credits": credits,
                    "expiry": expiry_iso,
                    "deleted": False
                }
            
            # Update expiry in user data
            user_data["expiry"] = expiry_iso
            # Encrypt new token
            new_token = encrypt_data(user_data)
            
            # Insert new token
            c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry_date) VALUES (?, ?, ?, ?)",
                      (account_id, new_token, credits, expiry_iso))
            
            conn.commit()
            # Log successful API key generation
            log_action("api_key_generated", {"username": username, "action": "API key generated"}, f"API key: {api_key[:8]}...")
            flash(f"API key generated for user with expiry {expiry_value} {expiry_unit}.", "success")
            return redirect(url_for('admin_dashboard'))
    except ValueError as e:
        # Log invalid input error
        log_action("generate_api_key_failed", {"error": str(e), "account_id": account_id}, "Invalid input")
        flash(f"Invalid input: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))
    except sqlite3.IntegrityError:
        # Log database error
        log_action("generate_api_key_failed", {"error": "Database integrity error", "account_id": account_id}, "Database error")
        flash("Error: Database error.", "danger")
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        # Log unexpected error
        log_action("generate_api_key_error", {"error": str(e), "account_id": account_id}, "Unexpected error")
        print(f"Error in generate_api_key_form: {str(e)}")
        flash(f"Failed to generate API key: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/refill_credits_form', methods=['POST'])
@admin_login_required
def refill_credits_form():
    """
    Refills user credits via admin form.
    Validates input, updates token, and logs history.
    Returns:
        Response: Redirects to admin dashboard.
    """
    try:
        # Get form data
        account_id = int(request.form.get('account_id'))
        add_credits = int(request.form.get('add_credits'))
        # Validate positive credits
        if add_credits <= 0:
            raise ValueError("Credits to add must be positive")
            
        with get_db_connection() as conn:
            c = conn.cursor()
            # Get latest token data
            c.execute("SELECT token, credits FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (account_id,))
            token_data = c.fetchone()
            if not token_data:
                flash("User not found or no token exists.", "danger")
                return redirect(url_for('admin_dashboard'))
                
            # Get username
            username = decrypt_user_acc_data(c.execute("SELECT username FROM accounts WHERE id = ?", (account_id,)).fetchone()[0])
            # Decrypt token
            user_data = decrypt_data(token_data["token"])
            # Add credits
            user_data["credits"] += add_credits
            # Encrypt new token
            new_token = encrypt_data(user_data)
            
            # Insert new token
            c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry_date) VALUES (?, ?, ?, ?)",
                      (account_id, new_token, user_data["credits"], user_data["expiry"]))
            
            # Log credit refill in history
            c.execute("INSERT INTO request_history (account_id, request_type, credits, timestamp) VALUES (?, ?, ?, ?)",
                      (account_id, "credits_refill", add_credits, datetime.now()))
            
            conn.commit()
            # Log successful credit refill
            log_action("credits_refilled", {"username": username, "action": "Credits added", "credits_added": add_credits}, f"new_credits: {user_data['credits']}")
            flash(f"Added {add_credits} credits to user.", "success")
            return redirect(url_for('admin_dashboard'))
    except ValueError as e:
        # Log invalid input error
        log_action("refill_credits_failed", {"error": str(e), "account_id": account_id}, "Invalid input")
        flash(f"Invalid input: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        # Log unexpected error
        log_action("refill_credits_error", {"error": str(e), "account_id": account_id}, "Unexpected error")
        print(f"Error in refill_credits_form: {str(e)}")
        flash(f"Error refilling credits: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/extend_time_form', methods=['POST'])
@admin_login_required
def extend_time_form():
    """
    Extends user token expiry time via admin form.
    Validates input, updates token, and logs history.
    Returns:
        Response: Redirects to admin dashboard.
    """
    try:
        # Get form data
        account_id = int(request.form.get('account_id'))
        add_value = int(request.form.get('add_value'))
        add_unit = request.form.get('add_unit', 'Days')
        # Validate positive time value
        if add_value <= 0:
            flash("Time to add must be positive.", "danger")
            return redirect(url_for('admin_dashboard'))
            
        with get_db_connection() as conn:
            c = conn.cursor()
            # Get latest token data
            c.execute("SELECT token, expiry_date FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (account_id,))
            token_data = c.fetchone()
            if not token_data:
                flash("User not found or no token exists.", "danger")
                return redirect(url_for('admin_dashboard'))
                
            # Get username
            username = decrypt_user_acc_data(c.execute("SELECT username FROM accounts WHERE id = ?", (account_id,)).fetchone()[0])
            # Decrypt token
            user_data = decrypt_data(token_data["token"])
            # Get current expiry time
            expiry_time = datetime.fromisoformat(user_data["expiry"])
            
            # Calculate new expiry based on unit
            if add_unit == "Minutes":
                new_expiry = expiry_time + timedelta(minutes=add_value)
            elif add_unit == "Days":
                new_expiry = expiry_time + timedelta(days=add_value)
            elif add_unit == "Months":
                new_expiry = expiry_time + timedelta(days=add_value * 30)
            else:
                flash("Invalid time unit.", "danger")
                return redirect(url_for('admin_dashboard'))
                
            # Update expiry in user data
            user_data["expiry"] = new_expiry.isoformat()
            # Encrypt new token
            new_token = encrypt_data(user_data)
            
            # Insert new token
            c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry_date) VALUES (?, ?, ?, ?)",
                      (account_id, new_token, user_data["credits"], user_data["expiry"]))
            
            # Log time extension in history
            c.execute("INSERT INTO request_history (account_id, request_type, credits, timestamp) VALUES (?, ?, ?, ?)",
                      (account_id, "time_extension", 0, datetime.now()))
            
            conn.commit()
            # Log successful time extension
            log_action("time_extended", {"username": username, "action": "time extended", "new_expiry": new_expiry.isoformat()},
                      f"extended_by: {add_value} {add_unit}")
            flash(f"Extended time for user by {add_value} {add_unit}.", "success")
            return redirect(url_for('admin_dashboard'))
    except ValueError as e:
        # Log invalid input error
        log_action("extend_time_failed", {"error": str(e)}, "Invalid input")
        flash(f"Invalid Input: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        # Log unexpected error
        log_action("extend_time_error", {"error": str(e), "account_id": account_id}, "Unexpected error")
        print(f"Error: {str(e)}")
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/check_user_status_form', methods=['POST'])
@admin_login_required
def check_user_status_form():
    """
    Checks user status via admin form.
    Retrieves and displays username, credits, and expiry.
    Returns:
        Response: Redirects to admin dashboard with status message.
    """
    try:
        # Get account ID from form
        account_id = int(request.form.get('account_id'))
        # Validate account ID
        if not account_id:
            flash("User is required.", "danger")
            return redirect(url_for('admin_dashboard'))
            
        with get_db_connection() as conn:
            c = conn.cursor()
            # Get latest token
            c.execute("SELECT token FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (account_id,))
            token_data = c.fetchone()
            if not token_data:
                # Log user not found error
                log_action("user_status_failed", {"error": "User not found"}, "User not found or no token")
                flash("User not found or no token exists.", "danger")
                return redirect(url_for('admin_dashboard'))
                
            # Get username
            username = decrypt_user_acc_data(c.execute("SELECT username FROM accounts WHERE id = ?", (account_id,)).fetchone()[0])
            # Decrypt token
            user_data = decrypt_data(token_data["token"])
            # Prepare status data
            status = {
                "username": username,
                "credits": user_data["credits"],
                "expiry": user_data["expiry"]
            }
            # Log successful status check
            log_action("user_status_checked", {"username": username, "action": "Status checked"}, "Success")
            flash(f"User Status: {username}, Credits: {status['credits']}, Expiry: {status['expiry']}", "status")
            return redirect(url_for('admin_dashboard'))
    except Exception as e:
        # Log unexpected error
        log_action("check_user_error", {"error": str(e)}, "Unexpected error")
        print(f"Error: {str(e)}")
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user_form', methods=['POST'])
@admin_login_required
def delete_user_form():
    """
    Deletes a user or all users via admin form.
    Removes associated tokens, API keys, and history.
    Returns:
        Response: Redirects to admin dashboard.
    """
    try:
        # Get account ID from form
        account_id = request.form.get('account_id')
        if account_id == "delete_all":
            with get_db_connection() as conn:
                c = conn.cursor()
                # Delete all records from relevant tables
                c.execute("DELETE FROM user_tokens")
                c.execute("DELETE FROM api_keys")
                c.execute("DELETE FROM accounts")
                c.execute("DELETE FROM request_history")
                conn.commit()
                # Log deletion of all users
                log_action("all_users_deleted", {"action": "All users deleted"}, "Success")
                flash("All users deleted", "success")
                return redirect(url_for('admin_dashboard'))
        else:
            account_id = int(account_id)
            with get_db_connection() as conn:
                c = conn.cursor()
                # Get user account
                c.execute("SELECT username FROM accounts WHERE id = ?", (account_id,))
                account = c.fetchone()
                if not account:
                    flash("User not found", "danger")
                    return redirect(url_for('admin_dashboard'))
                    
                # Decrypt username
                username = decrypt_user_acc_data(account["username"]).lower()
                
                # Delete related records
                c.execute("DELETE FROM api_keys WHERE account_id = ?", (account_id,))
                c.execute("DELETE FROM user_tokens WHERE account_id = ?", (account_id,))
                c.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
                c.execute("DELETE FROM request_history WHERE account_id = ?", (account_id,))
                
                conn.commit()
                # Log successful user deletion
                log_action("user_deleted", {"username": username, "action": "User deleted"}, f"account_id: {account_id}")
                flash(f"User {username} deleted successfully.", "success")
                return redirect(url_for('admin_dashboard'))
    except Exception as e:
        # Log unexpected error
        log_action("delete_user_error", {"error": str(e), "account_id": account_id}, "Unexpected error")
        print(f"Error in delete_user_form: {str(e)}")
        flash(f"Error deleting user: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_api_key_form', methods=['POST'])
@admin_login_required
def delete_api_key_form():
    """
    Deletes an API key via admin form.
    Logs the deletion in request history.
    Returns:
        Response: Redirects to admin dashboard.
    """
    api_key_id = None
    try:
        # Get API key ID from form
        api_key_id = request.form.get('api_key_id')
        if not api_key_id:
            flash("API key ID is required.", "danger")
            return redirect(url_for('admin_dashboard'))
            
        api_key_id = int(api_key_id)
        with get_db_connection() as conn:
            c = conn.cursor()
            # Get API key details
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
                
            # Decrypt username
            username = decrypt_user_acc_data(account["username"])
            
            # Delete API key
            c.execute("DELETE FROM api_keys WHERE id = ?", (api_key_id,))
            # Log deletion in request history
            c.execute("INSERT INTO request_history (account_id, request_type, credits, timestamp) VALUES (?, ?, ?, ?)",
                      (account_id, "api_key_deletion", 0, datetime.now()))
            conn.commit()
            
            # Log successful API key deletion
            log_action("api_key_deleted", {"username": username, "action": "API key deleted"}, f"api_key: {api_key[:8]}...")
            flash("API key deleted successfully.", "success")
            return redirect(url_for('admin_dashboard'))
    except ValueError:
        # Log invalid input error
        log_action("delete_api_key_error", {"error": "Invalid API key ID", "api_key_id": api_key_id}, "Invalid input")
        flash("Invalid API key ID.", "danger")
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        # Log unexpected error
        log_action("delete_api_key_error", {"error": str(e), "api_key_id": api_key_id}, "Unexpected error")
        print(f"Error in delete_api_key: {str(e)}")
        flash(f"Error deleting API key: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))

# === User Routes ===
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """
    Handles user signup functionality.
    GET: Renders signup template.
    POST: Creates new user account, token, and logs history.
    Returns:
        Response: Renders signup template or redirects to login.
    """
    try:
        if request.method == 'POST':
            # Get form data
            username = request.form.get('username').lower()
            password = request.form.get('password')

            # Validate required fields
            if not username or not password:
                flash("Email and password are required.", "danger")
                log_action("signup_failed", {"username": username, "action": "Invalid input"}, "Missing email or password")
                return redirect(url_for('signup'))

            # Validate email format
            if not is_valid_email(username):
                flash("Invalid email format.", "danger")
                log_action("signup_failed", {"username": username, "action": "Invalid email"}, "Invalid email format")
                return redirect(url_for('signup'))

            with get_db_connection() as conn:
                c = conn.cursor()
                # Check for existing username
                hashed_username = hash_user_acc_data(username)
                c.execute("SELECT id FROM accounts WHERE username = ?", (hashed_username,))
                if c.fetchone():
                    flash("Error: Email already exists. Please log in.", "danger")
                    log_action("signup_redirected", {"username": username, "action": "Email exists"}, "Redirect to login")
                    return redirect(url_for('user_login'))

            # Set expiry date to one year
            expiry = (datetime.now() + timedelta(days=365)).isoformat()
            # Get bonus credits
            credits = get_bonus_credits()
            # Create user data dictionary
            user_data = {
                "username": username,
                "credits": credits,
                "expiry": expiry,
                "deleted": False
            }
            # Encrypt user data to create token
            token = encrypt_data(user_data)

            with get_db_connection() as conn:
                c = conn.cursor()
                # Insert new account
                hashed_username = hash_user_acc_data(username)
                encrypted_password = generate_password_hash(password)
                c.execute("INSERT INTO accounts (username, password, created_at) VALUES (?, ?, ?)",
                          (hashed_username, encrypted_password, datetime.now().isoformat()))
                account_id = c.lastrowid
                # Insert user token
                c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry_date) VALUES (?, ?, ?, ?)",
                          (account_id, token, credits, expiry))
                # Log signup in request history
                c.execute("INSERT INTO request_history (account_id, request_type, credits, timestamp) VALUES (?, ?, ?, ?)",
                          (account_id, "signup", credits, datetime.now()))
                conn.commit()
                # Log successful signup
                log_action("user_signup", {"username": username, "action": "Account created", "credits": credits}, f"account_id: {account_id}")
                flash("Account created successfully. Please log in.", "success")
                return redirect(url_for('user_login'))

        return render_template('user_signup.html')
    except sqlite3.IntegrityError:
        # Log duplicate email error
        log_action("signup_failed", {"username": username, "action": "Duplicate email"}, "Duplicate email")
        flash("Error: Email already exists. Please log in.", "danger")
        return redirect(url_for('user_login'))
    except ValueError as e:
        # Log invalid input error
        log_action("signup_failed", {"error": str(e), "username": username}, "Invalid input")
        flash(f"Invalid input: {str(e)}", "danger")
        return redirect(url_for('signup'))
    except Exception as e:
        # Log unexpected error
        log_action("signup_error", {"error": str(e), "username": username}, "Unexpected error")
        print(f"Error in signup: {str(e)}")
        flash(f"Error creating account: {str(e)}", "danger")
        return redirect(url_for('signup'))

@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    """
    Handles user login functionality.
    GET: Renders login template.
    POST: Validates credentials and logs in user.
    Returns:
        Response: Renders login template or redirects to dashboard.
    """
    try:
        if request.method == 'POST':
            # Get form data
            username = request.form.get('username').lower()
            password = request.form.get('password')
            with get_db_connection() as conn:
                c = conn.cursor()
                # Get account by username
                hashed_username = hash_user_acc_data(username)
                c.execute("SELECT id, password FROM accounts WHERE username = ?", (hashed_username,))
                account = c.fetchone()
                if account:
                    # Validate password
                    password_valid = check_password_hash(account['password'], password)
                    if password_valid:
                        # Set session variables
                        session['user_logged_in'] = True
                        session['user_id'] = account['id']
                        session.permanent = True
                        flash("Logged in successfully!", "success")
                        # Log successful login
                        log_action("user_login", {"username": username, "action": "Login success"}, "Success")
                        # Redirect to next URL or dashboard
                        next_url = request.args.get('next') or url_for('user_dashboard')
                        return redirect(next_url)
                # Flash error for invalid credentials
                flash("Invalid email or password.", "danger")
                # Log failed login attempt
                log_action("login_failed", {"username": username, "action": "Invalid credentials"}, "Invalid email or password")
                return redirect(url_for('user_login'))
        return render_template('user_login.html')
    except Exception as e:
        # Log unexpected error
        log_action("login_error", {"error": str(e), "username": username}, "Unexpected error")
        print(f"Error in user_login: {str(e)}")
        flash(f"Error logging in: {str(e)}", "danger")
        return redirect(url_for('user_login'))

@app.route('/user_logout')
def user_logout():
    """
    Logs out the user by clearing session data.
    Returns:
        Response: Redirects to user login page.
    """
    # Remove user session data
    session.pop('user_logged_in', None)
    session.pop('user_id', None)
    flash("Logged out successfully.", "success")
    # Log successful logout
    log_action("user_logout", {"action": "Logout success"}, "Success")
    return redirect(url_for('user_login'))

@app.route('/user_dashboard')
@user_login_required
def user_dashboard():
    """
    Displays the user dashboard with account and request history.
    Retrieves user info, credits, expiry, API key, and history.
    Returns:
        Response: Renders user dashboard template.
    """
    try:
        # Get user ID from session
        user_id = session.get('user_id')
        with get_db_connection() as conn:
            c = conn.cursor()
            # Query user data, latest token, and API key
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
                # Decrypt username
                username = decrypt_user_acc_data(user_data["username"])
            except Exception as e:
                # Log decryption failure
                username = "Decryption Error"
                log_action("username_decryption_failed", {"error": str(e)}, "Failed to decrypt username")

            # Get recent request history
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

            # Get latest credits
            c.execute("""
                SELECT credits FROM user_tokens 
                WHERE account_id = ? 
                ORDER BY id DESC LIMIT 1
            """, (user_id,))
            latest_credits = c.fetchone()
            current_credits = latest_credits["credits"] if latest_credits else 0

            # Prepare user info dictionary
            user_info = {
                "username": username,
                "credits": current_credits,
                "expiry": user_data["expiry_date"] if user_data["expiry_date"] else "N/A",
                "api_key": user_data["api_key"] if user_data["api_key"] else None
            }
            
            return render_template('user_dashboard.html', 
                                user=user_info, 
                                request_history=request_history)
    except Exception as e:
        # Log dashboard loading error
        log_action("user_dashboard_error", {"error": str(e)}, "Failed to load dashboard")
        flash(f"Error retrieving dashboard: {str(e)}", "danger")
        return redirect(url_for('user_login'))

@app.route('/user_generate_api_key', methods=['POST'])
@user_login_required
def user_generate_api_key():
    """
    Generates an API key for the logged-in user.
    Validates input, creates API key, updates token, and logs history.
    Returns:
        Response: Redirects to user dashboard.
    """
    try:
        # Get user ID from session
        user_id = session.get('user_id')
        # Get form data
        expiry_value = int(request.form.get('expiry_value', 365))
        expiry_unit = request.form.get('expiry_unit', "Days")

        with get_db_connection() as conn:
            c = conn.cursor()
            # Get user account
            c.execute("SELECT username FROM accounts WHERE id = ?", (user_id,))
            account = c.fetchone()
            if not account:
                flash("User not found.", "danger")
                return redirect(url_for('user_dashboard'))
                
            # Decrypt username
            username = decrypt_user_acc_data(account["username"]).lower()

            # Check for existing API key
            c.execute("SELECT id FROM api_keys WHERE account_id = ?", (user_id,))
            if c.fetchone():
                flash("Error: You already have an API key.", "danger")
                return redirect(url_for('user_dashboard'))

            # Validate expiry value
            if expiry_value <= 0:
                flash("Invalid expiry value.", "danger")
                return redirect(url_for('user_dashboard'))
                
            # Calculate expiry date
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
            # Generate API key
            api_key = generate_api_key(username)

            # Insert API key
            c.execute("INSERT INTO api_keys (api_key, account_id, created_at) VALUES (?, ?, ?)",
                      (api_key, user_id, datetime.now().isoformat()))
            
            # Get current token
            c.execute("SELECT token, credits FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (user_id,))
            token_data = c.fetchone()
            
            if token_data:
                # Decrypt existing token
                user_data = decrypt_data(token_data["token"])
                credits = user_data["credits"]
            else:
                # Create new user data if no token
                credits = get_bonus_credits()
                user_data = {
                    "username": username,
                    "credits": credits,
                    "expiry": expiry_iso,
                    "deleted": False
                }
            
            # Update expiry
            user_data["expiry"] = expiry_iso
            # Encrypt new token
            new_token = encrypt_data(user_data)
            
            # Insert new token
            c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry_date) VALUES (?, ?, ?, ?)",
                      (user_id, new_token, credits, expiry_iso))
            
            # Log API key generation in history
            c.execute("INSERT INTO request_history (account_id, request_type, credits, timestamp) VALUES (?, ?, ?, ?)",
                      (user_id, "api_key_generation", credits, datetime.now()))
            
            conn.commit()
            flash("API key generated successfully.", "success")
            # Log successful API key generation
            log_action("user_api_key_generated", {"username": username, "action": "API key generated"}, "Success")
            return redirect(url_for('user_dashboard'))
    except ValueError as e:
        # Log invalid input error
        flash(f"Invalid input: {str(e)}", "danger")
        return redirect(url_for('user_dashboard'))
    except Exception as e:
        # Log unexpected error
        print(f"Error generating API key: {str(e)}")
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for('user_dashboard'))

@app.route('/user_delete_api_key', methods=['POST'])
@user_login_required
def user_delete_api_key():
    """
    Deletes the user's API key.
    Logs the deletion in request history.
    Returns:
        Response: Redirects to user dashboard.
    """
    try:
        # Get user ID from session
        user_id = session.get('user_id')
        with get_db_connection() as conn:
            c = conn.cursor()
            # Get API key
            c.execute("SELECT api_key FROM api_keys WHERE account_id = ?", (user_id,))
            api_key_row = c.fetchone()
            if not api_key_row:
                flash("No API key found.", "danger")
                return redirect(url_for('user_dashboard'))
                
            # Get current token data
            c.execute("SELECT token, credits FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (user_id,))
            token_data = c.fetchone()
            if token_data:
                # Decrypt token to get current credits
                user_data = decrypt_data(token_data["token"])
                current_credits = user_data["credits"]
            else:
                current_credits = 0
                
            # Delete API key
            c.execute("DELETE FROM api_keys WHERE account_id = ?", (user_id,))
            # Log deletion in history
            c.execute("INSERT INTO request_history (account_id, request_type, credits, timestamp) VALUES (?, ?, ?, ?)",
                      (user_id, "api_key_deletion", current_credits, datetime.now()))
            conn.commit()
            
            flash("API key deleted successfully.", "success")
            # Log successful deletion
            log_action("user_api_key_deleted", {"user_id": user_id, "action": "API key deleted"}, "Success")
            return redirect(url_for('user_dashboard'))
    except Exception as e:
        # Log unexpected error
        print(f"Error deleting API key: {str(e)}")
        flash(f"Error deleting API key: {str(e)}", "danger")
        return redirect(url_for('user_dashboard'))

# === API Endpoints ===
@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    """
    API endpoint to create a user account.
    Validates input, creates account, token, and logs history.
    Returns:
        Response: JSON with success message or error.
    """
    try:
        # Get JSON data
        data = request.get_json()
        username = data.get('username', '').lower()
        password = data.get('password', '')
        
        # Validate required fields
        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400

        # Validate email format
        if not is_valid_email(username):
            return jsonify({"error": "Invalid email format"}), 400

        with get_db_connection() as conn:
            c = conn.cursor()
            # Check for existing username
            hashed_username = hash_user_acc_data(username)
            c.execute("SELECT id FROM accounts WHERE username = ?", (hashed_username,))
            if c.fetchone():
                return jsonify({"error": "Email already exists"}), 409

        # Set expiry date to one year
        expiry = (datetime.now() + timedelta(days=365)).isoformat()
        # Get bonus credits
        credits = get_bonus_credits()
        # Create user data dictionary
        user_data = {
            "username": username,
            "credits": credits,
            "expiry": expiry,
            "deleted": False
        }
        # Encrypt token
        token = encrypt_data(user_data)

        with get_db_connection() as conn:
            c = conn.cursor()
            # Insert new account
            hashed_username = hash_user_acc_data(username)
            encrypted_password = generate_password_hash(password)
            c.execute("INSERT INTO accounts (username, password, created_at) VALUES (?, ?, ?)",
                      (hashed_username, encrypted_password, datetime.now().isoformat()))
            account_id = c.lastrowid
            # Insert user token
            c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry_date) VALUES (?, ?, ?, ?)",
                      (account_id, token, credits, expiry))
            # Log signup in history
            c.execute("INSERT INTO request_history (account_id, request_type, credits, timestamp) VALUES (?, ?, ?, ?)",
                      (account_id, "api_signup", 0, datetime.now()))
            conn.commit()
            
        # Return success response
        return jsonify({
            "message": "User created successfully",
            "token": token,
            "credits": credits,
            "expiry": expiry
        }), 201
        
    except sqlite3.IntegrityError:
        return jsonify({"error": "Email already exists"}), 409
    except Exception as e:
        # Log unexpected error
        print(f"API encrypt error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/generate', methods=['POST'])
@api_key_required
def api_generate():
    """
    API endpoint for image generation.
    Validates token, deducts credits, and logs request.
    Returns:
        Response: JSON with success message or error.
    """
    try:
        # Get account ID from request
        account_id = request.account_id
        credits_cost = 2  # Cost per image generation
        
        with get_db_connection() as conn:
            c = conn.cursor()
            # Get latest token
            c.execute("SELECT token, credits FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (account_id,))
            token_data = c.fetchone()
            if not token_data:
                return jsonify({"error": "User token not found"}), 404
                
            # Decrypt token
            user_data = decrypt_data(token_data["token"])
            # Check if account is disabled
            if user_data.get("deleted", False):
                return jsonify({"error": "Account disabled"}), 403
                
            # Check token expiry
            expiry_time = datetime.fromisoformat(user_data["expiry"])
            if datetime.now() > expiry_time:
                return jsonify({"error": "Token expired"}), 403
                
            # Check sufficient credits
            if user_data["credits"] < credits_cost:
                return jsonify({"error": "Insufficient credits"}), 403

            # Deduct credits
            user_data["credits"] -= credits_cost
            # Encrypt new token
            new_token = encrypt_data(user_data)
            
            # Insert new token
            c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry_date) VALUES (?, ?, ?, ?)",
                      (account_id, new_token, user_data["credits"], user_data["expiry"]))
            
            # Log request in history
            c.execute("INSERT INTO request_history (account_id, request_type, credits, timestamp) VALUES (?, ?, ?, ?)",
                      (account_id, "image_generation", credits_cost, datetime.now()))
            
            conn.commit()
            
            # Return success response
            return jsonify({
                "status": "success",
                "message": "Image generated",
                "credits_remaining": user_data["credits"]
            })
            
    except Exception as e:
        # Log unexpected error
        print(f"API generate error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/query', methods=['POST'])
@api_key_required
def handle_query():
    """
    API endpoint to handle user queries.
    Validates token, deducts credits, logs request, and returns response.
    Returns:
        Response: JSON with query response or error.
    """
    try:
        # Get account ID from request
        account_id = request.account_id
        # Get query from JSON
        query = request.json.get('query')
        credits_cost = 1  # Cost per query
        
        # Validate query
        if not query:
            return jsonify({"error": "Query is required"}), 400
            
        with get_db_connection() as conn:
            c = conn.cursor()
            # Check for API key
            c.execute("SELECT id FROM api_keys WHERE account_id = ?", (account_id,))
            if not c.fetchone():
                return jsonify({"error": "API key required to use Query Assistant"}), 403

            # Get latest token
            c.execute("SELECT token, credits FROM user_tokens WHERE account_id = ? ORDER BY id DESC LIMIT 1", (account_id,))
            token_data = c.fetchone()
            if not token_data:
                return jsonify({"error": "User token not found"}), 404
                
            # Decrypt token
            user_data = decrypt_data(token_data["token"])
            # Check if account is disabled
            if user_data.get("deleted", False):
                return jsonify({"error": "Account disabled"}), 403
                
            # Check token expiry
            expiry_time = datetime.fromisoformat(user_data["expiry"])
            if datetime.now() > expiry_time:
                return jsonify({"error": "Token expired"}), 403
                
            # Check sufficient credits
            if user_data["credits"] < credits_cost:
                return jsonify({"error": "Insufficient credits"}), 403

            # Deduct credits
            user_data["credits"] -= credits_cost
            # Encrypt new token
            new_token = encrypt_data(user_data)
            
            # Insert new token
            c.execute("INSERT INTO user_tokens (account_id, token, credits, expiry_date) VALUES (?, ?, ?, ?)",
                      (account_id, new_token, user_data["credits"], user_data["expiry"]))
            
            # Log request in history
            c.execute("INSERT INTO request_history (account_id, request_type, credits, timestamp) VALUES (?, ?, ?, ?)",
                      (account_id, "query", credits_cost, datetime.now()))
            
            # Get inserted request history
            c.execute("""
                SELECT request_type, credits, timestamp 
                FROM request_history 
                WHERE account_id = ? 
                ORDER BY id DESC LIMIT 1
            """, (account_id,))
            request_data = c.fetchone()
            
            conn.commit()
            
            # Prepare response
            response = {
                "status": "success",
                "message": f"Processed query: {query}",
                "response": f"This is a sample response to your query: '{query}'. In a real application, this would contain the actual response based on your query.",
                "credits_remaining": user_data["credits"],
                "request": {
                    "request_type": request_data["request_type"],
                    "credits": request_data["credits"],
                    "timestamp": request_data["timestamp"]
                }
            }
            
            return jsonify(response)
            
    except Exception as e:
        # Log unexpected error
        print(f"Query handling error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# === Template Filters ===
@app.template_filter('datetimeformat')
def datetimeformat(value):
    """
    Template filter to format ISO datetime strings.
    Args:
        value (str): ISO datetime string.
    Returns:
        str: Formatted datetime or original value if invalid.
    """
    try:
        # Parse ISO datetime and format
        dt = datetime.fromisoformat(value)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return str(value)

@app.template_filter('split')
def split_filter(value, delimiter=' '):
    """
    Template filter to split a string by delimiter.
    Args:
        value (str): String to split.
        delimiter (str): Delimiter to split by.
    Returns:
        list: List of split strings.
    """
    return value.split(delimiter)

@app.context_processor
def utility_processor():
    """
    Adds utility functions to template context.
    Returns:
        dict: Dictionary with current time function.
    """
    return {
        'now': datetime.now
    }

# === Error Handling ===
@app.errorhandler(404)
def page_not_found(e):
    """
    Handles 404 errors by rendering a custom template.
    Args:
        e: Error object.
    Returns:
        Response: 404 template with 404 status.
    """
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    """
    Handles 500 errors by rendering a custom template.
    Args:
        e: Error object.
    Returns:
        Response: 500 template with 500 status.
    """
    return render_template('500.html'), 500

# Add session timeout warning
@app.before_request
def before_request():
    """
    Checks session activity before each request.
    Displays timeout warning if session is near expiry.
    """
    if session.get('user_logged_in') or session.get('admin_logged_in'):
        if 'last_activity' in session:
            # Get last activity time
            last_activity = datetime.fromisoformat(session['last_activity'])
            # Check if session is near timeout
            if datetime.now() - last_activity > timedelta(minutes=14):
                flash("Your session will expire in 1 minute. Please save your work.", "warning")
        # Update last activity time
        session['last_activity'] = datetime.now().isoformat()

if __name__ == '__main__':
    # Run Flask app in debug mode
    app.run(debug=True)