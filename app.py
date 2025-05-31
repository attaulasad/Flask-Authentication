from flask import Flask, request, jsonify, abort, render_template, redirect, url_for, flash, session
from crypto_utils import encrypt_data, decrypt_data, validate_and_update_token, delete_user_and_get_token, get_db_connection
from datetime import datetime, timedelta
from log_utils import log_action
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


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

secret_key = os.getenv("secret_key")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")


# === User API Routes ===


@app.route('/encrypt', methods=['POST'])
def encrypt_route():
    data = request.json
    name = data.get("name", "unknown")
    credits = int(data.get("credits", 10))
    expiry_minutes = int(data.get("expiry_minutes", 60))

    user_data = {
        "name": name,
        "credits": credits,
        "expiry": (datetime.now() + timedelta(minutes=expiry_minutes)).isoformat(),
        "deleted": False
    }
    token = encrypt_data(user_data)
    log_action("user created", user_data, f"token: {token[:20]}...")
    return jsonify({"token": token})




@app.route('/decrypt', methods=['POST'])
def decrypt_route():
    token = request.json.get("token")
    try:
        result, error = validate_and_update_token(token)
        if error: return jsonify({"error": error}), 403

        user_data, updated_token = result
        log_action("accessed /decrypt", user_data, f"updated_token: {updated_token[:20]}...")
        return jsonify({
            "message": "Access granted",
            "user_data": user_data,
            "updated_token": updated_token
        })
    except Exception as e: return jsonify({"error": f"Invalid token: {str(e)}"}), 400




@app.route('/status', methods=['POST'])
def status_route():
    token = request.json.get("token")
    try:
        user_data = decrypt_data(token)
        if user_data.get("deleted"): return jsonify({"status": "deleted", "message": "User has been deleted"}), 403

        expiry_time = datetime.fromisoformat(user_data["expiry"])
        status = "active" if datetime.now() < expiry_time else "expired"
        return jsonify({
            "status": status,
            "credits": user_data["credits"],
            "expiry": user_data["expiry"]
        })
    except Exception as e: return jsonify({"error": f"Invalid token: {str(e)}"}), 400




@app.route('/delete_user', methods=['POST'])
def delete_user():
    token = request.headers.get("Authorization")
    if not token:return jsonify({"error": "Token missing"}), 400

    message, error = delete_user_and_get_token(token)
    if error: return jsonify({"error": error}), 401

    log_action("user deleted via API", {"token": token[:20] + "..."})
    return jsonify({"message": message}), 200





#############################################3
# === Admin API Routes ===
#############################################


def check_admin():
    key = request.headers.get("x-api-key")
    if key != ADMIN_API_KEY:
        abort(403, "Forbidden: Invalid Admin Key")



@app.route('/admin/create_user', methods=['POST'])
def admin_create_user():
    check_admin()
    data = request.json
    name = data.get("name", "unknown")
    credits = int(data.get("credits", 10))
    expiry_minutes = int(data.get("expiry_minutes", 60))

    user_data = {
        "name": name,
        "credits": credits,
        "expiry": (datetime.now() + timedelta(minutes=expiry_minutes)).isoformat(),
        "deleted": False
    }

    token = encrypt_data(user_data)
    log_action("admin created user", user_data, f"token: {token[:20]}...")
    return jsonify({"message": "User created", "token": token})



@app.route('/admin/refill_credits', methods=['POST'])
def admin_refill_credits():
    check_admin()
    token = request.json.get("token")
    add_credits = int(request.json.get("add_credits", 0))

    if add_credits <= 0:
        return jsonify({"error": "add_credits must be positive"}), 400

    try:
        user_data = decrypt_data(token)
        if user_data.get("deleted"):
            return jsonify({"error": "Cannot add credits. User is deleted."}), 403

        old_credits = user_data["credits"]
        user_data["credits"] += add_credits
        new_token = encrypt_data(user_data)
        log_action(f"credits refilled (+{add_credits}) from {old_credits} to {user_data['credits']}", user_data, f"old_token: {token[:20]}..., new_token: {new_token[:20]}...")
        return jsonify({"message": "Credits added", "new_token": new_token, "user_data": user_data})
    except Exception as e:
        return jsonify({"error": f"Failed to update credits: {str(e)}"}), 400




@app.route('/admin/extend_time', methods=['POST'])
def admin_extend_time():
    check_admin()
    token = request.json.get("token")
    add_minutes = int(request.json.get("add_minutes", 30))

    if add_minutes <= 0:
        return jsonify({"error": "add_minutes must be positive"}), 400

    try:
        user_data = decrypt_data(token)
        if user_data.get("deleted"):
            return jsonify({"error": "Cannot extend time. User is deleted."}), 403

        expiry = datetime.fromisoformat(user_data["expiry"])
        new_expiry = expiry + timedelta(minutes=add_minutes)
        user_data["expiry"] = new_expiry.isoformat()
        new_token = encrypt_data(user_data)
        log_action(f"expiry extended (+{add_minutes} mins)", user_data, f"old_token: {token[:20]}..., new_token: {new_token[:20]}...")
        return jsonify({"message": "Time extended", "new_token": new_token, "user_data": user_data})
    except Exception as e:
        return jsonify({"error": f"Failed to extend time: {str(e)}"}), 400




#############################################3
# === Admin Dashboard GUI ===
#############################################


@app.route('/admin')
@login_required
def admin_dashboard():
    new_token = request.args.get('new_token', '')
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT token, revoked_at FROM revoked_tokens ORDER BY revoked_at DESC")
            revoked_tokens = [{"token": row["token"], "revoked_at": row["revoked_at"]} for row in c.fetchall()]
        return render_template('admin_dashboard.html', new_token=new_token, revoked_tokens=revoked_tokens)
    except Exception as e:
        flash(f"Error loading dashboard: {str(e)}", "danger")
        return redirect(url_for('login'))

@app.route('/admin/create_user_form', methods=['POST'])
@login_required
def create_user_form():
    name = request.form.get('name', 'unknown')
    credits = int(request.form.get('credits', 10))
    expiry_minutes = int(request.form.get('expiry_minutes', 60))

    user_data = {
        "name": name,
        "credits": credits,
        "expiry": (datetime.now() + timedelta(minutes=expiry_minutes)).isoformat(),
        "deleted": False
    }
    token = encrypt_data(user_data)
    log_action("admin created user via form", user_data, f"token: {token[:20]}...")
    flash("User created! Copy the token from the 'New Token' section below.", "success")
    return redirect(url_for('admin_dashboard', new_token=token))




@app.route('/admin/refill_credits_form', methods=['POST'])
@login_required
def refill_credits_form():
    token = request.form.get('token')
    add_credits = int(request.form.get('add_credits', 0))

    if add_credits <= 0:
        flash("Add credits must be positive.", "danger")
        return redirect(url_for('admin_dashboard'))

    try:
        user_data = decrypt_data(token)
        if user_data.get("deleted"):
            flash("Cannot add credits. User is deleted.", "danger")
            return redirect(url_for('admin_dashboard'))

        old_credits = user_data["credits"]
        user_data["credits"] += add_credits
        new_token = encrypt_data(user_data)
        log_action(f"credits refilled via form (+{add_credits}) from {old_credits} to {user_data['credits']}", user_data, f"old_token: {token[:20]}..., new_token: {new_token[:20]}...")
        flash(f"Credits added! New credits: {user_data['credits']}. Copy the new token from the 'New Token' section below.", "success")
        return redirect(url_for('admin_dashboard', new_token=new_token))
    except Exception as e:
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))




@app.route('/admin/extend_time_form', methods=['POST'])
@login_required
def extend_time_form():
    token = request.form.get('token')
    add_minutes = int(request.form.get('add_minutes', 30))

    if add_minutes <= 0:
        flash("Add minutes must be positive.", "danger")
        return redirect(url_for('admin_dashboard'))

    try:
        user_data = decrypt_data(token)
        if user_data.get("deleted"):
            flash("Cannot extend time. User is deleted.", "danger")
            return redirect(url_for('admin_dashboard'))

        expiry = datetime.fromisoformat(user_data["expiry"])
        new_expiry = expiry + timedelta(minutes=add_minutes)
        user_data["expiry"] = new_expiry.isoformat()
        new_token = encrypt_data(user_data)
        log_action(f"expiry extended via form (+{add_minutes} mins)", user_data, f"old_token: {token[:20]}..., new_token: {new_token[:20]}...")
        flash(f"Time extended! Copy the new token from the 'New Token' section below.", "success")
        return redirect(url_for('admin_dashboard', new_token=new_token))
    except Exception as e:
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))



@app.route('/admin/check_user_status_form', methods=['POST'])
@login_required
def check_user_status_form():
    token = request.form.get('token')
    try:
        user_data = decrypt_data(token)
        if user_data.get("deleted"):
            flash("User is deleted.", "info")
            return redirect(url_for('admin_dashboard'))

        expiry_time = datetime.fromisoformat(user_data["expiry"])
        status = "active" if datetime.now() < expiry_time else "expired"
        formatted_expiry = expiry_time.strftime("%B %d, %Y, %I:%M %p")
        message = (
            f"User: {user_data['name']}<br>"
            f"Credits Left: {user_data['credits']}<br>"
            f"Expiry: {formatted_expiry}<br>"
            f"Status: {status}"
        )
        flash(message, "info")
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        flash(f"Invalid or revoked token: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))




@app.route('/admin/delete_user_form', methods=['POST'])
@login_required
def delete_user_form():
    token = request.form.get('token')
    message, error = delete_user_and_get_token(token)
    if error:
        flash(f"Error deleting user: {error}", "danger")
    else:
        log_action("user deleted via admin form", {"token": token[:20] + "..."})
        flash(f"{message}. The token is now invalid.", "success")
    return redirect(url_for('admin_dashboard'))






if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000", debug=True)