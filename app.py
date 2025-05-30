from flask import Flask, request, jsonify, abort, render_template, redirect, url_for, flash
from crypto_utils import encrypt_data, decrypt_data, validate_and_update_token, delete_user_and_get_token
from datetime import datetime, timedelta
from log_utils import log_action

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Needed for flash messages

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
    log_action("user created", user_data, f"token: {token}")
    return jsonify({"token": token})

@app.route('/decrypt', methods=['POST'])
def decrypt_route():
    token = request.json.get("token")
    try:
        result, error = validate_and_update_token(token)
        if error:
            return jsonify({"error": error}), 403

        user_data, updated_token = result
        log_action("accessed /decrypt", user_data, f"updated_token: {updated_token}")
        return jsonify({
            "message": "Access granted",
            "user_data": user_data,
            "updated_token": updated_token
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
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error": "Token missing"}), 400

    message, error = delete_user_and_get_token(token)
    if error:
        return jsonify({"error": error}), 401

    log_action("user deleted via API", {"token": token})
    return jsonify({"message": message}), 200

# === Admin API Routes ===

ADMIN_API_KEY = "myadminkey123"  # TODO: Move to environment variables for security

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
    log_action("admin created user", user_data, f"token: {token}")
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
        log_action(f"credits refilled (+{add_credits}) from {old_credits} to {user_data['credits']}", user_data, f"old_token: {token}, new_token: {new_token}")
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
        log_action(f"expiry extended (+{add_minutes} mins)", user_data, f"old_token: {token}, new_token: {new_token}")
        return jsonify({"message": "Time extended", "new_token": new_token, "user_data": user_data})
    except Exception as e:
        return jsonify({"error": f"Failed to extend time: {str(e)}"}), 400

# === Admin Dashboard GUI ===

@app.route('/admin')
def admin_dashboard():
    new_token = request.args.get('new_token', '')
    return render_template('admin_dashboard.html', new_token=new_token)

@app.route('/admin/create_user_form', methods=['POST'])
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
    log_action("admin created user via form", user_data, f"token: {token}")
    flash(f"User created! Token: {token}", "success")
    return redirect(url_for('admin_dashboard', new_token=token))

@app.route('/admin/refill_credits_form', methods=['POST'])
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
        log_action(f"credits refilled via form (+{add_credits}) from {old_credits} to {user_data['credits']}", user_data, f"old_token: {token}, new_token: {new_token}")
        flash(f"Credits added! New token: {new_token} (Credits: {user_data['credits']}). Use this new token for further operations.", "success")
        return redirect(url_for('admin_dashboard', new_token=new_token))
    except Exception as e:
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/extend_time_form', methods=['POST'])
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
        log_action(f"expiry extended via form (+{add_minutes} mins)", user_data, f"old_token: {token}, new_token: {new_token}")
        flash(f"Time extended! New token: {new_token}. Use this new token for further operations.", "success")
        return redirect(url_for('admin_dashboard', new_token=new_token))
    except Exception as e:
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/check_user_status_form', methods=['POST'])
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
def delete_user_form():
    token = request.form.get('token')
    message, error = delete_user_and_get_token(token)
    if error:
        flash(f"Error deleting user: {error}", "danger")
    else:
        log_action("user deleted via admin form", {"token": token})
        flash(f"{message}. The token is now invalid.", "success")
    return redirect(url_for('admin_dashboard'))

if __name__ == "__main__":
    app.run(debug=True)