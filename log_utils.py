from datetime import datetime

LOG_FILE = "user_actions.log"

def log_action(action: str, user_data: dict, extra: str = ""):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    name = user_data.get("name", "unknown")
    credits = user_data.get("credits", "N/A")
    expiry = user_data.get("expiry", "N/A")
    
    log_entry = f"{timestamp} {name} {action} – credits: {credits}, expiry: {expiry} {extra}\n"

    with open(LOG_FILE, "a") as f:
        f.write(log_entry)