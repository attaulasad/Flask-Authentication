import sqlite3

DB_PATH = "users.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def list_revoked_tokens():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT token, revoked_at FROM revoked_tokens ORDER BY revoked_at DESC")
            tokens = c.fetchall()
            if not tokens:
                print("No revoked tokens found in the database.")
                return
            print("Revoked Tokens:")
            for token in tokens:
                print(f"Token (truncated): {token['token'][:20]}...")
                print(f"Revoked At: {token['revoked_at']}")
                print("-" * 50)
    except sqlite3.Error as e:
        print(f"Database error: {e}")

if __name__ == "__main__":
    list_revoked_tokens()