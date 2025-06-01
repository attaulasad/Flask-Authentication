import sqlite3
from crypto_utils import encrypt_user_acc_data

def migrate_db():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Create accounts table if not exists
    c.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            created_at TIMESTAMP
        )
    """)

    # Check if api_keys has username column
    c.execute("PRAGMA table_info(api_keys)")
    columns = [row['name'] for row in c.fetchall()]
    has_username = 'username' in columns
    has_account_id = 'account_id' in columns

    if has_username and not has_account_id:
        print("Migrating api_keys table...")

        # Get existing api_keys data
        c.execute("SELECT api_key, username, created_at FROM api_keys")
        api_keys = c.fetchall()

        # Create new api_keys table with account_id
        c.execute("""
            CREATE TABLE api_keys_new (
                api_key TEXT PRIMARY KEY,
                account_id INTEGER NOT NULL,
                created_at TIMESTAMP,
                FOREIGN KEY (account_id) REFERENCES accounts(id)
            )
        """)

        # Migrate data
        for row in api_keys:
            api_key = row['api_key']
            username = row['username']
            created_at = row['created_at']

            # Insert username into accounts (with dummy password)
            encrypted_username = encrypt_user_acc_data(username)
            encrypted_password = encrypt_user_acc_data('migrated_password')
            c.execute("INSERT OR IGNORE INTO accounts (username, password, created_at) VALUES (?, ?, ?)",
                      (encrypted_username, encrypted_password, created_at))
            c.execute("SELECT id FROM accounts WHERE username = ?", (encrypted_username,))
            account_id = c.fetchone()['id']

            # Insert into new api_keys
            c.execute("INSERT INTO api_keys_new (api_key, account_id, created_at) VALUES (?, ?, ?)",
                      (api_key, account_id, created_at))

        # Drop old api_keys and rename new one
        c.execute("DROP TABLE api_keys")
        c.execute("ALTER TABLE api_keys_new RENAME TO api_keys")

        print("Migration complete.")
    else:
        print("No migration needed or already migrated.")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    migrate_db()