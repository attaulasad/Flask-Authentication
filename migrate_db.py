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
            created_at TIMESTAMP NOT NULL
        )
    """)

    # Check api_keys schema
    c.execute("PRAGMA table_info(api_keys)")
    columns = [row['name'] for row in c.fetchall()]
    has_id = 'id' in columns
    has_username = 'username' in columns
    has_account_id = 'account_id' in columns

    if has_username and not has_account_id:
        # Old schema with username column
        print("Migrating api_keys table from username to account_id...")
        c.execute("SELECT api_key, username, created_at FROM api_keys")
        api_keys = c.fetchall()
        c.execute("""
            CREATE TABLE api_keys_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key TEXT NOT NULL UNIQUE,
                account_id INTEGER NOT NULL UNIQUE,
                created_at TIMESTAMP NOT NULL,
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
            try:
                c.execute("INSERT INTO api_keys_new (api_key, account_id, created_at) VALUES (?, ?, ?)",
                          (api_key, account_id, created_at))
            except sqlite3.IntegrityError:
                print(f"Skipping duplicate account_id {account_id}")
        c.execute("DROP TABLE api_keys")
        c.execute("ALTER TABLE api_keys_new RENAME TO api_keys")
        print("Migration from username to account_id completed.")
    elif not has_id and has_account_id:
        # Schema missing id column
        print("Adding id column to api_keys table...")
        c.execute("SELECT api_key, account_id, created_at FROM api_keys")
        api_keys = c.fetchall()
        c.execute("""
            CREATE TABLE api_keys_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key TEXT NOT NULL UNIQUE,
                account_id INTEGER NOT NULL UNIQUE,
                created_at TIMESTAMP NOT NULL,
                FOREIGN KEY (account_id) REFERENCES accounts(id)
            )
        """)
        for row in api_keys:
            try:
                c.execute("INSERT INTO api_keys_new (api_key, account_id, created_at) VALUES (?, ?, ?)",
                          (row['api_key'], row['account_id'], row['created_at']))
            except sqlite3.IntegrityError:
                print(f"Skipping duplicate account_id {row['account_id']}")
        c.execute("DROP TABLE api_keys")
        c.execute("ALTER TABLE api_keys_new RENAME TO api_keys")
        print("Added id column to api_keys.")
    else:
        # Ensure table exists with correct schema
        c.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key TEXT NOT NULL UNIQUE,
                account_id INTEGER NOT NULL UNIQUE,
                created_at TIMESTAMP NOT NULL,
                FOREIGN KEY (account_id) REFERENCES accounts(id)
            )
        """)
        print("api_keys table is up to date or created.")

    # Update user_tokens table schema if needed
    c.execute("PRAGMA table_info(user_tokens)")
    columns = [row['name'] for row in c.fetchall()]
    if 'expiry' in columns:
        c.execute("PRAGMA table_info(user_tokens)")
        column_info = c.fetchall()
        for col in column_info:
            if col['name'] == 'expiry' and col['type'] != 'TEXT':
                print("Updating user_tokens expiry column to TEXT...")
                c.execute("""
                    CREATE TABLE user_tokens_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        account_id INTEGER NOT NULL,
                        token TEXT NOT NULL,
                        credits INTEGER NOT NULL,
                        expiry TEXT NOT NULL,
                        FOREIGN KEY (account_id) REFERENCES accounts(id)
                    )
                """)
                c.execute("SELECT id, account_id, token, credits, expiry FROM user_tokens")
                tokens = c.fetchall()
                for row in tokens:
                    c.execute("""
                        INSERT INTO user_tokens_new (id, account_id, token, credits, expiry)
                        VALUES (?, ?, ?, ?, ?)
                    """, (row['id'], row['account_id'], row['token'], row['credits'], row['expiry']))
                c.execute("DROP TABLE user_tokens")
                c.execute("ALTER TABLE user_tokens_new RENAME TO user_tokens")
                print("Updated user_tokens expiry column to TEXT.")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    migrate_db()