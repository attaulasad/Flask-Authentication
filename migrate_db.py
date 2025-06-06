import sqlite3
from crypto_utils import hash_user_acc_data, decrypt_data

def migrate_db():
    conn = sqlite3.connect('database.db')
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

    # Migrate usernames to hashed format
    c.execute("SELECT id, username, password, created_at FROM accounts")
    accounts = c.fetchall()
    for account in accounts:
        try:
            # Check if username is encrypted (Fernet) or already hashed
            if len(account['username']) > 64:  # Fernet tokens are typically longer
                c.execute("SELECT token_id FROM user_tokens WHERE account_id = ?", (account['id'],))
                token_row = c.fetchone()
                if token_row:
                    user_data = decrypt_data(token_row['token_id'])
                    username = user_data['username'].lower()
                    hashed_username = hash_user_acc_data(username)
                    c.execute("UPDATE accounts SET username = ? WHERE id = ?", (hashed_username, account['id']))
                    print(f"Migrated username for account_id {account['id']} to hashed format")
        except Exception as e:
            print(f"Error migrating username for account_id {account['id']}: {str(e)}")

    # Check api_keys schema
    c.execute("PRAGMA table_info(api_keys)")
    columns = [row['name'] for row in c.fetchall()]
    has_id = 'id' in columns
    has_username = 'username' in columns
    has_account_id = 'account_id' in columns

    if has_username and not has_account_id:
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
            hashed_username = hash_user_acc_data(username)
            c.execute("SELECT id FROM accounts WHERE username = ?", (hashed_username,))
            account_row = c.fetchone()
            if account_row:
                account_id = account_row['id']
                try:
                    c.execute("INSERT INTO api_keys_new (api_key, account_id, created_at) VALUES (?, ?, ?)",
                              (api_key, account_id, created_at))
                except sqlite3.IntegrityError:
                    print(f"Skipping duplicate account_id {account_id}")
        c.execute("DROP TABLE api_keys")
        c.execute("ALTER TABLE api_keys_new RENAME TO api_keys")
        print("Migration from username to account_id completed.")
    elif not has_id and has_account_id:
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
                        FOREIGN KEY (account_id) INDEX(id)
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