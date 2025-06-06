import sqlite3
from crypto_utils import get_db_connection, hash_user_acc_data, decrypt_data

def migrate_user_tokens():
    conn = get_db_connection()
    c = conn.cursor()

    # Check if user_tokens has api_key column
    c.execute("PRAGMA table_info(user_tokens)")
    columns = [row['name'] for row in c.fetchall()]
    has_api_key = 'api_key' in columns
    has_account_id = 'account_id' in columns

    if has_api_key and not has_account_id:
        print("Migrating user_tokens table...")
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
        c.execute("""
            SELECT ut.id, ut.api_key, ut.token, ut.credits, ut.expiry, ak.account_id
            FROM user_tokens ut
            JOIN api_keys ak ON ut.api_key = ak.api_key
        """)
        for row in c.fetchall():
            c.execute("""
                INSERT INTO user_tokens_new (id, account_id, token, credits, expiry)
                VALUES (?, ?, ?, ?, ?)
            """, (row['id'], row['account_id'], row['token'], row['credits'], row['expiry']))
        c.execute("DROP TABLE user_tokens")
        c.execute("ALTER TABLE user_tokens_new RENAME TO user_tokens")
        print("Migration complete.")
    else:
        print("No migration needed or already migrated.")

    # Ensure user_tokens have valid account_ids
    c.execute("SELECT id, token, account_id FROM user_tokens")
    tokens = c.fetchall()
    for token in tokens:
        try:
            user_data = decrypt_data(token['token'])
            username = user_data['username'].lower()
            hashed_username = hash_user_acc_data(username)
            c.execute("SELECT id FROM accounts WHERE username = ?", (hashed_username,))
            account = c.fetchone()
            if account and account['id'] != token['account_id']:
                c.execute("UPDATE user_tokens SET account_id = ? WHERE id = ?", (account['id'], token['id']))
                print(f"Updated account_id for token {token['id']} to match username")
        except Exception as e:
            print(f"Error processing token {token['id']}: {str(e)}")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    migrate_user_tokens()