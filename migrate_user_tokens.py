import sqlite3
from crypto_utils import get_db_connection

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

        # Create new user_tokens table
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

        # Migrate data
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

        # Drop old table and rename new one
        c.execute("DROP TABLE user_tokens")
        c.execute("ALTER TABLE user_tokens_new RENAME TO user_tokens")

        print("Migration complete.")
    else:
        print("No migration needed or already migrated.")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    migrate_user_tokens()