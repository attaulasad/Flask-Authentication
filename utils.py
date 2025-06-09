from log_utils import log_action
from crypto_utils import encrypt_data, decrypt_data, get_db_connection, hash_user_acc_data, decrypt_user_acc_data


class DATABASE_:
    def __init__(self):
        pass

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




    def execute_query(query: str, args: tuple):
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute(query, args)
            results = c.fetchone()
            return results



