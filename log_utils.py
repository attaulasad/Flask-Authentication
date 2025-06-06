import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

# Configure logging
DEBUG_LOG_PATH = os.getenv("DEBUG_LOG_PATH", "app_debug.log")
ACTION_LOG_PATH = os.getenv("ACTION_LOG_PATH", "user_actions.log")

logging.basicConfig(
    filename=DEBUG_LOG_PATH,
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

user_action_logger = logging.getLogger('user_actions')
user_action_handler = RotatingFileHandler(
    ACTION_LOG_PATH, maxBytes=1024*1024*5, backupCount=5  # 5MB per file, 5 backups
)
user_action_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
user_action_logger.addHandler(user_action_handler)
user_action_logger.setLevel(logging.INFO)

def log_action(action, data, extra_info=None):
    """Log user actions safely."""
    try:
        message = f"{action} - {data}"
        if extra_info:
            message += f" - {extra_info}"
        user_action_logger.info(message)
        logging.debug(message)
    except Exception as e:
        print(f"Logging failed: {str(e)}")  # Fallback to console