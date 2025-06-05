import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    filename='app_debug.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

user_action_logger = logging.getLogger('user_actions')
user_action_handler = logging.FileHandler('user_actions.log')
user_action_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
user_action_logger.addHandler(user_action_handler)
user_action_logger.setLevel(logging.INFO)

def log_action(action, data, extra_info=None):
    """Log user actions."""
    message = f"{action} - {data}"
    if extra_info:
        message += f" - {extra_info}"
    user_action_logger.info(message)
    logging.debug(message)