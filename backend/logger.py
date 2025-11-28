# simple logging config to keep track of events and errors

import logging
import logging.handlers
import os
from pathlib import Path


LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

logger = logging.getLogger("phishbuddy")
logger.setLevel(logging.DEBUG)

# console handler at the info level
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.WARNING)
console_formatter = logging.Formatter(
    "%(levelname)s - %(message)s"
)
console_handler.setFormatter(console_formatter)

# file handler at the debug level
from .config import LOGGING

file_handler = logging.handlers.RotatingFileHandler(
    LOG_DIR / "phishbuddy.log",
    maxBytes=LOGGING['max_bytes'],
    backupCount=LOGGING['backup_count']
)
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s"
)
file_handler.setFormatter(file_formatter)

logger.addHandler(console_handler)
logger.addHandler(file_handler)

# simple getter for logger
def get_logger():
    return logger

