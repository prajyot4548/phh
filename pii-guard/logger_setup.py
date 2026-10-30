"""One shared, rotating log file for the whole app (backend + CLI)."""
import logging
from logging.handlers import RotatingFileHandler
import config

def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:            # already configured (Flask reload, repeated import)
        return logger
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s | %(levelname)-7s | %(name)s | %(message)s")

    file_h = RotatingFileHandler(config.LOG_FILE, maxBytes=config.LOG_MAX_BYTES,
                                 backupCount=config.LOG_BACKUPS, encoding="utf-8")
    file_h.setFormatter(fmt)
    logger.addHandler(file_h)

    console_h = logging.StreamHandler()
    console_h.setFormatter(fmt)
    logger.addHandler(console_h)
    return logger
