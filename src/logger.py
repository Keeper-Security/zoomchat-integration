# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""Logging configuration for Keeper Zoom App."""

import logging
import os
import sys
from typing import Optional


# Custom log level for OK messages (between INFO and WARNING)
OK_LEVEL = 25
logging.addLevelName(OK_LEVEL, "OK")


class KeeperFormatter(logging.Formatter):
    """Custom formatter that matches the existing [LEVEL] prefix style."""

    FORMATS = {
        logging.DEBUG: "[DEBUG] %(message)s",
        logging.INFO: "[INFO] %(message)s",
        OK_LEVEL: "[OK] %(message)s",
        logging.WARNING: "[WARN] %(message)s",
        logging.ERROR: "[ERROR] %(message)s",
        logging.CRITICAL: "[CRITICAL] %(message)s",
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, "[%(levelname)s] %(message)s")
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


class KeeperLogger(logging.Logger):
    """Custom logger with an 'ok' method for success messages."""

    def ok(self, msg, *args, **kwargs):
        """Log a success message at OK level."""
        if self.isEnabledFor(OK_LEVEL):
            self._log(OK_LEVEL, msg, args, **kwargs)


def setup_logger(
    name: str = "keeper",
    level: int = logging.DEBUG,
    log_file: Optional[str] = None
) -> KeeperLogger:
    """
    Set up and return the Keeper logger.
    """
    # Register custom logger class
    logging.setLoggerClass(KeeperLogger)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    # waitress configures the root logger; don't print every line twice
    logger.propagate = False

    # Avoid adding duplicate handlers
    if logger.handlers:
        return logger

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(KeeperFormatter())
    logger.addHandler(console_handler)

    # Optional file handler
    if log_file:
        try:
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(level)
            file_handler.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            ))
            logger.addHandler(file_handler)
        except OSError as e:
            logger.warning(f"File logging disabled ({log_file}): {e}")

    return logger


# Get project root directory (parent of src/)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LOG_FILE = os.path.join(_PROJECT_ROOT, "logs", "keeper_zoom.log")

_LOG_LEVEL = getattr(logging, os.environ.get("LOG_LEVEL", "DEBUG").upper(), logging.DEBUG)

# Initialize the default logger with file logging
logger = setup_logger(level=_LOG_LEVEL, log_file=_LOG_FILE)


def get_logger(name: str = "keeper") -> KeeperLogger:
    """Get a logger instance by name."""
    return logging.getLogger(name)
