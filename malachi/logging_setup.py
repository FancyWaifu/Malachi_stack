"""
Logging infrastructure for Malachi Stack.

Provides both file-based logging with rotation and TUI-compatible logging.
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from queue import Queue, Full
from pathlib import Path
from typing import Optional

from .config import (
    LOG_FILE,
    LOG_MAX_BYTES,
    LOG_BACKUP_COUNT,
    LOG_QUEUE_SIZE,
    LOG_DIR,
)


# Global log queue for TUI display
_log_queue: "Queue[str]" = Queue(maxsize=LOG_QUEUE_SIZE)

# Module-level logger
_logger: Optional[logging.Logger] = None


class TUIHandler(logging.Handler):
    """
    Logging handler that sends messages to a queue for TUI display.

    Non-blocking: drops messages if queue is full.
    """

    def __init__(self, queue: "Queue[str]"):
        super().__init__()
        self.queue = queue

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            # Sanitize for curses display
            msg = msg.replace("\x00", r"\x00")
            self.queue.put_nowait(msg)
        except Full:
            pass  # Drop message if queue is full
        except Exception:
            self.handleError(record)


class ColorFormatter(logging.Formatter):
    """
    Formatter that adds colors for terminal output (non-TUI).
    """

    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_logging(
    log_to_file: bool = True,
    log_to_tui: bool = True,
    log_level: str = "INFO",
) -> logging.Logger:
    """
    Configure the logging system.

    Args:
        log_to_file: Enable rotating file logging
        log_to_tui: Enable TUI queue logging
        log_level: Minimum log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

    Returns:
        Configured logger instance
    """
    global _logger

    if _logger is not None:
        return _logger

    _logger = logging.getLogger("malachi")
    _logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    _logger.propagate = False

    # Clear existing handlers
    _logger.handlers.clear()

    # File handler with rotation
    if log_to_file:
        Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)  # Capture everything to file
        file_formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_formatter)
        _logger.addHandler(file_handler)

    # TUI handler
    if log_to_tui:
        tui_handler = TUIHandler(_log_queue)
        tui_handler.setLevel(getattr(logging, log_level.upper(), logging.INFO))
        # Simpler format for TUI display
        tui_formatter = logging.Formatter("%(message)s")
        tui_handler.setFormatter(tui_formatter)
        _logger.addHandler(tui_handler)

    return _logger


def get_logger() -> logging.Logger:
    """Get the Malachi logger, initializing if necessary."""
    global _logger
    if _logger is None:
        _logger = setup_logging(log_to_file=False, log_to_tui=True)
    return _logger


def get_log_queue() -> "Queue[str]":
    """Get the TUI log queue."""
    return _log_queue


def log(msg: str) -> None:
    """
    Log a message to both file and TUI.

    This is the primary logging function for backward compatibility.
    """
    logger = get_logger()
    logger.info(msg)


def log_debug(msg: str) -> None:
    """Log a debug message."""
    get_logger().debug(msg)


def log_warning(msg: str) -> None:
    """Log a warning message."""
    get_logger().warning(msg)


def log_error(msg: str) -> None:
    """Log an error message."""
    get_logger().error(msg)


def format_block(title: str, lines: list[str]) -> str:
    """
    Format a titled block for log output.

    Args:
        title: Block title (displayed in brackets)
        lines: Content lines (will be indented)

    Returns:
        Formatted multi-line string
    """
    pad = "  "
    return "\n".join([f"[{title}]", *[pad + ln for ln in lines]])
