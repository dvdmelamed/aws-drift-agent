"""
Logging utility for the drift detection agent.

Provides structured logging configuration with JSON formatting.
"""

import logging
import sys
from typing import Optional


class ColoredFormatter(logging.Formatter):
    """Custom formatter that adds grey color to log messages."""

    # ANSI color codes
    GREY = '\033[90m'
    RESET = '\033[0m'

    def format(self, record):
        # Get the original formatted message
        message = super().format(record)
        # Wrap it in grey color codes
        return f"{self.GREY}{message}{self.RESET}"


def setup_logging(config) -> None:
    """
    Set up logging configuration.

    Args:
        config: Application configuration
    """
    # Set log level
    log_level = getattr(logging, config.log_level.upper(), logging.WARN)

    # Create formatter
    if config.log_format == "json":
        base_formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
            '"logger": "%(name)s", "message": "%(message)s"}'
        )
        formatter = ColoredFormatter(
            '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
            '"logger": "%(name)s", "message": "%(message)s"}'
        )
    else:
        formatter = ColoredFormatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Set specific logger levels
    if config.enable_debug_logs:
        logging.getLogger("drift_agent").setLevel(logging.DEBUG)
        logging.getLogger("strands").setLevel(logging.DEBUG)
    else:
        logging.getLogger("drift_agent").setLevel(logging.INFO)
        logging.getLogger("strands").setLevel(logging.INFO)

    # Reduce noise from boto3
    logging.getLogger("boto3").setLevel(logging.WARN)
    logging.getLogger("botocore").setLevel(logging.WARN)
    logging.getLogger("urllib3").setLevel(logging.WARN)
