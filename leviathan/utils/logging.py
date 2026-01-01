"""Logging configuration for Leviathan."""

import sys
from typing import Any, Dict

import structlog

from ..core.config import get_config


def setup_logging() -> None:
    """Configure structured logging for Leviathan."""
    config = get_config()

    # Configure structlog
    shared_processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    if config.debug:
        # In debug mode, log to console with pretty printing
        shared_processors.append(structlog.dev.ConsoleRenderer())
    else:
        # In production, log JSON
        shared_processors.append(structlog.processors.JSONRenderer())

    structlog.configure(
        processors=shared_processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Configure standard library logging
    import logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, config.log_level.upper()),
    )


def get_logger(name: str) -> Any:
    """Get a configured logger instance."""
    return structlog.get_logger(name)