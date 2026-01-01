"""Configuration management for Leviathan."""

import os
from pathlib import Path
from typing import Any, Dict, Optional

from pydantic import Field
from pydantic_settings import BaseSettings


class LeviathanConfig(BaseSettings):
    """Main configuration class for Leviathan."""

    # General settings
    debug: bool = Field(default=False, description="Enable debug mode")
    log_level: str = Field(default="INFO", description="Logging level")
    workspace_dir: Path = Field(
        default=Path.cwd() / "workspace",
        description="Directory for temporary files and outputs"
    )

    # Pipeline settings
    max_concurrent_tasks: int = Field(
        default=10,
        description="Maximum number of concurrent tasks"
    )
    task_timeout: int = Field(
        default=300,
        description="Default task timeout in seconds"
    )

    # Module settings
    enabled_modules: list[str] = Field(
        default_factory=lambda: ["discovery", "detection", "fuzzing", "analysis", "reporting"],
        description="List of enabled modules"
    )

    # ML settings
    ml_enabled: bool = Field(default=True, description="Enable ML features")
    model_cache_dir: Path = Field(
        default=Path.cwd() / "models",
        description="Directory for ML model cache"
    )

    # Database settings
    db_url: str = Field(
        default="sqlite:///leviathan.db",
        description="Database connection URL"
    )

    # Redis settings (for caching)
    redis_url: str = Field(
        default="redis://localhost:6379",
        description="Redis connection URL"
    )

    # Prometheus settings
    metrics_enabled: bool = Field(default=True, description="Enable metrics collection")
    metrics_port: int = Field(default=8000, description="Metrics server port")

    class Config:
        env_prefix = "LEVIATHAN_"
        env_file = ".env"
        case_sensitive = False


# Global config instance
_config: Optional[LeviathanConfig] = None


def get_config() -> LeviathanConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = LeviathanConfig()
    return _config


def reload_config() -> LeviathanConfig:
    """Reload configuration from environment and files."""
    global _config
    _config = LeviathanConfig()
    return _config


def update_config(updates: Dict[str, Any]) -> LeviathanConfig:
    """Update configuration with new values."""
    global _config
    if _config is None:
        _config = LeviathanConfig()

    for key, value in updates.items():
        if hasattr(_config, key):
            setattr(_config, key, value)

    return _config