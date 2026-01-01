"""Custom exceptions for Leviathan."""


class LeviathanError(Exception):
    """Base exception for Leviathan errors."""
    pass


class ConfigurationError(LeviathanError):
    """Raised when there's a configuration error."""
    pass


class ModuleError(LeviathanError):
    """Raised when there's a module-related error."""
    pass


class PipelineError(LeviathanError):
    """Raised when there's a pipeline execution error."""
    pass


class TaskError(LeviathanError):
    """Raised when a task fails."""
    pass


class ValidationError(LeviathanError):
    """Raised when validation fails."""
    pass


class ResourceError(LeviathanError):
    """Raised when resource allocation fails."""
    pass