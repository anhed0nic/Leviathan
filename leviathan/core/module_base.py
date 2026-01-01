"""Base classes and interfaces for Leviathan modules."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from ..utils.logging import get_logger


class ModuleConfig(BaseModel):
    """Base configuration for modules."""
    enabled: bool = True
    priority: int = 0
    timeout: Optional[int] = None


class ModuleResult(BaseModel):
    """Base result class for module outputs."""
    module_name: str
    success: bool
    data: Dict[str, Any] = {}
    errors: List[str] = []
    metadata: Dict[str, Any] = {}


class BaseModule(ABC):
    """Abstract base class for all Leviathan modules."""

    def __init__(self, config: Optional[ModuleConfig] = None):
        self.config = config or ModuleConfig()
        self.logger = get_logger(f"leviathan.modules.{self.__class__.__name__}")

    @property
    @abstractmethod
    def name(self) -> str:
        """Module name."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Module description."""
        pass

    @abstractmethod
    async def execute(self, input_data: Dict[str, Any]) -> ModuleResult:
        """Execute the module with given input data."""
        pass

    async def validate_input(self, input_data: Dict[str, Any]) -> bool:
        """Validate input data before execution."""
        return True

    async def cleanup(self) -> None:
        """Cleanup resources after execution."""
        pass


class PipelineModule(BaseModule):
    """Base class for pipeline modules that process data sequentially."""

    @abstractmethod
    async def process(self, data: Any) -> Any:
        """Process input data and return result."""
        pass

    async def execute(self, input_data: Dict[str, Any]) -> ModuleResult:
        """Execute the pipeline module."""
        try:
            if not await self.validate_input(input_data):
                return ModuleResult(
                    module_name=self.name,
                    success=False,
                    errors=["Input validation failed"]
                )

            result_data = await self.process(input_data.get("data"))

            return ModuleResult(
                module_name=self.name,
                success=True,
                data={"result": result_data}
            )

        except Exception as e:
            self.logger.error("Module execution failed", error=str(e))
            return ModuleResult(
                module_name=self.name,
                success=False,
                errors=[str(e)]
            )


class AnalysisModule(BaseModule):
    """Base class for analysis modules."""

    @abstractmethod
    async def analyze(self, target: Any) -> Dict[str, Any]:
        """Perform analysis on target."""
        pass

    async def execute(self, input_data: Dict[str, Any]) -> ModuleResult:
        """Execute the analysis module."""
        try:
            target = input_data.get("target")
            if target is None:
                return ModuleResult(
                    module_name=self.name,
                    success=False,
                    errors=["No target provided"]
                )

            analysis_result = await self.analyze(target)

            return ModuleResult(
                module_name=self.name,
                success=True,
                data=analysis_result
            )

        except Exception as e:
            self.logger.error("Analysis failed", error=str(e))
            return ModuleResult(
                module_name=self.name,
                success=False,
                errors=[str(e)]
            )