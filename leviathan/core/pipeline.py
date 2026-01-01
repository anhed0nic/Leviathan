"""Core pipeline orchestration for Leviathan."""

import asyncio
from typing import Any, Dict, List, Optional
from enum import Enum

from ..utils.logging import get_logger
from ..utils.exceptions import PipelineError
from ..core.config import get_config
from .orchestrator import Orchestrator, Task
from .module_base import BaseModule, ModuleResult


class PipelinePhase(Enum):
    """Pipeline execution phases."""
    DISCOVERY = "discovery"
    DETECTION = "detection"
    FUZZING = "fuzzing"
    ANALYSIS = "analysis"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"


class Pipeline:
    """Main pipeline orchestrator for Leviathan analysis workflows."""

    def __init__(self):
        self.config = get_config()
        self.logger = get_logger("leviathan.pipeline")
        self.orchestrator = Orchestrator()
        self.modules: Dict[str, BaseModule] = {}
        self.phase_modules: Dict[PipelinePhase, List[str]] = {
            phase: [] for phase in PipelinePhase
        }

    def register_module(self, module: BaseModule, phase: PipelinePhase) -> None:
        """Register a module for a specific pipeline phase."""
        module_name = module.name
        if module_name in self.modules:
            self.logger.warning("Module already registered, overwriting", module=module_name)

        self.modules[module_name] = module
        self.phase_modules[phase].append(module_name)

        self.logger.info(
            "Module registered",
            module=module_name,
            phase=phase.value
        )

    def unregister_module(self, module_name: str) -> None:
        """Unregister a module."""
        if module_name in self.modules:
            del self.modules[module_name]

            # Remove from phase lists
            for phase_modules in self.phase_modules.values():
                if module_name in phase_modules:
                    phase_modules.remove(module_name)

            self.logger.info("Module unregistered", module=module_name)
        else:
            self.logger.warning("Module not found for unregistration", module=module_name)

    async def execute(
        self,
        target: Any,
        phases: Optional[List[PipelinePhase]] = None,
        module_overrides: Optional[Dict[str, bool]] = None
    ) -> Dict[str, ModuleResult]:
        """Execute the analysis pipeline."""
        if phases is None:
            phases = list(PipelinePhase)

        self.logger.info(
            "Starting pipeline execution",
            target=str(target)[:100],
            phases=[p.value for p in phases]
        )

        all_results = {}
        current_data = {"target": target, "data": target}

        # Execute phases sequentially
        for phase in phases:
            if phase.value not in self.config.enabled_modules:
                self.logger.info("Phase disabled, skipping", phase=phase.value)
                continue

            phase_results = await self._execute_phase(phase, current_data, module_overrides)
            all_results.update(phase_results)

            # Update data for next phase
            current_data = self._aggregate_phase_results(phase_results, current_data)

        self.logger.info("Pipeline execution completed", total_results=len(all_results))
        return all_results

    async def _execute_phase(
        self,
        phase: PipelinePhase,
        input_data: Dict[str, Any],
        module_overrides: Optional[Dict[str, bool]] = None
    ) -> Dict[str, ModuleResult]:
        """Execute all modules in a phase."""
        phase_modules = self.phase_modules[phase]
        if not phase_modules:
            self.logger.info("No modules registered for phase", phase=phase.value)
            return {}

        self.logger.info(
            "Executing phase",
            phase=phase.value,
            modules=phase_modules
        )

        # Create tasks for this phase
        tasks = []
        for module_name in phase_modules:
            if module_overrides and module_name in module_overrides:
                if not module_overrides[module_name]:
                    continue  # Skip disabled module

            module = self.modules[module_name]
            task = Task(
                module=module,
                input_data=input_data.copy(),
                task_id=f"{phase.value}_{module_name}"
            )
            tasks.append(task)

        if not tasks:
            return {}

        # Execute tasks concurrently within the phase
        results = await self.orchestrator.execute_pipeline(tasks)

        # Log phase completion
        successful = sum(1 for r in results.values() if r.success)
        total = len(results)
        self.logger.info(
            "Phase completed",
            phase=phase.value,
            successful=successful,
            total=total
        )

        return results

    def _aggregate_phase_results(
        self,
        phase_results: Dict[str, ModuleResult],
        current_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Aggregate results from a phase to pass to the next phase."""
        aggregated = current_data.copy()

        # Collect successful results
        successful_results = {
            task_id: result.data
            for task_id, result in phase_results.items()
            if result.success
        }

        aggregated["phase_results"] = successful_results

        # For some phases, we might want to merge data
        # This is a simple implementation - can be extended
        merged_data = {}
        for result_data in successful_results.values():
            merged_data.update(result_data)

        aggregated["data"] = merged_data

        return aggregated

    async def shutdown(self) -> None:
        """Shutdown the pipeline and cleanup resources."""
        await self.orchestrator.shutdown()

        # Cleanup modules
        for module in self.modules.values():
            await module.cleanup()

        self.logger.info("Pipeline shutdown complete")