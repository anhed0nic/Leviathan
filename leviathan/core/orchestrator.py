"""Async execution orchestrator for Leviathan."""

import asyncio
from typing import Any, Dict, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor
import time

from ..utils.logging import get_logger
from ..utils.exceptions import ResourceError, TaskError
from ..core.config import get_config
from .module_base import BaseModule, ModuleResult


class Task:
    """Represents a task in the execution pipeline."""

    def __init__(
        self,
        module: BaseModule,
        input_data: Dict[str, Any],
        task_id: str,
        dependencies: Optional[List[str]] = None
    ):
        self.module = module
        self.input_data = input_data
        self.task_id = task_id
        self.dependencies = dependencies or []
        self.result: Optional[ModuleResult] = None
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.status = "pending"  # pending, running, completed, failed

    @property
    def duration(self) -> Optional[float]:
        """Task execution duration in seconds."""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return None


class Orchestrator:
    """Async execution orchestrator for managing module pipelines."""

    def __init__(self):
        self.config = get_config()
        self.logger = get_logger("leviathan.orchestrator")
        self.executor = ThreadPoolExecutor(max_workers=self.config.max_concurrent_tasks)
        self.tasks: Dict[str, Task] = {}
        self.completed_tasks: Set[str] = set()
        self.failed_tasks: Set[str] = set()
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent_tasks)

    async def execute_pipeline(
        self,
        tasks: List[Task],
        max_retries: int = 3
    ) -> Dict[str, ModuleResult]:
        """Execute a pipeline of tasks with dependency management."""
        # Initialize tasks
        for task in tasks:
            self.tasks[task.task_id] = task

        results = {}

        # Execute tasks respecting dependencies
        while len(self.completed_tasks) + len(self.failed_tasks) < len(tasks):
            available_tasks = self._get_available_tasks()

            if not available_tasks:
                if len(self.failed_tasks) > 0:
                    break  # Cannot proceed due to failed dependencies
                await asyncio.sleep(0.1)  # Wait for dependencies
                continue

            # Execute available tasks concurrently
            execution_tasks = [
                self._execute_task(task, max_retries)
                for task in available_tasks
            ]

            await asyncio.gather(*execution_tasks, return_exceptions=True)

        # Collect results
        for task_id, task in self.tasks.items():
            if task.result:
                results[task_id] = task.result

        return results

    def _get_available_tasks(self) -> List[Task]:
        """Get tasks that are ready to execute (dependencies satisfied)."""
        available = []
        for task in self.tasks.values():
            if task.status == "pending":
                deps_satisfied = all(
                    dep_id in self.completed_tasks
                    for dep_id in task.dependencies
                )
                if deps_satisfied:
                    available.append(task)
        return available

    async def _execute_task(self, task: Task, max_retries: int) -> None:
        """Execute a single task with retry logic."""
        async with self._semaphore:
            task.status = "running"
            task.start_time = time.time()

            retries = 0
            while retries <= max_retries:
                try:
                    self.logger.info(
                        "Executing task",
                        task_id=task.task_id,
                        module=task.module.name,
                        attempt=retries + 1
                    )

                    # Execute in thread pool for CPU-bound operations
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(
                        self.executor,
                        self._sync_execute_module,
                        task.module,
                        task.input_data
                    )

                    task.result = result
                    task.status = "completed"
                    task.end_time = time.time()
                    self.completed_tasks.add(task.task_id)

                    self.logger.info(
                        "Task completed",
                        task_id=task.task_id,
                        duration=task.duration
                    )
                    break

                except Exception as e:
                    retries += 1
                    self.logger.warning(
                        "Task execution failed",
                        task_id=task.task_id,
                        error=str(e),
                        attempt=retries,
                        max_retries=max_retries
                    )

                    if retries > max_retries:
                        task.status = "failed"
                        task.end_time = time.time()
                        self.failed_tasks.add(task.task_id)
                        task.result = ModuleResult(
                            module_name=task.module.name,
                            success=False,
                            errors=[str(e)]
                        )
                        break

                    await asyncio.sleep(2 ** retries)  # Exponential backoff

    def _sync_execute_module(
        self,
        module: BaseModule,
        input_data: Dict[str, Any]
    ) -> ModuleResult:
        """Synchronous wrapper for module execution."""
        # Create a new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(module.execute(input_data))
        finally:
            loop.close()

    async def shutdown(self) -> None:
        """Shutdown the orchestrator and cleanup resources."""
        self.executor.shutdown(wait=True)
        self.logger.info("Orchestrator shutdown complete")