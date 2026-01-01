"""Tests for Leviathan core components."""

import pytest
from unittest.mock import Mock

from leviathan.core.config import LeviathanConfig, get_config
from leviathan.core.module_base import ModuleConfig, ModuleResult, PipelineModule
from leviathan.core.orchestrator import Orchestrator, Task
from leviathan.core.pipeline import Pipeline, PipelinePhase


class TestConfig:
    """Test configuration management."""

    def test_default_config(self):
        """Test default configuration values."""
        config = LeviathanConfig()
        assert config.debug is False
        assert config.log_level == "INFO"
        assert config.max_concurrent_tasks == 10
        assert "discovery" in config.enabled_modules

    def test_get_config(self):
        """Test global config instance."""
        config = get_config()
        assert isinstance(config, LeviathanConfig)


class MockModule(PipelineModule):
    """Mock module for testing."""

    def __init__(self, name="mock", should_succeed=True):
        super().__init__()
        self._name = name
        self.should_succeed = should_succeed

    @property
    def name(self):
        return self._name

    @property
    def description(self):
        return "Mock module for testing"

    async def process(self, data):
        if not self.should_succeed:
            raise Exception("Mock failure")
        return {"processed": data, "module": self.name}


class TestModuleBase:
    """Test module base classes."""

    @pytest.mark.asyncio
    async def test_pipeline_module_success(self):
        """Test successful pipeline module execution."""
        module = MockModule("test_module")
        result = await module.execute({"data": "test_input"})

        assert result.success is True
        assert result.module_name == "test_module"
        assert result.data["result"]["processed"] == "test_input"

    @pytest.mark.asyncio
    async def test_pipeline_module_failure(self):
        """Test failed pipeline module execution."""
        module = MockModule("failing_module", should_succeed=False)
        result = await module.execute({"data": "test_input"})

        assert result.success is False
        assert len(result.errors) > 0


class TestOrchestrator:
    """Test orchestrator functionality."""

    @pytest.mark.asyncio
    async def test_task_execution(self):
        """Test basic task execution."""
        orchestrator = Orchestrator()
        module = MockModule("test_task")
        task = Task(module, {"data": "test"}, "test_task_1")

        await orchestrator._execute_task(task, 0)

        assert task.status == "completed"
        assert task.result is not None
        assert task.result.success is True

        await orchestrator.shutdown()

    @pytest.mark.asyncio
    async def test_pipeline_execution(self):
        """Test pipeline execution with multiple tasks."""
        orchestrator = Orchestrator()

        tasks = [
            Task(MockModule("task1"), {"data": "input1"}, "task1"),
            Task(MockModule("task2"), {"data": "input2"}, "task2"),
        ]

        results = await orchestrator.execute_pipeline(tasks)

        assert len(results) == 2
        assert all(r.success for r in results.values())

        await orchestrator.shutdown()


class TestPipeline:
    """Test pipeline orchestration."""

    def test_module_registration(self):
        """Test module registration."""
        pipeline = Pipeline()
        module = MockModule("test_reg")

        pipeline.register_module(module, PipelinePhase.DISCOVERY)

        assert "test_reg" in pipeline.modules
        assert "test_reg" in pipeline.phase_modules[PipelinePhase.DISCOVERY]

    @pytest.mark.asyncio
    async def test_empty_pipeline(self):
        """Test pipeline execution with no modules."""
        pipeline = Pipeline()

        results = await pipeline.execute("test_target")

        assert len(results) == 0

        await pipeline.shutdown()