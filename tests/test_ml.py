"""Tests for Leviathan ML components."""

import pytest
import tempfile
import asyncio
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

from leviathan.modules.ml.core import PatternEvolutionModel, ZeroDayHypothesisModel
from leviathan.modules.ml.pattern_evolution import PatternEvolutionModule
from leviathan.modules.ml.zero_day_hypothesis import ZeroDayHypothesisModule
from leviathan.modules.ml.pipeline import MLPipelineModule
from leviathan.modules.ml.model_management import ModelManager, ModelTrainer


class TestPatternEvolutionModel:
    """Test pattern evolution ML model."""

    def test_model_initialization(self):
        """Test pattern evolution model initialization."""
        model = PatternEvolutionModel()
        assert model.model_type == "pattern_evolution"
        assert not model.is_trained

    def test_pattern_training(self):
        """Test pattern evolution model training."""
        model = PatternEvolutionModel()

        patterns = [
            {"name": "sql_injection", "pattern": "' OR '1'='1", "type": "injection"},
            {"name": "xss", "pattern": "<script>alert('xss')</script>", "type": "xss"}
        ]

        result = model.train(patterns)

        assert result["success"] is True
        assert model.is_trained
        assert len(result["evolved_patterns"]) > 0

    def test_pattern_prediction(self):
        """Test pattern evolution prediction."""
        model = PatternEvolutionModel()

        # Train first
        patterns = [{"name": "test", "pattern": "test123", "type": "test"}]
        model.train(patterns)

        # Predict
        input_pattern = {"name": "input", "pattern": "input456", "type": "test"}
        evolved = model.predict(input_pattern)

        assert isinstance(evolved, list)
        assert len(evolved) > 0

    def test_model_save_load(self):
        """Test model save and load functionality."""
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = Path(temp_dir) / "test_model.pkl"

            # Create and train model
            model = PatternEvolutionModel()
            patterns = [{"name": "test", "pattern": "test", "type": "test"}]
            model.train(patterns)

            # Save
            model.save(model_path)
            assert model_path.exists()

            # Load into new model
            new_model = PatternEvolutionModel()
            new_model.load(model_path)

            assert new_model.is_trained
            assert len(new_model.pattern_library) == 1


class TestZeroDayHypothesisModel:
    """Test zero-day hypothesis generation model."""

    def test_model_initialization(self):
        """Test hypothesis model initialization."""
        model = ZeroDayHypothesisModel()
        assert model.model_type == "zero_day_hypothesis"
        assert not model.is_trained

    def test_hypothesis_training(self):
        """Test hypothesis model training."""
        model = ZeroDayHypothesisModel()

        vuln_data = [
            {"type": "sql_injection", "description": "SQL injection vuln"},
            {"type": "xss", "description": "XSS vulnerability"}
        ]

        result = model.train(vuln_data)

        assert result["success"] is True
        assert model.is_trained

    def test_hypothesis_prediction(self):
        """Test hypothesis generation."""
        model = ZeroDayHypothesisModel()

        # Train first
        vuln_data = [{"type": "sql_injection", "description": "SQL injection"}]
        model.train(vuln_data)

        # Generate hypotheses
        target_info = {
            "type": "web_application",
            "features": ["user_input", "database"]
        }

        hypotheses = model.predict(target_info)

        assert isinstance(hypotheses, list)
        assert len(hypotheses) > 0
        assert "type" in hypotheses[0]
        assert "confidence" in hypotheses[0]

    def test_web_app_hypotheses(self):
        """Test web application specific hypotheses."""
        model = ZeroDayHypothesisModel()

        # Train the model first
        vuln_data = [
            {"type": "sql_injection", "description": "SQL injection vuln"},
            {"type": "xss", "description": "XSS vulnerability"}
        ]
        model.train(vuln_data)

        target_info = {
            "type": "web_application",
            "features": ["user_input"]
        }

        hypotheses = model.predict(target_info)

        # Should include SQL injection and XSS hypotheses
        hypothesis_types = [h["type"] for h in hypotheses]
        assert "sql_injection" in hypothesis_types
        assert "xss" in hypothesis_types


class TestPatternEvolutionModule:
    """Test pattern evolution module."""

    @pytest.mark.asyncio
    async def test_pattern_evolution_module(self):
        """Test pattern evolution module analysis."""
        module = PatternEvolutionModule()

        config = {
            "evolution_config": {
                "strategy": "comprehensive",
                "max_evolutions": 10,
                "confidence_threshold": 0.5
            },
            "base_patterns": [
                {"name": "test_pattern", "pattern": "test", "type": "test"}
            ]
        }

        result = await module.analyze(config)

        assert result["module"] == "pattern_evolution"
        assert "evolved_patterns" in result
        assert "model_metadata" in result


class TestZeroDayHypothesisModule:
    """Test zero-day hypothesis module."""

    @pytest.mark.asyncio
    async def test_hypothesis_module(self):
        """Test hypothesis generation module analysis."""
        module = ZeroDayHypothesisModule()

        config = {
            "target_info": {
                "type": "web_application",
                "name": "test_app",
                "features": ["user_input", "database"]
            },
            "hypothesis_config": {
                "max_hypotheses": 5,
                "min_confidence": 0.3
            }
        }

        result = await module.analyze(config)

        assert result["module"] == "zero_day_hypothesis"
        assert "hypotheses" in result
        assert len(result["hypotheses"]) <= 5
        assert all(h.get("confidence", 0) >= 0.3 for h in result["hypotheses"])


class TestMLPipelineModule:
    """Test ML pipeline integration module."""

    @pytest.mark.asyncio
    async def test_ml_pipeline_basic(self):
        """Test basic ML pipeline execution."""
        module = MLPipelineModule()

        config = {
            "target_info": {
                "type": "web_application",
                "name": "test_target",
                "features": ["user_input"]
            },
            "pipeline_config": {
                "enable_pattern_evolution": True,
                "enable_hypothesis_generation": True,
                "enable_learning": False,
                "model_dir": "./test_models"
            }
        }

        result = await module.analyze(config)

        assert result["module"] == "ml_pipeline"
        assert "pipeline_phases" in result
        assert len(result["pipeline_phases"]) >= 2  # pattern evolution + hypothesis

    @pytest.mark.asyncio
    async def test_ml_pipeline_with_learning(self):
        """Test ML pipeline with adaptive learning."""
        module = MLPipelineModule()

        config = {
            "target_info": {
                "type": "binary",
                "name": "test_binary",
                "features": ["network_io"]
            },
            "pipeline_config": {
                "enable_learning": True,
                "model_dir": "./test_models"
            }
        }

        result = await module.analyze(config)

        assert result["module"] == "ml_pipeline"
        assert "pipeline_phases" in result

        # Should include adaptive learning phase
        phase_names = [p["phase"] for p in result["pipeline_phases"]]
        assert "adaptive_learning" in phase_names

    def test_model_registry(self):
        """Test ML model registry functionality."""
        module = MLPipelineModule()

        # Register a mock model
        mock_model = MagicMock()
        module.register_model("test_model", mock_model)

        # Retrieve model
        retrieved = module.get_model("test_model")
        assert retrieved is mock_model

        # Test caching
        module.cache_model("cached_model", mock_model)
        cached = module.get_cached_model("cached_model")
        assert cached is mock_model


class TestModelManager:
    """Test model management functionality."""

    def test_model_registration(self):
        """Test model registration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ModelManager(model_dir=temp_dir)

            # Register a model
            model_id = manager.register_model(
                name="test_model",
                model_class=PatternEvolutionModel,
                version="1.0.0"
            )

            assert model_id == "test_model:1.0.0"
            assert model_id in manager.models

    def test_model_instance_creation(self):
        """Test model instance creation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ModelManager(model_dir=temp_dir)

            # Register and create instance
            model_id = manager.register_model("test_model", PatternEvolutionModel)
            instance = manager.create_model_instance(model_id)

            assert instance is not None
            assert isinstance(instance, PatternEvolutionModel)

    def test_model_save_load(self):
        """Test model save and load."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ModelManager(model_dir=temp_dir)

            # Create and train a model
            model = PatternEvolutionModel()
            patterns = [{"name": "test", "pattern": "test", "type": "test"}]
            model.train(patterns)

            # Register and save
            model_id = manager.register_model("test_model", PatternEvolutionModel)
            success = manager.save_model(model_id, model)

            assert success

            # Load the model
            loaded = manager.load_model(model_id, PatternEvolutionModel)
            assert loaded is not None
            assert loaded.is_trained

    def test_model_listing(self):
        """Test model listing functionality."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ModelManager(model_dir=temp_dir)

            # Register multiple models
            manager.register_model("model1", PatternEvolutionModel, version="1.0.0")
            manager.register_model("model2", ZeroDayHypothesisModel, version="2.0.0")

            models = manager.list_models()
            assert len(models) == 2

            # Test filtering
            filtered = manager.list_models("model1")
            assert len(filtered) == 1
            assert filtered[0]["name"] == "model1"

    def test_model_versions(self):
        """Test model version management."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ModelManager(model_dir=temp_dir)

            # Register multiple versions
            manager.register_model("test_model", PatternEvolutionModel, version="1.0.0")
            manager.register_model("test_model", PatternEvolutionModel, version="1.1.0")

            versions = manager.get_model_versions("test_model")
            assert len(versions) == 2
            assert "1.0.0" in versions
            assert "1.1.0" in versions

            latest = manager.get_latest_version("test_model")
            assert latest == "1.1.0"

    def test_model_caching(self):
        """Test model caching functionality."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ModelManager(model_dir=temp_dir)

            mock_model = MagicMock()

            # Cache a model
            manager.cache_model("test_model", mock_model, ttl_minutes=60)
            cached = manager.get_cached_model("test_model")

            assert cached is mock_model

            # Clear cache
            cleared = manager.clear_cache("test_model")
            assert cleared == 1

            # Should not find cached model anymore
            cached = manager.get_cached_model("test_model")
            assert cached is None


class TestModelTrainer:
    """Test model training orchestration."""

    @pytest.mark.asyncio
    async def test_async_training(self):
        """Test asynchronous model training."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ModelManager(model_dir=temp_dir)
            trainer = ModelTrainer(manager)

            # Register a model
            model_id = manager.register_model("test_model", PatternEvolutionModel)

            # Start training
            training_data = [{"name": "test", "pattern": "test", "type": "test"}]
            job_id = await trainer.train_model_async(model_id, training_data)

            assert job_id.startswith("train_")

            # Wait a bit for training to complete
            await asyncio.sleep(0.1)

            # Check status
            status = trainer.get_training_status(job_id)
            assert status is not None
            assert status["status"] in ["running", "completed"]

    def test_training_status_tracking(self):
        """Test training job status tracking."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ModelManager(model_dir=temp_dir)
            trainer = ModelTrainer(manager)

            # Create a fake job
            job_id = "test_job_123"
            trainer.training_jobs[job_id] = {
                "status": "running",
                "model_id": "test_model",
                "progress": 50
            }

            # Check status
            status = trainer.get_training_status(job_id)
            assert status["status"] == "running"
            assert status["progress"] == 50

    def test_training_cancellation(self):
        """Test training job cancellation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ModelManager(model_dir=temp_dir)
            trainer = ModelTrainer(manager)

            # Create a fake job
            job_id = "test_job_123"
            trainer.training_jobs[job_id] = {"status": "running"}

            # Cancel job
            cancelled = trainer.cancel_training(job_id)
            assert cancelled

            status = trainer.get_training_status(job_id)
            assert status["status"] == "cancelled"