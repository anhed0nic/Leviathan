"""Model management utilities for Leviathan ML components."""

import asyncio
from typing import Dict, List, Any, Optional, Callable
from pathlib import Path
from datetime import datetime, timedelta
import json
import hashlib

from ...utils.logging import get_logger


class ModelManager:
    """Manages ML model lifecycle, versioning, and deployment."""

    def __init__(self, model_dir: str = "./models", cache_dir: str = "./model_cache"):
        self.model_dir = Path(model_dir)
        self.cache_dir = Path(cache_dir)
        self.logger = get_logger("leviathan.ml.model_manager")

        # Model registry
        self.models = {}
        self.model_versions = {}
        self.cache = {}

        # Create directories
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Load model registry
        self._load_registry()

    def register_model(
        self,
        name: str,
        model_class: Any,
        config: Optional[Dict[str, Any]] = None,
        version: str = "1.0.0"
    ) -> str:
        """Register a model with the manager."""
        model_id = f"{name}:{version}"

        self.models[model_id] = {
            "name": name,
            "version": version,
            "class": model_class,
            "config": config or {},
            "registered_at": datetime.now().isoformat(),
            "status": "registered"
        }

        # Initialize version tracking
        if name not in self.model_versions:
            self.model_versions[name] = []
        if version not in self.model_versions[name]:
            self.model_versions[name].append(version)

        self.logger.info("Registered model", model_id=model_id)
        self._save_registry()

        return model_id

    def create_model_instance(self, model_id: str) -> Optional[Any]:
        """Create an instance of a registered model."""
        if model_id not in self.models:
            self.logger.error("Model not found", model_id=model_id)
            return None

        model_info = self.models[model_id]
        try:
            model_class = model_info["class"]
            config = model_info["config"]

            instance = model_class(config)
            self.logger.info("Created model instance", model_id=model_id)

            return instance
        except Exception as e:
            self.logger.error("Failed to create model instance", model_id=model_id, error=str(e))
            return None

    def save_model(self, model_id: str, model_instance: Any, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Save a model instance to disk."""
        try:
            model_path = self.model_dir / f"{model_id.replace(':', '_')}.pkl"
            model_instance.save(model_path)

            # Save metadata
            metadata_path = self.model_dir / f"{model_id.replace(':', '_')}_metadata.json"
            metadata = metadata or {}
            metadata.update({
                "model_id": model_id,
                "saved_at": datetime.now().isoformat(),
                "model_type": model_instance.model_type if hasattr(model_instance, 'model_type') else 'unknown'
            })

            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)

            self.logger.info("Saved model", model_id=model_id, path=str(model_path))
            return True

        except Exception as e:
            self.logger.error("Failed to save model", model_id=model_id, error=str(e))
            return False

    def load_model(self, model_id: str, model_class: Any) -> Optional[Any]:
        """Load a model instance from disk."""
        try:
            model_path = self.model_dir / f"{model_id.replace(':', '_')}.pkl"

            if not model_path.exists():
                self.logger.warning("Model file not found", model_id=model_id, path=str(model_path))
                return None

            instance = model_class()
            instance.load(model_path)

            self.logger.info("Loaded model", model_id=model_id, path=str(model_path))
            return instance

        except Exception as e:
            self.logger.error("Failed to load model", model_id=model_id, error=str(e))
            return None

    def get_model_metadata(self, model_id: str) -> Optional[Dict[str, Any]]:
        """Get metadata for a saved model."""
        try:
            metadata_path = self.model_dir / f"{model_id.replace(':', '_')}_metadata.json"

            if not metadata_path.exists():
                return None

            with open(metadata_path, 'r') as f:
                return json.load(f)

        except Exception as e:
            self.logger.error("Failed to load model metadata", model_id=model_id, error=str(e))
            return None

    def list_models(self, name_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all registered models."""
        models = []

        for model_id, model_info in self.models.items():
            if name_filter and not model_info["name"].startswith(name_filter):
                continue

            # Add metadata if available
            metadata = self.get_model_metadata(model_id)
            if metadata:
                model_info = {**model_info, **metadata}

            models.append({
                "id": model_id,
                **model_info
            })

        return models

    def get_model_versions(self, name: str) -> List[str]:
        """Get all versions of a model."""
        return self.model_versions.get(name, [])

    def get_latest_version(self, name: str) -> Optional[str]:
        """Get the latest version of a model."""
        versions = self.get_model_versions(name)
        if not versions:
            return None

        # Simple version comparison (assumes semantic versioning)
        return max(versions, key=lambda v: [int(x) for x in v.split('.')])

    def cache_model(self, model_id: str, model_instance: Any, ttl_minutes: int = 60) -> None:
        """Cache a model instance with TTL."""
        expires_at = datetime.now() + timedelta(minutes=ttl_minutes)

        self.cache[model_id] = {
            "instance": model_instance,
            "expires_at": expires_at,
            "cached_at": datetime.now()
        }

        self.logger.debug("Cached model", model_id=model_id, expires_at=expires_at.isoformat())

    def get_cached_model(self, model_id: str) -> Optional[Any]:
        """Get a cached model instance if not expired."""
        if model_id not in self.cache:
            return None

        cached_data = self.cache[model_id]
        if datetime.now() > cached_data["expires_at"]:
            # Cache expired
            del self.cache[model_id]
            self.logger.debug("Cache expired for model", model_id=model_id)
            return None

        self.logger.debug("Retrieved cached model", model_id=model_id)
        return cached_data["instance"]

    def clear_cache(self, model_id: Optional[str] = None) -> int:
        """Clear model cache."""
        if model_id:
            if model_id in self.cache:
                del self.cache[model_id]
                self.logger.info("Cleared cache for model", model_id=model_id)
                return 1
            return 0
        else:
            cleared_count = len(self.cache)
            self.cache.clear()
            self.logger.info("Cleared all model cache", count=cleared_count)
            return cleared_count

    def cleanup_old_models(self, days_old: int = 30) -> int:
        """Clean up old model files."""
        cutoff_date = datetime.now() - timedelta(days=days_old)
        cleaned_count = 0

        try:
            for model_file in self.model_dir.glob("*.pkl"):
                if model_file.stat().st_mtime < cutoff_date.timestamp():
                    model_file.unlink()
                    # Also remove metadata file
                    metadata_file = model_file.with_name(f"{model_file.stem}_metadata.json")
                    if metadata_file.exists():
                        metadata_file.unlink()

                    cleaned_count += 1
                    self.logger.info("Cleaned up old model file", path=str(model_file))

        except Exception as e:
            self.logger.error("Failed to cleanup old models", error=str(e))

        return cleaned_count

    def get_model_hash(self, model_instance: Any) -> str:
        """Generate a hash for model comparison."""
        try:
            # Simple hash based on model metadata
            metadata = model_instance.get_metadata() if hasattr(model_instance, 'get_metadata') else {}
            metadata_str = json.dumps(metadata, sort_keys=True, default=str)
            return hashlib.sha256(metadata_str.encode()).hexdigest()[:16]
        except Exception:
            return "unknown"

    def _load_registry(self) -> None:
        """Load model registry from disk."""
        registry_path = self.model_dir / "model_registry.json"

        if not registry_path.exists():
            return

        try:
            with open(registry_path, 'r') as f:
                data = json.load(f)

            self.models = data.get("models", {})
            self.model_versions = data.get("versions", {})

            self.logger.info("Loaded model registry", models=len(self.models))

        except Exception as e:
            self.logger.error("Failed to load model registry", error=str(e))

    def _save_registry(self) -> None:
        """Save model registry to disk."""
        registry_path = self.model_dir / "model_registry.json"

        try:
            data = {
                "models": self.models,
                "versions": self.model_versions,
                "updated_at": datetime.now().isoformat()
            }

            with open(registry_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)

        except Exception as e:
            self.logger.error("Failed to save model registry", error=str(e))


class ModelTrainer:
    """Handles model training orchestration."""

    def __init__(self, model_manager: ModelManager):
        self.model_manager = model_manager
        self.logger = get_logger("leviathan.ml.model_trainer")
        self.training_jobs = {}

    async def train_model_async(
        self,
        model_id: str,
        training_data: Any,
        training_config: Optional[Dict[str, Any]] = None,
        callback: Optional[Callable] = None
    ) -> str:
        """Train a model asynchronously."""
        job_id = f"train_{model_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        self.training_jobs[job_id] = {
            "status": "running",
            "model_id": model_id,
            "started_at": datetime.now(),
            "progress": 0
        }

        # Start training in background
        asyncio.create_task(self._train_model_task(job_id, model_id, training_data, training_config, callback))

        self.logger.info("Started async model training", job_id=job_id, model_id=model_id)
        return job_id

    def get_training_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a training job."""
        return self.training_jobs.get(job_id)

    def cancel_training(self, job_id: str) -> bool:
        """Cancel a training job."""
        if job_id in self.training_jobs:
            self.training_jobs[job_id]["status"] = "cancelled"
            self.logger.info("Cancelled training job", job_id=job_id)
            return True
        return False

    async def _train_model_task(
        self,
        job_id: str,
        model_id: str,
        training_data: Any,
        training_config: Optional[Dict[str, Any]],
        callback: Optional[Callable]
    ) -> None:
        """Background task for model training."""
        try:
            # Create model instance
            model_instance = self.model_manager.create_model_instance(model_id)
            if not model_instance:
                raise ValueError(f"Could not create model instance: {model_id}")

            # Update progress
            self.training_jobs[job_id]["progress"] = 25

            # Train the model
            config = training_config or {}
            result = model_instance.train(training_data, **config)

            # Update progress
            self.training_jobs[job_id]["progress"] = 75

            # Save the trained model
            metadata = {
                "training_result": result,
                "training_config": config,
                "job_id": job_id
            }

            self.model_manager.save_model(model_id, model_instance, metadata)

            # Complete job
            self.training_jobs[job_id].update({
                "status": "completed",
                "completed_at": datetime.now(),
                "progress": 100,
                "result": result
            })

            self.logger.info("Completed model training", job_id=job_id, model_id=model_id)

            # Call callback if provided
            if callback:
                await callback(job_id, result)

        except Exception as e:
            self.training_jobs[job_id].update({
                "status": "failed",
                "error": str(e),
                "completed_at": datetime.now()
            })

            self.logger.error("Model training failed", job_id=job_id, model_id=model_id, error=str(e))

            if callback:
                await callback(job_id, {"error": str(e)})