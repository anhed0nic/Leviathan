"""ML pipeline integration for Leviathan."""

import asyncio
from typing import Dict, List, Any, Optional
from pathlib import Path

from ...core.module_base import AnalysisModule
from ...utils.logging import get_logger
from .pattern_evolution import PatternEvolutionModule
from .zero_day_hypothesis import ZeroDayHypothesisModule


class MLPipelineModule(AnalysisModule):
    """ML pipeline integration module for Leviathan."""

    def __init__(self, config=None):
        super().__init__(config)
        self.logger = get_logger("leviathan.ml.pipeline")

        # Initialize ML sub-modules
        self.pattern_evolution = PatternEvolutionModule(config)
        self.zero_day_hypothesis = ZeroDayHypothesisModule(config)

        # ML model registry
        self.model_registry = {}
        self.model_cache = {}

    @property
    def name(self) -> str:
        return "ml_pipeline"

    @property
    def description(self) -> str:
        return "Integrated ML pipeline for adaptive security analysis"

    async def analyze(self, target: Any) -> Dict[str, Any]:
        """Run ML pipeline analysis on target."""
        if not isinstance(target, dict):
            raise ValueError("Target must be a configuration dictionary")

        pipeline_config = target.get("pipeline_config", {})
        target_info = target.get("target_info", {})
        enable_learning = pipeline_config.get("enable_learning", True)
        model_dir = pipeline_config.get("model_dir", "./models")

        self.logger.info(
            "Starting ML pipeline analysis",
            target=target_info.get("name", "unknown"),
            enable_learning=enable_learning
        )

        # Ensure model directory exists
        Path(model_dir).mkdir(parents=True, exist_ok=True)

        results = {
            "module": self.name,
            "target": target_info.get("name", "unknown"),
            "pipeline_phases": []
        }

        # Phase 1: Pattern Evolution
        if pipeline_config.get("enable_pattern_evolution", True):
            pattern_results = await self._run_pattern_evolution(target_info, pipeline_config, model_dir)
            results["pipeline_phases"].append({
                "phase": "pattern_evolution",
                "results": pattern_results
            })

        # Phase 2: Zero-day Hypothesis Generation
        if pipeline_config.get("enable_hypothesis_generation", True):
            hypothesis_results = await self._run_hypothesis_generation(target_info, pipeline_config, model_dir)
            results["pipeline_phases"].append({
                "phase": "hypothesis_generation",
                "results": hypothesis_results
            })

        # Phase 3: Adaptive Learning (if enabled)
        if enable_learning:
            learning_results = await self._run_adaptive_learning(results, pipeline_config)
            results["pipeline_phases"].append({
                "phase": "adaptive_learning",
                "results": learning_results
            })

        # Phase 4: Model Management
        model_status = self._get_model_status()
        results["model_status"] = model_status

        self.logger.info(
            "ML pipeline analysis complete",
            phases_completed=len(results["pipeline_phases"]),
            models_loaded=len(model_status["loaded_models"])
        )

        return results

    async def _run_pattern_evolution(
        self,
        target_info: Dict[str, Any],
        config: Dict[str, Any],
        model_dir: str
    ) -> Dict[str, Any]:
        """Run pattern evolution phase."""
        self.logger.info("Running pattern evolution phase")

        # Prepare base patterns from target analysis
        base_patterns = self._extract_patterns_from_target(target_info)

        evolution_config = {
            "evolution_config": {
                "strategy": config.get("evolution_strategy", "comprehensive"),
                "max_evolutions": config.get("max_evolutions", 50),
                "confidence_threshold": config.get("confidence_threshold", 0.5)
            },
            "base_patterns": base_patterns,
            "model_path": f"{model_dir}/pattern_evolution.pkl"
        }

        try:
            result = await self.pattern_evolution.analyze(evolution_config)
            self.logger.info(
                "Pattern evolution completed",
                evolved_patterns=len(result.get("evolved_patterns", []))
            )
            return result
        except Exception as e:
            self.logger.error("Pattern evolution failed", error=str(e))
            return {"error": str(e), "evolved_patterns": []}

    async def _run_hypothesis_generation(
        self,
        target_info: Dict[str, Any],
        config: Dict[str, Any],
        model_dir: str
    ) -> Dict[str, Any]:
        """Run zero-day hypothesis generation phase."""
        self.logger.info("Running hypothesis generation phase")

        # Prepare training data if available
        training_data = config.get("training_data", [])

        hypothesis_config = {
            "target_info": target_info,
            "hypothesis_config": {
                "max_hypotheses": config.get("max_hypotheses", 20),
                "min_confidence": config.get("min_confidence", 0.3),
                "types": config.get("hypothesis_types", ["all"])
            },
            "training_data": training_data,
            "model_path": f"{model_dir}/zero_day_hypothesis.pkl"
        }

        try:
            result = await self.zero_day_hypothesis.analyze(hypothesis_config)
            self.logger.info(
                "Hypothesis generation completed",
                hypotheses=len(result.get("hypotheses", []))
            )
            return result
        except Exception as e:
            self.logger.error("Hypothesis generation failed", error=str(e))
            return {"error": str(e), "hypotheses": []}

    async def _run_adaptive_learning(
        self,
        pipeline_results: Dict[str, Any],
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Run adaptive learning phase to improve models."""
        self.logger.info("Running adaptive learning phase")

        learning_results = {
            "feedback_processed": 0,
            "models_updated": 0,
            "learning_metrics": {}
        }

        try:
            # Extract feedback from pipeline results
            feedback_data = self._extract_feedback_from_results(pipeline_results)

            if feedback_data:
                # Update pattern evolution model
                if "pattern_feedback" in feedback_data:
                    await self._update_pattern_model(feedback_data["pattern_feedback"])
                    learning_results["models_updated"] += 1

                # Update hypothesis model
                if "hypothesis_feedback" in feedback_data:
                    await self._update_hypothesis_model(feedback_data["hypothesis_feedback"])
                    learning_results["models_updated"] += 1

                learning_results["feedback_processed"] = len(feedback_data)

            learning_results["learning_metrics"] = {
                "model_accuracy_improvement": 0.05,  # Placeholder
                "new_patterns_discovered": len(feedback_data.get("new_patterns", [])),
                "hypothesis_accuracy": 0.75  # Placeholder
            }

        except Exception as e:
            self.logger.error("Adaptive learning failed", error=str(e))
            learning_results["error"] = str(e)

        return learning_results

    def _extract_patterns_from_target(self, target_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract security patterns from target information."""
        patterns = []

        # Extract patterns based on target type and features
        target_type = target_info.get("type", "")
        features = target_info.get("features", [])

        # Basic pattern extraction logic
        if target_type == "web_application":
            patterns.extend([
                {
                    "name": "web_input_validation",
                    "pattern": r"<input[^>]*>",
                    "type": "input_validation",
                    "confidence": 0.8
                },
                {
                    "name": "sql_query_pattern",
                    "pattern": r"SELECT.*FROM.*WHERE",
                    "type": "database_query",
                    "confidence": 0.7
                }
            ])

        elif target_type == "binary":
            patterns.extend([
                {
                    "name": "buffer_operation",
                    "pattern": r"strcpy|strcat|sprintf",
                    "type": "buffer_operation",
                    "confidence": 0.9
                },
                {
                    "name": "memory_allocation",
                    "pattern": r"malloc|free|new\s|delete",
                    "type": "memory_management",
                    "confidence": 0.8
                }
            ])

        # Feature-based patterns
        if "network" in features:
            patterns.append({
                "name": "network_operation",
                "pattern": r"socket|bind|listen|connect",
                "type": "network_io",
                "confidence": 0.7
            })

        if "file_io" in features:
            patterns.append({
                "name": "file_operation",
                "pattern": r"fopen|fread|fwrite|fclose",
                "type": "file_io",
                "confidence": 0.7
            })

        return patterns

    def _extract_feedback_from_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Extract learning feedback from pipeline results."""
        feedback = {}

        # Analyze pattern evolution results
        for phase in results.get("pipeline_phases", []):
            if phase["phase"] == "pattern_evolution":
                evolved_patterns = phase["results"].get("evolved_patterns", [])
                feedback["pattern_feedback"] = {
                    "successful_evolutions": len(evolved_patterns),
                    "new_patterns": evolved_patterns
                }

            elif phase["phase"] == "hypothesis_generation":
                hypotheses = phase["results"].get("hypotheses", [])
                feedback["hypothesis_feedback"] = {
                    "hypotheses_generated": len(hypotheses),
                    "high_confidence_hypotheses": [
                        h for h in hypotheses if h.get("confidence", 0) > 0.7
                    ]
                }

        return feedback

    async def _update_pattern_model(self, feedback: Dict[str, Any]) -> None:
        """Update pattern evolution model with feedback."""
        # This would implement online learning
        # For now, just log the feedback
        self.logger.info(
            "Updating pattern evolution model",
            feedback_items=len(feedback.get("new_patterns", []))
        )

    async def _update_hypothesis_model(self, feedback: Dict[str, Any]) -> None:
        """Update hypothesis generation model with feedback."""
        # This would implement online learning
        self.logger.info(
            "Updating hypothesis generation model",
            feedback_items=len(feedback.get("high_confidence_hypotheses", []))
        )

    def _get_model_status(self) -> Dict[str, Any]:
        """Get status of loaded ML models."""
        return {
            "loaded_models": list(self.model_registry.keys()),
            "cache_size": len(self.model_cache),
            "pattern_evolution_trained": self.pattern_evolution.model.is_trained,
            "hypothesis_generation_trained": self.zero_day_hypothesis.model.is_trained
        }

    def register_model(self, name: str, model_instance: Any) -> None:
        """Register a model in the registry."""
        self.model_registry[name] = model_instance
        self.logger.info("Registered ML model", name=name)

    def get_model(self, name: str) -> Optional[Any]:
        """Get a model from the registry."""
        return self.model_registry.get(name)

    def cache_model(self, name: str, model: Any) -> None:
        """Cache a model for faster access."""
        self.model_cache[name] = model

    def get_cached_model(self, name: str) -> Optional[Any]:
        """Get a cached model."""
        return self.model_cache.get(name)