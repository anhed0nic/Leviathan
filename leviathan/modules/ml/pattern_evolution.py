"""Pattern evolution module for Leviathan."""

import asyncio
from typing import List, Dict, Any, Optional
from pathlib import Path

from ...core.module_base import AnalysisModule
from ...utils.logging import get_logger
from .core import PatternEvolutionModel


class PatternEvolutionModule(AnalysisModule):
    """Module for evolving security patterns using ML."""

    def __init__(self, config=None):
        super().__init__(config)
        self.logger = get_logger("leviathan.ml.pattern_evolution")
        self.model = PatternEvolutionModel(config.get("model_config", {}) if config else {})

    @property
    def name(self) -> str:
        return "pattern_evolution"

    @property
    def description(self) -> str:
        return "ML-assisted pattern evolution for security analysis"

    async def analyze(self, target: Any) -> Dict[str, Any]:
        """Evolve patterns based on target analysis."""
        if not isinstance(target, dict):
            raise ValueError("Target must be a configuration dictionary")

        evolution_config = target.get("evolution_config", {})
        base_patterns = target.get("base_patterns", [])
        model_path = target.get("model_path")

        # Load existing model if path provided
        if model_path and Path(model_path).exists():
            self.model.load(model_path)
            self.logger.info("Loaded existing pattern evolution model", path=model_path)

        # Train or update model if patterns provided
        if base_patterns:
            training_result = self.model.train(base_patterns)
            self.logger.info(
                "Trained pattern evolution model",
                input_patterns=len(base_patterns),
                evolved_patterns=len(training_result.get("evolved_patterns", []))
            )

        # Generate evolved patterns
        evolution_results = await self._evolve_patterns(evolution_config)

        # Save model if path specified
        if model_path:
            self.model.save(model_path)
            self.logger.info("Saved pattern evolution model", path=model_path)

        return {
            "module": self.name,
            "evolved_patterns": evolution_results,
            "model_metadata": self.model.get_metadata(),
            "training_result": training_result if base_patterns else None
        }

    async def _evolve_patterns(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evolve patterns using the trained model."""
        evolution_strategy = config.get("strategy", "comprehensive")
        max_evolutions = config.get("max_evolutions", 50)
        confidence_threshold = config.get("confidence_threshold", 0.5)

        self.logger.info(
            "Evolving patterns",
            strategy=evolution_strategy,
            max_evolutions=max_evolutions,
            confidence_threshold=confidence_threshold
        )

        evolved_patterns = []

        if not self.model.is_trained:
            self.logger.warning("Model not trained, using basic evolution")
            evolved_patterns = self._basic_pattern_evolution(max_evolutions)
        else:
            # Use ML model for evolution
            evolved_patterns = await self._ml_based_evolution(
                max_evolutions, confidence_threshold
            )

        # Filter by confidence
        filtered_patterns = [
            p for p in evolved_patterns
            if p.get("confidence", 0) >= confidence_threshold
        ]

        self.logger.info(
            "Pattern evolution complete",
            generated=len(evolved_patterns),
            filtered=len(filtered_patterns)
        )

        return filtered_patterns

    def _basic_pattern_evolution(self, max_patterns: int) -> List[Dict[str, Any]]:
        """Basic pattern evolution without ML model."""
        # Generate some basic security patterns
        base_patterns = [
            {
                "name": "sql_injection_basic",
                "pattern": "' OR '1'='1",
                "type": "injection",
                "confidence": 0.9
            },
            {
                "name": "xss_basic",
                "pattern": "<script>alert('xss')</script>",
                "type": "xss",
                "confidence": 0.8
            },
            {
                "name": "path_traversal",
                "pattern": "../../../etc/passwd",
                "type": "path_traversal",
                "confidence": 0.7
            }
        ]

        evolved = []
        for base in base_patterns:
            if len(evolved) >= max_patterns:
                break

            # Generate variations
            variations = self.model._generate_pattern_variations(base)
            evolved.extend(variations[:5])  # Limit variations per base pattern

        return evolved[:max_patterns]

    async def _ml_based_evolution(
        self,
        max_patterns: int,
        confidence_threshold: float
    ) -> List[Dict[str, Any]]:
        """ML-based pattern evolution."""
        evolved_patterns = []

        # Use the trained model to evolve patterns
        for base_pattern in self.model.pattern_library:
            if len(evolved_patterns) >= max_patterns:
                break

            try:
                variations = self.model.predict(base_pattern)
                # Filter and add variations
                for variation in variations:
                    if variation.get("confidence", 0) >= confidence_threshold:
                        evolved_patterns.append(variation)
                        if len(evolved_patterns) >= max_patterns:
                            break
            except Exception as e:
                self.logger.debug("Failed to evolve pattern", pattern=base_pattern.get("name"), error=str(e))

        return evolved_patterns