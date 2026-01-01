"""Machine learning core components for Leviathan."""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Union, Callable
from pathlib import Path
import json
import pickle
from datetime import datetime

from ...core.module_base import BaseModule
from ...utils.logging import get_logger


class MLModel(ABC):
    """Abstract base class for ML models in Leviathan."""

    def __init__(self, model_config: Optional[Dict[str, Any]] = None):
        self.config = model_config or {}
        self.is_trained = False
        self.training_metadata = {}
        self.logger = get_logger(f"leviathan.ml.{self.__class__.__name__}")

    @property
    @abstractmethod
    def model_type(self) -> str:
        """Return the type of ML model."""
        pass

    @abstractmethod
    def train(self, data: Any, labels: Optional[Any] = None, **kwargs) -> Dict[str, Any]:
        """Train the model on provided data."""
        pass

    @abstractmethod
    def predict(self, data: Any, **kwargs) -> Any:
        """Make predictions using the trained model."""
        pass

    @abstractmethod
    def save(self, path: Union[str, Path]) -> None:
        """Save the model to disk."""
        pass

    @abstractmethod
    def load(self, path: Union[str, Path]) -> None:
        """Load the model from disk."""
        pass

    def get_metadata(self) -> Dict[str, Any]:
        """Get model metadata."""
        return {
            "model_type": self.model_type,
            "is_trained": self.is_trained,
            "config": self.config,
            "training_metadata": self.training_metadata,
            "created_at": datetime.now().isoformat()
        }


class PatternEvolutionModel(MLModel):
    """ML model for evolving security patterns."""

    def __init__(self, model_config: Optional[Dict[str, Any]] = None):
        super().__init__(model_config)
        self.pattern_library = []
        self.evolution_history = []

    @property
    def model_type(self) -> str:
        return "pattern_evolution"

    def train(self, patterns: List[Dict[str, Any]], labels: Optional[List[float]] = None, **kwargs) -> Dict[str, Any]:
        """Train pattern evolution model."""
        self.logger.info("Training pattern evolution model", num_patterns=len(patterns))

        # Store patterns for evolution
        self.pattern_library = patterns.copy()

        # Simple evolution logic (placeholder for actual ML)
        evolved_patterns = []
        for pattern in patterns:
            # Generate variations
            variations = self._generate_pattern_variations(pattern)
            evolved_patterns.extend(variations)

        self.evolution_history.append({
            "timestamp": datetime.now().isoformat(),
            "input_patterns": len(patterns),
            "evolved_patterns": len(evolved_patterns)
        })

        self.is_trained = True
        self.training_metadata = {
            "trained_on": len(patterns),
            "evolved_to": len(evolved_patterns),
            "training_time": datetime.now().isoformat()
        }

        return {
            "success": True,
            "evolved_patterns": evolved_patterns,
            "metadata": self.training_metadata
        }

    def predict(self, input_pattern: Dict[str, Any], **kwargs) -> List[Dict[str, Any]]:
        """Generate evolved patterns from input."""
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")

        self.logger.info("Generating evolved patterns", input_pattern=input_pattern.get("name", "unknown"))

        # Generate evolved versions of the input pattern
        evolved = self._generate_pattern_variations(input_pattern)

        return evolved

    def _generate_pattern_variations(self, pattern: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate variations of a security pattern."""
        variations = []

        # Basic pattern evolution strategies
        base_name = pattern.get("name", "unknown")
        base_pattern = pattern.get("pattern", "")

        # Length variations
        if len(base_pattern) > 0:
            # Shorter version
            variations.append({
                "name": f"{base_name}_short",
                "pattern": base_pattern[:len(base_pattern)//2],
                "confidence": 0.7,
                "evolved_from": base_name
            })

            # Extended version
            variations.append({
                "name": f"{base_name}_extended",
                "pattern": base_pattern + base_pattern[-5:],
                "confidence": 0.6,
                "evolved_from": base_name
            })

        # Character substitution variations
        if isinstance(base_pattern, str):
            # Replace common characters
            substitutions = {
                "a": "@",
                "e": "3",
                "i": "1",
                "o": "0",
                "s": "$"
            }

            for old_char, new_char in substitutions.items():
                if old_char in base_pattern.lower():
                    new_pattern = base_pattern.lower().replace(old_char, new_char)
                    variations.append({
                        "name": f"{base_name}_sub_{old_char}to{new_char}",
                        "pattern": new_pattern,
                        "confidence": 0.8,
                        "evolved_from": base_name
                    })

        return variations

    def save(self, path: Union[str, Path]) -> None:
        """Save pattern evolution model."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        model_data = {
            "config": self.config,
            "pattern_library": self.pattern_library,
            "evolution_history": self.evolution_history,
            "training_metadata": self.training_metadata,
            "is_trained": self.is_trained
        }

        with open(path, 'wb') as f:
            pickle.dump(model_data, f)

    def load(self, path: Union[str, Path]) -> None:
        """Load pattern evolution model."""
        path = Path(path)

        with open(path, 'rb') as f:
            model_data = pickle.load(f)

        self.config = model_data.get("config", {})
        self.pattern_library = model_data.get("pattern_library", [])
        self.evolution_history = model_data.get("evolution_history", [])
        self.training_metadata = model_data.get("training_metadata", {})
        self.is_trained = model_data.get("is_trained", False)


class ZeroDayHypothesisModel(MLModel):
    """ML model for generating zero-day vulnerability hypotheses."""

    def __init__(self, model_config: Optional[Dict[str, Any]] = None):
        super().__init__(model_config)
        self.vulnerability_patterns = []
        self.hypothesis_history = []

    @property
    def model_type(self) -> str:
        return "zero_day_hypothesis"

    def train(self, vulnerability_data: List[Dict[str, Any]], labels: Optional[List[str]] = None, **kwargs) -> Dict[str, Any]:
        """Train zero-day hypothesis generation model."""
        self.logger.info("Training zero-day hypothesis model", num_samples=len(vulnerability_data))

        # Store vulnerability patterns
        self.vulnerability_patterns = vulnerability_data.copy()

        # Analyze patterns to build hypothesis generation rules
        self._analyze_vulnerability_patterns()

        self.is_trained = True
        self.training_metadata = {
            "trained_on": len(vulnerability_data),
            "training_time": datetime.now().isoformat(),
            "pattern_categories": self._get_pattern_categories()
        }

        return {
            "success": True,
            "metadata": self.training_metadata
        }

    def predict(self, target_info: Dict[str, Any], **kwargs) -> List[Dict[str, Any]]:
        """Generate zero-day hypotheses for target."""
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")

        self.logger.info("Generating zero-day hypotheses", target=target_info.get("name", "unknown"))

        hypotheses = []

        # Generate hypotheses based on target characteristics
        target_type = target_info.get("type", "unknown")
        target_features = target_info.get("features", [])

        # Common vulnerability hypotheses by target type
        if target_type == "web_application":
            hypotheses.extend(self._generate_web_hypotheses(target_features))
        elif target_type == "binary":
            hypotheses.extend(self._generate_binary_hypotheses(target_features))
        elif target_type == "network_service":
            hypotheses.extend(self._generate_network_hypotheses(target_features))

        # Cross-cutting hypotheses
        hypotheses.extend(self._generate_generic_hypotheses(target_features))

        # Record hypothesis generation
        self.hypothesis_history.append({
            "timestamp": datetime.now().isoformat(),
            "target": target_info.get("name", "unknown"),
            "hypotheses_generated": len(hypotheses)
        })

        return hypotheses

    def _analyze_vulnerability_patterns(self) -> None:
        """Analyze stored vulnerability patterns to build generation rules."""
        # This would contain actual ML analysis of vulnerability patterns
        # For now, it's a placeholder
        pass

    def _get_pattern_categories(self) -> List[str]:
        """Get categories of patterns learned."""
        categories = set()
        for pattern in self.vulnerability_patterns:
            vuln_type = pattern.get("type", "unknown")
            categories.add(vuln_type)
        return list(categories)

    def _generate_web_hypotheses(self, features: List[str]) -> List[Dict[str, Any]]:
        """Generate hypotheses for web applications."""
        hypotheses = []

        if "user_input" in features:
            hypotheses.append({
                "type": "injection",
                "description": "SQL injection via user input parameters",
                "confidence": 0.8,
                "test_vectors": ["' OR '1'='1", "1; DROP TABLE users--"],
                "mitigation": "Input sanitization and prepared statements"
            })

        if "file_upload" in features:
            hypotheses.append({
                "type": "file_upload_vulnerability",
                "description": "Arbitrary file upload leading to RCE",
                "confidence": 0.7,
                "test_vectors": ["shell.php", "malicious.exe"],
                "mitigation": "File type validation and secure upload paths"
            })

        return hypotheses

    def _generate_binary_hypotheses(self, features: List[str]) -> List[Dict[str, Any]]:
        """Generate hypotheses for binary applications."""
        hypotheses = []

        if "network_io" in features:
            hypotheses.append({
                "type": "buffer_overflow",
                "description": "Stack buffer overflow in network handling",
                "confidence": 0.6,
                "test_vectors": ["A" * 1024, "%n" * 100],
                "mitigation": "Bounds checking and safe string functions"
            })

        if "memory_management" in features:
            hypotheses.append({
                "type": "use_after_free",
                "description": "Use-after-free vulnerability in heap management",
                "confidence": 0.5,
                "test_vectors": ["trigger_double_free"],
                "mitigation": "Proper memory lifecycle management"
            })

        return hypotheses

    def _generate_network_hypotheses(self, features: List[str]) -> List[Dict[str, Any]]:
        """Generate hypotheses for network services."""
        hypotheses = []

        if "protocol_parsing" in features:
            hypotheses.append({
                "type": "protocol_fuzzing",
                "description": "Protocol parsing vulnerabilities",
                "confidence": 0.7,
                "test_vectors": ["invalid_protocol_data"],
                "mitigation": "Robust protocol validation"
            })

        return hypotheses

    def _generate_generic_hypotheses(self, features: List[str]) -> List[Dict[str, Any]]:
        """Generate cross-cutting vulnerability hypotheses."""
        hypotheses = []

        # Race condition hypothesis
        hypotheses.append({
            "type": "race_condition",
            "description": "Race condition in concurrent operations",
            "confidence": 0.4,
            "test_vectors": ["concurrent_access_test"],
            "mitigation": "Proper synchronization primitives"
        })

        # Information disclosure
        hypotheses.append({
            "type": "information_disclosure",
            "description": "Sensitive information leakage",
            "confidence": 0.5,
            "test_vectors": ["verbose_error_messages"],
            "mitigation": "Error handling without information disclosure"
        })

        return hypotheses

    def save(self, path: Union[str, Path]) -> None:
        """Save zero-day hypothesis model."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        model_data = {
            "config": self.config,
            "vulnerability_patterns": self.vulnerability_patterns,
            "hypothesis_history": self.hypothesis_history,
            "training_metadata": self.training_metadata,
            "is_trained": self.is_trained
        }

        with open(path, 'wb') as f:
            pickle.dump(model_data, f)

    def load(self, path: Union[str, Path]) -> None:
        """Load zero-day hypothesis model."""
        path = Path(path)

        with open(path, 'rb') as f:
            model_data = pickle.load(f)

        self.config = model_data.get("config", {})
        self.vulnerability_patterns = model_data.get("vulnerability_patterns", [])
        self.hypothesis_history = model_data.get("hypothesis_history", [])
        self.training_metadata = model_data.get("training_metadata", {})
        self.is_trained = model_data.get("is_trained", False)