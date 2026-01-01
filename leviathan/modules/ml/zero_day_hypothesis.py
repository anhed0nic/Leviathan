"""Zero-day hypothesis generation module for Leviathan."""

import asyncio
from typing import List, Dict, Any, Optional
from pathlib import Path

from ...core.module_base import AnalysisModule
from ...utils.logging import get_logger
from .core import ZeroDayHypothesisModel


class ZeroDayHypothesisModule(AnalysisModule):
    """Module for generating zero-day vulnerability hypotheses using ML."""

    def __init__(self, config=None):
        super().__init__(config)
        self.logger = get_logger("leviathan.ml.zero_day_hypothesis")
        self.model = ZeroDayHypothesisModel(config.get("model_config", {}) if config else {})

    @property
    def name(self) -> str:
        return "zero_day_hypothesis"

    @property
    def description(self) -> str:
        return "ML-assisted zero-day vulnerability hypothesis generation"

    async def analyze(self, target: Any) -> Dict[str, Any]:
        """Generate zero-day hypotheses for target."""
        if not isinstance(target, dict):
            raise ValueError("Target must be a configuration dictionary")

        target_info = target.get("target_info", {})
        hypothesis_config = target.get("hypothesis_config", {})
        model_path = target.get("model_path")
        training_data = target.get("training_data")

        # Load existing model if path provided
        if model_path and Path(model_path).exists():
            self.model.load(model_path)
            self.logger.info("Loaded existing zero-day hypothesis model", path=model_path)

        # Train model if training data provided
        training_result = None
        if training_data:
            training_result = self.model.train(training_data)
            self.logger.info(
                "Trained zero-day hypothesis model",
                training_samples=len(training_data)
            )

        # Generate hypotheses
        hypotheses = await self._generate_hypotheses(target_info, hypothesis_config)

        # Save model if path specified
        if model_path:
            self.model.save(model_path)
            self.logger.info("Saved zero-day hypothesis model", path=model_path)

        return {
            "module": self.name,
            "target": target_info.get("name", "unknown"),
            "hypotheses": hypotheses,
            "total_hypotheses": len(hypotheses),
            "model_metadata": self.model.get_metadata(),
            "training_result": training_result
        }

    async def _generate_hypotheses(
        self,
        target_info: Dict[str, Any],
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate hypotheses using the trained model."""
        max_hypotheses = config.get("max_hypotheses", 20)
        min_confidence = config.get("min_confidence", 0.3)
        hypothesis_types = config.get("types", ["all"])

        self.logger.info(
            "Generating zero-day hypotheses",
            target=target_info.get("name", "unknown"),
            max_hypotheses=max_hypotheses,
            min_confidence=min_confidence
        )

        hypotheses = []

        if not self.model.is_trained:
            self.logger.warning("Model not trained, using rule-based hypothesis generation")
            hypotheses = self._rule_based_hypotheses(target_info, max_hypotheses)
        else:
            # Use ML model for hypothesis generation
            try:
                raw_hypotheses = self.model.predict(target_info)
                hypotheses = [
                    h for h in raw_hypotheses
                    if h.get("confidence", 0) >= min_confidence
                ][:max_hypotheses]
            except Exception as e:
                self.logger.error("ML hypothesis generation failed", error=str(e))
                hypotheses = self._rule_based_hypotheses(target_info, max_hypotheses)

        # Filter by requested types
        if hypothesis_types != ["all"]:
            hypotheses = [
                h for h in hypotheses
                if h.get("type") in hypothesis_types
            ]

        # Sort by confidence
        hypotheses.sort(key=lambda x: x.get("confidence", 0), reverse=True)

        self.logger.info(
            "Hypothesis generation complete",
            generated=len(hypotheses),
            types=[h.get("type") for h in hypotheses[:5]]  # Log first 5 types
        )

        return hypotheses

    def _rule_based_hypotheses(self, target_info: Dict[str, Any], max_count: int) -> List[Dict[str, Any]]:
        """Generate hypotheses using rule-based approach when model not trained."""
        target_type = target_info.get("type", "unknown")
        features = target_info.get("features", [])

        hypotheses = []

        # Common hypotheses based on target type
        if target_type == "web_application":
            hypotheses.extend([
                {
                    "type": "sql_injection",
                    "description": "SQL injection vulnerability in user inputs",
                    "confidence": 0.8,
                    "severity": "high",
                    "test_vectors": ["' OR '1'='1 --", "1; DROP TABLE users --"],
                    "cwe": "CWE-89"
                },
                {
                    "type": "xss",
                    "description": "Cross-site scripting in output rendering",
                    "confidence": 0.7,
                    "severity": "medium",
                    "test_vectors": ["<script>alert('xss')</script>", "javascript:alert('xss')"],
                    "cwe": "CWE-79"
                },
                {
                    "type": "csrf",
                    "description": "Cross-site request forgery in state-changing operations",
                    "confidence": 0.6,
                    "severity": "medium",
                    "test_vectors": ["csrf_token_bypass"],
                    "cwe": "CWE-352"
                }
            ])

        elif target_type == "binary":
            hypotheses.extend([
                {
                    "type": "buffer_overflow",
                    "description": "Buffer overflow in input handling",
                    "confidence": 0.7,
                    "severity": "high",
                    "test_vectors": ["A" * 1024, "%x" * 100],
                    "cwe": "CWE-119"
                },
                {
                    "type": "format_string",
                    "description": "Format string vulnerability in logging/output",
                    "confidence": 0.6,
                    "severity": "high",
                    "test_vectors": ["%n" * 10, "%s" * 20],
                    "cwe": "CWE-134"
                },
                {
                    "type": "use_after_free",
                    "description": "Use-after-free in memory management",
                    "confidence": 0.5,
                    "severity": "high",
                    "test_vectors": ["double_free_trigger"],
                    "cwe": "CWE-416"
                }
            ])

        elif target_type == "network_service":
            hypotheses.extend([
                {
                    "type": "protocol_fuzzing",
                    "description": "Protocol parsing vulnerabilities",
                    "confidence": 0.7,
                    "severity": "high",
                    "test_vectors": ["invalid_protocol_data", "malformed_packets"],
                    "cwe": "CWE-20"
                },
                {
                    "type": "authentication_bypass",
                    "description": "Authentication mechanism bypass",
                    "confidence": 0.6,
                    "severity": "critical",
                    "test_vectors": ["null_auth", "weak_credentials"],
                    "cwe": "CWE-287"
                }
            ])

        # Feature-based hypotheses
        if "file_upload" in features:
            hypotheses.append({
                "type": "file_upload_vulnerability",
                "description": "Arbitrary file upload leading to RCE",
                "confidence": 0.8,
                "severity": "critical",
                "test_vectors": ["shell.php.jpg", "../../../shell.php"],
                "cwe": "CWE-434"
            })

        if "database" in features:
            hypotheses.append({
                "type": "nosql_injection",
                "description": "NoSQL injection in database queries",
                "confidence": 0.6,
                "severity": "high",
                "test_vectors": ["{$ne: null}", "{'$where': 'sleep(1000)'}"],
                "cwe": "CWE-943"
            })

        if "encryption" in features:
            hypotheses.append({
                "type": "weak_crypto",
                "description": "Weak cryptographic implementation",
                "confidence": 0.5,
                "severity": "medium",
                "test_vectors": ["known_weak_keys", "padding_oracle"],
                "cwe": "CWE-327"
            })

        # Generic hypotheses applicable to most targets
        generic_hypotheses = [
            {
                "type": "race_condition",
                "description": "Race condition in concurrent operations",
                "confidence": 0.4,
                "severity": "medium",
                "test_vectors": ["concurrent_access_stress"],
                "cwe": "CWE-362"
            },
            {
                "type": "information_disclosure",
                "description": "Sensitive information disclosure",
                "confidence": 0.5,
                "severity": "medium",
                "test_vectors": ["verbose_errors", "debug_mode_enabled"],
                "cwe": "CWE-200"
            },
            {
                "type": "denial_of_service",
                "description": "Denial of service through resource exhaustion",
                "confidence": 0.4,
                "severity": "medium",
                "test_vectors": ["large_input_flood", "infinite_loop_trigger"],
                "cwe": "CWE-400"
            }
        ]

        hypotheses.extend(generic_hypotheses)

        # Sort by confidence and limit count
        hypotheses.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        return hypotheses[:max_count]