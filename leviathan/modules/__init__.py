"""Leviathan analysis modules."""

# Import all module classes for easy access
from .discovery.file_discovery import FileDiscoveryModule as FileDiscovery
from .discovery.network_discovery import NetworkDiscoveryModule as NetworkDiscovery
from .detection.pattern_detection import PatternDetectionModule as PatternDetection
from .detection.signature_detection import SignatureDetectionModule as SignatureDetection
from .fuzzing.basic_fuzzer import BasicFuzzer
from .fuzzing.coverage_analyzer import CoverageAnalyzer
from .analysis.advanced_analyzer import AdvancedAnalyzer
from .ml.pattern_evolution import PatternEvolutionModule
from .ml.zero_day_hypothesis import ZeroDayHypothesisModule
from .ml.pipeline import MLPipelineModule

__all__ = [
    "FileDiscovery",
    "NetworkDiscovery",
    "PatternDetection",
    "SignatureDetection",
    "BasicFuzzer",
    "CoverageAnalyzer",
    "AdvancedAnalyzer",
    "PatternEvolutionModule",
    "ZeroDayHypothesisModule",
    "MLPipelineModule"
]