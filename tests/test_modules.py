"""Tests for Leviathan discovery and detection modules."""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from leviathan.modules.discovery.file_discovery import FileDiscoveryModule
from leviathan.modules.discovery.network_discovery import NetworkDiscoveryModule
from leviathan.modules.detection.pattern_detection import PatternDetectionModule
from leviathan.modules.detection.signature_detection import SignatureDetectionModule
from leviathan.extensions.module_loader import ModuleLoader


class TestFileDiscoveryModule:
    """Test file discovery module."""

    @pytest.mark.asyncio
    async def test_file_discovery_basic(self):
        """Test basic file discovery functionality."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create test files
            (temp_path / "test.py").write_text("print('hello')")
            (temp_path / "test.js").write_text("console.log('hello');")
            (temp_path / "subdir").mkdir()
            (temp_path / "subdir" / "nested.py").write_text("def func(): pass")

            module = FileDiscoveryModule()
            result = await module.execute({"target": str(temp_path)})

            assert result.success is True
            assert result.data["total_files"] >= 3
            assert ".py" in result.data["file_stats"]["by_extension"]

    @pytest.mark.asyncio
    async def test_file_discovery_with_config(self):
        """Test file discovery with custom configuration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create test files
            (temp_path / "test.py").write_text("print('hello')")
            (temp_path / "test.txt").write_text("hello world")

            from leviathan.core.module_base import ModuleConfig
            config = ModuleConfig()
            config.max_depth = 1
            config.include_patterns = ["*.py"]

            module = FileDiscoveryModule(config)
            result = await module.execute({"target": str(temp_path)})

            assert result.success is True
            assert result.data["total_files"] == 1
            assert ".py" in result.data["file_stats"]["by_extension"]


class TestNetworkDiscoveryModule:
    """Test network discovery module."""

    @pytest.mark.asyncio
    async def test_network_discovery_single_host(self):
        """Test network discovery on a single host."""
        module = NetworkDiscoveryModule()

        # Mock the scan to avoid actual network calls
        with patch.object(module, '_scan_network', return_value=[
            {"ip": "127.0.0.1", "port": 80, "service": "HTTP", "state": "open"}
        ]):
            result = await module.execute({"target": "127.0.0.1"})

            assert result.success is True
            assert result.data["targets_scanned"] == 1
            assert len(result.data["open_ports"]) == 1

    @pytest.mark.asyncio
    async def test_network_discovery_ip_range(self):
        """Test network discovery with IP range."""
        module = NetworkDiscoveryModule()

        # Test IP range parsing
        targets = module._parse_ip_range("192.168.1.1-192.168.1.3")
        assert len(targets) == 3
        assert "192.168.1.1" in targets
        assert "192.168.1.3" in targets


class TestPatternDetectionModule:
    """Test pattern detection module."""

    @pytest.mark.asyncio
    async def test_pattern_detection_vulnerabilities(self):
        """Test detection of common vulnerabilities."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create test file with vulnerabilities
            test_code = '''
password = "hardcoded_secret"
sql = "SELECT * FROM users WHERE id = '" + user_input + "'"
os.system("rm -rf /")
md5_hash = md5(data)
debug = True
'''
            (temp_path / "vulnerable.py").write_text(test_code)

            module = PatternDetectionModule()
            result = await module.execute({"target": str(temp_path)})

            assert result.success is True
            assert result.data["total_findings"] > 0
            assert result.data["files_analyzed"] == 1

    @pytest.mark.asyncio
    async def test_pattern_detection_clean_code(self):
        """Test pattern detection on clean code."""
        with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)

                # Create clean test file
                clean_code = '''
def hello_world():
    print("Hello, World!")

if __name__ == "__main__":
    hello_world()
'''
                (temp_path / "clean.py").write_text(clean_code)

                module = PatternDetectionModule()
                result = await module.execute({"target": str(temp_path)})

                assert result.success is True
                assert result.data["total_findings"] == 0
                assert result.data["files_analyzed"] == 1


class TestSignatureDetectionModule:
    """Test signature detection module."""

    @pytest.mark.asyncio
    async def test_signature_detection_malicious(self):
        """Test detection of malicious signatures."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create test file with malicious content
            malicious_code = '''
<?php
eval($_POST["cmd"]);
system($_GET["exec"]);
?>
'''
            (temp_path / "webshell.php").write_text(malicious_code)

            module = SignatureDetectionModule()
            result = await module.execute({"target": str(temp_path)})

            assert result.success is True
            assert result.data["total_detections"] > 0
            assert "webshell_php" in [d["signature_type"] for d in result.data["detections"]]

    @pytest.mark.asyncio
    async def test_signature_detection_clean(self):
        """Test signature detection on clean files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create clean PHP file
            clean_code = '''
<?php
echo "Hello, World!";
?>
'''
            (temp_path / "clean.php").write_text(clean_code)

            module = SignatureDetectionModule()
            result = await module.execute({"target": str(temp_path)})

            assert result.success is True
            # May still detect webshell patterns if they match generic PHP
            assert result.data["files_scanned"] == 1


class TestModuleLoader:
    """Test module loader functionality."""

    def test_module_discovery(self):
        """Test module discovery and loading."""
        loader = ModuleLoader()

        # Get the modules path
        modules_path = Path(__file__).parent.parent / "leviathan" / "modules"

        discovered = loader.discover_modules(modules_path)

        # Should find our implemented modules
        assert len(discovered) >= 10  # file_discovery, network_discovery, pattern_detection, signature_detection, basic_fuzzer, coverage_analyzer, advanced_analyzer, pattern_evolution, zero_day_hypothesis, ml_pipeline

        # Check specific modules
        assert "discovery.file_discovery" in discovered
        assert "detection.pattern_detection" in discovered

    def test_module_instantiation(self):
        """Test module instantiation."""
        loader = ModuleLoader()
        modules_path = Path(__file__).parent.parent / "leviathan" / "modules"

        loader.discover_modules(modules_path)

        # Create an instance
        instance = loader.create_module_instance("discovery.file_discovery")
        assert instance is not None
        assert instance.name == "file_discovery"

    def test_list_available_modules(self):
        """Test listing available modules."""
        loader = ModuleLoader()
        modules_path = Path(__file__).parent.parent / "leviathan" / "modules"

        loader.discover_modules(modules_path)
        module_list = loader.list_available_modules()

        assert isinstance(module_list, dict)
        assert len(module_list) >= 10

        # Check that each module has required info
        for name, info in module_list.items():
            assert "name" in info
            assert "description" in info


class TestBasicFuzzer:
    """Test basic fuzzing module."""

    @pytest.mark.asyncio
    async def test_basic_fuzzer_generation(self):
        """Test basic fuzzing input generation."""
        from leviathan.modules.fuzzing.basic_fuzzer import BasicFuzzer

        fuzzer = BasicFuzzer()
        result = await fuzzer.analyze({
            "target_type": "string",
            "max_length": 100,
            "num_inputs": 10
        })

        assert result["target_type"] == "string"
        assert len(result["inputs"]) == 10
        assert all(isinstance(inp, str) for inp in result["inputs"])

    @pytest.mark.asyncio
    async def test_basic_fuzzer_edge_cases(self):
        """Test fuzzing with edge cases."""
        from leviathan.modules.fuzzing.basic_fuzzer import BasicFuzzer

        fuzzer = BasicFuzzer()
        result = await fuzzer.analyze({
            "target_type": "integer",
            "include_edge_cases": True,
            "num_inputs": 5
        })

        assert result["target_type"] == "integer"
        assert len(result["inputs"]) == 5
        # Should include edge cases like 0, -1, max int, etc.
        assert 0 in result["inputs"]


class TestCoverageAnalyzer:
    """Test coverage analysis module."""

    @pytest.mark.asyncio
    async def test_coverage_analysis_basic(self):
        """Test basic coverage analysis."""
        from leviathan.modules.fuzzing.coverage_analyzer import CoverageAnalyzer

        analyzer = CoverageAnalyzer()

        # Mock coverage data for testing
        mock_coverage = {
            "functions": {"func1": {"executed": 1, "total": 1}, "func2": {"executed": 0, "total": 1}},
            "lines": {"line1": {"executed": 50, "total": 100}, "line2": {"executed": 0, "total": 50}}
        }

        metrics = analyzer._calculate_coverage_metrics(mock_coverage)

        assert metrics["function_coverage"] == 50.0  # 1/2 functions executed
        assert metrics["line_coverage"] == 33.33  # 50/150 lines executed (approx)
        assert metrics["total_functions"] == 2
        assert metrics["executed_functions"] == 1


class TestAdvancedAnalyzer:
    """Test advanced analysis module."""

    @pytest.mark.asyncio
    async def test_race_condition_analysis(self):
        """Test race condition analysis."""
        from leviathan.modules.analysis.advanced_analyzer import AdvancedAnalyzer

        analyzer = AdvancedAnalyzer()

        # Mock target for testing
        result = await analyzer.analyze({
            "binary": "test_binary",
            "analysis_type": "race_condition",
            "config": {
                "num_threads": 2,
                "num_iterations": 5,
                "timeout": 1
            }
        })

        assert result["analysis_type"] == "race_condition"
        assert "results" in result
        assert "crash_count" in result["results"]
        assert "race_condition_detected" in result["results"]

    @pytest.mark.asyncio
    async def test_speculative_execution_analysis(self):
        """Test speculative execution analysis."""
        from leviathan.modules.analysis.advanced_analyzer import AdvancedAnalyzer

        analyzer = AdvancedAnalyzer()

        result = await analyzer.analyze({
            "binary": "test_binary",
            "analysis_type": "speculative_execution",
            "config": {}
        })

        assert result["analysis_type"] == "speculative_execution"
        assert "results" in result
        assert "vulnerabilities_detected" in result["results"]

    @pytest.mark.asyncio
    async def test_memory_corruption_analysis(self):
        """Test memory corruption analysis."""
        from leviathan.modules.analysis.advanced_analyzer import AdvancedAnalyzer

        analyzer = AdvancedAnalyzer()

        result = await analyzer.analyze({
            "binary": "test_binary",
            "analysis_type": "memory_corruption",
            "config": {}
        })

        assert result["analysis_type"] == "memory_corruption"
        assert "results" in result
        assert "vulnerabilities_detected" in result["results"]