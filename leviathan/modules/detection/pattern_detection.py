"""Pattern-based vulnerability detection module for Leviathan."""

import re
import hashlib
from typing import List, Dict, Any, Optional, Pattern
from pathlib import Path

from ...core.module_base import AnalysisModule
from ...utils.logging import get_logger


class PatternDetectionModule(AnalysisModule):
    """Module for detecting vulnerabilities using pattern matching."""

    # Common vulnerability patterns
    DEFAULT_PATTERNS = {
        "hardcoded_secrets": {
            "patterns": [
                r'password\s*=\s*["\'][^"\']*["\']',
                r'secret\s*=\s*["\'][^"\']*["\']',
                r'api_key\s*=\s*["\'][^"\']*["\']',
                r'token\s*=\s*["\'][^"\']*["\']',
            ],
            "severity": "high",
            "description": "Potential hardcoded secrets or credentials"
        },
        "sql_injection": {
            "patterns": [
                r'(\'|").*?(SELECT|INSERT|UPDATE|DELETE).*?\1',
                r'(\'|").*?(UNION|DROP|ALTER).*?\1',
                r'(\'|").*?--.*?(\'|")',
            ],
            "severity": "critical",
            "description": "Potential SQL injection vulnerabilities"
        },
        "command_injection": {
            "patterns": [
                r'(os\.system|subprocess\.call|subprocess\.run|exec|eval)\s*\(',
                r'`.*?`',
                r'shell\s*=\s*True',
            ],
            "severity": "critical",
            "description": "Potential command injection vulnerabilities"
        },
        "weak_crypto": {
            "patterns": [
                r'(md5|sha1)\s*\(',
                r'des\s*\(',
                r'rc4\s*\(',
            ],
            "severity": "medium",
            "description": "Use of weak cryptographic algorithms"
        },
        "debug_enabled": {
            "patterns": [
                r'debug\s*=\s*True',
                r'DEBUG\s*=\s*True',
                r'setattr.*debug.*True',
            ],
            "severity": "low",
            "description": "Debug mode enabled in production"
        }
    }

    def __init__(self, config=None):
        super().__init__(config)
        self.logger = get_logger("leviathan.modules.detection.pattern")
        self.compiled_patterns = self._compile_patterns()

    @property
    def name(self) -> str:
        return "pattern_detection"

    @property
    def description(self) -> str:
        return "Detects vulnerabilities using pattern matching on source code and files"

    async def analyze(self, target: Any) -> Dict[str, Any]:
        """Analyze target for pattern-based vulnerabilities."""
        if isinstance(target, str):
            target_path = Path(target)
        elif isinstance(target, Path):
            target_path = target
        else:
            raise ValueError("Target must be a path string or Path object")

        if not target_path.exists():
            raise FileNotFoundError(f"Target path does not exist: {target_path}")

        # Get configuration
        file_extensions = getattr(self.config, 'file_extensions', ['.py', '.js', '.java', '.cpp', '.c', '.php', '.rb']) if self.config else ['.py', '.js', '.java', '.cpp', '.c', '.php', '.rb']
        max_file_size = getattr(self.config, 'max_file_size', 10 * 1024 * 1024) if self.config else 10 * 1024 * 1024  # 10MB

        self.logger.info(
            "Starting pattern detection",
            target=str(target_path),
            extensions=file_extensions
        )

        # Find files to analyze
        files_to_analyze = self._find_files(target_path, file_extensions, max_file_size)

        # Analyze files
        findings = []
        for file_path in files_to_analyze:
            file_findings = await self._analyze_file(file_path)
            findings.extend(file_findings)

        # Summarize results
        summary = self._summarize_findings(findings)

        return {
            "target_path": str(target_path),
            "files_analyzed": len(files_to_analyze),
            "total_findings": len(findings),
            "findings": findings,
            "summary": summary
        }

    def _compile_patterns(self) -> Dict[str, List[Pattern]]:
        """Compile regex patterns for better performance."""
        compiled = {}
        patterns = getattr(self.config, 'patterns', self.DEFAULT_PATTERNS) if self.config else self.DEFAULT_PATTERNS

        for vuln_type, vuln_config in patterns.items():
            compiled[vuln_type] = []
            for pattern in vuln_config["patterns"]:
                try:
                    compiled[vuln_type].append(re.compile(pattern, re.IGNORECASE | re.MULTILINE))
                except re.error as e:
                    self.logger.warning(
                        "Failed to compile pattern",
                        pattern=pattern,
                        error=str(e)
                    )

        return compiled

    def _find_files(self, root_path: Path, extensions: List[str], max_size: int) -> List[Path]:
        """Find files to analyze based on extensions and size."""
        files = []

        try:
            for ext in extensions:
                for file_path in root_path.rglob(f"*{ext}"):
                    if file_path.is_file():
                        try:
                            if file_path.stat().st_size <= max_size:
                                files.append(file_path)
                        except OSError:
                            continue  # Skip files we can't stat
        except Exception as e:
            self.logger.error("File discovery failed", error=str(e))

        return files

    async def _analyze_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Analyze a single file for vulnerabilities."""
        findings = []

        try:
            # Read file content
            content = file_path.read_text(encoding='utf-8', errors='ignore')

            # Skip empty files
            if not content.strip():
                return findings

            # Calculate file hash for uniqueness
            file_hash = hashlib.md5(content.encode()).hexdigest()

            # Check each pattern type
            for vuln_type, patterns in self.compiled_patterns.items():
                vuln_config = self.DEFAULT_PATTERNS.get(vuln_type, {})
                severity = vuln_config.get("severity", "unknown")
                description = vuln_config.get("description", "Pattern match")

                for pattern in patterns:
                    matches = pattern.findall(content)
                    if matches:
                        # Create finding for each match
                        for match in matches[:10]:  # Limit matches per file
                            findings.append({
                                "file": str(file_path),
                                "line": self._find_line_number(content, match),
                                "vulnerability_type": vuln_type,
                                "severity": severity,
                                "description": description,
                                "match": match[:100] if len(match) > 100 else match,  # Truncate long matches
                                "file_hash": file_hash
                            })

        except (UnicodeDecodeError, PermissionError, OSError) as e:
            self.logger.debug(
                "Could not analyze file",
                file=str(file_path),
                error=str(e)
            )

        return findings

    def _find_line_number(self, content: str, match: str) -> Optional[int]:
        """Find the line number of a match in content."""
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            if match in line:
                return i
        return None

    def _summarize_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create a summary of findings."""
        summary = {
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
            "by_type": {},
            "by_file": {},
            "total_files_affected": len(set(f["file"] for f in findings))
        }

        for finding in findings:
            # Count by severity
            severity = finding["severity"]
            summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1

            # Count by type
            vuln_type = finding["vulnerability_type"]
            summary["by_type"][vuln_type] = summary["by_type"].get(vuln_type, 0) + 1

            # Count by file
            file_path = finding["file"]
            summary["by_file"][file_path] = summary["by_file"].get(file_path, 0) + 1

        return summary