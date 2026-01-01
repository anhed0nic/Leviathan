"""Signature-based detection module for Leviathan."""

import hashlib
import re
from typing import List, Dict, Any, Optional
from pathlib import Path

from ...core.module_base import AnalysisModule
from ...utils.logging import get_logger


class SignatureDetectionModule(AnalysisModule):
    """Module for detecting known malicious patterns and signatures."""

    # Known malicious signatures (simplified examples)
    DEFAULT_SIGNATURES = {
        "webshell_php": {
            "signatures": [
                "eval($_POST[",
                "system($_GET[",
                "exec($_REQUEST[",
                "passthru($_SERVER[",
                "shell_exec($_FILES[",
            ],
            "file_types": [".php"],
            "severity": "critical",
            "description": "PHP webshell signatures"
        },
        "malicious_javascript": {
            "signatures": [
                "eval(atob(",
                "document.write(unescape(",
                "fromCharCode.*eval",
                "Function.*apply.*this",
            ],
            "file_types": [".js", ".html", ".htm"],
            "severity": "high",
            "description": "Malicious JavaScript patterns"
        },
        "suspicious_executables": {
            "signatures": [
                b'\x4D\x5A',  # MZ header (Windows PE)
                b'\x7F\x45\x4C\x46',  # ELF header
                b'\xCF\xFA\xED\xFE',  # Mach-O header
            ],
            "file_types": [],  # Check all files
            "severity": "medium",
            "description": "Executable file signatures"
        },
        "backdoor_indicators": {
            "signatures": [
                "nc -e /bin/sh",
                "bash -i >& /dev/tcp/",
                "/dev/tcp/",
                "reverse shell",
                "bind shell",
            ],
            "file_types": [".sh", ".py", ".pl", ".rb"],
            "severity": "critical",
            "description": "Backdoor and reverse shell indicators"
        }
    }

    def __init__(self, config=None):
        super().__init__(config)
        self.logger = get_logger("leviathan.modules.detection.signature")
        self.signatures = getattr(self.config, 'signatures', self.DEFAULT_SIGNATURES) if self.config else self.DEFAULT_SIGNATURES

    @property
    def name(self) -> str:
        return "signature_detection"

    @property
    def description(self) -> str:
        return "Detects known malicious patterns and file signatures"

    async def analyze(self, target: Any) -> Dict[str, Any]:
        """Analyze target for known signatures."""
        if isinstance(target, str):
            target_path = Path(target)
        elif isinstance(target, Path):
            target_path = target
        else:
            raise ValueError("Target must be a path string or Path object")

        if not target_path.exists():
            raise FileNotFoundError(f"Target path does not exist: {target_path}")

        # Get configuration
        max_file_size = getattr(self.config, 'max_file_size', 50 * 1024 * 1024) if self.config else 50 * 1024 * 1024  # 50MB
        scan_all_files = getattr(self.config, 'scan_all_files', False) if self.config else False

        self.logger.info(
            "Starting signature detection",
            target=str(target_path),
            max_file_size=max_file_size
        )

        # Find files to scan
        files_to_scan = self._find_files(target_path, max_file_size, scan_all_files)

        # Scan files
        detections = []
        for file_path in files_to_scan:
            file_detections = await self._scan_file(file_path)
            detections.extend(file_detections)

        # Summarize results
        summary = self._summarize_detections(detections)

        return {
            "target_path": str(target_path),
            "files_scanned": len(files_to_scan),
            "total_detections": len(detections),
            "detections": detections,
            "summary": summary
        }

    def _find_files(self, root_path: Path, max_size: int, scan_all: bool) -> List[Path]:
        """Find files to scan."""
        files = []

        try:
            if scan_all:
                # Scan all files
                for file_path in root_path.rglob("*"):
                    if file_path.is_file():
                        try:
                            if file_path.stat().st_size <= max_size:
                                files.append(file_path)
                        except OSError:
                            continue
            else:
                # Scan files that match signature file types
                relevant_extensions = set()
                for sig_config in self.signatures.values():
                    relevant_extensions.update(sig_config["file_types"])

                for ext in relevant_extensions:
                    for file_path in root_path.rglob(f"*{ext}"):
                        if file_path.is_file():
                            try:
                                if file_path.stat().st_size <= max_size:
                                    files.append(file_path)
                            except OSError:
                                continue

        except Exception as e:
            self.logger.error("File discovery failed", error=str(e))

        return files

    async def _scan_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Scan a single file for signatures."""
        detections = []

        try:
            # Read file content
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                is_text = True
            except UnicodeDecodeError:
                # Binary file
                content = file_path.read_bytes()
                is_text = False

            # Calculate file hash
            if is_text:
                file_hash = hashlib.md5(content.encode()).hexdigest()
            else:
                file_hash = hashlib.md5(content).hexdigest()

            # Check each signature type
            for sig_type, sig_config in self.signatures.items():
                severity = sig_config.get("severity", "unknown")
                description = sig_config.get("description", "Signature match")
                signatures = sig_config.get("signatures", [])

                # Check file type filter
                file_types = sig_config.get("file_types", [])
                if file_types and file_path.suffix.lower() not in file_types:
                    continue

                for signature in signatures:
                    if self._check_signature(content, signature, is_text):
                        detections.append({
                            "file": str(file_path),
                            "signature_type": sig_type,
                            "severity": severity,
                            "description": description,
                            "signature": signature if isinstance(signature, str) else signature.hex(),
                            "file_hash": file_hash,
                            "is_binary": not is_text
                        })

        except (PermissionError, OSError) as e:
            self.logger.debug(
                "Could not scan file",
                file=str(file_path),
                error=str(e)
            )

        return detections

    def _check_signature(self, content: Any, signature: Any, is_text: bool) -> bool:
        """Check if signature matches content."""
        if is_text and isinstance(signature, str):
            # Text signature in text file
            return signature in content
        elif not is_text and isinstance(signature, bytes):
            # Binary signature in binary file
            return signature in content
        elif not is_text and isinstance(signature, str):
            # Text signature in binary file (convert to bytes)
            return signature.encode() in content
        else:
            # Binary signature in text file (unlikely but handle)
            return False

    def _summarize_detections(self, detections: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create a summary of detections."""
        summary = {
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
            "by_type": {},
            "by_file": {},
            "total_files_affected": len(set(d["file"] for d in detections)),
            "binary_files_detected": sum(1 for d in detections if d["is_binary"])
        }

        for detection in detections:
            # Count by severity
            severity = detection["severity"]
            summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1

            # Count by type
            sig_type = detection["signature_type"]
            summary["by_type"][sig_type] = summary["by_type"].get(sig_type, 0) + 1

            # Count by file
            file_path = detection["file"]
            summary["by_file"][file_path] = summary["by_file"].get(file_path, 0) + 1

        return summary