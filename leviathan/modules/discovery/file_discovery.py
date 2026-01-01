"""File system discovery module for Leviathan."""

import os
import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional
from fnmatch import fnmatch

from ...core.module_base import AnalysisModule
from ...utils.logging import get_logger


class FileDiscoveryModule(AnalysisModule):
    """Module for discovering files and directories in target paths."""

    def __init__(self, config=None):
        super().__init__(config)
        self.logger = get_logger("leviathan.modules.discovery.file")

    @property
    def name(self) -> str:
        return "file_discovery"

    @property
    def description(self) -> str:
        return "Discovers files and directories in target paths with filtering"

    async def analyze(self, target: Any) -> Dict[str, Any]:
        """Analyze target path for files and directories."""
        if not isinstance(target, (str, Path)):
            raise ValueError("Target must be a path string or Path object")

        target_path = Path(target)
        if not target_path.exists():
            raise FileNotFoundError(f"Target path does not exist: {target_path}")

        # Get configuration
        max_depth = getattr(self.config, 'max_depth', 3) if self.config else 3
        include_patterns = getattr(self.config, 'include_patterns', ['*']) if self.config else ['*']
        exclude_patterns = getattr(self.config, 'exclude_patterns', []) if self.config else []
        follow_symlinks = getattr(self.config, 'follow_symlinks', False) if self.config else False

        self.logger.info(
            "Starting file discovery",
            target=str(target_path),
            max_depth=max_depth,
            include_patterns=include_patterns
        )

        # Perform discovery
        discovered_files = await self._discover_files(
            target_path,
            max_depth=max_depth,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns,
            follow_symlinks=follow_symlinks
        )

        # Analyze file types and sizes
        file_stats = self._analyze_file_stats(discovered_files)

        return {
            "target_path": str(target_path),
            "total_files": len(discovered_files),
            "file_stats": file_stats,
            "files": [str(f) for f in discovered_files[:100]],  # Limit for output
            "truncated": len(discovered_files) > 100
        }

    async def _discover_files(
        self,
        root_path: Path,
        max_depth: int = 3,
        include_patterns: List[str] = None,
        exclude_patterns: List[str] = None,
        follow_symlinks: bool = False
    ) -> List[Path]:
        """Recursively discover files matching patterns."""
        if include_patterns is None:
            include_patterns = ['*']
        if exclude_patterns is None:
            exclude_patterns = []

        discovered = []

        try:
            # Use asyncio.to_thread for I/O operations
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                self._sync_discover_files,
                root_path,
                max_depth,
                include_patterns,
                exclude_patterns,
                follow_symlinks
            )
            discovered = result
        except Exception as e:
            self.logger.error("File discovery failed", error=str(e))

        return discovered

    def _sync_discover_files(
        self,
        root_path: Path,
        max_depth: int,
        include_patterns: List[str],
        exclude_patterns: List[str],
        follow_symlinks: bool
    ) -> List[Path]:
        """Synchronous file discovery implementation."""
        discovered = []

        def should_include(path: Path) -> bool:
            """Check if path should be included based on patterns."""
            path_str = str(path)

            # Check exclude patterns first
            for pattern in exclude_patterns:
                if fnmatch(path_str, pattern):
                    return False

            # Check include patterns
            for pattern in include_patterns:
                if fnmatch(path_str, pattern):
                    return True

            return False

        def walk_directory(current_path: Path, current_depth: int):
            """Recursively walk directory tree."""
            if current_depth > max_depth:
                return

            try:
                for item in current_path.iterdir():
                    # Handle symlinks
                    if item.is_symlink() and not follow_symlinks:
                        continue

                    # Check if item should be included
                    if should_include(item):
                        discovered.append(item)

                    # Recurse into directories
                    if item.is_dir() and not item.is_symlink():
                        walk_directory(item, current_depth + 1)

            except (PermissionError, OSError) as e:
                self.logger.warning(
                    "Access denied to directory",
                    path=str(current_path),
                    error=str(e)
                )

        walk_directory(root_path, 0)
        return discovered

    def _analyze_file_stats(self, files: List[Path]) -> Dict[str, Any]:
        """Analyze statistics of discovered files."""
        stats = {
            "by_extension": {},
            "by_size_ranges": {
                "small": 0,    # < 1KB
                "medium": 0,   # 1KB - 1MB
                "large": 0,    # 1MB - 100MB
                "huge": 0      # > 100MB
            },
            "total_size": 0,
            "executable_files": 0,
            "hidden_files": 0
        }

        for file_path in files:
            try:
                stat = file_path.stat()

                # Size analysis
                size = stat.st_size
                stats["total_size"] += size

                if size < 1024:
                    stats["by_size_ranges"]["small"] += 1
                elif size < 1024 * 1024:
                    stats["by_size_ranges"]["medium"] += 1
                elif size < 100 * 1024 * 1024:
                    stats["by_size_ranges"]["large"] += 1
                else:
                    stats["by_size_ranges"]["huge"] += 1

                # Extension analysis
                ext = file_path.suffix.lower()
                if ext:
                    stats["by_extension"][ext] = stats["by_extension"].get(ext, 0) + 1

                # Special file types
                if os.access(file_path, os.X_OK):
                    stats["executable_files"] += 1

                if file_path.name.startswith('.'):
                    stats["hidden_files"] += 1

            except (OSError, PermissionError):
                # Skip files we can't stat
                continue

        return stats