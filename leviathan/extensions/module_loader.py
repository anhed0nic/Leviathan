"""Module loading and management for Leviathan."""

import importlib
import inspect
from typing import Dict, List, Any, Optional, Type
from pathlib import Path

from ..core.module_base import BaseModule
from ..utils.logging import get_logger
from ..utils.exceptions import ModuleError


class ModuleLoader:
    """Handles dynamic loading and management of Leviathan modules."""

    def __init__(self):
        self.logger = get_logger("leviathan.modules.loader")
        self.loaded_modules: Dict[str, Type[BaseModule]] = {}
        self.module_instances: Dict[str, BaseModule] = {}

    def discover_modules(self, modules_path: Path) -> Dict[str, Type[BaseModule]]:
        """Discover and load all available modules from the modules directory."""
        discovered = {}

        if not modules_path.exists():
            self.logger.warning("Modules path does not exist", path=str(modules_path))
            return discovered

        # Iterate through module categories
        for category_dir in modules_path.iterdir():
            if not category_dir.is_dir() or category_dir.name.startswith('_'):
                continue

            category_name = category_dir.name
            self.logger.info("Discovering modules in category", category=category_name)

            # Iterate through module files
            for module_file in category_dir.glob("*.py"):
                if module_file.name.startswith('_'):
                    continue

                try:
                    module_name = module_file.stem
                    full_module_name = f"leviathan.modules.{category_name}.{module_name}"

                    # Import the module
                    spec = importlib.util.spec_from_file_location(full_module_name, module_file)
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)

                        # Find module classes
                        for name, obj in inspect.getmembers(module):
                            if (inspect.isclass(obj) and
                                issubclass(obj, BaseModule) and
                                obj != BaseModule):

                                # Register the module
                                registered_name = f"{category_name}.{module_name}"
                                discovered[registered_name] = obj
                                self.logger.debug(
                                    "Discovered module",
                                    name=registered_name,
                                    class_name=name
                                )

                except Exception as e:
                    self.logger.error(
                        "Failed to load module",
                        file=str(module_file),
                        error=str(e)
                    )

        self.loaded_modules.update(discovered)
        self.logger.info("Module discovery complete", total_modules=len(discovered))
        return discovered

    def get_module_class(self, module_name: str) -> Optional[Type[BaseModule]]:
        """Get a module class by name."""
        return self.loaded_modules.get(module_name)

    def create_module_instance(
        self,
        module_name: str,
        config: Optional[Any] = None
    ) -> Optional[BaseModule]:
        """Create an instance of a module."""
        module_class = self.get_module_class(module_name)
        if not module_class:
            self.logger.error("Module not found", module=module_name)
            return None

        try:
            instance = module_class(config)
            self.module_instances[module_name] = instance
            self.logger.debug("Module instance created", module=module_name)
            return instance
        except Exception as e:
            self.logger.error(
                "Failed to create module instance",
                module=module_name,
                error=str(e)
            )
            return None

    def get_module_instance(self, module_name: str) -> Optional[BaseModule]:
        """Get an existing module instance."""
        return self.module_instances.get(module_name)

    def list_available_modules(self) -> Dict[str, Dict[str, Any]]:
        """List all available modules with metadata."""
        modules_info = {}

        for name, module_class in self.loaded_modules.items():
            try:
                # Create a temporary instance to get metadata
                temp_instance = module_class()
                modules_info[name] = {
                    "name": temp_instance.name,
                    "description": temp_instance.description,
                    "class": module_class.__name__,
                    "module": module_class.__module__
                }
            except Exception as e:
                self.logger.warning(
                    "Could not get module info",
                    module=name,
                    error=str(e)
                )
                modules_info[name] = {
                    "name": name,
                    "description": "Unknown",
                    "class": module_class.__name__,
                    "error": str(e)
                }

        return modules_info

    def unload_module(self, module_name: str) -> bool:
        """Unload a module instance."""
        if module_name in self.module_instances:
            instance = self.module_instances[module_name]
            try:
                # Cleanup if needed
                if hasattr(instance, 'cleanup'):
                    import asyncio
                    asyncio.create_task(instance.cleanup())
            except Exception as e:
                self.logger.warning(
                    "Module cleanup failed",
                    module=module_name,
                    error=str(e)
                )

            del self.module_instances[module_name]
            self.logger.debug("Module instance unloaded", module=module_name)
            return True

        return False

    def reload_module(self, module_name: str) -> Optional[BaseModule]:
        """Reload a module (useful for development)."""
        if module_name in self.loaded_modules:
            # Unload existing instance
            self.unload_module(module_name)

            # Re-import the module
            module_class = self.loaded_modules[module_name]
            module_parts = module_class.__module__.split('.')
            if len(module_parts) >= 3:
                category = module_parts[-2]
                module_file = module_parts[-1]

                # Try to reload from file system
                modules_path = Path(__file__).parent
                module_file_path = modules_path / category / f"{module_file}.py"

                if module_file_path.exists():
                    try:
                        # Remove from sys.modules to force reload
                        import sys
                        if module_class.__module__ in sys.modules:
                            del sys.modules[module_class.__module__]

                        # Re-discover
                        self.discover_modules(modules_path)
                        return self.create_module_instance(module_name)
                    except Exception as e:
                        self.logger.error(
                            "Module reload failed",
                            module=module_name,
                            error=str(e)
                        )

        return None