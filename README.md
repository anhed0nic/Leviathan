# Leviathan Framework (Public-Safe Overview)

A modular, extensible security automation and intelligent analysis framework. It orchestrates multi-phase software and binary analysis: discovery, detection, fuzzing, ML-assisted pattern evolution, exploitation pipeline simulation, validation, and structured reporting. It emphasizes adaptive intelligence (pattern evolution + ML inference), and production-grade orchestration primitives (async IO, caching, connection pooling, distributed runners).

---
## Key Capabilities (Public-Safe Summary)

- Modular pipeline: Discovery → Detection → Coverage & Fuzzing → Analysis → (Simulated) Exploitation → Reporting & Validation.
- Adaptive ML integration for pattern evolution and zero-day hypothesis generation (pluggable models).
- Differential & edge-guided fuzzing with semantic eBPF modeling hooks.
- Structured orchestration: async execution, caching, connection pools, model lifecycle management.
- Advanced analysis: race condition scanning, speculative execution surfaces, post-quantum considerations (conceptual analyzers).
- Extensible CLI for automation, research, deployment, dashboards, and server/control routines.
- Clean extension points for adding:
  - New detection engines
  - Fuzzing strategies
  - Coverage heuristics
  - ML inference providers
  - Exploit simulation modules
  - Reporting backends

---
Preject TBR Mid-September 2025

## Installation

### Prerequisites
- Python 3.8 or higher
- pip

### Install from source
```bash
git clone https://github.com/anhed0nic/Leviathan.git
cd Leviathan
pip install -e .
```

### Development installation
```bash
pip install -e .[dev]
pre-commit install
```

## Usage

### Basic Analysis
```bash
leviathan analyze /path/to/target
```

### List available modules
```bash
leviathan modules
```

### Start metrics server
```bash
leviathan serve --port 8000
```

### Configuration
Copy `.env.example` to `.env` and modify settings as needed.

## Development

### Running tests
```bash
pytest
```

### Code quality
```bash
pre-commit run --all-files
```

### Building documentation
```bash
mkdocs build
```

## Architecture

Leviathan follows a modular pipeline architecture:

- **Core Framework**: Pipeline orchestration, async execution, configuration
- **Modules**: Pluggable analysis components for each phase
- **ML Integration**: Adaptive pattern evolution and inference
- **CLI**: Command-line interface for automation
- **Extensions**: Plugin system for custom components

See `PLAN.md` for detailed implementation roadmap.
