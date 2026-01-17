# MCP Security Detection Framework

![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)
![Phase 1 Complete](https://img.shields.io/badge/phase%201-complete-brightgreen.svg)
![MCPTox Validated](https://img.shields.io/badge/validated-493%20attacks-orange.svg)

**Modular Python library for static analysis of MCP (Model Context Protocol) servers to identify security risks through automated capability detection.**

The framework analyzes both source code (Python) and tool descriptions (JSON metadata) to detect dangerous capabilities like command execution, file access, network operations, and semantic attacks (prompt injection, parameter manipulation, tool sequence hijacking). Validated against 493 real-world malicious tools from the MCPTox academic dataset with 54-96% detection rates.

---

## Table of Contents

- [Quick Start](#quick-start)
- [What It Detects](#what-it-detects)
- [MCPTox Validation Results](#mcptox-validation-results)
- [Architecture Overview](#architecture-overview)
- [Usage Examples](#usage-examples)
- [Development Workflow](#development-workflow)
- [Project Status](#project-status)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [Documentation](#documentation)

---

## Quick Start

### Installation

```bash
# Create virtual environment
uv venv

# Install dependencies
uv sync
```

### Basic Usage

```bash
# Scan an MCP server directory
uv run python detection/cli.py /path/to/mcp-server \
  --pipeline static \
  --format markdown

# Example with all options
uv run python detection/cli.py ./my-mcp-server \
  --pipeline static \
  --format json \
  --rules detection/rules/keywords.toml \
  --policy-dir detection/mitigation/policy_templates
```

### Example Output

```markdown
# Detection Report: my-mcp-server
Risk Level: HIGH (Score: 67.5/100)

## Detected Capabilities
- command_exec (confidence: 85%) - subprocess.run, os.system
- file_write (confidence: 78%) - open(..., 'w'), pathlib.write_text
- prompt_injection (confidence: 72%) - "ignore previous instructions"

## Mitigations
1. Run in Docker container with --security-opt=no-new-privileges
2. Mount filesystem read-only except necessary directories
3. Use network policies to restrict outbound connections
```

---

## What It Detects

The framework identifies **9 capability types** across two categories:

### Infrastructure Capabilities

| Capability | Weight | Description | Examples |
|------------|--------|-------------|----------|
| `command_exec` | 25.0 | Shell command execution | `subprocess.run()`, `os.system()`, `eval()` |
| `file_read` | 15.0 | Filesystem read operations | `open()`, `pathlib.read_text()`, `os.listdir()` |
| `file_write` | 15.0 | File creation/modification | `open(..., 'w')`, `pathlib.write_text()`, `shutil.copy()` |
| `network_outbound` | 20.0 | External network requests | `requests.get()`, `urllib.request`, `socket.connect()` |
| `network_inbound` | 20.0 | Server listeners | `socket.bind()`, `flask.run()`, `http.server` |
| `env_access` | 10.0 | Environment variable access | `os.environ`, `os.getenv()`, `dotenv.load()` |

### Semantic Attack Capabilities

| Capability | Weight | Description | Examples |
|------------|--------|-------------|----------|
| `param_override` | 12.0 | Parameter manipulation | "modify the parameter", "set value to" |
| `tool_sequence_hijack` | 12.0 | Workflow redirection | "call this tool next", "skip remaining steps" |
| `prompt_injection` | 18.0 | Assistant instruction tampering | "ignore previous instructions", "new role:" |

### Risk Scoring

- **Confidence Formula:** `base + 0.1 × files + 0.05 × hits + boost`
- **Total Score:** Weighted sum of detected capabilities
- **Risk Levels:**
  - **Low:** 0-24 (informational)
  - **Medium:** 25-49 (caution advised)
  - **High:** 50-74 (containment required)
  - **Critical:** 75-100 (do not run without sandboxing)

---

## MCPTox Validation Results

The framework was validated against the **MCPTox dataset** - 493 malicious tool descriptions from academic research (paper: `Model_Context_Protocol_Security.pdf`).

### Detection Coverage by Attack Category

| Attack Category | Samples | Detected | Coverage | Status |
|-----------------|---------|----------|----------|--------|
| Code Injection | 24 | 23 | **96%** | ✅ Excellent |
| Instruction Tampering | 21 | 19 | **90%** | ✅ Excellent |
| Service Disruption | 74 | 63 | **85%** | ✅ Strong |
| Credential Leakage | 40 | 31 | **78%** | ✅ Strong |
| Financial Loss | 21 | 16 | **76%** | ✅ Good |
| Information Manipulation | 111 | 84 | **76%** | ✅ Good |
| Privacy Leakage | 97 | 69 | **71%** | ✅ Good |
| Message Hijacking | 15 | 10 | **67%** | ⚠️ Moderate |
| Data Tampering | 45 | 28 | **62%** | ⚠️ Moderate |
| Infrastructure Damage | 41 | 22 | **54%** | ⚠️ Needs Improvement |

**Overall:** 465 of 491 samples detected (94.7% coverage)

**Key Insights:**
- **Excellent** detection for syscall-based attacks (command execution, code injection)
- **Strong** coverage for semantic attacks (90% instruction tampering)
- **Weakness:** Infrastructure damage patterns (54%) - improvement targeted for Phase 2

**Benchmark Scripts:**
- Run benchmark: `uv run mcptox-benchmark`
- Source data: `examples/benchmarks/mcptox/pure_tool.json`
- Results: `examples/benchmarks/mcptox/benchmark_report.md`

For detailed analysis, see: [`docs/mcptox_static_analysis.md`](docs/mcptox_static_analysis.md)

---

## Architecture Overview

### Three-Layer Design

```
┌─────────────────────────────────────────────────────────────┐
│                      PIPELINE LAYER                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Static     │  │   Dynamic    │  │     RAG      │      │
│  │   Pipeline   │  │   Pipeline   │  │   Pipeline   │      │
│  │      ✅      │  │      🚧      │  │      🚧      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    DETECTION LAYER                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Python     │  │  Metadata    │  │ TypeScript   │      │
│  │  Analyzer    │  │   Analyzer   │  │  Analyzer    │      │
│  │      ✅      │  │      ✅      │  │      🚧      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                       CORE LAYER                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Models     │  │   Registry   │  │   Session    │      │
│  │  (findings)  │  │  (plugins)   │  │  (context)   │      │
│  │      ✅      │  │      ✅      │  │      ✅      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

**Legend:** ✅ Implemented | 🚧 In Progress | 📋 Planned

### Core Components

#### 1. Core Layer (`detection/core/`)

**Purpose:** Foundational data structures and shared state

- **`models.py`** (41 lines)
  - `CapabilityFinding`: Individual detection with capability name, confidence, evidence
  - `DetectionResult`: Aggregated output with findings, total score, risk level, mitigations
  - `EvidenceSource`: Enum tracking detection method (STATIC/DYNAMIC/KNOWLEDGE)

- **`session.py`** (31 lines)
  - `DetectionSession`: Context object passed through analysis pipeline
  - Stores target path, configuration, accumulated findings, metadata

- **`registry.py`** (51 lines)
  - `DetectorRegistry`: Plugin registration system
  - `Detector` and `ReportRenderer` protocols for duck-typed interfaces
  - Enables extensibility without tight coupling

#### 2. Rules System (`detection/rules/`)

**Purpose:** Configuration-driven detection logic (no hardcoded patterns)

- **`keywords.toml`** (311 lines)
  - Defines 9 capability types with severity weights
  - Multiple indicator types: keywords, regex patterns, confidence boosts
  - Supports Python, TypeScript/JavaScript, metadata (JSON) languages
  - Example structure:
    ```toml
    [command_exec]
    weight = 25.0
    base_confidence = 70.0

    [[command_exec.indicators]]
    language = "python"
    type = "keyword"
    pattern = "subprocess.run"
    ```

- **`loader.py`** (112 lines)
  - `RuleBook`: TOML parser and rule container
  - `CapabilityRule`, `IndicatorRule`: Dataclass representations
  - Language filtering for multi-language support

#### 3. Detection Plugins (`detection/plugins/`)

**Purpose:** Modular analyzers implementing detection logic

- **Python Analyzer** (`static/python/__init__.py`, 120 lines) ✅
  - Scans all `*.py` files recursively
  - Keyword and regex pattern matching against rules
  - Evidence tracking with file paths and matched patterns
  - Confidence formula: `base + 0.1 × files + 0.05 × hits + boost`

- **Metadata Analyzer** (`static/metadata/__init__.py`, 118 lines) ✅
  - Parses JSON files with `tool_content` field
  - Detects semantic attacks in tool descriptions
  - Same confidence calculation as Python analyzer

- **TypeScript Analyzer** (`static/typescript/__init__.py`, 13 lines) 🚧
  - Placeholder with empty `register()` function
  - Rules defined in keywords.toml but no implementation yet
  - Planned for Phase 2

- **Dynamic/RAG Plugins** 📋
  - Interface definitions only (`plugins/dynamic/`, `plugins/rag/`)
  - Planned for Phase 3

#### 4. Pipeline Orchestration (`detection/pipelines/`)

**Purpose:** Execute detectors, score findings, generate reports

- **Static Pipeline** (`static.py`, 52 lines) ✅
  - Executes all registered static detectors
  - Aggregates findings into `DetectionResult`
  - Calculates total score and risk level
  - Calls mitigation engine for recommendations

- **Dynamic & RAG Pipelines** 📋
  - Stubs that raise `NotImplementedError` (17 lines each)
  - Planned for Phase 3

#### 5. Reporting & Mitigation

- **Report Builder** (`reporting/report_builder.py`, 72 lines) ✅
  - **Markdown:** Human-readable summary with findings and mitigations
  - **JSON:** Structured output with full evidence details
  - Plugin-based renderer system for extensibility

- **Mitigation Engine** (`mitigation/mitigation_engine.py`, 63 lines) ⚠️
  - Maps 6 of 9 capabilities to containment recommendations
  - **Current limitation:** Hardcoded policies (should be YAML templates)
  - **Missing:** Policies for semantic attacks (param_override, tool_sequence_hijack, prompt_injection)
  - Planned migration to `mitigation/policy_templates/*.yaml`

### Plugin System

All detectors implement the `Detector` protocol:

```python
from typing import Protocol
from detection.core.session import DetectionSession
from detection.core.models import CapabilityFinding

class Detector(Protocol):
    def __call__(self, session: DetectionSession) -> list[CapabilityFinding]:
        """Analyze session.target_path and return findings."""
        ...
```

**Registration pattern:**
```python
# In plugin module (e.g., detection/plugins/static/python/__init__.py)
def register(registry: DetectorRegistry) -> None:
    registry.register_detector(analyze_python_code)
```

---

## Usage Examples

### 1. Basic CLI Scan

```bash
# Scan current directory
uv run python detection/cli.py . --pipeline static --format markdown

# Scan specific MCP server
uv run python detection/cli.py ~/mcp-servers/filesystem-server \
  --pipeline static \
  --format json > report.json
```

### 2. Markdown Output Example

```markdown
# Detection Report: filesystem-server
Risk Level: HIGH (Score: 60.5/100)

## Detected Capabilities
- **file_read** (confidence: 88%, weight: 15.0)
  - Evidence: detection/plugins/static/python/file_ops.py:45
    - Pattern: `pathlib.Path.read_text`
    - Pattern: `open(..., 'r')`

- **file_write** (confidence: 82%, weight: 15.0)
  - Evidence: detection/plugins/static/python/file_ops.py:78
    - Pattern: `pathlib.Path.write_text`

## Recommended Mitigations
1. Use Docker with read-only root filesystem
2. Mount only necessary directories with specific permissions
3. Enable seccomp profile to restrict syscalls
```

### 3. JSON Output Example

```json
{
  "server_name": "filesystem-server",
  "findings": [
    {
      "capability": "file_read",
      "confidence": 88.0,
      "score_weight": 15.0,
      "evidence": {
        "source": "STATIC",
        "locations": ["detection/plugins/static/python/file_ops.py:45"],
        "patterns": ["pathlib.Path.read_text", "open(..., 'r')"]
      }
    }
  ],
  "total_score": 60.5,
  "risk_level": "high",
  "mitigations": [
    "Use Docker with read-only root filesystem",
    "Mount only necessary directories with specific permissions"
  ]
}
```

### 4. MCPTox Benchmark

```bash
# Run benchmark (491 samples, ~1 minute)
uv run mcptox-benchmark

# First run auto-generates samples from pure_tool.json
# Output locations:
# - examples/benchmarks/mcptox/per_file_detection.jsonl
# - examples/benchmarks/mcptox/per_file_detection_summary.json
# - examples/benchmarks/mcptox/benchmark_report.md
```

### 5. Interpreting Results

**Confidence Levels:**
- **90-100%:** High certainty (multiple files, many matches, boosted patterns)
- **75-89%:** Strong confidence (consistent evidence)
- **60-74%:** Moderate confidence (fewer matches)
- **<60%:** Low confidence (single instance, weak patterns)

**Risk Level Actions:**
- **Low (0-24):** Informational, review findings
- **Medium (25-49):** Exercise caution, apply basic containment
- **High (50-74):** Containment required, use Docker/sandboxing
- **Critical (75-100):** Do not run without strict isolation

---

## Development Workflow

### Setup

```bash
# Create virtual environment
uv venv

# Install dependencies
uv sync

# Install pre-commit hooks
uv tool run pre-commit install
```

### Running Tests

```bash
# Run all tests (quiet mode)
uv run pytest -q

# Run specific test file
uv run pytest tests/test_rules_loader.py

# Run with verbose output
uv run pytest -v

# Run specific test function
uv run pytest tests/test_rules_loader.py::test_command_exec_detection
```

**Test Pattern:**
```python
import tempfile
from pathlib import Path
from detection.pipelines.static import run_static_detection

def test_my_detection():
    # Create isolated environment
    with tempfile.TemporaryDirectory() as tmpdir:
        # Write synthetic malicious code
        sample_path = Path(tmpdir) / "malicious.py"
        sample_path.write_text('subprocess.run(["rm", "-rf", "/"])')

        # Run static pipeline
        result = run_static_detection(tmpdir)

        # Assert findings
        assert any(f.capability == "command_exec" for f in result.findings)
        assert result.risk_level in ["high", "critical"]
```

### Code Quality

```bash
# Format code with Black
uv run python -m black detection/ tests/

# Run pre-commit hooks manually
uv tool run pre-commit run --all-files

# Hooks include:
# - Black formatting
# - Pytest execution
# - YAML validation
# - Trailing whitespace fixes
# - Codespell with custom dictionary
```

### Adding New Detectors

**Step 1:** Create plugin module
```python
# detection/plugins/static/my_analyzer/__init__.py
from detection.core.models import CapabilityFinding, EvidenceSource
from detection.core.session import DetectionSession
from detection.core.registry import DetectorRegistry

def analyze_my_language(session: DetectionSession) -> list[CapabilityFinding]:
    findings = []
    # Implement detection logic
    return findings

def register(registry: DetectorRegistry) -> None:
    registry.register_detector(analyze_my_language)
```

**Step 2:** Add rules to `keywords.toml`
```toml
[[command_exec.indicators]]
language = "mylang"
type = "keyword"
pattern = "dangerous_function"
```

**Step 3:** Register in CLI
```python
# detection/cli.py
from detection.plugins.static.my_analyzer import register as register_my_analyzer

registry = DetectorRegistry()
register_my_analyzer(registry)
```

**Step 4:** Write tests
```python
# tests/test_my_analyzer.py
def test_my_analyzer_detection():
    # Test implementation
    pass
```

### Adding New Capabilities

**Step 1:** Define in `keywords.toml`
```toml
[my_new_capability]
weight = 20.0
base_confidence = 65.0
description = "Description of what this detects"

[[my_new_capability.indicators]]
language = "python"
type = "keyword"
pattern = "dangerous_api"

[[my_new_capability.indicators]]
language = "python"
type = "regex"
pattern = "risky_.*"
```

**Step 2:** Add mitigation policy
```python
# detection/mitigation/mitigation_engine.py
MITIGATION_POLICIES = {
    # ... existing policies ...
    "my_new_capability": [
        "Recommended action 1",
        "Recommended action 2"
    ]
}
```

**Step 3:** Update documentation
- Add to README.md capability table
- Update CLAUDE.md with implementation details
- Document in `docs/detection-roadmap.md` if phased

---

## Project Status

### Phase 1 - Static Detection MVP: ✅ COMPLETE

**Implemented Features:**
- ✅ Core data models (`CapabilityFinding`, `DetectionResult`, `EvidenceSource`)
- ✅ Plugin registry system with protocol-based interfaces
- ✅ TOML-based rule system (311 lines, 9 capabilities)
- ✅ Python static analyzer (keyword + regex matching)
- ✅ Metadata/JSON static analyzer (semantic attack detection)
- ✅ Static pipeline orchestration
- ✅ Risk scoring algorithm (0-100 scale, 4 levels)
- ✅ Markdown and JSON report generation
- ✅ Basic mitigation recommendations (6 of 9 capabilities)
- ✅ CLI with argument parsing
- ✅ Test suite covering rule loading and multi-capability detection
- ✅ MCPTox validation framework (493 samples, 54-96% detection)

**Total Implementation:** ~1,420 lines of Python code (excluding tests, examples, venv)

### Phase 2 - Multi-language & Knowledge: 🚧 IN PROGRESS

**Completed:**
- ✅ TypeScript rule definitions in `keywords.toml`
- ✅ Plugin scaffold at `detection/plugins/static/typescript/`

**In Development:**
- 🚧 TypeScript code parsing/analysis logic
- 🚧 YAML-based mitigation policies (currently hardcoded)
- 🚧 Semantic attack mitigation coverage (3 of 9 capabilities missing)

**Planned:**
- 📋 Knowledge store implementation (`KnowledgeService` interface defined)
- 📋 Report aggregation across pipelines

### Phase 3 - RAG & Dynamic Analysis: 📋 PLANNED

**Interface Definitions:**
- 📋 `KnowledgeService` protocol (24 lines)
- 📋 `SandboxProvider` protocol (26 lines)
- 📋 Dynamic and RAG pipeline stubs

**Not Yet Implemented:**
- 📋 Sandbox-based dynamic analysis
- 📋 RAG-powered knowledge enrichment
- 📋 Multi-pipeline result aggregation

### Phase 4 - Integration & Deployment: 📋 PLANNED

- 📋 CI/CD integration examples
- 📋 Container image distribution
- 📋 GitHub Actions workflow
- 📋 Pre-commit hook integration guide

### Current Limitations

1. **TypeScript Support:** Rules defined but analyzer not implemented (13-line stub)
2. **Mitigation Policies:** Hardcoded in Python, need YAML template migration
3. **Semantic Attack Mitigations:** Missing policies for 3 of 9 capabilities
4. **Detection Coverage:** 54% for infrastructure damage attacks (target: 75%+)
5. **Dynamic Analysis:** No sandbox execution capability yet (17-line placeholder)
6. **Knowledge Enrichment:** No RAG/LLM-powered detection yet (17-line placeholder)

### Roadmap

See [`docs/detection-roadmap.md`](docs/detection-roadmap.md) for detailed phase breakdown and timeline.

---

## Configuration

### Rule Definitions (`detection/rules/keywords.toml`)

311-line TOML file defining detection patterns:

```toml
[command_exec]
weight = 25.0
base_confidence = 70.0
description = "Command execution capabilities"

[[command_exec.indicators]]
language = "python"
type = "keyword"
pattern = "subprocess.run"

[[command_exec.indicators]]
language = "python"
type = "regex"
pattern = "os\\.system\\(.*\\)"
confidence_boost = 5.0
```

### Dependencies (`pyproject.toml`)

Managed by `uv`:

```toml
[project]
name = "mcp-security-detection"
version = "0.1.0"
requires-python = ">=3.13"

[project.dependencies]
# Core detection: standard library only (no external deps)

[project.optional-dependencies]
dev = [
    "black>=24.0.0",
    "pytest>=8.0.0",
    "freezegun>=1.5.0"
]
```

### Pre-commit Hooks (`.pre-commit-config.yaml`)

Automated code quality checks:

```yaml
repos:
  - repo: https://github.com/psf/black
    rev: 24.10.0
    hooks:
      - id: black
        language_version: python3.13

  - repo: local
    hooks:
      - id: pytest
        name: pytest
        entry: uv run pytest -q
        language: system
        pass_filenames: false
        always_run: true
```

### Pipeline Profiles (`configs/profiles.yaml`)

Placeholder for future feature flags:

```yaml
# Static pipeline configuration
static:
  enabled_detectors:
    - python
    - metadata
    # - typescript  # Uncomment when implemented

# Dynamic pipeline (Phase 3)
dynamic:
  sandbox_provider: docker  # or firejail, none
  timeout_seconds: 30
```

---

## Contributing

### Code Style

**Required:**
- Python 3.13+ (see `.python-version`)
- Type hints mandatory (`from __future__ import annotations`)
- Black formatting (4-space indentation)
- `snake_case` for functions/variables, `PascalCase` for classes

**Design Patterns:**
1. **Protocol-Based Plugins:** Use `typing.Protocol` for duck-typed interfaces
2. **Registry Pattern:** Centralized plugin registration via `DetectorRegistry`
3. **Configuration-Driven:** Rules in TOML files, not hardcoded logic
4. **Dataclass-First:** Extensive use of `@dataclass(frozen=True, slots=True)`
5. **Evidence Tracking:** All findings tagged with `EvidenceSource`

### Testing Strategy

**Framework:** `pytest` (via `uv run pytest`)

**Coverage Requirements:**
- All new detectors must have test coverage
- Use `tempfile.TemporaryDirectory()` for isolation
- Test both positive (malicious) and negative (benign) cases
- Validate confidence scores and risk levels

**Example Test:**
```python
def test_command_exec_detection():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Write malicious code
        sample = Path(tmpdir) / "exploit.py"
        sample.write_text('import subprocess\nsubprocess.run(["rm", "-rf", "/"])')

        # Run detection
        result = run_static_detection(tmpdir)

        # Assert findings
        cmd_exec = [f for f in result.findings if f.capability == "command_exec"]
        assert len(cmd_exec) > 0
        assert cmd_exec[0].confidence >= 70.0
        assert result.risk_level in ["high", "critical"]
```

### Pull Request Workflow

1. **Fork & Branch:** Create feature branch from `main`
2. **Implement:** Follow code style, add tests
3. **Quality Checks:** Run `uv tool run pre-commit run --all-files`
4. **Test:** Ensure `uv run pytest -q` passes
5. **Document:** Update README.md and CLAUDE.md if needed
6. **PR:** Submit with clear description and test evidence

### Extensibility Points

**Add New Detector:**
1. Implement `Detector` protocol
2. Register in `DetectorRegistry`
3. Add rules to `keywords.toml`
4. Write tests in `tests/`

**Add New Capability:**
1. Define in `keywords.toml` with indicators
2. Add mitigation policy to `mitigation_engine.py`
3. Update documentation tables

**Add New Report Format:**
1. Implement `ReportRenderer` protocol
2. Register in `ReportBuilder`
3. Add CLI argument option

**Add New Pipeline:**
1. Create in `pipelines/` directory
2. Inherit scoring/mitigation logic from static pipeline
3. Add CLI argument option

---

## Documentation

### For Developers

- **[CLAUDE.md](CLAUDE.md)** - Detailed architecture guide for AI assistants
  - Internal architecture, plugin system, registry patterns
  - Development patterns (Protocol usage, dataclass design, TOML rules)
  - Extension points and implementation status

- **[AGENTS.md](AGENTS.md)** - Repository-wide development guidelines
  - Multi-module context (assistant_bot, tool-poisoning, mcp-server)
  - Commit message conventions (imperative mood, scope-focused)
  - Security best practices (secrets management, untrusted outputs)

### Technical Documentation

- **[docs/detection-roadmap.md](docs/detection-roadmap.md)** - 4-phase development plan
  - Phase breakdown with deliverables
  - Extensibility principles
  - Differentiation from MCP-Guard

- **[docs/mcptox_static_analysis.md](docs/mcptox_static_analysis.md)** - Validation report
  - Coverage tables by attack category
  - Representative missed cases
  - Remediation roadmap

### Research Context

- **[Model_Context_Protocol_Security.pdf](Model_Context_Protocol_Security.pdf)** - Academic research
  - Threat model definitions
  - MCPTox dataset methodology
  - Attack taxonomy

---

## License

[Specify license here]

## Citation

If you use this framework in your research, please cite:

```bibtex
@software{mcp_security_detection,
  title = {MCP Security Detection Framework},
  author = {[Authors]},
  year = {2025},
  url = {https://github.com/[repo-url]}
}
```

For the MCPTox dataset:
```bibtex
[Citation from Model_Context_Protocol_Security.pdf]
```

---

## Acknowledgments

- MCPTox dataset from academic research (see `Model_Context_Protocol_Security.pdf`)
- Inspired by static analysis tools: Bandit, Semgrep, CodeQL
- MCP protocol: https://modelcontextprotocol.io

---

**Questions or issues?** Open an issue on GitHub or consult [CLAUDE.md](CLAUDE.md) for detailed architecture guidance.
