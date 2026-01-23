# MCP Security Tools Detection

Security analysis system for Model Context Protocol (MCP) servers - combining static analysis detection with web-based visualization.

## Overview

This repository contains two integrated components:

1. **[Detection Module](detection/)** - Static analysis framework for identifying security risks in MCP servers
2. **[Web Detection Portal](web-detection-portal/)** - Dashboard for visualizing and managing detection results

## Quick Start

### Prerequisites

- Python 3.9+ (Detection module requires 3.13+)
- [uv](https://github.com/astral-sh/uv) package manager

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh  # macOS/Linux
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"  # Windows
```

### Run the System

**Step 1: Generate detection results**
```bash
cd detection
uv sync
uv run mcptox-benchmark
```

**Step 2: Start web portal**
```bash
cd ../web-detection-portal
uv sync
uv run python app.py
```

**Step 3: Open browser**
```
http://localhost:3003
```

## Docker Deployment

```bash
# From project root
docker-compose up --build

# Access at http://localhost:3003
```

## Project Structure

```
mcp-tools-detection/
├── detection/              # Static analysis framework
│   └── README.md          # Full documentation
├── web-detection-portal/  # Web dashboard
│   └── README.md          # Full documentation
└── docker-compose.yml     # Docker deployment
```

## Key Features

### Detection Module
- Detects 9 capability types (command exec, file access, network, prompt injection, etc.)
- Validated against 493 malicious tools from MCPTox dataset
- 94.7% overall detection coverage
- TOML-based configurable rules

### Web Portal
- Auto-imports detection results
- Color-coded dashboard (Normal/Warning/Injection)
- REST API for automated scanning
- Real-time statistics

## Documentation

- **[detection/README.md](detection/README.md)** - Complete detection framework documentation
- **[web-detection-portal/README.md](web-detection-portal/README.md)** - Web portal documentation

## License

This project is provided as-is for educational and security research purposes.
