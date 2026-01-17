#!/bin/bash

# Quick Start Script for MCP Tool Detection System with uv

echo "=========================================="
echo "  MCP Tool Detection System - Quick Start"
echo "=========================================="
echo ""

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "❌ uv is not installed."
    echo ""
    echo "Install uv with one of these commands:"
    echo ""
    echo "  macOS/Linux:"
    echo "    curl -LsSf https://astral.sh/uv/install.sh | sh"
    echo ""
    echo "  Windows:"
    echo "    powershell -c \"irm https://astral.sh/uv/install.ps1 | iex\""
    echo ""
    echo "  Or with pip:"
    echo "    pip install uv"
    echo ""
    exit 1
fi

echo "✓ uv found: $(uv --version)"
echo ""

# Sync dependencies (creates venv and installs packages)
echo "📦 Setting up environment and installing dependencies..."
uv sync

if [ $? -eq 0 ]; then
    echo "✓ Dependencies installed successfully"
else
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo ""
echo "=========================================="
echo "  Starting MCP Tool Detection System"
echo "=========================================="
echo ""
echo "🌐 Web Interface: http://localhost:5000"
echo "🧪 Test Page: http://localhost:5000/test"
echo "📊 API Endpoint: http://localhost:5000/api/detect"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Run the Flask application with uv
uv run python app.py
