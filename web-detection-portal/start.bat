@echo off
REM Quick Start Script for MCP Tool Detection System with uv (Windows)

echo ==========================================
echo   MCP Tool Detection System - Quick Start
echo ==========================================
echo.

REM Check if uv is installed
where uv >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] uv is not installed.
    echo.
    echo Install uv with:
    echo   powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
    echo.
    echo Or with pip:
    echo   pip install uv
    echo.
    pause
    exit /b 1
)

echo [OK] uv found
echo.

REM Sync dependencies
echo [*] Setting up environment and installing dependencies...
uv sync

if %errorlevel% neq 0 (
    echo [X] Failed to install dependencies
    pause
    exit /b 1
)

echo [OK] Dependencies installed successfully
echo.

echo ==========================================
echo   Starting MCP Tool Detection System
echo ==========================================
echo.
echo Web Interface: http://localhost:5000
echo Test Page: http://localhost:5000/test
echo API Endpoint: http://localhost:5000/api/detect
echo.
echo Press Ctrl+C to stop the server
echo.

REM Run the Flask application with uv
uv run python app.py
