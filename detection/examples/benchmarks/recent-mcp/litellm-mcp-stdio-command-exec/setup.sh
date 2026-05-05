#!/bin/bash
#
# LiteLLM MCP stdio command execution benchmark fixture - setup
#
# Installs affected LiteLLM version for detector-driven dynamic analysis.
# This does NOT execute any PoC or start the proxy.

set -euo pipefail

echo "[*] Installing LiteLLM with proxy support..."

python3 -m pip install "litellm[proxy]==1.83.6" --quiet

echo "[*] Setup complete. Run /target/run.sh to execute detector."