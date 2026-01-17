"""Configuration for mcp-tools-detection with automatic detection integration."""

from pathlib import Path

# ===== Detection Integration Configuration =====

# Enable automatic import of detection results on startup
AUTO_IMPORT_ON_STARTUP = True

# Path to detection module output directory
DETECTION_OUTPUT_DIR = Path(__file__).parent.parent / "detection" / "examples" / "benchmarks" / "mcptox" / "output"

# Detection JSONL file name
DETECTION_JSONL_FILENAME = "per_file_detection.jsonl"

# Full path to detection results file
DETECTION_JSONL_PATH = DETECTION_OUTPUT_DIR / DETECTION_JSONL_FILENAME

# Track imported files to avoid duplicates
IMPORT_TRACKING_FILE = Path(__file__).parent / ".import_tracking.json"

# ===== Application Configuration =====

# Flask server configuration
HOST = "0.0.0.0"
PORT = 3003
DEBUG = True

# Storage configuration
STORAGE_FILE = Path(__file__).parent / "detection_results.json"

# Detection rules configuration
RULES_FILE = Path(__file__).parent / "detection_rules.yaml"

# ===== Logging Configuration =====

# Enable verbose logging for imports
VERBOSE_IMPORT_LOGGING = True

# Log file path (None = console only)
LOG_FILE = None
