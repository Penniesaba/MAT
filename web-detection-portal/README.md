# MCP Web Detection Portal

A comprehensive web application for detecting malicious patterns in Model Context Protocol (MCP) tool descriptions using rule-based analysis.

## 🎯 Features

1. **🔄 Auto-Import Integration** - Automatically loads detection module results on startup
   - Incremental import (only new/modified results)
   - Smart tracking with timestamps
   - Zero manual configuration

2. **Web Interface** - Beautiful dashboard displaying detection results with three columns:
   - Tool Name
   - Description
   - Detection Result (Normal/Warning/Injection with color coding)

3. **REST API** - Accept tool name and description parameters for automated scanning

4. **Rule-Based Detection** - Process descriptions using configurable YAML rules:
   - File access patterns
   - Network activity indicators
   - Command execution keywords
   - Risk scoring system
   - Configurable thresholds

5. **Flexible Storage** - JSON-based storage with easy database migration path

6. **Statistics Dashboard** - Real-time metrics on detection results

## 📋 Requirements

- Python 3.9+
- [uv](https://github.com/astral-sh/uv) - Modern Python package manager (10-100x faster than pip!)

## 🚀 Installation

### 1. Install uv (if not already installed)

**macOS/Linux:**
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

**Windows:**
```powershell
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**Alternative (with pip):**
```bash
pip install uv
```

### 2. Clone/Download the Project

```bash
cd mcp-tools-detection
cd web-detection portal
```

### 3. Install Dependencies with uv

```bash
# Automatically creates virtual environment and installs dependencies
uv sync
```

This single command:
- ✅ Creates a `.venv` virtual environment
- ✅ Installs all dependencies from `pyproject.toml`
- ✅ Creates `uv.lock` for reproducible builds
- ✅ Takes just seconds (not minutes!)

### 4. Start the Application

```bash
# Run with uv (auto-activates virtual environment)
uv run python app.py

# Or activate environment manually
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate     # Windows
python app.py
```

### 5. Open Your Browser

Navigate to: **http://localhost:3003**

## 📁 Project Structure

```
mcp-tools-detection/
├── .python-version         # Python version for uv
├── pyproject.toml         # Project metadata and dependencies (replaces requirements.txt)
├── uv.lock                # Locked dependencies (auto-generated)
├── app.py                 # Flask web application
├── detector.py            # Detection engine
├── storage.py             # JSON storage manager
├── detection_rules.yaml   # Detection rules configuration
├── detection_results.json # Stored results (auto-created)
├── templates/
│   ├── index.html        # Main results page
│   └── test.html         # Manual testing page
├── README.md             # This file
├── Dockerfile            # Docker containerization
└── docker-compose.yml    # Docker Compose configuration
```

## 🔧 Configuration

Edit `detection_rules.yaml` to customize detection rules:

```yaml
suspicious_keywords:
  file_access:
    - "~/.ssh"
    - "~/.cursor"
    - "/etc/passwd"
  network:
    - "http://"
    - "curl"
    - "POST"
  execution:
    - "exec"
    - "eval"
    - "bash"

risk_scoring:
  file_access: 15
  network: 10
  execution: 20

threshold:
  block: 30    # Injection threshold
  warn: 15     # Warning threshold
```

## 🌐 API Usage

### Detect Tool (POST)

**Endpoint:** `POST /api/detect`

**Request Body:**
```json
{
    "tool_name": "example_tool",
    "description": "Tool description to analyze"
}
```

**Response:**
```json
{
    "success": true,
    "result": {
        "tool_name": "example_tool",
        "description": "Tool description to analyze",
        "result": "Normal",
        "severity": "low",
        "risk_score": 0,
        "detected_patterns": [],
        "timestamp": "2025-01-01T12:00:00"
    }
}
```

**Possible Results:**
- `Normal` - No suspicious patterns detected (risk score < 15)
- `Warning` - Some suspicious patterns found (15 ≤ risk score < 30)
- `Injection` - High-risk patterns detected (risk score ≥ 30)

### Get All Results (GET)

**Endpoint:** `GET /api/results?limit=50`

### Get Statistics (GET)

**Endpoint:** `GET /api/stats`

## 💻 Example API Calls

### Using cURL:

```bash
# Detect a tool
curl -X POST http://localhost:3003/api/detect \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "file_reader",
    "description": "Read files from ~/.ssh directory"
  }'
```


## 📊 Web Interface

### Main Dashboard (`/`)
- View all detection results in a table
- Statistics cards showing totals and detection rates
- Color-coded results (Red = Injection, Yellow = Warning, Green = Normal)
- Quick actions: Test new tool, Clear results, Refresh

### Test Page (`/test`)
- Manual tool testing interface
- Form for entering tool name and description
- Immediate detection results with detailed pattern analysis
- Example malicious and safe descriptions

## 🗄️ Storage & Database Migration

### Current Storage (JSON)
Results are stored in `detection_results.json`

### Migrate to Database

```bash
# Add database support
uv add sqlalchemy

# Run migration script
uv run python db_storage_example.py
```

See `db_storage_example.py` for full database integration guide.

## 🎨 Color Coding

- 🟢 **Green (Normal)** - No threats detected
- 🟡 **Yellow (Warning)** - Potential concerns, review recommended
- 🔴 **Red (Injection)** - High-risk patterns detected, block recommended

## 🔒 Security Considerations

1. **API Rate Limiting** - Consider adding rate limiting for production use
2. **Input Validation** - Description length limits recommended
3. **Authentication** - Add authentication for production deployments
4. **HTTPS** - Use HTTPS in production environments
5. **CORS** - Configure CORS policies as needed



## 📈 Performance

- **Detection Speed:** < 10ms per tool (rule-based matching)
- **Startup Time:** ~1 second with uv
- **Storage:** JSON file suitable for < 10,000 results
- **Scalability:** Consider database migration for > 10,000 results

## 🛠️ Development

### Add New Detection Categories

1. Edit `detection_rules.yaml`:
```yaml
suspicious_keywords:
  new_category:
    - "keyword1"
    - "keyword2"

risk_scoring:
  new_category: 25
```

2. The detector will automatically use the new rules

### Run in Development Mode

```bash
# Flask debug mode (auto-reload on changes)
FLASK_ENV=development uv run python app.py
```

## 🤝 Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## 📄 License

This project is provided as-is for educational and security research purposes.

## 👥 Support

For questions or issues, please create an issue in the project repository.

---

**Built with ❤️ for MCP Security Research**
