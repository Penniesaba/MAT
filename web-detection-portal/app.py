import os
from pathlib import Path

from flask import Flask, jsonify, render_template, request

import config
from detection_adapter import DetectionAdapter
from detector import MCPToolDetector
from storage import DetectionStorage

app = Flask(__name__)
detector = MCPToolDetector(str(config.RULES_FILE))
storage = DetectionStorage(str(config.STORAGE_FILE))
adapter = DetectionAdapter()


@app.route("/")
def index():
    """Main page showing detection results with pagination and filtering"""
    # Get query parameters
    page = request.args.get("page", 1, type=int)
    limit = request.args.get("limit", 50, type=int)
    severity_filter = request.args.get("severity", None)
    result_filter = request.args.get("result", None)
    search_query = request.args.get("search", None)

    # Ensure valid page and limit
    page = max(1, page)
    limit = min(max(10, limit), 500)  # Between 10 and 500

    # Get all results
    all_results = storage.get_recent_results(limit=10000)  # Get more for filtering

    # Apply filters
    filtered_results = all_results
    if severity_filter:
        filtered_results = [r for r in filtered_results if r.get("severity") == severity_filter]
    if result_filter:
        filtered_results = [r for r in filtered_results if r.get("result") == result_filter]
    if search_query:
        search_lower = search_query.lower()
        filtered_results = [
            r
            for r in filtered_results
            if search_lower in r.get("tool_name", "").lower()
            or search_lower in r.get("description", "").lower()
        ]

    # Calculate pagination
    total_results = len(filtered_results)
    total_pages = max(1, (total_results + limit - 1) // limit)  # Ceiling division
    page = min(page, total_pages)  # Ensure page doesn't exceed total pages

    # Slice results for current page
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    results = filtered_results[start_idx:end_idx]

    stats = storage.get_statistics()

    # Add pagination info
    pagination = {
        "page": page,
        "limit": limit,
        "total_results": total_results,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "start_idx": start_idx + 1 if total_results > 0 else 0,
        "end_idx": min(end_idx, total_results),
    }

    return render_template(
        "index.html",
        results=results,
        stats=stats,
        pagination=pagination,
        filters={
            "severity": severity_filter,
            "result": result_filter,
            "search": search_query,
        },
    )


@app.route("/api/detect", methods=["POST"])
def api_detect():
    """
    API endpoint for tool detection

    Accepts JSON:
    {
        "tool_name": "example_tool",
        "description": "Tool description text"
    }

    Returns JSON:
    {
        "success": true,
        "result": {
            "tool_name": "example_tool",
            "description": "Tool description text",
            "result": "Normal" or "Injection" or "Warning",
            "severity": "low" or "medium" or "critical",
            "risk_score": 0,
            "detected_patterns": [...],
            "timestamp": "2025-01-01T00:00:00"
        }
    }
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({"success": False, "error": "No JSON data provided"}), 400

        tool_name = data.get("tool_name", "")
        description = data.get("description", "")

        if not tool_name or not description:
            return jsonify(
                {"success": False, "error": "Both tool_name and description are required"}
            ), 400

        # Run detection
        result = detector.detect(tool_name, description)

        # Save result
        storage.save_result(result)

        return jsonify({"success": True, "result": result}), 200

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/results", methods=["GET"])
def api_get_results():
    """Get all detection results"""
    try:
        limit = request.args.get("limit", 50, type=int)
        results = storage.get_recent_results(limit=limit)

        return jsonify({"success": True, "count": len(results), "results": results}), 200

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/stats", methods=["GET"])
def api_get_stats():
    """Get detection statistics"""
    try:
        stats = storage.get_statistics()
        detector_stats = detector.get_stats()

        return jsonify(
            {"success": True, "storage_stats": stats, "detector_stats": detector_stats}
        ), 200

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/test", methods=["GET", "POST"])
def test_page():
    """Test page for manual tool detection"""
    if request.method == "POST":
        tool_name = request.form.get("tool_name", "")
        description = request.form.get("description", "")

        if tool_name and description:
            result = detector.detect(tool_name, description)
            storage.save_result(result)
            return render_template("test.html", result=result)

    return render_template("test.html", result=None)


@app.route("/clear", methods=["POST"])
def clear_results():
    """Clear all detection results"""
    storage.clear_all_results()
    return jsonify({"success": True, "message": "All results cleared"})


@app.route("/api/import/detection", methods=["POST"])
def api_import_detection():
    """
    Import results from detection module (JSONL format)

    Accepts JSON:
    {
        "jsonl_path": "/path/to/per_file_detection.jsonl"
    }

    Or file upload with key 'file'

    Returns JSON:
    {
        "success": true,
        "imported_count": 10,
        "message": "Imported 10 detection results"
    }
    """
    try:
        # Check if file upload
        if "file" in request.files:
            file = request.files["file"]
            if file.filename == "":
                return jsonify({"success": False, "error": "No file selected"}), 400

            # Save temporarily
            temp_path = Path("/tmp") / file.filename
            file.save(temp_path)
            jsonl_path = temp_path
        else:
            # Get path from JSON
            data = request.get_json()
            if not data or "jsonl_path" not in data:
                return jsonify({"success": False, "error": "jsonl_path is required"}), 400

            jsonl_path = Path(data["jsonl_path"])

        if not jsonl_path.exists():
            return jsonify({"success": False, "error": f"File not found: {jsonl_path}"}), 404

        # Convert and import
        converted_results = adapter.convert_jsonl_file(jsonl_path)

        # Save each result to storage
        for result in converted_results:
            storage.save_result(result)

        return jsonify(
            {
                "success": True,
                "imported_count": len(converted_results),
                "message": f"Imported {len(converted_results)} detection results",
            }
        ), 200

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/import/single", methods=["POST"])
def api_import_single():
    """
    Import a single detection module result

    Accepts JSON (detection module format):
    {
        "server_name": "example_server",
        "findings": [...],
        "total_score": 45.5,
        "risk_level": "medium"
    }

    Returns JSON:
    {
        "success": true,
        "result": {...}
    }
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({"success": False, "error": "No JSON data provided"}), 400

        # Convert detection format to mcp-tools-detection format
        converted = adapter.convert_detection_result(data)

        # Save result
        storage.save_result(converted)

        return jsonify({"success": True, "result": converted}), 200

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


def auto_import_detection_results():
    """Automatically import detection results on startup if enabled."""
    if not config.AUTO_IMPORT_ON_STARTUP:
        print("ℹ Auto-import is disabled in config")
        return

    print("=" * 60)
    print("🔍 Checking for detection results to import...")
    print("=" * 60)

    # Check if detection file exists
    if not config.DETECTION_JSONL_PATH.exists():
        print(f"⚠ Detection file not found: {config.DETECTION_JSONL_PATH}")
        print(f"ℹ Run detection first:")
        print(f"  cd {config.DETECTION_OUTPUT_DIR.parent.parent}")
        print(f"  python examples/run_mcptox_detection.py")
        return

    # Import results using adapter with tracking
    try:
        results, was_imported = adapter.auto_import_if_new(
            config.DETECTION_JSONL_PATH, config.IMPORT_TRACKING_FILE
        )

        if was_imported:
            # Clear existing and save new results
            storage.clear_all_results()
            for result in results:
                storage.save_result(result)

            print(f"✓ Automatically imported {len(results)} detection results")
            print(f"  - Source: {config.DETECTION_JSONL_PATH.name}")
            print(f"  - Total in storage: {storage.get_statistics()['total']}")
        else:
            print(f"ℹ Detection results already up-to-date")
            print(f"  - File: {config.DETECTION_JSONL_PATH.name}")
            print(f"  - Total in storage: {storage.get_statistics()['total']}")

    except Exception as e:
        print(f"✗ Error importing detection results: {e}")
        import traceback

        traceback.print_exc()

    print("=" * 60)


if __name__ == "__main__":
    # Create templates directory if it doesn't exist
    os.makedirs("templates", exist_ok=True)

    # Auto-import detection results on startup
    auto_import_detection_results()

    # Run the application
    print(f"\n🚀 Starting mcp-tools-detection server...")
    print(f"   URL: http://{config.HOST}:{config.PORT}")
    print(f"   Storage: {config.STORAGE_FILE}")
    print()
    app.run(debug=config.DEBUG, host=config.HOST, port=config.PORT)
