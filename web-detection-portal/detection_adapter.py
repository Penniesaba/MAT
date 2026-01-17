"""Adapter to convert detection module output to mcp-tools-detection format."""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


class DetectionAdapter:
    """Converts detection module results to mcp-tools-detection API format."""

    # Mapping from detection capabilities to mcp-tools-detection categories
    CAPABILITY_MAPPING = {
        "command_exec": "execution",
        "file_read": "file_access",
        "file_write": "file_access",
        "network_outbound": "network",
        "network_inbound": "network",
        "env_access": "file_access",
        "param_override": "execution",
        "tool_sequence_hijack": "execution",
        "prompt_injection": "execution",
    }

    def __init__(self):
        """Initialize the adapter."""
        self.imported_files: Dict[str, float] = {}  # filepath -> last_modified_time
        self._load_import_tracking()

    def convert_detection_result(self, detection_result: Dict[str, Any], jsonl_base_path: Optional[Path] = None) -> Dict[str, Any]:
        """
        Convert a detection module result to mcp-tools-detection format.

        Args:
            detection_result: Output from detection.pipelines.run_static_pipeline
            jsonl_base_path: Base path of the JSONL file (used to resolve relative sample paths)

        Returns:
            Dict compatible with mcp-tools-detection API format
        """
        findings = detection_result.get("findings", [])
        high_risk_indicators = detection_result.get("high_risk_indicators", [])
        total_score = detection_result.get("total_score", 0)
        risk_level = detection_result.get("risk_level", "low")
        sample_path = detection_result.get("sample", "")

        # Try to load tool_content and tool_name from the sample file
        tool_content, sample_tool_name = self._load_tool_content(sample_path, jsonl_base_path)

        # Build a map of capability -> keywords from high_risk_indicators (cleaner data)
        capability_keywords_map = {}
        for indicator in high_risk_indicators:
            capability = indicator.get("capability", "")
            keywords = indicator.get("keywords", [])
            if capability:
                capability_keywords_map[capability] = keywords

        # Convert findings to detected_patterns
        detected_patterns = []
        for finding in findings:
            capability_name = finding.get("name", "unknown")
            category = self.CAPABILITY_MAPPING.get(capability_name, "execution")
            confidence = finding.get("confidence", 0)
            score_weight = finding.get("score_weight", 0)

            # Use high_risk_indicators keywords if available, otherwise clean evidence
            if capability_name in capability_keywords_map:
                keywords = capability_keywords_map[capability_name]
            else:
                # Fallback: clean evidence keywords - remove path prefixes
                raw_evidence = finding.get("evidence", [])
                keywords = self._clean_evidence_keywords(raw_evidence)

            pattern_entry = {
                "category": category,
                "capability_name": capability_name,  # Preserve original capability name
                "keywords": keywords,
                "score": score_weight * confidence,
                "confidence": confidence,  # Preserve confidence (0-1)
                "score_weight": score_weight,  # Preserve weight
            }
            detected_patterns.append(pattern_entry)

        # Map risk_level to result and severity
        if risk_level == "critical":
            result = "Injection"
            severity = "critical"
        elif risk_level == "high":
            result = "Warning"
            severity = "medium"
        elif risk_level == "medium":
            result = "Warning"
            severity = "medium"
        else:
            result = "Normal"
            severity = "low"

        # Extract tool name with priority: sample file > server_name > filename > unknown
        tool_name = sample_tool_name or detection_result.get("server_name")
        if not tool_name:
            # Fallback to extracting filename from sample path
            if sample_path:
                tool_name = Path(sample_path).stem  # Get filename without extension
            else:
                tool_name = "unknown"

        return {
            "tool_name": tool_name,
            "description": self._extract_description(findings),
            "result": result,
            "severity": severity,
            "risk_score": total_score,
            "detected_patterns": detected_patterns,
            "tool_content": tool_content,  # Original tool prompt/description
            "timestamp": datetime.now().isoformat(),
        }

    def convert_jsonl_file(self, jsonl_path: Path) -> List[Dict[str, Any]]:
        """
        Convert a JSONL file from detection module to mcp-tools-detection format.

        Args:
            jsonl_path: Path to the JSONL file (e.g., per_file_detection.jsonl)

        Returns:
            List of converted results
        """
        results = []

        with jsonl_path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    detection_data = json.loads(line)
                    # Pass the JSONL file path to resolve relative sample paths
                    converted = self.convert_detection_result(detection_data, jsonl_path)
                    results.append(converted)

        return results

    def _load_tool_content(self, sample_path: str, jsonl_base_path: Optional[Path] = None) -> tuple[Optional[str], Optional[str]]:
        """
        Load tool_content and tool_name from the sample JSON file.

        Args:
            sample_path: Path to the sample file (relative or absolute)
            jsonl_base_path: Base path of the JSONL file (used to resolve relative paths)

        Returns:
            Tuple of (tool_content, tool_name), both can be None if not found
        """
        if not sample_path:
            return None, None

        try:
            # Convert to Path object
            path = Path(sample_path)

            # If path is relative, try to resolve it relative to the JSONL file location
            if not path.is_absolute():
                if jsonl_base_path:
                    # Resolve relative to JSONL file directory
                    path = jsonl_base_path.parent / sample_path
                else:
                    # Fallback: Try detection examples directory
                    detection_base = Path(__file__).parent.parent / "detection"
                    path = detection_base / sample_path

            # Read the sample file
            if path.exists():
                with path.open("r", encoding="utf-8") as f:
                    sample_data = json.load(f)
                    tool_content = sample_data.get("tool_content")
                    tool_name = sample_data.get("tool_name")
                    return tool_content, tool_name
        except Exception as e:
            # Silently fail - tool_content is optional
            print(f"Warning: Could not load tool_content from {sample_path}: {e}")

        return None, None

    def _clean_evidence_keywords(self, evidence: List[str]) -> List[str]:
        """
        Clean evidence keywords by removing path prefixes.

        Example:
            Input: ["/path/to/file.json:bash", "/path/to/file.json:eval"]
            Output: ["bash", "eval"]
        """
        cleaned = []
        for item in evidence:
            # If item contains a colon, take only the part after the last colon
            if ":" in item:
                # Split by colon and take the last part
                keyword = item.split(":")[-1].strip()
            else:
                keyword = item.strip()

            # Only add non-empty keywords
            if keyword:
                cleaned.append(keyword)

        return cleaned

    def _extract_description(self, findings: List[Dict[str, Any]]) -> str:
        """Extract a description from findings evidence."""
        descriptions = []
        for finding in findings:
            evidence = finding.get("evidence", [])
            if evidence:
                capability_name = finding.get('name', 'unknown')
                # Clean evidence keywords
                cleaned_evidence = self._clean_evidence_keywords(evidence)
                # Show up to first 3 evidence items
                evidence_display = ", ".join(cleaned_evidence[:3])
                # Add count if there are more
                if len(cleaned_evidence) > 3:
                    evidence_display += f" (+{len(cleaned_evidence) - 3} more)"
                descriptions.append(f"{capability_name}: {evidence_display}")

        return "; ".join(descriptions) if descriptions else "No description available"

    def batch_convert_and_save(self, input_jsonl: Path, output_json: Path) -> None:
        """
        Convert a JSONL file and save as JSON for mcp-tools-detection.

        Args:
            input_jsonl: Input JSONL file from detection module
            output_json: Output JSON file for mcp-tools-detection
        """
        converted = self.convert_jsonl_file(input_jsonl)

        with output_json.open("w", encoding="utf-8") as f:
            json.dump(converted, f, ensure_ascii=False, indent=2)

        print(f"Converted {len(converted)} results from {input_jsonl} to {output_json}")

    def auto_import_if_new(
        self, jsonl_path: Path, tracking_file: Optional[Path] = None
    ) -> tuple[List[Dict[str, Any]], bool]:
        """
        Import detection results only if file is new or modified.

        Args:
            jsonl_path: Path to JSONL file
            tracking_file: Path to tracking file (optional)

        Returns:
            Tuple of (converted_results, was_imported)
            - converted_results: List of converted results (empty if not imported)
            - was_imported: True if file was imported, False if skipped
        """
        if tracking_file:
            self.tracking_file = tracking_file
            self._load_import_tracking()

        if not jsonl_path.exists():
            return [], False

        # Check if file was already imported using content hash
        file_key = str(jsonl_path.absolute())
        content = jsonl_path.read_bytes()
        current_hash = hashlib.md5(content).hexdigest()

        if file_key in self.imported_files:
            last_hash = self.imported_files[file_key]
            if current_hash == last_hash:
                # File content hasn't changed, skip import
                return [], False

        # Import the file
        converted = self.convert_jsonl_file(jsonl_path)

        # Update tracking with content hash
        self.imported_files[file_key] = current_hash
        self._save_import_tracking()

        return converted, True

    def _load_import_tracking(self, tracking_file: Optional[Path] = None) -> None:
        """Load import tracking data from file."""
        if tracking_file:
            self.tracking_file = tracking_file
        elif not hasattr(self, "tracking_file"):
            self.tracking_file = Path(".import_tracking.json")

        if self.tracking_file.exists():
            try:
                with self.tracking_file.open("r") as f:
                    self.imported_files = json.load(f)
            except Exception:
                self.imported_files = {}
        else:
            self.imported_files = {}

    def _save_import_tracking(self) -> None:
        """Save import tracking data to file."""
        try:
            with self.tracking_file.open("w") as f:
                json.dump(self.imported_files, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save import tracking: {e}")

    def get_latest_detection_file(self, search_dir: Path) -> Optional[Path]:
        """
        Find the most recent detection JSONL file in a directory.

        Args:
            search_dir: Directory to search

        Returns:
            Path to the most recent JSONL file, or None if not found
        """
        if not search_dir.exists():
            return None

        jsonl_files = list(search_dir.glob("**/*.jsonl"))
        if not jsonl_files:
            return None

        # Return the most recently modified file
        return max(jsonl_files, key=lambda p: p.stat().st_mtime)


def main():
    """CLI entry point for converting detection results."""
    if len(sys.argv) < 3:
        print("Usage: python detection_adapter.py <input.jsonl> <output.json>")
        sys.exit(1)

    input_file = Path(sys.argv[1])
    output_file = Path(sys.argv[2])

    if not input_file.exists():
        print(f"Error: Input file not found: {input_file}")
        sys.exit(1)

    adapter = DetectionAdapter()
    adapter.batch_convert_and_save(input_file, output_file)


if __name__ == "__main__":
    main()
