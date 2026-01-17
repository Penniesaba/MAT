"""Utility class for aggregating findings into textual reports."""

from __future__ import annotations

from typing import List

from detection.core.models import CapabilityFinding, DetectionResult


class ReportBuilder:
    """Builds markdown or JSON reports from detection results."""

    def __init__(self, format_: str = "markdown") -> None:
        self.format = format_

    def render(self, result: DetectionResult) -> str:
        """Render the detection result according to the configured format."""

        if self.format == "markdown":
            return self._render_markdown(result)
        if self.format == "json":
            return self._render_json(result)
        raise ValueError(f"Unsupported report format: {self.format}")

    def _render_markdown(self, result: DetectionResult) -> str:
        lines: List[str] = [
            f"# Detection Summary — {result.server_name}",
            "",
            f"- Total Score: {result.total_score:.2f}",
            f"- Risk Level: {result.risk_level}",
            "",
            "## Findings",
        ]
        for finding in result.findings:
            sources = ", ".join(source.value for source in finding.sources) or "unknown"
            lines.append(
                f"- **{finding.name}** ({finding.confidence:.2f}) — {finding.description} *(sources: {sources})*"
            )
        if result.mitigations:
            lines.append("")
            lines.append("## Recommended Mitigations")
            for mitigation in result.mitigations:
                lines.append(f"- {mitigation}")
        if result.notes:
            lines.append("")
            lines.append("## Notes")
            lines.append(result.notes)
        return "\n".join(lines)

    def _render_json(self, result: DetectionResult) -> str:
        import json

        payload = {
            "server": result.server_name,
            "total_score": result.total_score,
            "risk_level": result.risk_level,
            "findings": [
                {
                    "name": finding.name,
                    "description": finding.description,
                    "score_weight": finding.score_weight,
                    "confidence": finding.confidence,
                    "sources": [source.value for source in finding.sources],
                    "evidence": list(finding.evidence),
                    "metadata": dict(finding.metadata),
                }
                for finding in result.findings
            ],
            "mitigations": list(result.mitigations),
            "notes": result.notes,
        }
        return json.dumps(payload, indent=2)
