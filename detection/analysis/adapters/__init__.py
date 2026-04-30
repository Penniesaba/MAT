"""Adapters for converting between different fact and finding types."""

from analysis.adapters.finding_adapter import adapt_findings, finding_to_capability

__all__ = ["finding_to_capability", "adapt_findings"]