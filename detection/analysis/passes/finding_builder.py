"""Reachability + SinkFact → FindingFact Builder.

Phase 3 of the AST implementation checklist:
- Consumes ReachabilityResult (entrypoint → sink reachable path)
- Correlates with SinkFact metadata (severity, confidence, category)
- Produces stable FindingFact records with call chain evidence
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping

from analysis.facts.ids import make_finding_id
from analysis.facts.schema import (
    Confidence,
    EntryPointFact,
    Fact,
    FindingFact,
    FindingStatus,
    Severity,
    SinkFact,
)

from .call_graph import CallChainLink, ReachabilityResult

__all__ = ["build_finding_facts", "FindingFactsBuilder"]

# ---------------------------------------------------------------------------
# Default severity / confidence when SinkFact metadata is absent
# ---------------------------------------------------------------------------

_DEFAULT_SEVERITY = Severity.MEDIUM
_DEFAULT_CONFIDENCE = Confidence.MEDIUM


# ---------------------------------------------------------------------------
# Main API
# ---------------------------------------------------------------------------


def build_finding_facts(
    reachability_results: list[ReachabilityResult],
    facts: list[Fact],
    *,
    skip_missing_sinks: bool = True,
) -> list[FindingFact]:
    """Build FindingFact records from reachability analysis results.

    Args:
        reachability_results: List of ReachabilityResult from
            ``find_reachable_sinks()``.
        facts: Full fact list (used for sink + entrypoint lookups by id).
        skip_missing_sinks: If True (default), reachability results whose
            sink_id has no corresponding SinkFact in ``facts`` are silently
            skipped instead of raising ValueError.

    Returns:
        List of FindingFact, one per reachable sink. The list is ordered
        by the input reachability_results order.
    """
    builder = FindingFactsBuilder(facts=facts, skip_missing_sinks=skip_missing_sinks)
    return builder.build(reachability_results)


class FindingFactsBuilder:
    """Stateful builder that holds the fact index for efficient lookups."""

    __slots__ = ("_fact_by_id", "_sink_by_id", "_ep_by_id", "_skip_missing_sinks")

    def __init__(
        self,
        facts: list[Fact],
        *,
        skip_missing_sinks: bool = True,
    ) -> None:
        self._fact_by_id: dict[str, Fact] = {f.id: f for f in facts}
        self._sink_by_id: dict[str, SinkFact] = {
            f.id: f for f in facts if f.type == "sink"
        }
        self._ep_by_id: dict[str, EntryPointFact] = {
            f.id: f for f in facts if f.type == "entrypoint"
        }
        self._skip_missing_sinks = skip_missing_sinks

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self, reachability_results: list[ReachabilityResult]) -> list[FindingFact]:
        """Convert a list of ReachabilityResult into FindingFact records."""
        findings: list[FindingFact] = []
        for result in reachability_results:
            sink_fact = self._sink_by_id.get(result.sink_id)
            if sink_fact is None:
                if self._skip_missing_sinks:
                    continue
                raise ValueError(
                    f"ReachabilityResult references unknown sink_id={result.sink_id!r}"
                )

            ep_fact = self._ep_by_id.get(result.entrypoint_id)

            finding = self._build_finding(result, sink_fact, ep_fact)
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_finding(
        self,
        result: ReachabilityResult,
        sink: SinkFact,
        entrypoint: EntryPointFact | None,
    ) -> FindingFact:
        """Construct a single FindingFact from one ReachabilityResult."""
        category = sink.category
        name = self._make_finding_name(result, sink, entrypoint)
        finding_id = make_finding_id(category, name)

        severity = sink.severity_base if sink.severity_base is not None else _DEFAULT_SEVERITY
        confidence = sink.confidence if sink.confidence is not None else _DEFAULT_CONFIDENCE

        evidence = self._build_evidence(result, sink, entrypoint)
        call_chain = self._serialize_chain(result.call_chain)

        return FindingFact(
            type="finding",
            id=finding_id,
            file=sink.file,
            line=sink.line,
            title=self._make_title(sink, entrypoint),
            category=category,
            severity=severity,
            confidence=confidence,
            status=FindingStatus.POTENTIAL,
            entrypoint_id=result.entrypoint_id,
            sink_id=result.sink_id,
            call_chain=call_chain,
            evidence=evidence,
        )

    def _make_finding_name(
        self,
        result: ReachabilityResult,
        sink: SinkFact,
        entrypoint: EntryPointFact | None,
    ) -> str:
        """Derive a stable deterministic name for the finding.

        Format: ``ep_<ep_name>_sink_<sink_name>``.
        Spaces become single underscores; original underscores are doubled
        to avoid collision (e.g. ``my_func`` → ``my__func``).
        """
        raw_ep = entrypoint.name if entrypoint else result.entrypoint_id
        ep_parts = raw_ep.split()
        ep_name = "_".join(p.replace("_", "__") for p in ep_parts)

        raw_sink = sink.sink_name
        sink_parts = raw_sink.split()
        sink_name = "_".join(p.replace("_", "__") for p in sink_parts)

        return f"ep_{ep_name}_sink_{sink_name}"

    def _make_title(
        self,
        sink: SinkFact,
        entrypoint: EntryPointFact | None,
    ) -> str:
        """Human-readable title summarising the finding."""
        ep_label = entrypoint.name if entrypoint else "unknown entrypoint"
        return (
            f"Potential {sink.category} via {ep_label} → {sink.sink_name}"
        )

    def _build_evidence(
        self,
        result: ReachabilityResult,
        sink: SinkFact,
        entrypoint: EntryPointFact | None,
    ) -> list[str]:
        """Build the evidence list from entrypoint + sink metadata."""
        evidence: list[str] = []

        if entrypoint:
            evidence.append(
                f"Entrypoint: {entrypoint.name} "
                f"(function={entrypoint.function_id}, kind={entrypoint.kind})"
            )
        else:
            evidence.append(
                f"Entrypoint: {result.entrypoint_id} (not found in fact store)"
            )

        evidence.append(
            f"Sink: {sink.sink_name} "
            f"(category={sink.category}, rule={sink.rule_id}, reason={sink.reason})"
        )

        if result.call_chain:
            first_link = result.call_chain[0]
            last_link = result.call_chain[-1]
            evidence.append(
                f"Call chain: {len(result.call_chain)} hops  "
                f"first={first_link.snippet!r}  last={last_link.snippet!r}"
            )
        else:
            evidence.append("Call chain: direct call (no intermediate hops)")

        return evidence

    @staticmethod
    def _serialize_chain(chain: list[CallChainLink]) -> list[Mapping[str, Any]]:
        """Serialize CallChainLink list to plain dict list for FindingFact."""
        return [
            {
                "call_id": link.call_id,
                "caller_func_id": link.caller_func_id,
                "callee_func_id": link.callee_func_id,
                "snippet": link.snippet,
                "line": link.line,
            }
            for link in chain
        ]
