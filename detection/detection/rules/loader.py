"""Load capability rules from TOML configuration files."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Tuple

import tomllib


@dataclass(frozen=True)
class IndicatorRule:
    """Single indicator definition for a capability."""

    languages: Tuple[str, ...]
    type: str
    patterns: Tuple[str, ...] = ()
    pattern: str | None = None
    case_sensitive: bool = True
    confidence_boost: float = 0.0


@dataclass(frozen=True)
class CapabilityRule:
    """Capability description with associated indicators."""

    name: str
    description: str
    weight: float
    base_confidence: float
    indicators: Tuple[IndicatorRule, ...]


@dataclass(frozen=True)
class RuleBook:
    """Container for all capability rules, addressable by name."""

    capabilities: Dict[str, CapabilityRule]

    def for_language(self, language: str) -> Dict[str, CapabilityRule]:
        """Return rules that include at least one indicator for the language."""

        result: Dict[str, CapabilityRule] = {}
        key = language.lower()
        for name, rule in self.capabilities.items():
            if any(key in indicator.languages for indicator in rule.indicators):
                result[name] = rule
        return result


def load_rulebook(path: Path) -> RuleBook:
    """Parse a TOML file into a structured rule book."""

    data = _read_toml(path)
    capabilities = {}
    for entry in data.get("capabilities", []):
        name = entry["name"]
        description = entry.get("description", "")
        weight = float(entry.get("weight", 0.0))
        base_confidence = float(entry.get("base_confidence", 0.3))

        indicators_data = entry.get("indicators", [])
        indicators = tuple(_parse_indicator(item) for item in indicators_data)
        capabilities[name] = CapabilityRule(
            name=name,
            description=description,
            weight=weight,
            base_confidence=base_confidence,
            indicators=indicators,
        )
    return RuleBook(capabilities=capabilities)


def _read_toml(path: Path) -> Dict[str, object]:
    with path.open("rb") as fh:
        return tomllib.load(fh)


def _parse_indicator(entry: Dict[str, object]) -> IndicatorRule:
    languages_iter = entry.get("languages")
    if not languages_iter:
        raise ValueError("Indicator is missing 'languages' definition")
    languages = tuple(str(lang).lower() for lang in languages_iter)

    indicator_type = str(entry.get("type", "keyword")).lower()
    case_sensitive = bool(entry.get("case_sensitive", True))
    confidence_boost = float(entry.get("confidence_boost", 0.0))

    patterns: Tuple[str, ...] = ()
    pattern: str | None = None
    if indicator_type == "keyword":
        raw_patterns = entry.get("patterns") or []
        patterns = tuple(str(p) for p in raw_patterns)
        if not patterns:
            raise ValueError("Keyword indicator requires 'patterns'")
    elif indicator_type == "regex":
        pattern_value = entry.get("pattern")
        if not pattern_value:
            raise ValueError("Regex indicator requires 'pattern'")
        pattern = str(pattern_value)
    else:
        raise ValueError(f"Unsupported indicator type: {indicator_type}")

    return IndicatorRule(
        languages=languages,
        type=indicator_type,
        patterns=patterns,
        pattern=pattern,
        case_sensitive=case_sensitive,
        confidence_boost=confidence_boost,
    )
