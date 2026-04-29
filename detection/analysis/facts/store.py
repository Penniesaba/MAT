"""Fact Store for AST-based security analysis framework.

In-memory storage for security facts with deduplication and querying capabilities.
"""

from __future__ import annotations

from typing import Iterator, Sequence

from .schema import Fact


class DuplicateFactError(Exception):
    """Raised when attempting to add a fact with an ID that already exists."""

    def __init__(self, fact_id: str, existing_type: str, new_type: str) -> None:
        self.fact_id = fact_id
        self.existing_type = existing_type
        self.new_type = new_type
        super().__init__(
            f"Duplicate fact ID: {fact_id!r} "
            f"(existing type={existing_type}, new type={new_type})"
        )


class FactStore:
    """In-memory store for security facts with deduplication and querying."""

    def __init__(self) -> None:
        self._facts: dict[str, Fact] = {}

    def add(self, fact: Fact) -> None:
        """Add a fact. Raises DuplicateFactError if ID already exists."""
        if fact.id in self._facts:
            existing = self._facts[fact.id]
            raise DuplicateFactError(fact.id, existing.type, fact.type)
        self._facts[fact.id] = fact

    def add_or_update(self, fact: Fact) -> None:
        """Add a fact, replacing any existing fact with the same ID."""
        self._facts[fact.id] = fact

    def add_all(self, facts: Sequence[Fact]) -> None:
        """Add multiple facts. Raises DuplicateFactError on first duplicate."""
        for fact in facts:
            self.add(fact)

    def get(self, fact_id: str) -> Fact | None:
        """Retrieve a fact by ID, or None if not found."""
        return self._facts.get(fact_id)

    def has_id(self, fact_id: str) -> bool:
        """Check if a fact with the given ID exists."""
        return fact_id in self._facts

    def remove(self, fact_id: str) -> bool:
        """Remove a fact by ID. Returns True if removed, False if not found."""
        if fact_id in self._facts:
            del self._facts[fact_id]
            return True
        return False

    def query(
        self,
        type: str | None = None,
        file: str | None = None,
        language: str | None = None,
    ) -> list[Fact]:
        """Query facts by filtering conditions.

        Args:
            type: Filter by fact type (e.g., "function", "call", "sink").
            file: Filter by file path (exact match).
            language: Filter by language (e.g., "python", "javascript").
                      Only facts with a language attribute are matched.

        Returns:
            List of matching facts.
        """
        results = list(self._facts.values())
        if type is not None:
            results = [f for f in results if f.type == type]
        if file is not None:
            results = [f for f in results if f.file == file]
        if language is not None:
            results = [
                f for f in results if getattr(f, "language", None) == language
            ]
        return results

    def all_facts(self) -> list[Fact]:
        """Return all stored facts."""
        return list(self._facts.values())

    def count(self) -> int:
        """Return the number of stored facts."""
        return len(self._facts)

    def ids(self) -> set[str]:
        """Return all fact IDs."""
        return set(self._facts.keys())

    def clear(self) -> None:
        """Remove all facts."""
        self._facts.clear()

    def __len__(self) -> int:
        return len(self._facts)

    def __contains__(self, fact_id: str) -> bool:
        return fact_id in self._facts

    def __iter__(self) -> Iterator[Fact]:
        return iter(self._facts.values())
