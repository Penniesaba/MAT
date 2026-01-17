"""Abstract knowledge service interface for enrichment plugins."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Protocol


@dataclass(slots=True)
class KnowledgeItem:
    """Represents a retrieved knowledge snippet."""

    title: str
    content: str
    source: str
    score: float


class KnowledgeService(Protocol):
    """Protocol implemented by knowledge retrieval backends."""

    def search(self, query: str, *, limit: int = 5) -> List[KnowledgeItem]:
        """Return the most relevant knowledge items for a query."""
