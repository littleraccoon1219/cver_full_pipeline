from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9_.:/-]{1,80}|[\u4e00-\u9fff]{2,8}")


def tokenize(text: str) -> list[str]:
    return [match.group(0).lower() for match in _TOKEN.finditer(text or "")]


def hashing_vector(text: str, *, dimensions: int = 384) -> dict[int, float]:
    counts: Counter[int] = Counter()
    tokens = tokenize(text)
    for token in tokens:
        digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
        index = int.from_bytes(digest, "big") % dimensions
        sign = 1.0 if digest[0] & 1 else -1.0
        counts[index] += sign
    norm = math.sqrt(sum(value * value for value in counts.values())) or 1.0
    return {index: value / norm for index, value in counts.items()}


def cosine(left: dict[int, float], right: dict[int, float]) -> float:
    if len(left) > len(right):
        left, right = right, left
    return sum(value * right.get(index, 0.0) for index, value in left.items())


@dataclass(frozen=True, slots=True)
class HybridDocument:
    document_id: str
    text: str
    metadata: dict[str, Any] = field(default_factory=dict)
    trust_score: float = 0.5
    evidence_quality: float = 0.5


class HybridRetriever:
    """Privacy-preserving layered retrieval baseline.

    This M1 implementation combines metadata filtering, lexical/BM25-like
    matching, a local hashing-vector representation, and MMR-style diversity.
    It never sends internal source code to a cloud embedding service. A learned
    local embedding provider can replace `hashing_vector` without changing the
    retrieval contract in M2.
    """

    def __init__(self, documents: Iterable[HybridDocument]) -> None:
        self.documents = list(documents)
        self._tokens = {item.document_id: Counter(tokenize(item.text)) for item in self.documents}
        self._vectors = {item.document_id: hashing_vector(item.text) for item in self.documents}
        self._document_frequency: Counter[str] = Counter()
        for counts in self._tokens.values():
            self._document_frequency.update(counts.keys())

    def _lexical_score(self, query_tokens: list[str], document_id: str) -> float:
        counts = self._tokens[document_id]
        length = sum(counts.values()) or 1
        total = max(len(self.documents), 1)
        score = 0.0
        for token in query_tokens:
            frequency = counts.get(token, 0)
            if not frequency:
                continue
            document_frequency = self._document_frequency.get(token, 0)
            idf = math.log(1.0 + (total - document_frequency + 0.5) / (document_frequency + 0.5))
            score += idf * (frequency / (frequency + 1.2 * (0.25 + 0.75 * length / 300.0)))
        return score

    @staticmethod
    def _metadata_match(metadata: dict[str, Any], filters: dict[str, Any]) -> bool:
        for key, expected in filters.items():
            actual = metadata.get(key)
            if isinstance(expected, (list, tuple, set)):
                if actual not in expected and not (isinstance(actual, list) and set(actual) & set(expected)):
                    return False
            elif actual != expected:
                return False
        return True

    def search(
        self,
        query: str,
        *,
        limit: int = 12,
        metadata_filters: dict[str, Any] | None = None,
        excluded_document_ids: set[str] | None = None,
        excluded_split_groups: set[str] | None = None,
        diversity_lambda: float = 0.75,
    ) -> list[dict[str, Any]]:
        metadata_filters = metadata_filters or {}
        excluded_document_ids = excluded_document_ids or set()
        excluded_split_groups = excluded_split_groups or set()
        query_tokens = tokenize(query)
        query_vector = hashing_vector(query)
        scored: list[tuple[HybridDocument, float]] = []
        for document in self.documents:
            if document.document_id in excluded_document_ids:
                continue
            if document.metadata.get("split_group_id") in excluded_split_groups:
                continue
            if not self._metadata_match(document.metadata, metadata_filters):
                continue
            lexical = self._lexical_score(query_tokens, document.document_id)
            vector = max(0.0, cosine(query_vector, self._vectors[document.document_id]))
            score = 0.45 * lexical + 0.35 * vector + 0.1 * document.trust_score + 0.1 * document.evidence_quality
            scored.append((document, score))
        scored.sort(key=lambda item: item[1], reverse=True)

        selected: list[tuple[HybridDocument, float]] = []
        pool = scored[: max(limit * 8, limit)]
        while pool and len(selected) < max(1, limit):
            best_index = 0
            best_value = -float("inf")
            for index, (document, relevance) in enumerate(pool):
                redundancy = 0.0
                if selected:
                    redundancy = max(
                        cosine(self._vectors[document.document_id], self._vectors[other.document_id])
                        for other, _ in selected
                    )
                mmr = diversity_lambda * relevance - (1.0 - diversity_lambda) * redundancy
                if mmr > best_value:
                    best_value = mmr
                    best_index = index
            selected.append(pool.pop(best_index))

        return [
            {
                "document_id": document.document_id,
                "score": round(score, 6),
                "text": document.text,
                "metadata": document.metadata,
                "trust_score": document.trust_score,
                "evidence_quality": document.evidence_quality,
                "embedding_backend": "local-hashing-v1",
            }
            for document, score in selected
        ]
