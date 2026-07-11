from __future__ import annotations
from ..vulndb import VulnDB

class KeywordRAG:
    def __init__(self, vulndb: VulnDB, mode: str="keyword-rag") -> None:
        self.vulndb=vulndb; self.mode=mode
    def retrieve(self, query: str, limit: int=5) -> list[dict]:
        if self.mode == "no-rag": return []
        return self.vulndb.search(query, limit)
