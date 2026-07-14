"""Candidate-only collectors for the formal trusted knowledge base.

Collectors never promote records to Verified or Gold. They create immutable raw
snapshots and a reviewable Candidate bundle that must pass validation before a
separate import step writes to the trusted knowledge database.
"""

from .common import CandidateBundleBuilder, CollectorError

__all__ = ["CandidateBundleBuilder", "CollectorError"]
