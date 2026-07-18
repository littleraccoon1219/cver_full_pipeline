"""Legacy pipeline compatibility import.

The implementation remains in :mod:`cver.pipeline` in v1 to avoid breaking
existing imports and commands. New code should use :mod:`cver.discovery`.
"""

from ..pipeline import CVERPipeline

__all__ = ["CVERPipeline"]
