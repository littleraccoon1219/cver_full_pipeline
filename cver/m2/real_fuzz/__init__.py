"""Version-pinned real kata-agent fuzzing support.

The package separates mock/interface tests from evidence-bearing real-handler fuzzing.
No model-generated patch or replay input is executed without explicit approval.
"""

from .engine import RealFuzzEngine
from .models import AdapterState, CandidateLevel, ReplayLevel

__all__ = ["RealFuzzEngine", "AdapterState", "CandidateLevel", "ReplayLevel"]
