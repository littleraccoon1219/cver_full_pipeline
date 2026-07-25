"""M2 Kata vulnerability-discovery stage.

The package performs evidence-gated, non-weaponized vulnerability research for
Kata Containers and adjacent VMM/host boundaries. It intentionally does not
create or execute guest-to-host escape payloads.
"""

from .config import M2Settings

__all__ = ["M2Settings"]
__version__ = "0.1.0"
