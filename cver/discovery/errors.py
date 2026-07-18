class DiscoveryError(RuntimeError):
    """Base class for discovery subsystem failures."""


class ConfigurationError(DiscoveryError):
    """Raised when mandatory runtime configuration is absent or invalid."""


class PolicyDenied(DiscoveryError):
    """Raised when a requested action is denied by the non-bypassable policy."""


class ToolUnavailable(DiscoveryError):
    """Raised when an optional external tool is unavailable."""


class EmergencyStopActive(DiscoveryError):
    """Raised when the operator emergency-stop interlock is active."""
