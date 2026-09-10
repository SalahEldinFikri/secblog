"""Exception types for the configextract package."""


class ConfigExtractError(Exception):
    """Base class for all errors raised by configextract."""


class NoMatchInstancesError(ConfigExtractError):
    """Raised when a YARA rule matched but produced no usable string instances."""

    def __init__(self, rule_name: str):
        self.rule_name = rule_name
        super().__init__(
            f"Rule '{rule_name}' matched but has no string instances to extract "
            f"an offset from."
        )


class ResolutionError(ConfigExtractError):
    """Raised when a LocationResolver cannot determine a valid ConfigRegion."""

    def __init__(self, rule_name: str, reason: str):
        self.rule_name = rule_name
        self.reason = reason
        super().__init__(f"Failed to resolve config region for '{rule_name}': {reason}")


class InvalidRegionError(ConfigExtractError):
    """Raised when a resolved ConfigRegion is structurally invalid (e.g. negative size)."""

    def __init__(self, address: int, size: int, reason: str):
        self.address = address
        self.size = size
        self.reason = reason
        super().__init__(
            f"Invalid region (address=0x{address:x}, size={size}): {reason}"
        )
