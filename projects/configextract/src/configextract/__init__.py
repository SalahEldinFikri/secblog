"""
configextract — links a YARA extraction rule's match to the analyst's
decoder for that malware family's configuration.

Step 1 (this far): normalize a yara.Match into YaraHit objects, then
resolve each hit to a ConfigRegion (address + size) via a
LocationResolver.
"""

from .hits import YaraHit, normalize_matches, normalize_all
from .regions import (
    ConfigRegion,
    LocationResolver,
    FixedDeltaResolver,
    MetaResolver,
    MatchOnlyResolver,
)
from .exceptions import (
    ConfigExtractError,
    NoMatchInstancesError,
    ResolutionError,
    InvalidRegionError,
)

__all__ = [
    "YaraHit",
    "normalize_matches",
    "normalize_all",
    "ConfigRegion",
    "LocationResolver",
    "FixedDeltaResolver",
    "MetaResolver",
    "MatchOnlyResolver",
    "ConfigExtractError",
    "NoMatchInstancesError",
    "ResolutionError",
    "InvalidRegionError",
]
