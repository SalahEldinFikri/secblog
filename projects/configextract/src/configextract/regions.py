"""
Step 1, second half: given a normalized YaraHit, decide *where* the real
config data lives — the (address, size) pair that views.py will later
read bytes from.

Kept separate from hits.py on purpose: this module never touches a raw
yara.Match, only the normalized YaraHit type.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .hits import YaraHit
from .exceptions import InvalidRegionError, ResolutionError


@dataclass(frozen=True)
class ConfigRegion:
    """The resolved location and size of a config blob to extract."""
    address: int
    size: int

    def __post_init__(self):
        if self.address < 0:
            raise InvalidRegionError(self.address, self.size, "address cannot be negative")
        if self.size <= 0:
            raise InvalidRegionError(self.address, self.size, "size must be positive")


@runtime_checkable
class LocationResolver(Protocol):
    """
    One of these per family/rule. Encapsulates the analyst's knowledge of
    "given this match, here's where the real config lives" — a fixed
    delta, a pointer to follow, a disassembly step, whatever the family
    needs.
    """
    def resolve(self, hit: YaraHit) -> ConfigRegion: ...


class FixedDeltaResolver:
    """Simplest case: config = match_offset + delta, fixed size.

    Use this when the config always sits a constant number of bytes
    after (or before, via a negative delta) the YARA match.
    """
    def __init__(self, delta: int, size: int):
        self.delta = delta
        self.size = size

    def resolve(self, hit: YaraHit) -> ConfigRegion:
        address = hit.match_offset + self.delta
        try:
            return ConfigRegion(address=address, size=self.size)
        except InvalidRegionError as e:
            raise ResolutionError(hit.rule_name, str(e)) from e


class MetaResolver:
    """Reads delta/size straight from the YARA rule's `meta` block.

    Lets an analyst write extraction hints directly into the rule
    instead of maintaining a parallel Python resolver per family:

        rule ExampleFamily_Config
        {
            meta:
                delta = 4
                config_size = 256
            strings:
                $marker = { 90 90 90 90 }
            condition:
                $marker
        }

    meta_delta_key / meta_size_key let you match whatever field names
    your team's YARA style guide already uses.
    """
    def __init__(self, meta_delta_key: str = "delta", meta_size_key: str = "config_size"):
        self.meta_delta_key = meta_delta_key
        self.meta_size_key = meta_size_key

    def resolve(self, hit: YaraHit) -> ConfigRegion:
        if self.meta_delta_key not in hit.meta:
            raise ResolutionError(
                hit.rule_name,
                f"meta field '{self.meta_delta_key}' not present on rule",
            )
        if self.meta_size_key not in hit.meta:
            raise ResolutionError(
                hit.rule_name,
                f"meta field '{self.meta_size_key}' not present on rule",
            )

        delta = hit.meta[self.meta_delta_key]
        size = hit.meta[self.meta_size_key]
        address = hit.match_offset + delta
        try:
            return ConfigRegion(address=address, size=size)
        except InvalidRegionError as e:
            raise ResolutionError(hit.rule_name, str(e)) from e


class MatchOnlyResolver:
    """Degenerate case: the config *is* the matched bytes themselves.

    Useful for the simplest families where the YARA string literally
    captures the whole encoded config (e.g. a fixed-size encrypted blob
    matched directly by the rule).
    """
    def resolve(self, hit: YaraHit) -> ConfigRegion:
        return ConfigRegion(address=hit.match_offset, size=len(hit.matched_bytes))
