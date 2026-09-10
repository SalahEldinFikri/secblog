"""
This is the only module in the package that should know about the shape
of yara-python's match objects. Everything downstream works with the
normalized ``YaraHit`` type instead.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

from .exceptions import NoMatchInstancesError


@dataclass(frozen=True)
class YaraHit:
    """One normalized string-match instance from a YARA rule hit.

    A single yara.Match can contain multiple matched strings, and each
    matched string can occur multiple times in the buffer. normalize_matches()
    flattens all of that into a list of these.
    """
    rule_name: str
    namespace: str
    match_offset: int          # raw offset of the matched string in the scanned buffer
    matched_bytes: bytes
    identifier: str            # e.g. "$config_marker"
    meta: dict[str, Any] = field(default_factory=dict)
    tags: tuple[str, ...] = field(default_factory=tuple)


def normalize_matches(yara_match: Any) -> list[YaraHit]:
    """Flatten a single yara.Match into a list of YaraHit, one per string instance.

    Supports both the modern yara-python API (>=4.3, StringMatch/
    StringMatchInstance objects) and the legacy API (match.strings as a
    list of (offset, identifier, data) tuples), so this works regardless
    of which yara-python version is installed.

    Raises NoMatchInstancesError if the rule matched but yielded no
    string instances at all (can happen with rules that match purely on
    e.g. imphash/filesize conditions with no $string references).
    """
    hits: list[YaraHit] = []
    meta = dict(getattr(yara_match, "meta", {}) or {})
    tags = tuple(getattr(yara_match, "tags", ()) or ())
    rule_name = yara_match.rule
    namespace = getattr(yara_match, "namespace", "default")

    for string_match in yara_match.strings:
        if hasattr(string_match, "instances"):
            # modern API: StringMatch with .identifier and .instances
            identifier = string_match.identifier
            for instance in string_match.instances:
                hits.append(YaraHit(
                    rule_name=rule_name,
                    namespace=namespace,
                    match_offset=instance.offset,
                    matched_bytes=bytes(instance.matched_data),
                    identifier=identifier,
                    meta=meta,
                    tags=tags,
                ))
        else:
            # legacy API: bare (offset, identifier, data) tuple
            offset, identifier, data = string_match
            hits.append(YaraHit(
                rule_name=rule_name,
                namespace=namespace,
                match_offset=offset,
                matched_bytes=bytes(data),
                identifier=identifier,
                meta=meta,
                tags=tags,
            ))

    if not hits:
        raise NoMatchInstancesError(rule_name)

    return hits


def normalize_all(yara_matches: list[Any]) -> list[YaraHit]:
    """Convenience wrapper: normalize every match in a yara.rules.match() result.

    Rules with no string instances are skipped rather than raising, since
    a batch scan shouldn't die because one rule in the set matched on
    conditions alone.
    """
    hits: list[YaraHit] = []
    for m in yara_matches:
        try:
            hits.extend(normalize_matches(m))
        except NoMatchInstancesError:
            continue
    return hits
