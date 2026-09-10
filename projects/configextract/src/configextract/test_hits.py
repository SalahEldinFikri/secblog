import pytest
import yara

from configextract.hits import normalize_matches, normalize_all
from configextract.exceptions import NoMatchInstancesError


MODERN_RULE = """
rule ExampleFamily_Config
{
    meta:
        delta = 4
        config_size = 16
    strings:
        $marker = { 90 90 90 90 }
    condition:
        $marker
}
"""

NO_STRING_RULE = """
rule NoStrings_Config
{
    condition:
        filesize > 0
}
"""

MULTI_INSTANCE_RULE = """
rule Repeated_Marker
{
    strings:
        $m = { AA BB }
    condition:
        #m >= 2
}
"""


def _match_for(rule_source: str, data: bytes):
    rules = yara.compile(source=rule_source)
    matches = rules.match(data=data)
    assert matches, "expected the rule to match the test buffer"
    return matches[0]


def test_normalize_single_instance():
    data = b"\x00" * 8 + b"\x90\x90\x90\x90" + b"\xff" * 16
    match = _match_for(MODERN_RULE, data)

    hits = normalize_matches(match)

    assert len(hits) == 1
    hit = hits[0]
    assert hit.rule_name == "ExampleFamily_Config"
    assert hit.identifier == "$marker"
    assert hit.match_offset == 8
    assert hit.matched_bytes == b"\x90\x90\x90\x90"
    assert hit.meta["delta"] == 4
    assert hit.meta["config_size"] == 16


def test_normalize_multiple_instances():
    data = b"\xaa\xbb" + b"\x00" * 4 + b"\xaa\xbb"
    match = _match_for(MULTI_INSTANCE_RULE, data)

    hits = normalize_matches(match)

    assert len(hits) == 2
    assert hits[0].match_offset == 0
    assert hits[1].match_offset == 6


def test_no_string_instances_raises():
    data = b"\x01\x02\x03"
    match = _match_for(NO_STRING_RULE, data)

    with pytest.raises(NoMatchInstancesError):
        normalize_matches(match)


def test_normalize_all_skips_rules_without_instances():
    combined = MODERN_RULE + "\n" + NO_STRING_RULE
    rules = yara.compile(source=combined)
    data = b"\x00" * 8 + b"\x90\x90\x90\x90" + b"\xff" * 16
    matches = rules.match(data=data)

    # both rules should have matched (NoStrings_Config always matches)
    assert len(matches) == 2

    hits = normalize_all(matches)

    # only the rule with an actual string instance should produce a hit
    assert len(hits) == 1
    assert hits[0].rule_name == "ExampleFamily_Config"
