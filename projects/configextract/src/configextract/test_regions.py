import pytest

from configextract.hits import YaraHit
from configextract.regions import (
    ConfigRegion,
    FixedDeltaResolver,
    MetaResolver,
    MatchOnlyResolver,
)
from configextract.exceptions import ResolutionError, InvalidRegionError


def make_hit(offset=100, matched_bytes=b"\x90\x90\x90\x90", meta=None):
    return YaraHit(
        rule_name="TestRule",
        namespace="default",
        match_offset=offset,
        matched_bytes=matched_bytes,
        identifier="$marker",
        meta=meta or {},
    )


def test_config_region_rejects_negative_address():
    with pytest.raises(InvalidRegionError):
        ConfigRegion(address=-1, size=16)


def test_config_region_rejects_zero_or_negative_size():
    with pytest.raises(InvalidRegionError):
        ConfigRegion(address=0, size=0)
    with pytest.raises(InvalidRegionError):
        ConfigRegion(address=0, size=-4)


def test_fixed_delta_resolver_basic():
    hit = make_hit(offset=100)
    resolver = FixedDeltaResolver(delta=4, size=64)

    region = resolver.resolve(hit)

    assert region.address == 104
    assert region.size == 64


def test_fixed_delta_resolver_negative_delta():
    hit = make_hit(offset=100)
    resolver = FixedDeltaResolver(delta=-20, size=16)

    region = resolver.resolve(hit)

    assert region.address == 80


def test_fixed_delta_resolver_raises_on_invalid_result():
    # delta pushes address negative -> should surface as ResolutionError,
    # not a raw InvalidRegionError, so callers only need to catch one type
    hit = make_hit(offset=5)
    resolver = FixedDeltaResolver(delta=-100, size=16)

    with pytest.raises(ResolutionError):
        resolver.resolve(hit)


def test_meta_resolver_reads_from_rule_meta():
    hit = make_hit(offset=200, meta={"delta": 8, "config_size": 32})
    resolver = MetaResolver()

    region = resolver.resolve(hit)

    assert region.address == 208
    assert region.size == 32


def test_meta_resolver_custom_keys():
    hit = make_hit(offset=0, meta={"cfg_delta": 16, "cfg_len": 48})
    resolver = MetaResolver(meta_delta_key="cfg_delta", meta_size_key="cfg_len")

    region = resolver.resolve(hit)

    assert region.address == 16
    assert region.size == 48


def test_meta_resolver_missing_field_raises():
    hit = make_hit(offset=0, meta={"delta": 4})  # config_size missing
    resolver = MetaResolver()

    with pytest.raises(ResolutionError):
        resolver.resolve(hit)


def test_match_only_resolver_uses_matched_bytes_span():
    hit = make_hit(offset=50, matched_bytes=b"\x01\x02\x03\x04\x05")
    resolver = MatchOnlyResolver()

    region = resolver.resolve(hit)

    assert region.address == 50
    assert region.size == 5
