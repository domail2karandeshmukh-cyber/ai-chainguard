import math

import pytest

from chainguard.crypto.canonical import canonical_json


def test_key_order_does_not_matter():
    assert canonical_json({"b": 1, "a": {"y": 2, "x": 3}}) == canonical_json({"a": {"x": 3, "y": 2}, "b": 1})


def test_compact_form():
    assert canonical_json({"a": [1, 2], "b": "x"}) == b'{"a":[1,2],"b":"x"}'


def test_unicode_kept_as_utf8():
    assert canonical_json({"name": "Angers é"}) == '{"name":"Angers é"}'.encode()


def test_nan_rejected():
    with pytest.raises(ValueError):
        canonical_json({"x": math.nan})


def test_float_roundtrip_is_stable():
    import json

    obj = {"lr": 0.0005, "acc": 0.9472}
    assert canonical_json(json.loads(canonical_json(obj))) == canonical_json(obj)
