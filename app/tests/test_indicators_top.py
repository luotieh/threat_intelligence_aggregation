import pytest
from fastapi import HTTPException

from app.api.indicators import top_indicators


def test_top_groups_by_source(db, make_indicator):
    db.add(make_indicator(value="a", normalized_value="a", confidence=90,
                          tags=[{"name": "source:otx"}]))
    db.add(make_indicator(value="b", normalized_value="b", confidence=80,
                          tags=[{"name": "source:whoisxml"}]))
    db.commit()
    resp = top_indicators(top_per_source=10, min_severity="high", db=db)
    sources = {s["source"]: s for s in resp["sources"]}
    assert set(sources) == {"otx", "whoisxml"}
    assert sources["otx"]["count"] == 1
    assert sources["otx"]["items"][0]["confidence"] == 90


def test_top_invalid_severity_raises_422(db):
    with pytest.raises(HTTPException) as exc:
        top_indicators(top_per_source=None, min_severity="bogus", db=db)
    assert exc.value.status_code == 422


def test_top_uses_config_defaults_when_omitted(db, make_indicator):
    db.add(make_indicator(value="a", normalized_value="a", tags=[{"name": "source:otx"}]))
    db.commit()
    resp = top_indicators(top_per_source=None, min_severity=None, db=db)
    assert resp["top_per_source"] == 10
    assert resp["min_severity"] == "high"
