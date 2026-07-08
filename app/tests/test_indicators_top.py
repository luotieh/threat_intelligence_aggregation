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


def test_top_includes_whoisxml_summary(db, make_indicator):
    db.add(make_indicator(value="e.com", normalized_value="e.com", confidence=90,
                          tags=[{"name": "source:otx"}],
                          raw={"whoisxml": {"results": [{"threatType": "malware",
                                                         "firstSeen": "2025-01-01", "lastSeen": "2026-01-01"}]}}))
    db.commit()
    item = top_indicators(top_per_source=10, min_severity="high", db=db)["sources"][0]["items"][0]
    assert item["whoisxml"]["threat_type"] == "malware"
    assert item["whoisxml"]["last_seen"] == "2026-01-01"


def test_top_date_filter(db, make_indicator):
    from datetime import datetime, timezone
    db.add(make_indicator(value="a", normalized_value="a", tags=[{"name": "source:otx"}],
                          last_seen=datetime(2026, 7, 5, tzinfo=timezone.utc)))
    db.commit()
    r = top_indicators(top_per_source=10, min_severity="high", date_from="2026-07-01", date_to="2026-07-10", db=db)
    assert r["date_from"] == "2026-07-01"
    assert sum(s["count"] for s in r["sources"]) == 1
    r2 = top_indicators(top_per_source=10, min_severity="high", date_from="2026-08-01", db=db)
    assert sum(s["count"] for s in r2["sources"]) == 0


def test_top_invalid_date_422(db):
    with pytest.raises(HTTPException) as exc:
        top_indicators(date_from="not-a-date", db=db)
    assert exc.value.status_code == 422
