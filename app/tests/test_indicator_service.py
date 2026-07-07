from app.services.indicator_service import upsert_indicator


def test_upsert_fills_source_org_from_event_orgc(db):
    attribute = {
        "uuid": "attr-1",
        "type": "domain",
        "category": "Network activity",
        "value": "evil.example.com",
        "to_ids": True,
        "Event": {"Orgc": {"name": "CIRCL"}},
    }
    indicator = upsert_indicator(db, attribute)
    assert indicator.source_org == "CIRCL"


def test_upsert_source_org_none_when_absent(db):
    attribute = {"uuid": "attr-2", "type": "domain", "value": "x.example.com"}
    indicator = upsert_indicator(db, attribute)
    assert indicator.source_org is None
