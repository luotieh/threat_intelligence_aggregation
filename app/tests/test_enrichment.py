from app.models import AppConfig
from app.services import enrichment
from app.services.enrichment import enrich_high_severity_indicators


def test_enrich_skipped_without_key(db, make_indicator):
    db.add(make_indicator(normalized_type="domain", severity="high"))
    db.commit()
    assert enrich_high_severity_indicators(db)["status"] == "skipped"


def test_enrich_stores_result_and_tags(db, make_indicator, monkeypatch):
    db.add(AppConfig(key="WHOISXML_API_KEY", value="k"))
    ind = make_indicator(normalized_type="domain", normalized_value="evil.com", severity="high")
    db.add(ind)
    db.commit()
    monkeypatch.setattr(enrichment, "query_whoisxml",
                        lambda key, ioc: {"total": 1, "results": [{"threatType": "malware", "value": ioc}]})
    result = enrich_high_severity_indicators(db, limit=5)
    assert result["enriched"] == 1
    assert result["confirmed_malicious"] == 1
    db.refresh(ind)
    assert ind.raw["whoisxml"]["results"][0]["threatType"] == "malware"
    assert any((t.get("name") if isinstance(t, dict) else t) == "whoisxml:enriched" for t in ind.tags)


def test_enrich_skips_already_enriched(db, make_indicator, monkeypatch):
    db.add(AppConfig(key="WHOISXML_API_KEY", value="k"))
    db.add(make_indicator(normalized_type="domain", normalized_value="e.com", severity="high",
                          tags=[{"name": "whoisxml:enriched"}]))
    db.commit()
    calls = []
    monkeypatch.setattr(enrichment, "query_whoisxml", lambda key, ioc: calls.append(ioc) or {"results": []})
    result = enrich_high_severity_indicators(db, limit=5)
    assert result["enriched"] == 0
    assert calls == []


def test_enrich_only_high_domain_ip(db, make_indicator, monkeypatch):
    db.add(AppConfig(key="WHOISXML_API_KEY", value="k"))
    db.add(make_indicator(normalized_type="domain", normalized_value="h.com", severity="high"))
    db.add(make_indicator(normalized_type="domain", normalized_value="m.com", severity="medium"))
    db.commit()
    seen = []
    monkeypatch.setattr(enrichment, "query_whoisxml", lambda key, ioc: seen.append(ioc) or {"results": []})
    enrich_high_severity_indicators(db, limit=5)
    assert seen == ["h.com"]
