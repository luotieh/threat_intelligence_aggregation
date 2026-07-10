from app.models import AppConfig, IntelIndicator
from app.services import otx_source
from app.services.otx_source import pulse_to_attributes, sync_otx_direct


def test_pulse_to_attributes_maps_and_tags():
    pulse = {"id": "p1", "name": "Test", "tlp": "green", "tags": ["malware"],
             "indicators": [{"type": "IPv4", "indicator": "1.2.3.4"},
                            {"type": "UnknownX", "indicator": "x"}]}
    attrs = list(pulse_to_attributes(pulse))
    assert len(attrs) == 1
    assert attrs[0]["type"] == "ip-dst"
    names = [t["name"] for t in attrs[0]["Tag"]]
    assert "source:otx" in names
    assert "tlp:green" in names
    assert attrs[0]["Event"]["info"] == "OTX | Test"


def test_sync_skipped_without_otx_key(db):
    assert sync_otx_direct(db)["status"] == "skipped"


def test_sync_direct_imports_and_filters_benign(db, monkeypatch):
    db.add(AppConfig(key="OTX_API_KEY", value="k"))
    db.commit()
    pulses = [{"id": "p1", "name": "A", "indicators": [
        {"type": "domain", "indicator": "evil.com"},
        {"type": "IPv4", "indicator": "10.0.0.5"},   # 私网 → 去误报
        {"type": "IPv4", "indicator": "8.8.8.8"},     # 公共 DNS → 去误报
    ]}]
    monkeypatch.setattr(otx_source, "fetch_pulses", lambda key, since, mx: iter(pulses))
    result = sync_otx_direct(db)
    assert result["status"] == "success"
    assert result["imported"] == 1
    assert result["filtered_benign"] == 2
    assert db.query(IntelIndicator).count() == 1
    ind = db.query(IntelIndicator).first()
    assert ind.value == "evil.com"
    assert any(t.get("name") == "source:otx" for t in ind.tags)


def test_sync_direct_dedupes_duplicate_uuids(db, monkeypatch):
    """OTX 同一 pulse 内重复 indicator(相同 id→相同 uuid)不得撞唯一约束。"""
    db.add(AppConfig(key="OTX_API_KEY", value="k"))
    db.commit()
    pulses = [{"id": "p1", "name": "A", "indicators": [
        {"type": "domain", "indicator": "evil.com", "id": 42},
        {"type": "domain", "indicator": "evil.com", "id": 42},   # 同 id → 同 uuid,重复
    ]}]
    monkeypatch.setattr(otx_source, "fetch_pulses", lambda key, since, mx: iter(pulses))
    result = sync_otx_direct(db)
    assert result["status"] == "success"
    assert result["imported"] == 1
    assert db.query(IntelIndicator).count() == 1
