from app.models import AppConfig
from app.services import otx_source
from app.services.otx_source import pulse_to_event, sync_otx_to_misp


def test_pulse_to_event_maps_and_tags():
    pulse = {"id": "p1", "name": "Test", "tlp": "green", "tags": ["malware"],
             "indicators": [{"type": "IPv4", "indicator": "1.2.3.4"},
                            {"type": "UnknownX", "indicator": "x"}]}
    event = pulse_to_event(pulse)
    assert len(event["Attribute"]) == 1
    assert event["Attribute"][0]["type"] == "ip-dst"
    names = [t["name"] for t in event["Tag"]]
    assert "source:otx" in names
    assert "tlp:green" in names


def test_sync_skipped_without_otx_key(db):
    assert sync_otx_to_misp(db)["status"] == "skipped"


def test_sync_creates_and_publishes_events(db, monkeypatch):
    db.add(AppConfig(key="OTX_API_KEY", value="k"))
    db.add(AppConfig(key="MISP_API_KEY", value="m"))
    db.commit()
    pulses = [{"id": "p1", "name": "A", "indicators": [{"type": "domain", "indicator": "evil.com"}]}]
    monkeypatch.setattr(otx_source, "fetch_pulses", lambda key, since, mx: iter(pulses))
    posts = []

    def fake_post(url, key, path, payload):
        posts.append(path)
        return {"Event": {"id": "99"}}

    monkeypatch.setattr(otx_source, "_misp_post", fake_post)
    result = sync_otx_to_misp(db)
    assert result["status"] == "success"
    assert result["created"] == 1
    assert any("/events/add" in p for p in posts)
    assert any("/events/publish" in p for p in posts)
