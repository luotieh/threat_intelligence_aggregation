from app.models import AppConfig
from app.services import daily_pipeline
from app.services.daily_pipeline import run_daily_pipeline


def test_pipeline_skipped_without_whoisxml_key(db):
    assert run_daily_pipeline(db)["status"] == "skipped"


def _mute_io(monkeypatch):
    monkeypatch.setattr(daily_pipeline, "sync_otx_direct", lambda db, max_pulses=None: None)


def test_pipeline_confirms_and_pushes(db, make_indicator, monkeypatch, tmp_path):
    db.add(AppConfig(key="WHOISXML_API_KEY", value="k"))
    db.add(AppConfig(key="IOC_OUTPUT_DIR", value=str(tmp_path)))
    for i in range(3):
        db.add(make_indicator(value=f"e{i}.com", normalized_value=f"e{i}.com",
                              normalized_type="domain", severity="high", confidence=90 - i,
                              tags=[{"name": "source:otx"}]))
    db.commit()
    _mute_io(monkeypatch)
    monkeypatch.setattr(daily_pipeline, "query_whoisxml",
                        lambda key, ioc: {"results": [{"threatType": "malware"}]})
    written = {}
    monkeypatch.setattr(daily_pipeline, "write_ta_node_ioc_files",
                        lambda path, items: written.update({"n": len(items)}))
    result = run_daily_pipeline(db, target=3, max_enrich=10)
    assert result["status"] == "success"
    assert result["confirmed"] == 3
    assert result["pushed"] == 3
    assert written["n"] == 3


def test_pipeline_respects_enrich_cap(db, make_indicator, monkeypatch, tmp_path):
    db.add(AppConfig(key="WHOISXML_API_KEY", value="k"))
    db.add(AppConfig(key="IOC_OUTPUT_DIR", value=str(tmp_path)))
    for i in range(10):
        db.add(make_indicator(value=f"n{i}.com", normalized_value=f"n{i}.com",
                              normalized_type="domain", severity="high", tags=[{"name": "source:otx"}]))
    db.commit()
    _mute_io(monkeypatch)
    monkeypatch.setattr(daily_pipeline, "query_whoisxml", lambda key, ioc: {"results": []})
    monkeypatch.setattr(daily_pipeline, "write_ta_node_ioc_files", lambda path, items: None)
    result = run_daily_pipeline(db, target=10, max_enrich=4)
    assert result["enrich_attempts"] == 4
    assert result["confirmed"] == 0
