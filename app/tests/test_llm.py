from app.models import AppConfig
from app.services import llm
from app.services.llm import enrich_narratives, llm_health


def test_llm_health_disabled(db):
    assert llm_health(db)["status"] == "disabled"


def test_llm_health_unconfigured_without_key(db):
    db.add(AppConfig(key="LLM_ENABLED", value="true"))
    db.commit()
    assert llm_health(db)["status"] == "unconfigured"


def test_llm_health_ok(db, monkeypatch):
    db.add(AppConfig(key="LLM_ENABLED", value="true"))
    db.add(AppConfig(key="LLM_API_KEY", value="k"))
    db.commit()
    monkeypatch.setattr(llm, "chat_completion", lambda *a, **k: "OK")
    result = llm_health(db)
    assert result["status"] == "ok"
    assert result["reply"] == "OK"


def test_enrich_narratives_disabled(db):
    assert enrich_narratives(db)["status"] == "disabled"


def test_enrich_narratives_generates_and_caches(db, make_indicator, monkeypatch):
    db.add(AppConfig(key="LLM_ENABLED", value="true"))
    db.add(AppConfig(key="LLM_API_KEY", value="k"))
    ind = make_indicator(normalized_value="evil.com", severity="high",
                         tags=[{"name": "source:otx"}], raw={"Event": {"info": "OTX | Akira"}})
    db.add(ind)
    db.commit()
    calls = []
    monkeypatch.setattr(llm, "chat_completion",
                        lambda *a, **k: calls.append(1) or "命中 Akira 勒索,建议阻断上报。")
    result = enrich_narratives(db, limit=5)
    assert result["generated"] == 1
    db.refresh(ind)
    assert "Akira" in ind.raw["narrative"]
    # 已生成的不重复调 LLM
    enrich_narratives(db, limit=5)
    assert len(calls) == 1
