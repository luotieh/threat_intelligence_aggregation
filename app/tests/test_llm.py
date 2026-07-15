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
                        lambda *a, **k: calls.append(1) or "命中 Akira 勒索软件 C2 域名,建议立即阻断访问并上报应急。")
    result = enrich_narratives(db, limit=5)
    assert result["generated"] == 1
    db.refresh(ind)
    assert "Akira" in ind.raw["narrative"]
    # 已生成的不重复调 LLM
    enrich_narratives(db, limit=5)
    assert len(calls) == 1


def test_ensure_narratives_fills_missing_and_skips_present(db, make_indicator, monkeypatch):
    db.add(AppConfig(key="LLM_ENABLED", value="true"))
    db.add(AppConfig(key="LLM_API_KEY", value="k"))
    a = make_indicator(normalized_value="a.com", raw={"Event": {"info": "OTX | Akira"}})
    b = make_indicator(normalized_value="b.com",
                       raw={"narrative": "已有描述:命中勒索软件 C2,建议立即阻断并上报应急处置。"})
    db.add(a); db.add(b); db.commit()
    calls = []
    monkeypatch.setattr(llm, "chat_completion",
                        lambda *a, **k: calls.append(1) or "命中威胁,建议阻断并上报,叙述足够长以通过非空校验门槛判定。")
    from app.services.llm import ensure_narratives
    r = ensure_narratives(db, [a, b])
    assert r["generated"] == 1          # 只补 a
    db.refresh(a); assert a.raw.get("narrative")
    assert len(calls) == 1              # b 已有,跳过


def test_ensure_narratives_disabled_when_llm_off(db, make_indicator):
    ind = make_indicator(normalized_value="a.com")
    db.add(ind); db.commit()
    from app.services.llm import ensure_narratives
    assert ensure_narratives(db, [ind])["status"] == "disabled"
