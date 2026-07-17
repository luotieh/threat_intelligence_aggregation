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


# ---- 类型配额 6:2:2 ----
def _confirm_all(monkeypatch):
    monkeypatch.setattr(daily_pipeline, "query_whoisxml",
                        lambda key, ioc: {"results": [{"threatType": "malware"}]})


def _seed(db, n, ntype, prefix, value=None):
    from app.models import AppConfig  # noqa: F401
    for i in range(n):
        v = value(i) if value else f"{prefix}{i}"
        db.add(make_ind(value=v, normalized_value=v, normalized_type=ntype))


def make_ind(**kw):
    from app.models import IntelIndicator
    d = {"platform_category": "traffic", "misp_type": "domain", "value": "x",
         "normalized_type": "domain", "to_ids": True, "severity": "high",
         "tags": [{"name": "source:otx"}]}
    d.update(kw)
    return IntelIndicator(**d)


def test_pipeline_enforces_type_ratio(db, monkeypatch, tmp_path):
    from app.models import AppConfig
    db.add(AppConfig(key="WHOISXML_API_KEY", value="k"))
    db.add(AppConfig(key="IOC_OUTPUT_DIR", value=str(tmp_path)))
    for i in range(8):
        db.add(make_ind(value=f"1.1.1.{i}", normalized_value=f"1.1.1.{i}", normalized_type="ip"))
        db.add(make_ind(value=f"d{i}.com", normalized_value=f"d{i}.com", normalized_type="domain"))
        db.add(make_ind(value=f"http://u{i}.com/p", normalized_value=f"http://u{i}.com/p", normalized_type="url"))
    db.commit()
    _mute_io(monkeypatch); _confirm_all(monkeypatch)
    monkeypatch.setattr(daily_pipeline, "write_ta_node_ioc_files", lambda path, items: None)
    result = run_daily_pipeline(db, target=10, max_enrich=100)
    assert result["confirmed"] == 10
    assert result["confirmed_by_type"] == {"ip": 6, "domain": 2, "url": 2}


def test_pipeline_ip_shortfall_filled_by_domain(db, monkeypatch, tmp_path):
    from app.models import AppConfig
    db.add(AppConfig(key="WHOISXML_API_KEY", value="k"))
    db.add(AppConfig(key="IOC_OUTPUT_DIR", value=str(tmp_path)))
    for i in range(2):
        db.add(make_ind(value=f"1.1.1.{i}", normalized_value=f"1.1.1.{i}", normalized_type="ip"))
    for i in range(20):
        db.add(make_ind(value=f"d{i}.com", normalized_value=f"d{i}.com", normalized_type="domain"))
    for i in range(5):
        db.add(make_ind(value=f"http://u{i}.com/p", normalized_value=f"http://u{i}.com/p", normalized_type="url"))
    db.commit()
    _mute_io(monkeypatch); _confirm_all(monkeypatch)
    monkeypatch.setattr(daily_pipeline, "write_ta_node_ioc_files", lambda path, items: None)
    result = run_daily_pipeline(db, target=10, max_enrich=100)
    # IP 只有 2 个(配额 6),缺口 4 用域名补:domain 2+4=6
    assert result["confirmed_by_type"] == {"ip": 2, "domain": 6, "url": 2}
    assert result["confirmed"] == 10


def test_pipeline_url_confirmed_via_host(db, monkeypatch, tmp_path):
    from app.models import AppConfig
    db.add(AppConfig(key="WHOISXML_API_KEY", value="k"))
    db.add(AppConfig(key="IOC_OUTPUT_DIR", value=str(tmp_path)))
    db.add(make_ind(value="http://evil.com/malware?x=1",
                    normalized_value="http://evil.com/malware?x=1", normalized_type="url"))
    db.commit()
    _mute_io(monkeypatch)
    seen = []
    monkeypatch.setattr(daily_pipeline, "query_whoisxml",
                        lambda key, ioc: seen.append(ioc) or {"results": [{"threatType": "malware"}]})
    monkeypatch.setattr(daily_pipeline, "write_ta_node_ioc_files", lambda path, items: None)
    run_daily_pipeline(db, target=1, max_enrich=5)
    # URL 应以提取出的主机名(evil.com)查 WhoisXML,而非整条 URL
    assert "evil.com" in seen
    assert "http://evil.com/malware?x=1" not in seen


def _llm_on(db, monkeypatch, text="命中威胁研判,建议阻断并上报,叙述足够长以通过非空校验判定门槛。"):
    from app.models import AppConfig
    from app.services import llm as _llm
    db.add(AppConfig(key="LLM_ENABLED", value="true"))
    db.add(AppConfig(key="LLM_API_KEY", value="k"))
    monkeypatch.setattr(_llm, "chat_completion", lambda *a, **k: text)


def test_pipeline_describes_even_without_whoisxml(db, monkeypatch, tmp_path):
    """WhoisXML 额度耗尽(全部抛错)时,仍产出 target 条并全部有 LLM 描述。"""
    from app.models import AppConfig
    db.add(AppConfig(key="WHOISXML_API_KEY", value="k"))
    db.add(AppConfig(key="IOC_OUTPUT_DIR", value=str(tmp_path)))
    for i in range(8):
        db.add(make_ind(value=f"d{i}.com", normalized_value=f"d{i}.com", normalized_type="domain",
                        raw={"Event": {"info": "OTX | Akira"}}))
    db.commit()
    _mute_io(monkeypatch); _llm_on(db, monkeypatch)

    def boom(key, ioc):
        raise RuntimeError("insufficient credits balance")
    monkeypatch.setattr(daily_pipeline, "query_whoisxml", boom)
    written = {}
    monkeypatch.setattr(daily_pipeline, "write_ta_node_ioc_files",
                        lambda path, items: written.update(items=items))
    result = run_daily_pipeline(db, target=5, max_enrich=3)
    assert result["confirmed"] == 0            # WhoisXML 一条没确认
    assert result["pushed"] == 5               # 兜底仍产出 5 条
    assert result["otx_only"] == 5
    assert all(it["evidence"].get("narrative") for it in written["items"])  # 全部有 LLM 研判


def test_pipeline_fallback_honors_ratio(db, monkeypatch, tmp_path):
    from app.models import AppConfig
    db.add(AppConfig(key="WHOISXML_API_KEY", value="k"))
    db.add(AppConfig(key="IOC_OUTPUT_DIR", value=str(tmp_path)))
    for i in range(8):
        db.add(make_ind(value=f"1.1.1.{i}", normalized_value=f"1.1.1.{i}", normalized_type="ip"))
        db.add(make_ind(value=f"d{i}.com", normalized_value=f"d{i}.com", normalized_type="domain"))
        db.add(make_ind(value=f"http://u{i}.com/p", normalized_value=f"http://u{i}.com/p", normalized_type="url"))
    db.commit()
    _mute_io(monkeypatch)
    monkeypatch.setattr(daily_pipeline, "query_whoisxml",
                        lambda key, ioc: (_ for _ in ()).throw(RuntimeError("no credits")))
    monkeypatch.setattr(daily_pipeline, "write_ta_node_ioc_files", lambda path, items: None)
    result = run_daily_pipeline(db, target=10, max_enrich=2)
    assert result["pushed_by_type"] == {"ip": 6, "domain": 2, "url": 2}
    assert result["pushed"] == 10


# ---- 运行日志:写完文件当场落库,网闸取走文件也不影响追溯 ----

def test_pipeline_skipped_is_recorded_with_reason(db):
    from app.models import PipelineRun

    assert run_daily_pipeline(db)["status"] == "skipped"

    run = db.query(PipelineRun).one()
    assert run.status == "skipped"
    assert "WHOISXML_API_KEY" in run.reason
    assert run.trigger == "manual"


def test_pipeline_records_run_with_real_file_facts(db, make_indicator, monkeypatch, tmp_path):
    """不 mock 写文件:验证 yaml/zip 的大小与 sha 是真从磁盘取的。"""
    from app.models import PipelineRun

    db.add(AppConfig(key="WHOISXML_API_KEY", value="k"))
    db.add(AppConfig(key="IOC_OUTPUT_DIR", value=str(tmp_path)))
    for i in range(2):
        db.add(make_indicator(value=f"e{i}.com", normalized_value=f"e{i}.com",
                              normalized_type="domain", severity="high", confidence=90 - i,
                              tags=[{"name": "source:otx"}]))
    db.commit()
    _mute_io(monkeypatch)
    monkeypatch.setattr(daily_pipeline, "query_whoisxml",
                        lambda key, ioc: {"results": [{"threatType": "malware"}]})

    result = run_daily_pipeline(db, target=2, max_enrich=10, trigger="beat")

    assert result["pushed"] == 2
    run = db.query(PipelineRun).one()
    assert run.trigger == "beat" and run.status == "success"
    assert run.enrich_attempts == 2 and run.confirmed == 2 and run.pushed == 2
    assert run.files["yaml"]["exists"] is True
    assert run.files["yaml"]["count"] == 2
    assert run.files["yaml"]["size"] == (tmp_path / "intel.yaml").stat().st_size
    assert len(run.files["yaml"]["sha256"]) == 64
    assert run.files["zip"]["exists"] is True
    # 规则清单可在文件被网闸取走后追溯当批发了什么
    assert sorted(r["value"] for r in run.rules) == ["e0.com", "e1.com"]


def test_pipeline_records_failure_and_reraises(db, monkeypatch, tmp_path):
    from app.models import PipelineRun
    import pytest

    db.add(AppConfig(key="WHOISXML_API_KEY", value="k"))
    db.add(AppConfig(key="IOC_OUTPUT_DIR", value=str(tmp_path)))
    db.commit()

    def boom(db, max_pulses=None):
        raise RuntimeError("OTX 炸了")

    monkeypatch.setattr(daily_pipeline, "sync_otx_direct", boom)
    monkeypatch.setattr(daily_pipeline, "_candidates_by_type", boom)

    with pytest.raises(RuntimeError):
        run_daily_pipeline(db, target=1, max_enrich=1)

    run = db.query(PipelineRun).one()
    assert run.status == "failed"
    assert "OTX 炸了" in run.reason


def test_run_log_failure_never_loses_the_rule_file(db, make_indicator, monkeypatch, tmp_path):
    """日志写不进去,也绝不能让已经落地的规则文件白写。"""
    db.add(AppConfig(key="WHOISXML_API_KEY", value="k"))
    db.add(AppConfig(key="IOC_OUTPUT_DIR", value=str(tmp_path)))
    db.add(make_indicator(value="e.com", normalized_value="e.com", normalized_type="domain",
                          severity="high", confidence=90, tags=[{"name": "source:otx"}]))
    db.commit()
    _mute_io(monkeypatch)
    monkeypatch.setattr(daily_pipeline, "query_whoisxml",
                        lambda key, ioc: {"results": [{"threatType": "malware"}]})

    def broken_record(db, **kw):
        raise RuntimeError("落库失败")

    monkeypatch.setattr(daily_pipeline, "record_run", broken_record)

    result = run_daily_pipeline(db, target=1, max_enrich=5)

    assert result["status"] == "success" and result["pushed"] == 1
    assert (tmp_path / "intel.yaml").exists()
