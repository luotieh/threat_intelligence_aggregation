from pathlib import Path

import pytest
import yaml

from app.models import AppConfig
from app.services.ta_node_client import push_traffic_to_ta_node, save_uploaded_ioc_rule


def add_cfg(db, key, value):
    db.add(AppConfig(key=key, value=value))


def output_cfg(db, tmp_path):
    add_cfg(db, "IOC_OUTPUT_DIR", str(tmp_path))
    add_cfg(db, "IOC_RULE_FILENAME", "intel.yaml")


def test_push_disabled_skips(db, make_indicator, tmp_path):
    add_cfg(db, "TA_NODE_ENABLED", "false")
    output_cfg(db, tmp_path)
    db.add(make_indicator())
    db.commit()
    assert push_traffic_to_ta_node(db)["status"] == "skipped"


def test_generate_writes_ta_node_yaml(db, make_indicator, tmp_path):
    output_cfg(db, tmp_path)
    db.add(make_indicator())
    db.commit()
    result = push_traffic_to_ta_node(db)
    assert result["status"] == "success"

    rule_path = Path(result["rule_file"])
    data = yaml.safe_load(rule_path.read_text())
    assert data["items"][0]["value"] == "evil.example.com"
    assert data["items"][0]["source"] == "Threat Intel Hub"
    assert {"id", "type", "value", "category", "severity", "source", "enabled"} <= set(data["items"][0])


def test_generate_uses_custom_source_name(db, make_indicator, tmp_path):
    output_cfg(db, tmp_path)
    add_cfg(db, "TA_NODE_SOURCE_NAME", "MISP Hub")
    db.add(make_indicator())
    db.commit()
    result = push_traffic_to_ta_node(db)
    data = yaml.safe_load(Path(result["rule_file"]).read_text())
    assert data["items"][0]["source"] == "MISP Hub"


def test_generate_failure_records_error(db, make_indicator, tmp_path, monkeypatch):
    output_cfg(db, tmp_path)
    indicator = make_indicator()
    db.add(indicator)
    db.commit()

    def fail(*args, **kwargs):
        raise RuntimeError("cannot write")

    monkeypatch.setattr("app.services.ta_node_client.write_ta_node_ioc_files", fail)
    result = push_traffic_to_ta_node(db)
    db.refresh(indicator)
    assert result["status"] == "failed"
    assert indicator.push_error == "cannot write"


def test_full_push_includes_all_traffic_ioc(db, make_indicator, tmp_path):
    output_cfg(db, tmp_path)
    add_cfg(db, "TA_NODE_TOP_PER_SOURCE", "0")
    db.add(make_indicator(pushed_to_ta_node=True))
    db.commit()
    result = push_traffic_to_ta_node(db, mode="full")
    assert result["count"] == 1


def test_incremental_push_includes_unpushed_only(db, make_indicator, tmp_path):
    output_cfg(db, tmp_path)
    add_cfg(db, "TA_NODE_TOP_PER_SOURCE", "0")
    db.add(make_indicator(value="a", normalized_value="a", pushed_to_ta_node=True))
    db.add(make_indicator(value="b", normalized_value="b", pushed_to_ta_node=False))
    db.commit()
    result = push_traffic_to_ta_node(db, mode="incremental")
    data = yaml.safe_load(Path(result["rule_file"]).read_text())
    assert result["count"] == 1
    assert data["items"][0]["value"] == "b"


def test_upload_yaml_validates_and_saves(tmp_path):
    content = b"""
items:
  - id: ioc-1
    type: domain
    value: evil.example.com
    category: c2
    severity: high
    source: Threat Intel Hub
    enabled: true
"""
    result = save_uploaded_ioc_rule(str(tmp_path), "intel.yaml", content)
    assert Path(result["rule_file"]).exists()


def test_upload_yaml_rejects_invalid_ta_node_format(tmp_path):
    with pytest.raises(ValueError):
        save_uploaded_ioc_rule(str(tmp_path), "intel.yaml", b"items: [{type: domain}]")


def test_top_per_source_limits_each_source(db, make_indicator, tmp_path):
    output_cfg(db, tmp_path)
    add_cfg(db, "TA_NODE_TOP_PER_SOURCE", "2")
    for i in range(3):
        db.add(make_indicator(value=f"o{i}", normalized_value=f"o{i}",
                              confidence=90 - i, tags=[{"name": "source:otx"}]))
    for i in range(3):
        db.add(make_indicator(value=f"w{i}", normalized_value=f"w{i}",
                              confidence=90 - i, tags=[{"name": "source:whoisxml"}]))
    db.commit()
    result = push_traffic_to_ta_node(db)
    assert result["count"] == 4


def test_top_per_source_zero_keeps_full_behavior(db, make_indicator, tmp_path):
    output_cfg(db, tmp_path)
    add_cfg(db, "TA_NODE_TOP_PER_SOURCE", "0")
    for i in range(3):
        db.add(make_indicator(value=f"o{i}", normalized_value=f"o{i}",
                              tags=[{"name": "source:otx"}]))
    db.commit()
    result = push_traffic_to_ta_node(db, mode="full")
    assert result["count"] == 3


# ---- 磁盘规则文件检查(网闸取走探测)----
def _write_rule_files(tmp_path, count=3):
    items = [{"id": f"i{n}", "type": "domain", "value": f"e{n}.com",
              "category": "c2", "severity": "high", "source": "Threat Intel Hub",
              "enabled": True} for n in range(count)]
    yaml_path = tmp_path / "intel.yaml"
    yaml_path.write_text(yaml.safe_dump({"items": items}, allow_unicode=True), encoding="utf-8")
    return yaml_path


def test_inspect_yaml_present(tmp_path):
    from app.services.ta_node_client import inspect_rule_files
    _write_rule_files(tmp_path, count=5)
    r = inspect_rule_files(str(tmp_path), "intel.yaml")
    assert r["yaml"]["exists"] is True and r["yaml"]["count"] == 5
    assert r["taken_by_gate"] is False


def test_inspect_yaml_missing(tmp_path):
    from app.services.ta_node_client import inspect_rule_files
    r = inspect_rule_files(str(tmp_path), "intel.yaml")
    assert r["yaml"]["exists"] is False
    assert r["taken_by_gate"] is False


def test_inspect_bad_yaml_count_none(tmp_path):
    from app.services.ta_node_client import inspect_rule_files
    (tmp_path / "intel.yaml").write_text("::: not valid yaml :::\n  - [", encoding="utf-8")
    r = inspect_rule_files(str(tmp_path), "intel.yaml")
    assert r["yaml"]["exists"] is True
    assert r["yaml"]["count"] is None
    assert r["yaml"].get("error")


def test_file_status_endpoint_reads_configured_dir(db, tmp_path):
    """端点应按 effective settings 的输出目录扫盘并给出网闸结论。"""
    from app.api.push import ioc_rules_file_status
    add_cfg(db, "IOC_OUTPUT_DIR", str(tmp_path))
    add_cfg(db, "IOC_RULE_FILENAME", "intel.yaml")
    db.commit()
    _write_rule_files(tmp_path, count=7)
    r = ioc_rules_file_status(db)
    assert r["output_dir"] == str(tmp_path)
    assert r["yaml"]["count"] == 7


def test_generate_fills_llm_narrative_before_write(db, make_indicator, tmp_path, monkeypatch):
    """规则生成路径写入前应补齐缺失的 LLM 研判(llm 开启时)。"""
    from app.services import llm as _llm
    output_cfg(db, tmp_path)
    add_cfg(db, "LLM_ENABLED", "true")
    add_cfg(db, "LLM_API_KEY", "k")
    add_cfg(db, "TA_NODE_TOP_PER_SOURCE", "0")
    ind = make_indicator(raw={"Event": {"info": "OTX | Akira"}})
    db.add(ind)
    db.commit()
    monkeypatch.setattr(_llm, "chat_completion",
                        lambda *a, **k: "命中威胁研判,建议阻断并上报,叙述足够长以通过非空校验判定门槛。")
    result = push_traffic_to_ta_node(db, mode="full")
    data = yaml.safe_load(Path(result["rule_file"]).read_text())
    assert data["items"][0]["evidence"].get("narrative")
    db.refresh(ind)
    assert ind.raw.get("narrative")
