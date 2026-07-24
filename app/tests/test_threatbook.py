"""微步研判(ThreatBook)链路的测试:核心映射、规则结构校验、API 端点。

网络调用一律 monkeypatch 掉,不依赖真实 ThreatBook 账号。
"""

import pytest
import yaml

from app.services.threatbook import (
    build_intel_yaml,
    map_hit,
    parse_ips,
    summarize,
)
from app.services.ta_node_client import validate_ta_node_yaml


MALICIOUS_C2 = {
    "is_malicious": True,
    "severity": "critical",
    "confidence_level": "high",
    "judgments": ["C2"],
    "tags_classes": [{"tags_type": "virus_family", "tags": ["CobaltStrike"]}],
    "update_time": "2026-07-19 12:00:00",
    "permalink": "https://x.threatbook.com/v5/ip/203.0.113.10",
}
MALICIOUS_SCANNER = {
    "is_malicious": True,
    "severity": "medium",
    "confidence_level": "medium",
    "judgments": ["Scanner"],
    "tags_classes": [],
    "update_time": "2026-07-18 08:00:00",
}
BENIGN = {"is_malicious": False, "severity": "info", "judgments": ["Whitelist"], "tags_classes": []}


def test_parse_ips_filters_and_dedups():
    ips, skipped = parse_ips(["1.2.3.4", "# comment", "", "bad value", "1.2.3.4", "10.0.0.1"])
    assert ips == ["1.2.3.4", "10.0.0.1"]
    assert skipped == ["bad value"]


def test_map_hit_c2_critical_is_high_and_report():
    mapped = map_hit(MALICIOUS_C2)
    assert mapped == {"category": "c2", "severity": "high", "recommended_action": "block_and_report"}


def test_map_hit_scanner_medium_is_block():
    mapped = map_hit(MALICIOUS_SCANNER)
    assert mapped["category"] == "scanner"
    assert mapped["severity"] == "medium"
    assert mapped["recommended_action"] == "block"


def test_map_hit_unknown_judgment_falls_back_to_malware():
    hit = {"is_malicious": True, "severity": "low", "judgments": ["SomeNewType"]}
    assert map_hit(hit)["category"] == "malware"


def test_summarize_item_passes_platform_validator():
    items = [summarize("203.0.113.10", MALICIOUS_C2), summarize("203.0.113.11", MALICIOUS_SCANNER)]
    text = build_intel_yaml(items)
    validate_ta_node_yaml(text.encode())  # 平台自己的 schema 校验
    parsed = yaml.safe_load(text)
    assert len(parsed["items"]) == 2
    c2 = parsed["items"][0]
    assert c2["type"] == "ip" and c2["value"] == "203.0.113.10"
    assert c2["category"] == "c2" and c2["severity"] == "high" and c2["enabled"] is True
    assert "source:threatbook" in c2["tags"]
    assert c2["evidence"]["permalink"].endswith("/203.0.113.10")


# ---- API 端点 ----

def _query_endpoint(monkeypatch, db, ips_text, hits):
    from app.api.threatbook import QueryRequest, threatbook_query

    monkeypatch.setenv("THREATBOOK_API_KEY", "test-key")
    monkeypatch.setattr("app.api.threatbook.query_ip_info", lambda key, ips: hits)
    return threatbook_query(QueryRequest(ips_text=ips_text), db)


def test_query_endpoint_maps_results(monkeypatch, db):
    hits = {"203.0.113.10": MALICIOUS_C2, "8.8.8.8": BENIGN}
    resp = _query_endpoint(monkeypatch, db, "203.0.113.10\n8.8.8.8", hits)
    assert resp["total"] == 2 and resp["malicious"] == 1 and resp["benign"] == 1
    item = resp["results"][0]
    assert item["category"] == "c2" and item["hit"] is MALICIOUS_C2  # hit 原样保留供回传


def test_query_endpoint_requires_key(monkeypatch, db):
    from fastapi import HTTPException
    from app.api.threatbook import QueryRequest, threatbook_query

    monkeypatch.delenv("THREATBOOK_API_KEY", raising=False)
    with pytest.raises(HTTPException) as exc:
        threatbook_query(QueryRequest(ips_text="1.2.3.4"), db)
    assert exc.value.status_code == 400


def test_query_endpoint_batch_failure_isolated(monkeypatch, db):
    from app.api.threatbook import threatbook_query, QueryRequest

    monkeypatch.setenv("THREATBOOK_API_KEY", "test-key")

    def boom(key, ips):
        raise RuntimeError("quota exceeded")

    monkeypatch.setattr("app.api.threatbook.query_ip_info", boom)
    resp = threatbook_query(QueryRequest(ips_text="1.2.3.4"), db)
    assert resp["failed_batches"] == 1 and resp["errors"] == 1
    assert resp["results"][0]["error"] == "quota exceeded"


def test_generate_endpoint_only_malicious(monkeypatch, db):
    from app.api.threatbook import GenerateRequest, threatbook_generate

    results = [
        {"ip": "203.0.113.10", "is_malicious": True, "hit": MALICIOUS_C2},
        {"ip": "8.8.8.8", "is_malicious": False, "hit": BENIGN},
        {"ip": "9.9.9.9", "error": "接口未返回该 IP 的结果"},
    ]
    resp = threatbook_generate(GenerateRequest(results=results))
    body = bytes(resp.body).decode()
    validate_ta_node_yaml(body.encode())
    parsed = yaml.safe_load(body)
    assert [i["value"] for i in parsed["items"]] == ["203.0.113.10"]
    assert resp.headers["content-disposition"].startswith("attachment")


def test_config_roundtrip_threatbook_key(db):
    from app.models import AppConfig
    from app.schemas.config import ConfigPayload
    from app.services.config_service import public_config, save_config

    save_config(db, ConfigPayload(threatbook_api_key="secret").model_dump(exclude_unset=True))
    data = public_config(db)
    assert data["threatbook_api_key_masked"] is True
    assert "secret" not in str(data)
    row = db.query(AppConfig).filter(AppConfig.key == "THREATBOOK_API_KEY").one()
    assert row.encrypted is True
