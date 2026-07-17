from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from app.models import IntelIndicator, PipelineRun
from app.services.run_log import (
    collect_file_facts,
    list_runs,
    record_run,
    rule_manifest,
)

T0 = datetime(2026, 7, 17, 2, 27, 0, tzinfo=timezone.utc)


def _indicator(value="evil.com", ntype="domain", raw=None):
    return IntelIndicator(platform_category="traffic", misp_type=ntype, value=value,
                          normalized_type=ntype, normalized_value=value, to_ids=True,
                          severity="high", raw=raw or {})


def test_collect_file_facts_records_size_and_hash(tmp_path):
    rule = tmp_path / "intel.yaml"
    rule.write_bytes(b"items: []\n")
    (tmp_path / "intel.zip").write_bytes(b"PK-fake")

    facts = collect_file_facts(rule, count=10)

    assert facts["yaml"]["exists"] is True
    assert facts["yaml"]["count"] == 10
    assert facts["yaml"]["size"] == len(b"items: []\n")
    assert facts["yaml"]["sha256"] == hashlib.sha256(b"items: []\n").hexdigest()
    assert facts["zip"]["exists"] is True
    assert facts["zip"]["sha256"] == hashlib.sha256(b"PK-fake").hexdigest()


def test_collect_file_facts_missing_zip_does_not_raise(tmp_path):
    rule = tmp_path / "intel.yaml"
    rule.write_bytes(b"items: []\n")

    facts = collect_file_facts(rule, count=1)

    assert facts["yaml"]["exists"] is True
    assert facts["zip"]["exists"] is False
    assert "sha256" not in facts["zip"]


def test_rule_manifest_marks_narrated_and_confirmed():
    a = _indicator("a.com", raw={"narrative": "有描述"})
    b = _indicator("b.com", raw={"whoisxml": {"results": [{"threatType": "malware"}]}})

    manifest = rule_manifest([a, b])

    assert manifest[0] == {"type": "domain", "value": "a.com",
                           "narrated": True, "whoisxml_confirmed": False}
    assert manifest[1]["narrated"] is False
    assert manifest[1]["whoisxml_confirmed"] is True


def test_record_run_persists_all_stage_facts(db):
    log = {"target": 10, "type_quota": {"ip": 6, "domain": 2, "url": 2},
           "otx_pull_rounds": 1, "enrich_attempts": 16, "confirmed": 4,
           "confirmed_by_type": {"ip": 2, "domain": 1, "url": 1}, "otx_only": 6,
           "narrative": {"status": "success", "generated": 9, "failed": 1, "missing": 1},
           "pushed": 10, "pushed_by_type": {"ip": 6, "domain": 2, "url": 2},
           "notes": ["WhoisXML 额度耗尽"]}

    run = record_run(db, trigger="beat", status="success", started_at=T0, log=log,
                     files={"yaml": {"exists": True}}, rules=[{"value": "a.com"}],
                     now=T0 + timedelta(seconds=42))

    assert run.id is not None
    assert run.trigger == "beat" and run.status == "success"
    assert run.duration_ms == 42_000
    assert run.enrich_attempts == 16 and run.confirmed == 4 and run.otx_only == 6
    # narrative 的三个数都要落库,不能只留 generated
    assert (run.narrated, run.narrate_failed, run.narrate_missing) == (9, 1, 1)
    assert run.pushed_by_type == {"ip": 6, "domain": 2, "url": 2}
    assert run.notes == ["WhoisXML 额度耗尽"]


def test_record_run_for_skipped_keeps_reason(db):
    run = record_run(db, trigger="manual", status="skipped", started_at=T0,
                     reason="WHOISXML_API_KEY 未配置", now=T0)

    assert run.status == "skipped"
    assert run.reason == "WHOISXML_API_KEY 未配置"
    assert run.pushed is None


def test_list_runs_returns_newest_first(db):
    for i in range(3):
        record_run(db, trigger="beat", status="success", started_at=T0 + timedelta(hours=i),
                   log={"pushed": i}, now=T0 + timedelta(hours=i, seconds=1))

    runs = list_runs(db, limit=10)

    assert [r["pushed"] for r in runs] == [2, 1, 0]


def test_list_runs_honours_limit(db):
    for i in range(5):
        record_run(db, trigger="beat", status="success", started_at=T0, log={"pushed": i}, now=T0)

    assert len(list_runs(db, limit=2)) == 2


def test_list_runs_empty_when_never_run(db):
    assert list_runs(db) == []
    assert db.query(PipelineRun).count() == 0
