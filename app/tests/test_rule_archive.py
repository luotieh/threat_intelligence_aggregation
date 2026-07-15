import json
import zipfile
from datetime import datetime, timedelta, timezone

import yaml

from app.services.rule_archive import archive_rule_files

TZ = timezone(timedelta(hours=8))  # Asia/Shanghai


def _write_rule_files(out_dir, count=3, make_zip=True):
    out_dir.mkdir(parents=True, exist_ok=True)
    items = [{"id": f"i{n}", "type": "domain", "value": f"e{n}.com",
              "category": "c2", "severity": "high", "source": "Threat Intel Hub",
              "enabled": True} for n in range(count)]
    yaml_path = out_dir / "intel.yaml"
    yaml_path.write_text(yaml.safe_dump({"items": items}, allow_unicode=True), encoding="utf-8")
    if make_zip:
        with zipfile.ZipFile(out_dir / "intel.zip", "w") as z:
            z.write(yaml_path, arcname="intel.yaml")
    return yaml_path


def _log_lines(archive_dir):
    log = archive_dir / "audit.jsonl"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_archive_copies_files_and_writes_log(tmp_path):
    out = tmp_path / "ioc"
    arc = tmp_path / "archive"
    _write_rule_files(out, count=5)
    now = datetime(2026, 7, 15, 23, 30, tzinfo=TZ)
    rec = archive_rule_files(str(out), "intel.yaml", str(arc), retention_days=90, now=now)

    day_dir = arc / "2026-07-15"
    assert (day_dir / "intel.yaml").exists()
    assert (day_dir / "intel.zip").exists()
    assert rec["date"] == "2026-07-15"
    assert rec["yaml"]["count"] == 5
    assert rec["zip"]["count"] == 5
    assert rec["archived"] == {"yaml": True, "zip": True}
    assert rec["taken_by_gate"] is False

    lines = _log_lines(arc)
    assert len(lines) == 1
    assert lines[0]["date"] == "2026-07-15"
    assert lines[0]["yaml"]["count"] == 5


def test_archive_zip_taken_records_gate(tmp_path):
    out = tmp_path / "ioc"
    arc = tmp_path / "archive"
    _write_rule_files(out, count=4)
    (out / "intel.zip").unlink()  # 网闸取走 zip
    now = datetime(2026, 7, 15, 23, 30, tzinfo=TZ)
    rec = archive_rule_files(str(out), "intel.yaml", str(arc), now=now)

    assert rec["taken_by_gate"] is True
    assert rec["archived"] == {"yaml": True, "zip": False}
    assert (arc / "2026-07-15" / "intel.yaml").exists()
    assert not (arc / "2026-07-15" / "intel.zip").exists()
    assert "网闸" in rec["verdict"]


def test_archive_both_missing_no_crash(tmp_path):
    out = tmp_path / "ioc"
    out.mkdir()
    arc = tmp_path / "archive"
    now = datetime(2026, 7, 15, 23, 30, tzinfo=TZ)
    rec = archive_rule_files(str(out), "intel.yaml", str(arc), now=now)

    assert rec["yaml"]["exists"] is False
    assert rec["zip"]["exists"] is False
    assert rec["archived"] == {"yaml": False, "zip": False}
    assert len(_log_lines(arc)) == 1  # 仍写审计日志


def test_archive_appends_multiple_days(tmp_path):
    out = tmp_path / "ioc"
    arc = tmp_path / "archive"
    _write_rule_files(out, count=2)
    archive_rule_files(str(out), "intel.yaml", str(arc),
                       now=datetime(2026, 7, 14, 23, 30, tzinfo=TZ))
    archive_rule_files(str(out), "intel.yaml", str(arc),
                       now=datetime(2026, 7, 15, 23, 30, tzinfo=TZ))
    lines = _log_lines(arc)
    assert len(lines) == 2
    assert [x["date"] for x in lines] == ["2026-07-14", "2026-07-15"]


def test_archive_prunes_old_snapshots(tmp_path):
    out = tmp_path / "ioc"
    arc = tmp_path / "archive"
    _write_rule_files(out, count=1)
    old = arc / "2026-01-01"
    old.mkdir(parents=True)
    (old / "intel.yaml").write_text("stale", encoding="utf-8")
    now = datetime(2026, 7, 15, 23, 30, tzinfo=TZ)
    archive_rule_files(str(out), "intel.yaml", str(arc), retention_days=90, now=now)

    assert not old.exists()                       # 超过 90 天,已清理
    assert (arc / "2026-07-15").exists()          # 当天保留


def test_archive_keeps_within_retention(tmp_path):
    out = tmp_path / "ioc"
    arc = tmp_path / "archive"
    _write_rule_files(out, count=1)
    recent = arc / "2026-07-01"
    recent.mkdir(parents=True)
    (recent / "intel.yaml").write_text("recent", encoding="utf-8")
    now = datetime(2026, 7, 15, 23, 30, tzinfo=TZ)
    archive_rule_files(str(out), "intel.yaml", str(arc), retention_days=90, now=now)

    assert recent.exists()                        # 14 天内,保留


# ---- 端点级 ----
def test_archive_endpoint_and_log(db, tmp_path):
    from app.models import AppConfig
    from app.api.push import ioc_rules_archive, ioc_rules_archive_log
    out = tmp_path / "ioc"
    _write_rule_files(out, count=6)
    db.add(AppConfig(key="IOC_OUTPUT_DIR", value=str(out)))
    db.add(AppConfig(key="IOC_RULE_FILENAME", value="intel.yaml"))
    db.add(AppConfig(key="IOC_ARCHIVE_DIR", value=str(tmp_path / "arc")))
    db.commit()

    rec = ioc_rules_archive(db)
    assert rec["yaml"]["count"] == 6
    assert rec["archived"]["yaml"] is True

    log = ioc_rules_archive_log(limit=10, db=db)
    assert len(log["records"]) == 1
    assert log["records"][0]["yaml"]["count"] == 6
