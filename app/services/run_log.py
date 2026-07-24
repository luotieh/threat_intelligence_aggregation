from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from app.models import PipelineRun


def _file_facts(path: Path, count: int | None = None) -> dict:
    """落地文件的客观事实。文件不存在(写失败/已被取走)如实记 exists=False,不抛。"""
    facts: dict = {"name": path.name, "path": str(path), "exists": path.exists()}
    if not facts["exists"]:
        return facts
    try:
        data = path.read_bytes()
        facts["size"] = len(data)
        facts["sha256"] = hashlib.sha256(data).hexdigest()
        facts["mtime"] = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
        if count is not None:
            facts["count"] = count
    except OSError as exc:
        facts["error"] = str(exc)
    return facts


def collect_file_facts(rule_path: Path, count: int) -> dict:
    """写完 yaml 后当场取事实。此刻文件必然还在,不受网闸后续取走影响。"""
    return {"yaml": _file_facts(rule_path, count)}


def rule_manifest(indicators) -> list[dict]:
    """当批规则清单:发了什么、每条有没有 LLM 描述。网闸取走文件后靠它追溯。"""
    out = []
    for ind in indicators:
        raw = ind.raw or {}
        out.append({
            "type": ind.normalized_type,
            "value": ind.normalized_value or ind.value,
            "narrated": bool(raw.get("narrative")),
            "whoisxml_confirmed": bool((raw.get("whoisxml") or {}).get("results")),
        })
    return out


def record_run(db: Session, *, trigger: str, status: str, started_at: datetime,
               reason: str | None = None, log: dict | None = None,
               files: dict | None = None, rules: list[dict] | None = None,
               now: datetime | None = None) -> PipelineRun:
    """落一条运行记录。log 为 run_daily_pipeline 内部的统计字典。

    记录失败绝不能连累已经写好的规则文件,调用方需自行吞异常。now 可注入以便测试。
    """
    log = log or {}
    finished = now or datetime.now(timezone.utc)
    narr = log.get("narrative") or {}
    run = PipelineRun(
        trigger=trigger,
        status=status,
        reason=reason,
        started_at=started_at,
        finished_at=finished,
        duration_ms=int((finished - started_at).total_seconds() * 1000),
        target=log.get("target"),
        type_quota=log.get("type_quota"),
        otx_pull_rounds=log.get("otx_pull_rounds"),
        enrich_attempts=log.get("enrich_attempts"),
        confirmed=log.get("confirmed"),
        confirmed_by_type=log.get("confirmed_by_type"),
        otx_only=log.get("otx_only"),
        narrated=narr.get("generated"),
        narrate_failed=narr.get("failed"),
        narrate_missing=narr.get("missing"),
        pushed=log.get("pushed"),
        pushed_by_type=log.get("pushed_by_type"),
        files=files,
        rules=rules,
        notes=log.get("notes"),
    )
    db.add(run)
    db.commit()
    return run


def serialize_run(run: PipelineRun) -> dict:
    return {
        "id": run.id,
        "trigger": run.trigger,
        "status": run.status,
        "reason": run.reason,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "duration_ms": run.duration_ms,
        "target": run.target,
        "type_quota": run.type_quota,
        "otx_pull_rounds": run.otx_pull_rounds,
        "enrich_attempts": run.enrich_attempts,
        "confirmed": run.confirmed,
        "confirmed_by_type": run.confirmed_by_type,
        "otx_only": run.otx_only,
        "narrated": run.narrated,
        "narrate_failed": run.narrate_failed,
        "narrate_missing": run.narrate_missing,
        "pushed": run.pushed,
        "pushed_by_type": run.pushed_by_type,
        "files": run.files,
        "rules": run.rules,
        "notes": run.notes,
    }


def list_runs(db: Session, limit: int = 30) -> list[dict]:
    """最近的运行记录,最新在前。"""
    rows = (db.query(PipelineRun).order_by(PipelineRun.id.desc()).limit(max(1, limit)).all())
    return [serialize_run(r) for r in rows]
