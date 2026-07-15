from __future__ import annotations

import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.services.ta_node_client import inspect_rule_files

AUDIT_LOG_NAME = "audit.jsonl"


def _resolve_archive_dir(output_dir: str, archive_dir: str | None) -> Path:
    """归档目录:显式给了就用,否则落到 <output_dir>/archive。"""
    if archive_dir:
        return Path(archive_dir)
    return Path(output_dir) / "archive"


def _prune_old_snapshots(archive_dir: Path, retention_days: int, today: datetime) -> list[str]:
    """删除早于 retention_days 的日期子目录(名形如 YYYY-MM-DD)。返回被删目录名。"""
    if retention_days <= 0:
        return []
    cutoff = (today - timedelta(days=retention_days)).date()
    removed = []
    for child in archive_dir.iterdir():
        if not child.is_dir():
            continue
        try:
            day = datetime.strptime(child.name, "%Y-%m-%d").date()
        except ValueError:
            continue  # 非日期目录不动
        if day < cutoff:
            shutil.rmtree(child, ignore_errors=True)
            removed.append(child.name)
    return removed


def archive_rule_files(output_dir: str, filename: str, archive_dir: str | None = None,
                       retention_days: int = 90, now: datetime | None = None) -> dict:
    """把当前 intel.yaml/intel.zip 快照到按日期分的归档目录,并追加一条审计记录。

    - 复用 inspect_rule_files 取磁盘状态(存在性/条数/大小/mtime/是否被网闸取走);
    - 存在的文件拷到 archive_dir/<YYYY-MM-DD>/;缺失的不拷,只如实记录;
    - 向 archive_dir/audit.jsonl 追加一行 JSON;
    - 清理早于 retention_days 的旧快照。
    纯磁盘操作,不读数据库。now 可注入以便测试。
    """
    now = now or datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    arc_dir = _resolve_archive_dir(output_dir, archive_dir)
    arc_dir.mkdir(parents=True, exist_ok=True)

    status = inspect_rule_files(output_dir, filename)
    rule_path = Path(status["output_dir"]) / status["rule_filename"]
    zip_path = Path(status["output_dir"]) / status["zip_filename"]

    day_dir = arc_dir / date_str
    archived = {"yaml": False, "zip": False}
    if status["yaml"]["exists"] or status["zip"]["exists"]:
        day_dir.mkdir(parents=True, exist_ok=True)
        if status["yaml"]["exists"]:
            shutil.copy2(rule_path, day_dir / rule_path.name)
            archived["yaml"] = True
        if status["zip"]["exists"]:
            shutil.copy2(zip_path, day_dir / zip_path.name)
            archived["zip"] = True

    record = {
        "ts": now.isoformat(),
        "date": date_str,
        "output_dir": status["output_dir"],
        "yaml": status["yaml"],
        "zip": status["zip"],
        "consistent": status["consistent"],
        "taken_by_gate": status["taken_by_gate"],
        "verdict": status["verdict"],
        "archived": archived,
        "archive_path": str(day_dir) if (archived["yaml"] or archived["zip"]) else None,
    }

    with (arc_dir / AUDIT_LOG_NAME).open("a", encoding="utf-8") as log:
        log.write(json.dumps(record, ensure_ascii=False) + "\n")

    record["pruned"] = _prune_old_snapshots(arc_dir, retention_days, now)
    return record


def read_audit_log(output_dir: str, archive_dir: str | None = None, limit: int = 30) -> list[dict]:
    """读取最近 limit 条审计记录(按时间倒序:最新在前)。"""
    arc_dir = _resolve_archive_dir(output_dir, archive_dir)
    log = arc_dir / AUDIT_LOG_NAME
    if not log.exists():
        return []
    lines = [ln for ln in log.read_text(encoding="utf-8").splitlines() if ln.strip()]
    out = []
    for ln in reversed(lines[-max(0, limit):]):
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return out
