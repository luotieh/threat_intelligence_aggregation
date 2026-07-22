#!/usr/bin/env python3
"""导出最近 N 次流水线产生的规则文件到本地目录。

用法（在服务器上或有DB访问的环境）:
  cd /path/to/threat-intel-hub
  python3 scripts/export_pipeline_rules.py --runs 6 --out ./pipeline_exports

输出:
  pipeline_exports/
    run_001_20260721_2300_pushed5.yaml
    run_001_20260721_2300_pushed5.zip
    run_002_...
"""
import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db import SessionLocal
from app.services.run_log import list_runs


def build_rule_yaml(rules: list[dict]) -> str:
    items = []
    for r in rules:
        item = {
            "id": r.get("rule_id", ""),
            "type": r.get("type", "ip"),
            "value": r.get("value", ""),
            "category": r.get("category", ""),
            "severity": r.get("severity", "high"),
            "source": "Threat Intel Hub (exported)",
            "description": r.get("narrative", "") or r.get("value", ""),
            "tags": [],
            "enabled": True,
        }
        items.append(item)
    import yaml
    return yaml.safe_dump({"items": items}, sort_keys=False, allow_unicode=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=6, help="导出最近 N 次(默认6)")
    parser.add_argument("--out", default="pipeline_exports", help="输出目录")
    parser.add_argument("--zip", action="store_true", help="同时生成 zip")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        runs = list_runs(db, args.runs)
    finally:
        db.close()

    if not runs:
        print("没有找到流水线运行记录")
        return

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    for i, run in enumerate(runs):
        rules = run.rules or []
        if not rules:
            print(f"  skip #{run.id}: 无规则")
            continue

        ts = run.started_at.strftime("%Y%m%d_%H%M") if run.started_at else "unknown"
        prefix = f"run_{i+1:03d}_{ts}_pushed{run.pushed or 0}"

        yaml_text = build_rule_yaml(rules)
        yaml_path = out_dir / f"{prefix}.yaml"
        yaml_path.write_text(yaml_text, encoding="utf-8")
        print(f"  #{run.id} → {yaml_path}  ({len(rules)} 条)")

        if args.zip:
            import io, zipfile
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr(f"{prefix}.yaml", yaml_text)
            zip_path = out_dir / f"{prefix}.zip"
            zip_path.write_bytes(buf.getvalue())
            print(f"         → {zip_path}")

    print(f"\n完成: {out_dir.absolute()}")


if __name__ == "__main__":
    main()
