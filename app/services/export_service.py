from __future__ import annotations

import csv
import json
from io import StringIO

from sqlalchemy.orm import Session

from app.models import IntelIndicator


def traffic_indicators(db: Session):
    return db.query(IntelIndicator).filter(
        IntelIndicator.platform_category == "traffic",
        IntelIndicator.to_ids.is_(True),
    ).order_by(IntelIndicator.id.asc()).all()


def export_traffic(db: Session, fmt: str) -> tuple[str, str]:
    rows = traffic_indicators(db)
    if fmt == "txt":
        return "text/plain", "\n".join(row.normalized_value or row.value for row in rows) + ("\n" if rows else "")
    if fmt == "csv":
        out = StringIO()
        writer = csv.writer(out)
        writer.writerow(["type", "value", "category", "severity", "tags", "last_seen"])
        for row in rows:
            writer.writerow([
                row.normalized_type or row.misp_type,
                row.normalized_value or row.value,
                row.misp_category or "",
                row.severity or "medium",
                json.dumps(row.tags or [], ensure_ascii=False),
                row.last_seen.isoformat() if row.last_seen else "",
            ])
        return "text/csv", out.getvalue()
    if fmt == "json":
        return "application/json", json.dumps([
            {
                "type": row.normalized_type or row.misp_type,
                "value": row.normalized_value or row.value,
                "category": row.misp_category,
                "severity": row.severity or "medium",
                "tags": row.tags or [],
                "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            }
            for row in rows
        ], ensure_ascii=False)
    raise ValueError("format must be one of txt, csv, json")
