from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from datetime import datetime, timedelta, timezone

from app.db import get_db
from app.models import IntelIndicator
from app.services.config_service import get_effective_settings
from app.services.selection import SEVERITY_TIERS, select_top_per_source

router = APIRouter()


def _whoisxml_summary(raw: dict | None) -> dict | None:
    wx = (raw or {}).get("whoisxml")
    if not isinstance(wx, dict):
        return None
    results = wx.get("results") or []
    if not results:
        return {"checked": True, "threat_type": None}
    top = results[0]
    return {"checked": True, "threat_type": top.get("threatType"),
            "first_seen": top.get("firstSeen"), "last_seen": top.get("lastSeen")}


def serialize(row: IntelIndicator) -> dict:
    return {
        "id": row.id,
        "misp_attribute_uuid": row.misp_attribute_uuid,
        "platform_category": row.platform_category,
        "misp_category": row.misp_category,
        "misp_type": row.misp_type,
        "value": row.value,
        "normalized_type": row.normalized_type,
        "normalized_value": row.normalized_value,
        "to_ids": row.to_ids,
        "severity": row.severity,
        "confidence": row.confidence,
        "tags": row.tags or [],
        "pushed_to_ta_node": row.pushed_to_ta_node,
        "push_error": row.push_error,
        "last_seen": row.last_seen.isoformat() if row.last_seen else None,
        "whoisxml": _whoisxml_summary(row.raw),
        "narrative": (row.raw or {}).get("narrative"),
    }


@router.get("/indicators")
def list_indicators(
    category: str | None = None,
    misp_type: str | None = None,
    value: str | None = None,
    tag: str | None = None,
    pushed_to_ta_node: bool | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    query = db.query(IntelIndicator)
    if category:
        query = query.filter(IntelIndicator.platform_category == category)
    if misp_type:
        query = query.filter(IntelIndicator.misp_type == misp_type)
    if value:
        query = query.filter(IntelIndicator.normalized_value.contains(value))
    if pushed_to_ta_node is not None:
        query = query.filter(IntelIndicator.pushed_to_ta_node.is_(pushed_to_ta_node))
    rows = query.order_by(IntelIndicator.id.desc()).offset(offset).limit(limit).all()
    if tag:
        rows = [row for row in rows if tag in " ".join(str(t) for t in (row.tags or []))]
    return {"items": [serialize(row) for row in rows], "limit": limit, "offset": offset}


def _parse_top_date(value: str | None):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid date, expected YYYY-MM-DD") from exc


@router.get("/indicators/top")
def top_indicators(
    top_per_source: int | None = None,
    min_severity: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    db: Session = Depends(get_db),
):
    s = get_effective_settings(db)
    top_n = s.ta_node_top_per_source if top_per_source is None else top_per_source
    sev = s.ta_node_min_severity if min_severity is None else min_severity
    if sev not in SEVERITY_TIERS:
        raise HTTPException(status_code=422, detail="invalid min_severity")
    df = _parse_top_date(date_from)
    dt = _parse_top_date(date_to)
    dt_excl = dt + timedelta(days=1) if dt else None  # date_to 含当天
    groups = select_top_per_source(db, top_n, sev, date_from=df, date_to=dt_excl)
    return {
        "generated_at": int(datetime.now(timezone.utc).timestamp()),
        "top_per_source": top_n,
        "min_severity": sev,
        "date_from": date_from,
        "date_to": date_to,
        "sources": [
            {"source": g["source"], "count": len(g["items"]),
             "items": [serialize(row) for row in g["items"]]}
            for g in groups
        ],
    }


@router.get("/indicators/{indicator_id}")
def get_indicator(indicator_id: int, db: Session = Depends(get_db)):
    row = db.get(IntelIndicator, indicator_id)
    if row is None:
        raise HTTPException(status_code=404, detail="indicator not found")
    return serialize(row)
