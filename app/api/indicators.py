from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import IntelIndicator

router = APIRouter()


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
        "tags": row.tags or [],
        "pushed_to_ta_node": row.pushed_to_ta_node,
        "push_error": row.push_error,
        "last_seen": row.last_seen.isoformat() if row.last_seen else None,
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


@router.get("/indicators/{indicator_id}")
def get_indicator(indicator_id: int, db: Session = Depends(get_db)):
    row = db.get(IntelIndicator, indicator_id)
    if row is None:
        raise HTTPException(status_code=404, detail="indicator not found")
    return serialize(row)
