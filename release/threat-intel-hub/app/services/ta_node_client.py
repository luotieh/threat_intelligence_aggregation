from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Iterable

import httpx
from sqlalchemy.orm import Session

from app.models import IntelIndicator, SyncState
from app.services.config_service import get_effective_settings


TYPE_MAP = {
    "ip-src": "ip",
    "ip-dst": "ip",
    "ip-src|port": "ip_port",
    "ip-dst|port": "ip_port",
    "domain": "domain",
    "domain|ip": "domain",
    "hostname": "domain",
    "hostname|port": "domain",
    "url": "url",
    "uri": "url",
    "user-agent": "user_agent",
    "ja3-fingerprint-md5": "ja3",
    "jarm-fingerprint": "jarm",
    "snort": "rule",
    "zeek": "rule",
    "bro": "rule",
    "pattern-in-traffic": "pattern",
}


def map_indicator_to_ta_node_item(indicator: IntelIndicator) -> dict:
    value = indicator.normalized_value or indicator.value
    item_id = indicator.misp_attribute_uuid or hashlib.sha256(f"{indicator.misp_type}:{value}".encode()).hexdigest()
    return {
        "id": item_id,
        "type": TYPE_MAP.get(indicator.misp_type, "pattern"),
        "value": value,
        "category": derive_category(indicator),
        "severity": indicator.severity or "medium",
        "enabled": bool(indicator.to_ids and indicator.platform_category == "traffic"),
    }


def derive_category(indicator: IntelIndicator) -> str:
    tags = indicator.tags or []
    text = " ".join(tag.get("name", "") if isinstance(tag, dict) else str(tag) for tag in tags).lower()
    for candidate in ("c2", "phishing", "malware", "botnet", "scanner"):
        if candidate in text:
            return candidate
    return (indicator.misp_category or "misp").lower().replace(" ", "_")


def push_traffic_to_ta_node(db: Session, mode: str = "incremental", batch_size: int = 5000) -> dict:
    s = get_effective_settings(db)
    state = _state(db)
    if not s.ta_node_enabled:
        state.status = "skipped"
        state.error_message = None
        db.commit()
        return {"status": "skipped", "reason": "TA_NODE_ENABLED is false"}

    query = db.query(IntelIndicator).filter(
        IntelIndicator.platform_category == "traffic",
        IntelIndicator.to_ids.is_(True),
    )
    if mode != "full":
        query = query.filter(IntelIndicator.pushed_to_ta_node.is_(False))
    indicators = query.limit(batch_size).all()
    items = [map_indicator_to_ta_node_item(indicator) for indicator in indicators]
    headers = {"Content-Type": "application/json"}
    if s.ta_node_token:
        headers["Authorization"] = f"Bearer {s.ta_node_token}"

    try:
        with httpx.Client(timeout=20) as client:
            response = client.post(
                f"{s.ta_node_base_url}/api/v1/intel/sync-source",
                headers=headers,
                json={"source": s.ta_node_source_name, "items": items},
            )
            response.raise_for_status()
    except Exception as exc:
        message = str(exc)
        for indicator in indicators:
            indicator.push_error = message
        state.status = "failed"
        state.error_message = message
        db.commit()
        return {"status": "failed", "error": message, "count": len(items)}

    now = datetime.now(timezone.utc)
    for indicator in indicators:
        indicator.pushed_to_ta_node = True
        indicator.pushed_at = now
        indicator.push_error = None
    state.status = "success"
    state.error_message = None
    state.last_success_at = now
    db.commit()
    return {"status": "success", "count": len(items)}


def pending_and_pushed_counts(db: Session) -> tuple[int, int]:
    pending = db.query(IntelIndicator).filter(
        IntelIndicator.platform_category == "traffic",
        IntelIndicator.to_ids.is_(True),
        IntelIndicator.pushed_to_ta_node.is_(False),
    ).count()
    pushed = db.query(IntelIndicator).filter(IntelIndicator.pushed_to_ta_node.is_(True)).count()
    return pending, pushed


def _state(db: Session) -> SyncState:
    state = db.query(SyncState).filter(SyncState.source_name == "ta_node_push").one_or_none()
    if state is None:
        state = SyncState(source_name="ta_node_push")
        db.add(state)
    return state
