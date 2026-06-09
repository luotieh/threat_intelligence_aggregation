from __future__ import annotations

from datetime import datetime, timezone

import httpx
from sqlalchemy.orm import Session

from app.models import SyncState
from app.services.config_service import get_effective_settings
from app.services.indicator_service import upsert_indicator
from app.services.ta_node_client import push_traffic_to_ta_node


def check_misp_health(db: Session) -> dict:
    s = get_effective_settings(db)
    try:
        headers = {"Authorization": s.misp_api_key, "Accept": "application/json"}
        with httpx.Client(timeout=10, verify=s.misp_verify_cert) as client:
            response = client.get(f"{s.misp_url.rstrip('/')}/servers/getVersion", headers=headers)
            response.raise_for_status()
        return {"status": "ok", "misp_url": s.misp_url}
    except Exception as exc:
        return {"status": "failed", "error": str(exc)}


def sync_misp_attributes(db: Session) -> dict:
    state = _state(db)
    s = get_effective_settings(db)
    timestamp = state.last_timestamp or "24h"
    try:
        attributes = _fetch_attributes(s, timestamp)
        for attribute in attributes:
            upsert_indicator(db, attribute)
        now = datetime.now(timezone.utc)
        state.last_timestamp = str(int(now.timestamp()))
        state.last_success_at = now
        state.status = "success"
        state.error_message = None
        db.commit()
        push_result = push_traffic_to_ta_node(db)
        return {"status": "success", "count": len(attributes), "push": push_result}
    except Exception as exc:
        state.status = "failed"
        state.error_message = str(exc)
        db.commit()
        return {"status": "failed", "error": str(exc)}


def _fetch_attributes(settings, timestamp: str) -> list[dict]:
    try:
        from pymisp import PyMISP
    except ImportError as exc:
        raise RuntimeError("PyMISP is not installed") from exc
    misp = PyMISP(settings.misp_url, settings.misp_api_key, ssl=settings.misp_verify_cert)
    result = misp.search(
        controller="attributes",
        published=True,
        to_ids=True,
        enforceWarninglist=True,
        timestamp=timestamp,
        pythonify=False,
    )
    if isinstance(result, dict):
        result = result.get("Attribute") or result.get("response", {}).get("Attribute") or []
    return list(result or [])


def _state(db: Session) -> SyncState:
    state = db.query(SyncState).filter(SyncState.source_name == "misp").one_or_none()
    if state is None:
        state = SyncState(source_name="misp")
        db.add(state)
    return state
