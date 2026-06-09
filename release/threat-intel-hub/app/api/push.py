from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy.orm import Session

from app.db import SessionLocal, get_db
from app.models import SyncState
from app.schemas.sync import PushRequest
from app.services.config_service import get_effective_settings
from app.services.ta_node_client import pending_and_pushed_counts, push_traffic_to_ta_node

router = APIRouter()


def _push_job(mode: str) -> None:
    db = SessionLocal()
    try:
        push_traffic_to_ta_node(db, mode=mode)
    finally:
        db.close()


@router.post("/push/ta-node")
def push_ta_node(payload: PushRequest, background_tasks: BackgroundTasks):
    background_tasks.add_task(_push_job, payload.mode)
    return {"task_id": "background-ta-node-push", "status": "queued"}


@router.get("/push/ta-node/status")
def push_status(db: Session = Depends(get_db)):
    s = get_effective_settings(db)
    pending, pushed = pending_and_pushed_counts(db)
    state = db.query(SyncState).filter(SyncState.source_name == "ta_node_push").one_or_none()
    return {
        "enabled": s.ta_node_enabled,
        "ta_node_base_url": s.ta_node_base_url,
        "last_success_at": state.last_success_at.isoformat() if state and state.last_success_at else None,
        "last_error": state.error_message if state else None,
        "pending_count": pending,
        "pushed_count": pushed,
    }
