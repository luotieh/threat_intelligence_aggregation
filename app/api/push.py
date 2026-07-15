from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.db import SessionLocal, get_db
from app.models import SyncState
from app.schemas.sync import PushRequest
from app.services.config_service import get_effective_settings
from app.services.ta_node_client import (
    generate_ta_node_ioc_package,
    inspect_rule_files,
    pending_and_pushed_counts,
    save_uploaded_ioc_rule,
)

router = APIRouter()


def _push_job(mode: str) -> None:
    db = SessionLocal()
    try:
        generate_ta_node_ioc_package(db, mode=mode)
    finally:
        db.close()


@router.post("/push/ta-node")
def push_ta_node(payload: PushRequest, background_tasks: BackgroundTasks):
    background_tasks.add_task(_push_job, payload.mode)
    return {"task_id": "background-ioc-rule-generate", "status": "queued"}


@router.post("/ioc-rules/generate")
def generate_ioc_rules(payload: PushRequest, db: Session = Depends(get_db)):
    return generate_ta_node_ioc_package(db, mode=payload.mode)


@router.post("/ioc-rules/upload")
async def upload_ioc_rule(file: UploadFile = File(...), db: Session = Depends(get_db)):
    s = get_effective_settings(db)
    content = await file.read()
    try:
        return save_uploaded_ioc_rule(s.ioc_output_dir, file.filename or s.ioc_rule_filename, content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/ioc-rules/file-status")
def ioc_rules_file_status(db: Session = Depends(get_db)):
    """检查输出目录里 intel.yaml / intel.zip 的实际磁盘状态与条数。

    与 /push/ta-node/status(读数据库计数)不同,本接口直接扫磁盘,
    可判断内网网闸是否已把 zip 取走。
    """
    s = get_effective_settings(db)
    return inspect_rule_files(s.ioc_output_dir, s.ioc_rule_filename)


@router.get("/push/ta-node/status")
def push_status(db: Session = Depends(get_db)):
    s = get_effective_settings(db)
    pending, pushed = pending_and_pushed_counts(db)
    state = db.query(SyncState).filter(SyncState.source_name == "ta_node_push").one_or_none()
    return {
        "enabled": s.ta_node_enabled,
        "output_dir": s.ioc_output_dir,
        "rule_filename": s.ioc_rule_filename,
        "last_success_at": state.last_success_at.isoformat() if state and state.last_success_at else None,
        "last_error": state.error_message if state else None,
        "pending_count": pending,
        "generated_count": pushed,
    }
