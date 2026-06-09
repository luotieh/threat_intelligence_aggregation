from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy.orm import Session

from app.db import SessionLocal, get_db
from app.services.misp_client import sync_misp_attributes

router = APIRouter()


def _sync_job() -> None:
    db = SessionLocal()
    try:
        sync_misp_attributes(db)
    finally:
        db.close()


@router.post("/sync/misp")
def sync_misp(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    background_tasks.add_task(_sync_job)
    return {"task_id": "background-misp-sync", "status": "queued"}
