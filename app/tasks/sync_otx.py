from app.db import SessionLocal
from app.services.otx_source import sync_otx_to_misp
from app.tasks.celery_app import celery_app


@celery_app.task(name="app.tasks.sync_otx.sync_otx_task")
def sync_otx_task():
    db = SessionLocal()
    try:
        return sync_otx_to_misp(db)
    finally:
        db.close()
