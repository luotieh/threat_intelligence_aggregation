from app.db import SessionLocal
from app.services.misp_client import sync_misp_attributes
from app.tasks.celery_app import celery_app


@celery_app.task(name="app.tasks.sync_misp.sync_misp_task")
def sync_misp_task():
    db = SessionLocal()
    try:
        return sync_misp_attributes(db)
    finally:
        db.close()
