from app.db import SessionLocal
from app.services.daily_pipeline import run_daily_pipeline
from app.tasks.celery_app import celery_app


@celery_app.task(name="app.tasks.daily_pipeline.daily_pipeline_task")
def daily_pipeline_task():
    db = SessionLocal()
    try:
        return run_daily_pipeline(db)
    finally:
        db.close()
