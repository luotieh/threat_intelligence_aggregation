from app.db import SessionLocal
from app.services.enrichment import enrich_high_severity_indicators
from app.tasks.celery_app import celery_app


@celery_app.task(name="app.tasks.enrich_whoisxml.enrich_whoisxml_task")
def enrich_whoisxml_task():
    db = SessionLocal()
    try:
        return enrich_high_severity_indicators(db)
    finally:
        db.close()
