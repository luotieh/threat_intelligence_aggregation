from app.db import SessionLocal
from app.services.config_service import get_effective_settings
from app.services.rule_archive import archive_rule_files
from app.tasks.celery_app import celery_app


@celery_app.task(name="app.tasks.rule_archive.rule_archive_task")
def rule_archive_task():
    db = SessionLocal()
    try:
        s = get_effective_settings(db)
        return archive_rule_files(
            s.ioc_output_dir, s.ioc_rule_filename,
            archive_dir=s.ioc_archive_dir or None,
            retention_days=s.ioc_archive_retention_days,
        )
    finally:
        db.close()
