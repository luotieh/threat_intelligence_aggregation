from app.db import SessionLocal
from app.services.ta_node_client import generate_ta_node_ioc_package
from app.tasks.celery_app import celery_app


@celery_app.task(name="app.tasks.push_ta_node.push_ta_node_task")
def push_ta_node_task(mode: str = "incremental"):
    db = SessionLocal()
    try:
        return generate_ta_node_ioc_package(db, mode=mode)
    finally:
        db.close()
