from celery import Celery

from app.config import settings

celery_app = Celery("threat_intel_hub", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.beat_schedule = {
    "sync-misp": {
        "task": "app.tasks.sync_misp.sync_misp_task",
        "schedule": settings.misp_sync_interval_seconds,
    },
    "push-ta-node": {
        "task": "app.tasks.push_ta_node.push_ta_node_task",
        "schedule": settings.ta_node_push_interval_seconds,
    },
    "enrich-whoisxml": {
        "task": "app.tasks.enrich_whoisxml.enrich_whoisxml_task",
        "schedule": settings.whoisxml_enrich_interval_seconds,
    },
    "sync-otx": {
        "task": "app.tasks.sync_otx.sync_otx_task",
        "schedule": settings.otx_sync_interval_seconds,
    },
}
