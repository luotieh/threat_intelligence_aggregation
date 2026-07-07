from celery import Celery
from celery.schedules import crontab

from app.config import settings

celery_app = Celery("threat_intel_hub", broker=settings.redis_url, backend=settings.redis_url)

# 定点调度按本地时区(用户在 Asia/Shanghai)
celery_app.conf.timezone = "Asia/Shanghai"
celery_app.conf.enable_utc = False

celery_app.conf.beat_schedule = {
    # 常规:每 10 分钟把 MISP(feeds/OTX)增量同步进平台表
    "sync-misp": {
        "task": "app.tasks.sync_misp.sync_misp_task",
        "schedule": settings.misp_sync_interval_seconds,
    },
    # 每日 23:00 编排:拉 OTX → WhoisXML 富化补足 → LLM 描述 → 推送
    # (统一流程,取代独立的 sync-otx / enrich-whoisxml / push-ta-node 定时,避免重复烧额度与覆盖)
    "daily-pipeline": {
        "task": "app.tasks.daily_pipeline.daily_pipeline_task",
        "schedule": crontab(hour=23, minute=0),
    },
}
