from celery import Celery
from celery.schedules import crontab

from app.config import settings

celery_app = Celery("threat_intel_hub", broker=settings.redis_url, backend=settings.redis_url)

# 定点调度按本地时区(用户在 Asia/Shanghai)
celery_app.conf.timezone = "Asia/Shanghai"
celery_app.conf.enable_utc = False

celery_app.conf.beat_schedule = {
    # 每日 23:00 编排:直连拉 OTX(去误报)→ WhoisXML 富化补足 → LLM 描述 → 推送
    # OTX 已直连平台,不再需要 MISP 中转与 sync-misp 定时
    "daily-pipeline": {
        "task": "app.tasks.daily_pipeline.daily_pipeline_task",
        "schedule": crontab(hour=23, minute=0),
    },
}
