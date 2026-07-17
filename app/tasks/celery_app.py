from celery import Celery
from celery.schedules import crontab

from app.config import settings

# worker 启动只 import 本模块,不 include 的话任务模块永远不会被 import,
# @celery_app.task 不执行 → 注册表为空 → beat 发来的任务全被 "unregistered" 丢弃。
TASK_MODULES = [
    "app.tasks.daily_pipeline",
    "app.tasks.rule_archive",
    "app.tasks.enrich_whoisxml",
    "app.tasks.push_ta_node",
    "app.tasks.sync_otx",
    "app.tasks.sync_misp",
]

celery_app = Celery("threat_intel_hub", broker=settings.redis_url, backend=settings.redis_url,
                    include=TASK_MODULES)

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
    # 每日 23:30(在生成规则之后)归档 intel.yaml/zip 快照并写审计日志
    "daily-rule-archive": {
        "task": "app.tasks.rule_archive.rule_archive_task",
        "schedule": crontab(hour=23, minute=30),
    },
}
