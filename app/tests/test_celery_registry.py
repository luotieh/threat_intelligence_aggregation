"""守护 Celery 任务注册表。

历史故障:celery_app.py 只建实例不 import 任务模块,worker 启动后注册表为空,
beat 按名字发的定时任务全部 "Received unregistered task" 被丢弃(静默失效)。
这些用例保证 `celery -A app.tasks.celery_app.celery_app` 能加载到全部任务。
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from app.tasks.celery_app import TASK_MODULES, celery_app

# beat_schedule 之外也全量覆盖:API 可用 .delay() 触发任意一个
EXPECTED_TASKS = [
    "app.tasks.daily_pipeline.daily_pipeline_task",
    "app.tasks.enrich_whoisxml.enrich_whoisxml_task",
    "app.tasks.push_ta_node.push_ta_node_task",
    "app.tasks.sync_otx.sync_otx_task",
    "app.tasks.sync_misp.sync_misp_task",
]

# worker 启动时执行的正是 loader.import_default_modules();裸 import celery_app
# 不会加载 include 里的模块,所以断言前必须走同一条路径,否则测试是假绿。
_WORKER_BOOT = (
    "from app.tasks.celery_app import celery_app;"
    "celery_app.loader.import_default_modules();"
)


def test_include_covers_every_task_module() -> None:
    assert set(celery_app.conf.include) == set(TASK_MODULES)


def test_worker_boot_registers_every_task() -> None:
    """另起解释器复刻 worker 的加载路径。

    同进程内其它测试可能已 import 过任务模块,让注册表"看起来"是满的 —— 那样就测不出
    include 缺失这个原始故障了。子进程保证从干净状态开始。
    """
    code = _WORKER_BOOT + (
        f"missing=[n for n in {EXPECTED_TASKS!r} if n not in celery_app.tasks];"
        "print('RESULT:' + __import__('json').dumps(missing))"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0, f"worker 加载任务模块时崩溃:\n{out.stderr}"
    missing = json.loads(out.stdout.split("RESULT:")[1])
    assert not missing, f"worker 加载后仍缺失任务: {missing}"


@pytest.mark.parametrize("module", TASK_MODULES)
def test_task_module_imports_cleanly(module: str) -> None:
    """任一模块 import 失败都会让 worker 启动即崩(比不注册更糟:全量停摆)。"""
    out = subprocess.run([sys.executable, "-c", f"import {module}"], capture_output=True, text=True)
    assert out.returncode == 0, f"{module} 无法 import:\n{out.stderr}"


def test_every_beat_schedule_entry_is_registered() -> None:
    """beat 按字符串发任务,不 import 也能发出去 —— 必须逐条核对 worker 认得。"""
    code = _WORKER_BOOT + (
        "names=[c['task'] for c in celery_app.conf.beat_schedule.values()];"
        "missing=[n for n in names if n not in celery_app.tasks];"
        "print('RESULT:' + __import__('json').dumps(missing))"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    missing = json.loads(out.stdout.split("RESULT:")[1])
    assert not missing, f"beat 排程指向未注册任务: {missing}"
