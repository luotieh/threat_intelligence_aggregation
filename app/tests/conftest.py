import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test_intel.db")
os.environ.setdefault("TA_NODE_BASE_URL", "http://ta-node.test")

import pytest

from app.db import Base, SessionLocal, engine
from app.models import IntelIndicator  # noqa: F401 - 让 make_indicator 可用并确保模型已注册


@pytest.fixture(autouse=True)
def clean_db():
    """按 metadata 清空所有表 —— 新增模型无需改这里,避免遗漏导致用例间数据泄漏。"""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        for table in reversed(Base.metadata.sorted_tables):  # 反序:先子后父,避开外键
            db.execute(table.delete())
        db.commit()
    finally:
        db.close()
    yield


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def make_indicator():
    def factory(**kwargs):
        defaults = {
            "platform_category": "traffic",
            "misp_type": "domain",
            "misp_category": "Network activity",
            "value": "evil.example.com",
            "normalized_type": "domain",
            "normalized_value": "evil.example.com",
            "to_ids": True,
            "severity": "high",
            "tags": [{"name": "c2"}],
        }
        defaults.update(kwargs)
        return IntelIndicator(**defaults)

    return factory
