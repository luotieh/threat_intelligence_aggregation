import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test_intel.db")
os.environ.setdefault("TA_NODE_BASE_URL", "http://ta-node.test")

import pytest

from app.db import Base, SessionLocal, engine
from app.models import AppConfig, IntelIndicator, SyncState


@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        db.query(IntelIndicator).delete()
        db.query(AppConfig).delete()
        db.query(SyncState).delete()
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
