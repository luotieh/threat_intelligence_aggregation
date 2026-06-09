from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class IntelIndicator(Base):
    __tablename__ = "intel_indicator"

    id: Mapped[int] = mapped_column(primary_key=True)
    misp_event_id: Mapped[str | None] = mapped_column(Text)
    misp_event_uuid: Mapped[str | None] = mapped_column(String(64))
    misp_attribute_uuid: Mapped[str | None] = mapped_column(String(64), unique=True)
    platform_category: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    misp_category: Mapped[str | None] = mapped_column(Text)
    misp_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_type: Mapped[str | None] = mapped_column(String(128))
    normalized_value: Mapped[str | None] = mapped_column(Text, index=True)
    to_ids: Mapped[bool] = mapped_column(Boolean, default=False)
    tlp: Mapped[str | None] = mapped_column(String(32))
    confidence: Mapped[int | None] = mapped_column(Integer)
    threat_level: Mapped[str | None] = mapped_column(String(64))
    severity: Mapped[str | None] = mapped_column(String(32))
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_org: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[list | None] = mapped_column(JSON)
    galaxies: Mapped[list | None] = mapped_column(JSON)
    raw: Mapped[dict | None] = mapped_column(JSON)
    pushed_to_ta_node: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    pushed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    push_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


Index("idx_intel_type_value", IntelIndicator.normalized_type, IntelIndicator.normalized_value)
