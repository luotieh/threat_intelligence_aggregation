from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class PipelineRun(Base):
    """一次规则生成的完整运行记录:富化 → LLM 描述 → 写 yaml/zip。

    流水线自己知道每一步的结果,写完文件当场落库。不靠事后扫磁盘反推。
    """

    __tablename__ = "pipeline_run"
    __table_args__ = (Index("idx_pipeline_run_started_at", "started_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    trigger: Mapped[str] = mapped_column(String(32), nullable=False)  # beat / manual
    status: Mapped[str] = mapped_column(String(32), nullable=False)  # success / skipped / failed
    reason: Mapped[str | None] = mapped_column(Text)  # skipped/failed 的原因

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)

    # 目标与配额
    target: Mapped[int | None] = mapped_column(Integer)
    type_quota: Mapped[dict | None] = mapped_column(JSON)  # {"ip":6,"domain":2,"url":2}

    # 各阶段事实
    otx_pull_rounds: Mapped[int | None] = mapped_column(Integer)
    enrich_attempts: Mapped[int | None] = mapped_column(Integer)  # WhoisXML 查询次数(耗额度)
    confirmed: Mapped[int | None] = mapped_column(Integer)  # WhoisXML 交叉确认数
    confirmed_by_type: Mapped[dict | None] = mapped_column(JSON)
    otx_only: Mapped[int | None] = mapped_column(Integer)  # 未确认、用高危 OTX 候选补足的条数
    narrated: Mapped[int | None] = mapped_column(Integer)  # 本次新生成的 LLM 描述数
    narrate_failed: Mapped[int | None] = mapped_column(Integer)
    narrate_missing: Mapped[int | None] = mapped_column(Integer)  # 写入时仍无描述的条数
    pushed: Mapped[int | None] = mapped_column(Integer)
    pushed_by_type: Mapped[dict | None] = mapped_column(JSON)

    # 写文件事实:落地即记,网闸取走后仍可追溯当时发了什么
    files: Mapped[dict | None] = mapped_column(JSON)  # {"yaml":{...},"zip":{...}}
    rules: Mapped[list | None] = mapped_column(JSON)  # [{"type","value","narrated"}...] 当批规则清单
    notes: Mapped[list | None] = mapped_column(JSON)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
