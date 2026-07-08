from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import IntelIndicator

# min_severity -> 参与精选的 severity 集合
SEVERITY_TIERS: dict[str, set[str]] = {
    "high": {"high"},
    "medium": {"high", "medium"},
    "low": {"high", "medium", "low"},
}


def indicator_source(indicator: IntelIndicator) -> str:
    """源识别:tags 中第一个 'source:' 标签值 -> source_org -> 'unknown'。"""
    for tag in indicator.tags or []:
        name = tag.get("name") if isinstance(tag, dict) else str(tag)
        if name and name.lower().startswith("source:"):
            return name.split(":", 1)[1].strip() or "unknown"
    if indicator.source_org:
        return indicator.source_org
    return "unknown"


def _rank_key(indicator: IntelIndicator) -> tuple[int, float]:
    """排序键:confidence DESC(NULL 视为最低),平手按 last_seen DESC(NULL 视为最早)。"""
    confidence = indicator.confidence if indicator.confidence is not None else -1
    last_seen = indicator.last_seen.timestamp() if indicator.last_seen else 0.0
    return (confidence, last_seen)


def select_top_per_source(db: Session, top_n: int, min_severity: str,
                          date_from=None, date_to=None) -> list[dict]:
    """按源分组精选流量侧高危 IOC,每源取前 top_n 条(top_n<=0 表示不截断)。

    date_from/date_to(datetime,可选)按 last_seen 过滤:[date_from, date_to)。
    返回 [{"source": str, "items": list[IntelIndicator]}, ...],分组按 source 名升序。
    """
    allowed = SEVERITY_TIERS.get(min_severity, SEVERITY_TIERS["high"])
    query = db.query(IntelIndicator).filter(
        IntelIndicator.platform_category == "traffic",
        IntelIndicator.to_ids.is_(True),
        IntelIndicator.severity.in_(sorted(allowed)),
    )
    if date_from is not None:
        query = query.filter(IntelIndicator.last_seen >= date_from)
    if date_to is not None:
        query = query.filter(IntelIndicator.last_seen < date_to)
    rows = query.all()
    groups: dict[str, list[IntelIndicator]] = {}
    for row in rows:
        groups.setdefault(indicator_source(row), []).append(row)
    result: list[dict] = []
    for source in sorted(groups):
        items = sorted(groups[source], key=_rank_key, reverse=True)
        if top_n > 0:
            items = items[:top_n]
        result.append({"source": source, "items": items})
    return result
