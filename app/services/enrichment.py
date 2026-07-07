from __future__ import annotations

import os
from datetime import datetime, timezone

import httpx
from sqlalchemy.orm import Session

from app.models import IntelIndicator
from app.services.config_service import get_effective_settings

WHOISXML_TI_URL = "https://threat-intelligence.whoisxmlapi.com/api/v1"
ENRICHED_TAG = "whoisxml:enriched"


def _outbound_proxy() -> str | None:
    """WhoisXML 在公网,容器经 socat 转发器出网(见 OUTBOUND_HTTPS_PROXY)。"""
    return os.environ.get("OUTBOUND_HTTPS_PROXY") or None


def query_whoisxml(api_key: str, ioc: str) -> dict:
    """查询单个 IOC 的威胁画像。size<=100 计 1 credit。"""
    with httpx.Client(timeout=25, proxy=_outbound_proxy()) as client:
        response = client.get(WHOISXML_TI_URL, params={
            "apiKey": api_key, "ioc": ioc, "size": 10, "outputFormat": "JSON",
        })
        response.raise_for_status()
        return response.json()


def _is_enriched(indicator: IntelIndicator) -> bool:
    for tag in indicator.tags or []:
        name = tag.get("name") if isinstance(tag, dict) else str(tag)
        if name == ENRICHED_TAG:
            return True
    return False


def enrich_high_severity_indicators(db: Session, limit: int | None = None) -> dict:
    """每次挑最多 limit 条未富化的 high 档 domain/ip,查 WhoisXML 交叉验证。

    结果写入 indicator.raw['whoisxml'],并打 whoisxml:enriched 与 whoisxml:threat 标签,
    避免重复消耗额度。返回本次富化统计。
    """
    s = get_effective_settings(db)
    if not s.whoisxml_api_key:
        return {"status": "skipped", "reason": "WHOISXML_API_KEY 未配置"}
    limit = s.whoisxml_enrich_limit if limit is None else limit
    if limit <= 0:
        return {"status": "skipped", "reason": "enrich limit <= 0"}

    candidates = (
        db.query(IntelIndicator)
        .filter(
            IntelIndicator.severity == "high",
            IntelIndicator.normalized_type.in_(["domain", "ip"]),
        )
        .order_by(IntelIndicator.last_seen.desc())
        .all()
    )
    todo = [c for c in candidates if not _is_enriched(c)][:limit]

    enriched = failed = confirmed = 0
    now = datetime.now(timezone.utc)
    for indicator in todo:
        try:
            data = query_whoisxml(s.whoisxml_api_key, indicator.normalized_value)
            indicator.raw = {**(indicator.raw or {}), "whoisxml": data}
            tags = list(indicator.tags or [])
            tags.append({"name": ENRICHED_TAG})
            results = data.get("results") or []
            if results and results[0].get("threatType"):
                tags.append({"name": f'whoisxml:threat="{results[0]["threatType"]}"'})
                confirmed += 1
            indicator.tags = tags
            indicator.updated_at = now
            enriched += 1
        except Exception as exc:  # noqa: BLE001 - 记录错误但不中断整批
            indicator.raw = {**(indicator.raw or {}), "whoisxml_error": str(exc)}
            failed += 1
    db.commit()
    return {"status": "success", "queued": len(todo), "enriched": enriched,
            "confirmed_malicious": confirmed, "failed": failed}
