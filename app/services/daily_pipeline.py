from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from app.models import IntelIndicator
from app.services.config_service import get_effective_settings
from app.services.enrichment import ENRICHED_TAG, query_whoisxml
from app.services.otx_source import sync_otx_direct
from app.services.ta_node_client import (
    _safe_rule_path,
    map_indicator_to_ta_node_item,
    write_ta_node_ioc_files,
)

MAX_ROUNDS = 6  # 补拉 OTX 的轮次上限,防无限循环


def _is_enriched(indicator: IntelIndicator) -> bool:
    for tag in indicator.tags or []:
        name = tag.get("name") if isinstance(tag, dict) else str(tag)
        if name == ENRICHED_TAG:
            return True
    return False


def _unenriched_high_traffic(db: Session) -> list[IntelIndicator]:
    rows = (db.query(IntelIndicator)
            .filter(IntelIndicator.severity == "high",
                    IntelIndicator.to_ids.is_(True),
                    IntelIndicator.normalized_type.in_(["domain", "ip"]))
            .all())
    cand = [r for r in rows if not _is_enriched(r)]
    cand.sort(key=lambda i: ((i.confidence if i.confidence is not None else -1),
                             i.last_seen.timestamp() if i.last_seen else 0.0), reverse=True)
    return cand


def _mark_enriched(indicator: IntelIndicator, data: dict) -> bool:
    """写入 whoisxml 结果并打 enriched 标签;返回是否为 WhoisXML 确认(有记录)。"""
    tags = list(indicator.tags or [])
    tags.append({"name": ENRICHED_TAG})
    results = data.get("results") or []
    confirmed = bool(results and results[0].get("threatType"))
    if confirmed:
        tags.append({"name": f'whoisxml:threat="{results[0]["threatType"]}"'})
    indicator.raw = {**(indicator.raw or {}), "whoisxml": data}
    indicator.tags = tags
    return confirmed


def run_daily_pipeline(db: Session, target: int | None = None, max_enrich: int | None = None) -> dict:
    """每日编排:攒够 target 条 WhoisXML 确认的高危流量情报 → LLM 描述 → 推送。

    额度保护:整个流程最多富化 max_enrich 次(默认 16,≈WhoisXML Free 500/月)。
    无记录/失败的不计入,继续补(现有 high 档不足时补拉 OTX),直到达标或触顶。
    """
    s = get_effective_settings(db)
    if not s.whoisxml_api_key:
        return {"status": "skipped", "reason": "WHOISXML_API_KEY 未配置"}
    target = s.pipeline_target if target is None else target
    max_enrich = s.pipeline_max_enrich if max_enrich is None else max_enrich

    log = {"status": "success", "target": target, "max_enrich": max_enrich,
           "enrich_attempts": 0, "confirmed": 0, "narrated": 0, "pushed": 0,
           "otx_pull_rounds": 0, "notes": []}
    confirmed: list[IntelIndicator] = []
    rounds = 0

    # 先直连拉一批 OTX(去误报后入库),保证当天有新的高危候选
    try:
        sync_otx_direct(db, max_pulses=s.otx_max_pulses)
        log["otx_pull_rounds"] = 1
    except Exception as exc:  # noqa: BLE001
        log["notes"].append(f"初始 OTX 拉取异常: {exc}")

    while len(confirmed) < target and log["enrich_attempts"] < max_enrich and rounds < MAX_ROUNDS:
        rounds += 1
        cand = _unenriched_high_traffic(db)
        if not cand:
            sync_otx_direct(db, max_pulses=s.otx_max_pulses)
            log["otx_pull_rounds"] += 1
            cand = _unenriched_high_traffic(db)
            if not cand:
                log["notes"].append("OTX 无更多高危候选,提前结束补足")
                break
        for ind in cand:
            if log["enrich_attempts"] >= max_enrich or len(confirmed) >= target:
                break
            try:
                data = query_whoisxml(s.whoisxml_api_key, ind.normalized_value or ind.value)
                log["enrich_attempts"] += 1
                if _mark_enriched(ind, data):
                    confirmed.append(ind)
            except Exception as exc:  # noqa: BLE001 - 失败不标记 enriched,下次可重试
                log["enrich_attempts"] += 1
                ind.raw = {**(ind.raw or {}), "whoisxml_error": str(exc)}
        db.commit()

    log["confirmed"] = len(confirmed)
    if log["confirmed"] < target:
        log["notes"].append(f"达额度/候选上限,当日仅确认 {log['confirmed']}/{target} 条")

    # LLM 描述(仅对确认的这批,重试补齐,保证每条有叙述)
    if s.llm_enabled and s.llm_api_key:
        from app.services.llm import generate_narrative
        for ind in confirmed[:target]:
            if not (ind.raw or {}).get("narrative"):
                text = generate_narrative(db, ind)
                if text:
                    ind.raw = {**(ind.raw or {}), "narrative": text}
                    log["narrated"] += 1
        db.commit()
        missing = [i for i in confirmed[:target] if not (i.raw or {}).get("narrative")]
        if missing:
            log["notes"].append(f"{len(missing)} 条 LLM 描述重试后仍失败")
    else:
        log["notes"].append("LLM 未启用,跳过描述优化")

    # 推送:这批确认的情报生成 intel.yaml
    push_set = confirmed[:target]
    if push_set:
        now = datetime.now(timezone.utc)
        now_ts = int(now.timestamp())
        items = []
        for ind in push_set:
            item = map_indicator_to_ta_node_item(ind)
            item["source"] = s.ta_node_source_name
            item["updated_at"] = now_ts
            items.append(item)
            ind.pushed_to_ta_node = True
            ind.pushed_at = now
        rule_path = _safe_rule_path(Path(s.ioc_output_dir), s.ioc_rule_filename)
        write_ta_node_ioc_files(rule_path, items)
        db.commit()
        log["pushed"] = len(items)
        log["rule_file"] = str(rule_path)
    return log
