from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

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
from app.services.type_quota import parse_ratio, type_quotas

MAX_ROUNDS = 6  # 补拉 OTX 的轮次上限,防无限循环

# normalized_type -> 配额类别(ip 类含 ip_port;域名类含 hostname)
TYPE_CLASSES = {"ip": ("ip", "ip_port"), "domain": ("domain", "hostname"), "url": ("url",)}
_CLASS_OF = {t: cls for cls, types in TYPE_CLASSES.items() for t in types}


def _is_enriched(indicator: IntelIndicator) -> bool:
    for tag in indicator.tags or []:
        name = tag.get("name") if isinstance(tag, dict) else str(tag)
        if name == ENRICHED_TAG:
            return True
    return False


def _sort_candidates(rows: list[IntelIndicator]) -> list[IntelIndicator]:
    rows.sort(key=lambda i: ((i.confidence if i.confidence is not None else -1),
                             i.last_seen.timestamp() if i.last_seen else 0.0), reverse=True)
    return rows


def _candidates_by_type(db: Session) -> dict[str, list[IntelIndicator]]:
    """未富化的高危流量候选按 ip/domain/url 三类分组,每类按 confidence/last_seen 降序。"""
    rows = (db.query(IntelIndicator)
            .filter(IntelIndicator.severity == "high",
                    IntelIndicator.to_ids.is_(True),
                    IntelIndicator.normalized_type.in_(list(_CLASS_OF)))
            .all())
    pools: dict[str, list[IntelIndicator]] = {"ip": [], "domain": [], "url": []}
    for r in rows:
        if not _is_enriched(r):
            pools[_CLASS_OF[r.normalized_type]].append(r)
    for lst in pools.values():
        _sort_candidates(lst)
    return pools


def _whoisxml_query_value(indicator: IntelIndicator) -> str:
    """WhoisXML 只吃域名/IP。URL 取其主机名去查(整条 URL 查不到威胁记录)。"""
    value = indicator.normalized_value or indicator.value or ""
    if indicator.normalized_type == "url":
        host = urlsplit(value).hostname or urlsplit("//" + value).hostname
        return host or value
    return value


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
    quota = type_quotas(target, parse_ratio(s.pipeline_type_ratio))

    log = {"status": "success", "target": target, "max_enrich": max_enrich,
           "type_quota": quota, "enrich_attempts": 0, "confirmed": 0,
           "confirmed_by_type": {"ip": 0, "domain": 0, "url": 0},
           "narrated": 0, "pushed": 0, "otx_pull_rounds": 0, "notes": []}
    by_type: dict[str, list[IntelIndicator]] = {"ip": [], "domain": [], "url": []}
    rounds = 0

    def total() -> int:
        return sum(len(v) for v in by_type.values())

    def pick(pools: dict[str, list[IntelIndicator]], ptr: dict[str, int]) -> str | None:
        # 1) 优先填未满配额且仍有候选的类型(先 ip、再 url,domain 留作补口)
        for t in ("ip", "url", "domain"):
            if len(by_type[t]) < quota[t] and ptr[t] < len(pools[t]):
                return t
        # 2) 尽力而为:总数未达标,用还有候选的类型补(优先 domain)
        if total() < target:
            for t in ("domain", "ip", "url"):
                if ptr[t] < len(pools[t]):
                    return t
        return None

    # 先直连拉一批 OTX(去误报后入库),保证当天有新的高危候选
    try:
        sync_otx_direct(db, max_pulses=s.otx_max_pulses)
        log["otx_pull_rounds"] = 1
    except Exception as exc:  # noqa: BLE001
        log["notes"].append(f"初始 OTX 拉取异常: {exc}")

    while total() < target and log["enrich_attempts"] < max_enrich and rounds < MAX_ROUNDS:
        rounds += 1
        pools = _candidates_by_type(db)  # 每轮重取,已富化的自动排除
        ptr = {"ip": 0, "domain": 0, "url": 0}
        progressed = False
        while total() < target and log["enrich_attempts"] < max_enrich:
            t = pick(pools, ptr)
            if t is None:
                break
            ind = pools[t][ptr[t]]
            ptr[t] += 1
            progressed = True
            try:
                data = query_whoisxml(s.whoisxml_api_key, _whoisxml_query_value(ind))
                log["enrich_attempts"] += 1
                if _mark_enriched(ind, data):
                    by_type[t].append(ind)
            except Exception as exc:  # noqa: BLE001 - 失败不标记 enriched,下次可重试
                log["enrich_attempts"] += 1
                ind.raw = {**(ind.raw or {}), "whoisxml_error": str(exc)}
        db.commit()
        if total() >= target or log["enrich_attempts"] >= max_enrich:
            break
        # 本轮候选用尽仍不足 → 补拉 OTX 再来一轮;补不出新候选就收手
        if not progressed:
            sync_otx_direct(db, max_pulses=s.otx_max_pulses)
            log["otx_pull_rounds"] += 1
            if not any(_candidates_by_type(db).values()):
                log["notes"].append("OTX 无更多高危候选,提前结束补足")
                break

    confirmed: list[IntelIndicator] = by_type["ip"] + by_type["domain"] + by_type["url"]
    log["confirmed"] = len(confirmed)
    log["confirmed_by_type"] = {t: len(v) for t, v in by_type.items()}
    for t in ("ip", "url", "domain"):
        if len(by_type[t]) < quota[t]:
            log["notes"].append(f"{t} 类未凑满配额({len(by_type[t])}/{quota[t]}),缺口已由其它类型补足")
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
