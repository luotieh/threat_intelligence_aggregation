from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from app.models import IntelIndicator
from app.services.config_service import get_effective_settings
from app.services.enrichment import ENRICHED_TAG, query_whoisxml
from app.services.otx_source import sync_otx_direct
from app.services.run_log import collect_file_facts, record_run, rule_manifest
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


def _new_candidates_query(db: Session):
    """高危流量候选,排除已出过规则的。

    每日新增语义:发过的不再重复出规则,也不再浪费 WhoisXML 额度去查。
    is_not(True) 而非 is_(False):兼容历史数据里可能的 NULL。
    """
    return (db.query(IntelIndicator)
            .filter(IntelIndicator.severity == "high",
                    IntelIndicator.to_ids.is_(True),
                    IntelIndicator.pushed_to_ta_node.is_not(True),
                    IntelIndicator.normalized_type.in_(list(_CLASS_OF))))


def _candidates_by_type(db: Session) -> dict[str, list[IntelIndicator]]:
    """未富化、未出过规则的高危流量候选按 ip/domain/url 分组,每类按 confidence/last_seen 降序。"""
    pools: dict[str, list[IntelIndicator]] = {"ip": [], "domain": [], "url": []}
    for r in _new_candidates_query(db).all():
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


def _total(by_type: dict[str, list]) -> int:
    return sum(len(v) for v in by_type.values())


def _pick_type(by_type: dict[str, list], quota: dict[str, int],
               pools: dict[str, list], ptr: dict[str, int], target: int) -> str | None:
    """选下一个要处理的类型:先填未满配额且有候选的(ip→url→domain),
    再尽力而为按 domain→ip→url 补足总数。"""
    for t in ("ip", "url", "domain"):
        if len(by_type[t]) < quota[t] and ptr[t] < len(pools[t]):
            return t
    if _total(by_type) < target:
        for t in ("domain", "ip", "url"):
            if ptr[t] < len(pools[t]):
                return t
    return None


def _fallback_fill(db: Session, by_type: dict[str, list], quota: dict[str, int], target: int) -> int:
    """WhoisXML 无法确认时,用高危 OTX 候选(未交叉验证)按同一配额补足 target。返回补入条数。

    同样排除已出过规则的:否则确认不了时每天都会挑中同一批头部候选,规则永不更新。
    """
    selected = {id(i) for lst in by_type.values() for i in lst}
    pools: dict[str, list[IntelIndicator]] = {"ip": [], "domain": [], "url": []}
    for r in _new_candidates_query(db).all():
        if id(r) not in selected:
            pools[_CLASS_OF[r.normalized_type]].append(r)
    for lst in pools.values():
        _sort_candidates(lst)
    ptr = {"ip": 0, "domain": 0, "url": 0}
    added = 0
    while _total(by_type) < target:
        t = _pick_type(by_type, quota, pools, ptr, target)
        if t is None:
            break
        by_type[t].append(pools[t][ptr[t]])
        ptr[t] += 1
        added += 1
    return added


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


def run_daily_pipeline(db: Session, target: int | None = None, max_enrich: int | None = None,
                       trigger: str = "manual") -> dict:
    """每日编排:攒够 target 条 WhoisXML 确认的高危流量情报 → LLM 描述 → 推送。

    额度保护:整个流程最多富化 max_enrich 次(默认 16,≈WhoisXML Free 500/月)。
    无记录/失败的不计入,继续补(现有 high 档不足时补拉 OTX),直到达标或触顶。

    每次运行(含跳过/异常)都落一条 PipelineRun 记录。
    """
    started_at = datetime.now(timezone.utc)
    try:
        return _run_daily_pipeline(db, target, max_enrich, trigger, started_at)
    except Exception as exc:  # noqa: BLE001 - 异常也要留痕,记完再抛
        _safe_record(db, trigger=trigger, status="failed", started_at=started_at,
                     reason=f"{type(exc).__name__}: {exc}")
        raise


def _safe_record(db: Session, **kwargs) -> None:
    """写运行日志失败绝不能连累已经落地的规则文件。"""
    try:
        record_run(db, **kwargs)
    except Exception:  # noqa: BLE001
        db.rollback()


def _run_daily_pipeline(db: Session, target: int | None, max_enrich: int | None,
                        trigger: str, started_at: datetime) -> dict:
    s = get_effective_settings(db)
    if not s.whoisxml_api_key:
        reason = "WHOISXML_API_KEY 未配置"
        _safe_record(db, trigger=trigger, status="skipped", started_at=started_at, reason=reason)
        return {"status": "skipped", "reason": reason}
    target = s.pipeline_target if target is None else target
    max_enrich = s.pipeline_max_enrich if max_enrich is None else max_enrich
    quota = type_quotas(target, parse_ratio(s.pipeline_type_ratio))

    log = {"status": "success", "target": target, "max_enrich": max_enrich,
           "type_quota": quota, "enrich_attempts": 0, "confirmed": 0,
           "confirmed_by_type": {"ip": 0, "domain": 0, "url": 0},
           "narrated": 0, "pushed": 0, "otx_pull_rounds": 0, "notes": []}
    by_type: dict[str, list[IntelIndicator]] = {"ip": [], "domain": [], "url": []}
    rounds = 0

    # 先直连拉一批 OTX(去误报后入库),保证当天有新的高危候选
    try:
        sync_otx_direct(db, max_pulses=s.otx_max_pulses)
        log["otx_pull_rounds"] = 1
    except Exception as exc:  # noqa: BLE001
        log["notes"].append(f"初始 OTX 拉取异常: {exc}")

    while _total(by_type) < target and log["enrich_attempts"] < max_enrich and rounds < MAX_ROUNDS:
        rounds += 1
        pools = _candidates_by_type(db)  # 每轮重取,已富化的自动排除
        ptr = {"ip": 0, "domain": 0, "url": 0}
        progressed = False
        while _total(by_type) < target and log["enrich_attempts"] < max_enrich:
            t = _pick_type(by_type, quota, pools, ptr, target)
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
        if _total(by_type) >= target or log["enrich_attempts"] >= max_enrich:
            break
        # 本轮候选用尽仍不足 → 补拉 OTX 再来一轮;补不出新候选就收手
        if not progressed:
            sync_otx_direct(db, max_pulses=s.otx_max_pulses)
            log["otx_pull_rounds"] += 1
            if not any(_candidates_by_type(db).values()):
                log["notes"].append("OTX 无更多高危候选,提前结束补足")
                break

    # WhoisXML 交叉确认数(此时 by_type 里全是确认过的)
    log["confirmed"] = _total(by_type)
    log["confirmed_by_type"] = {t: len(v) for t, v in by_type.items()}

    # 兜底:确认不足 target(如 WhoisXML 额度耗尽)时,用高危 OTX 单源候选按配额补足
    if _total(by_type) < target:
        added = _fallback_fill(db, by_type, quota, target)
        log["otx_only"] = added
        if _total(by_type) < target:
            # 新候选见底:如实少发,不拿旧规则凑数(已推送的一律不再入选)
            log["notes"].append(
                f"新候选不足,本次仅出规则 {_total(by_type)}/{target} 条(已出过规则的不再重复)")
        if added:
            log["notes"].append(f"WhoisXML 未确认部分用高危 OTX 单源候选补足 {added} 条")

    push_set: list[IntelIndicator] = (by_type["ip"] + by_type["domain"] + by_type["url"])[:target]
    log["pushed_by_type"] = {t: sum(1 for i in push_set if _CLASS_OF.get(i.normalized_type) == t)
                             for t in ("ip", "domain", "url")}
    for t in ("ip", "url", "domain"):
        if log["pushed_by_type"][t] < quota[t]:
            log["notes"].append(f"{t} 类不足配额({log['pushed_by_type'][t]}/{quota[t]}),缺口由其它类型补")

    # LLM 描述:对整批 push_set 补齐,与 WhoisXML 无关,保证每条规则都有研判
    from app.services.llm import ensure_narratives
    narr = ensure_narratives(db, push_set)
    log["narrated"] = narr.get("generated", 0)
    log["narrative"] = narr  # 完整结果(generated/failed/missing)进运行日志
    if narr["status"] == "disabled":
        log["notes"].append("LLM 未启用,跳过描述优化")
    elif narr.get("missing"):
        log["notes"].append(f"{narr['missing']} 条 LLM 描述重试后仍失败")

    # 推送:这批情报生成 intel.yaml
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
        # 写完立刻取事实:网闸可能几十秒内就把文件取走,晚一步就只剩空目录
        files = collect_file_facts(rule_path, len(items))
        rules = rule_manifest(push_set)
    else:
        files, rules = None, []
        log["notes"].append("无可推送情报,未生成规则文件")

    _safe_record(db, trigger=trigger, status="success", started_at=started_at,
                 log=log, files=files, rules=rules)
    return log
