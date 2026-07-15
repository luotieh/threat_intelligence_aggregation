from __future__ import annotations

import hashlib
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import yaml
from sqlalchemy.orm import Session

from app.models import IntelIndicator, SyncState
from app.services.config_service import get_effective_settings
from app.services.selection import select_top_per_source


TYPE_MAP = {
    "ip-src": "ip",
    "ip-dst": "ip",
    "ip-src|port": "ip_port",
    "ip-dst|port": "ip_port",
    "domain": "domain",
    "domain|ip": "domain",
    "hostname": "domain",
    "hostname|port": "domain",
    "url": "url",
    "uri": "url",
    "user-agent": "user_agent",
    "ja3-fingerprint-md5": "ja3",
    "jarm-fingerprint": "jarm",
    "snort": "rule",
    "zeek": "rule",
    "bro": "rule",
    "pattern-in-traffic": "pattern",
}


def build_evidence(indicator: IntelIndicator) -> dict:
    """从 raw(MISP 事件)+ tags + whoisxml 提取结构化命中证据,全部可溯源,无 LLM。"""
    raw = indicator.raw or {}
    event = raw.get("Event") or {}
    tags = tag_names(indicator)
    threat_labels = []
    for t in tags:
        if t.startswith("otx:tag="):
            threat_labels.append(t.split("=", 1)[1].strip('"'))
        elif not t.startswith(("tlp:", "source:", "type:", "whoisxml:", "misp:")):
            threat_labels.append(t)
    wx_results = (raw.get("whoisxml") or {}).get("results") or []
    cross_check = None
    if wx_results:
        r = wx_results[0]
        cross_check = (f"WhoisXML={r.get('threatType')}, "
                       f"seen {(r.get('firstSeen') or '')[:10]}~{(r.get('lastSeen') or '')[:10]}")
    source = next((t.split(":", 1)[1] for t in tags if t.startswith("source:")), None) \
        or (event.get("Org") or {}).get("name") or "misp"
    n_sources = 1 + (1 if cross_check else 0)
    activity = (event.get("info") or "").replace("OTX | ", "").strip() or None
    return {
        "activity": activity,
        "threat_labels": threat_labels[:8],
        "source": source,
        "cross_check": cross_check,
        "confidence": f"{indicator.severity or 'medium'} ({n_sources} source{'s' if n_sources > 1 else ''})",
        "tlp": indicator.tlp,
        "misp_event_id": event.get("id") or indicator.misp_event_id,
        "narrative": raw.get("narrative"),
    }


def build_description(evidence: dict) -> str:
    parts = []
    if evidence.get("activity"):
        parts.append(f"命中威胁: {evidence['activity']}")
    if evidence.get("threat_labels"):
        parts.append(f"关联: {', '.join(evidence['threat_labels'][:6])}")
    if evidence.get("cross_check"):
        parts.append(f"交叉验证: {evidence['cross_check']}")
    parts.append(f"来源: {evidence['source']} · 置信: {evidence['confidence']}")
    if evidence.get("tlp"):
        parts.append(f"TLP:{evidence['tlp'].upper()}")
    return " | ".join(parts)


def recommended_action(indicator: IntelIndicator, category: str) -> str:
    if category in {"c2", "ransomware", "botnet"} or (indicator.severity or "") == "high":
        return "block_and_report"
    return "block"


def map_indicator_to_ta_node_item(indicator: IntelIndicator) -> dict:
    value = indicator.normalized_value or indicator.value
    item_id = indicator.misp_attribute_uuid or hashlib.sha256(f"{indicator.misp_type}:{value}".encode()).hexdigest()
    category = derive_category(indicator)
    evidence = build_evidence(indicator)
    return {
        "id": item_id,
        "type": TYPE_MAP.get(indicator.misp_type, "pattern"),
        "value": value,
        "category": category,
        "severity": indicator.severity or "medium",
        "source": "",
        "description": build_description(evidence),
        "evidence": evidence,
        "recommended_action": recommended_action(indicator, category),
        "tags": tag_names(indicator),
        "enabled": bool(indicator.to_ids and indicator.platform_category == "traffic"),
        "created_at": _timestamp(indicator.created_at),
        "updated_at": _timestamp(indicator.updated_at or indicator.last_seen),
        **({"expire_at": _timestamp(indicator.valid_until)} if indicator.valid_until else {}),
    }


def derive_category(indicator: IntelIndicator) -> str:
    tags = indicator.tags or []
    text = " ".join(tag.get("name", "") if isinstance(tag, dict) else str(tag) for tag in tags).lower()
    for candidate in ("c2", "phishing", "malware", "botnet", "scanner"):
        if candidate in text:
            return candidate
    return (indicator.misp_category or "misp").lower().replace(" ", "_")


def tag_names(indicator: IntelIndicator) -> list[str]:
    values = []
    for tag in indicator.tags or []:
        if isinstance(tag, dict):
            name = tag.get("name")
        else:
            name = str(tag)
        if name:
            values.append(name)
    return values


def push_traffic_to_ta_node(db: Session, mode: str = "incremental", batch_size: int = 5000) -> dict:
    return generate_ta_node_ioc_package(db, mode=mode, batch_size=batch_size)


def generate_ta_node_ioc_package(db: Session, mode: str = "incremental", batch_size: int = 5000) -> dict:
    s = get_effective_settings(db)
    state = _state(db)
    if not s.ta_node_enabled:
        state.status = "skipped"
        state.error_message = None
        db.commit()
        return {"status": "skipped", "reason": "TA_NODE_ENABLED is false"}

    top_n = s.ta_node_top_per_source
    if top_n and top_n > 0:
        groups = select_top_per_source(db, top_n, s.ta_node_min_severity)
        indicators = [row for group in groups for row in group["items"]]
    else:
        query = db.query(IntelIndicator).filter(
            IntelIndicator.platform_category == "traffic",
            IntelIndicator.to_ids.is_(True),
        )
        if mode != "full":
            query = query.filter(IntelIndicator.pushed_to_ta_node.is_(False))
        indicators = query.limit(batch_size).all()

    # 写入前补齐缺失的 LLM 研判(llm 开启时;与 WhoisXML 无关)
    from app.services.llm import ensure_narratives
    ensure_narratives(db, indicators)

    now = datetime.now(timezone.utc)
    items = []
    for indicator in indicators:
        item = map_indicator_to_ta_node_item(indicator)
        item["source"] = s.ta_node_source_name
        item.setdefault("created_at", int(now.timestamp()))
        item["updated_at"] = int(now.timestamp())
        items.append(item)

    rule_path = _safe_rule_path(Path(s.ioc_output_dir), s.ioc_rule_filename)
    zip_path = rule_path.with_suffix(".zip")
    try:
        write_ta_node_ioc_files(rule_path, items)
    except Exception as exc:
        message = str(exc)
        for indicator in indicators:
            indicator.push_error = message
        state.status = "failed"
        state.error_message = message
        db.commit()
        return {"status": "failed", "error": message, "count": len(items)}

    for indicator in indicators:
        indicator.pushed_to_ta_node = True
        indicator.pushed_at = now
        indicator.push_error = None
    state.status = "success"
    state.error_message = None
    state.last_success_at = now
    db.commit()
    return {
        "status": "success",
        "count": len(items),
        "rule_file": str(rule_path),
        "zip_file": str(zip_path),
        "format": "ta_node intel.yaml",
    }


def write_ta_node_ioc_files(rule_path: Path, items: list[dict]) -> None:
    rule_path.parent.mkdir(parents=True, exist_ok=True)
    data = yaml.safe_dump({"items": items}, sort_keys=False, allow_unicode=True)
    rule_path.write_text(data, encoding="utf-8")
    zip_path = rule_path.with_suffix(".zip")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(rule_path, arcname=rule_path.name)


def _count_items(data: bytes | str) -> int:
    """数 ta_node 规则里的条数(items 列表长度);解析失败或结构不符则抛异常。"""
    parsed = yaml.safe_load(data) or {}
    if not isinstance(parsed, dict) or not isinstance(parsed.get("items"), list):
        raise ValueError("规则内容缺少顶层 items 列表")
    return len(parsed["items"])


def _inspect_yaml(path: Path) -> dict:
    info = {"exists": path.exists(), "count": None, "size": None, "mtime": None}
    if not info["exists"]:
        return info
    stat = path.stat()
    info["size"] = stat.st_size
    info["mtime"] = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
    try:
        info["count"] = _count_items(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - 坏文件不抛,count 置空并带说明
        info["error"] = str(exc)
    return info


def _inspect_zip(path: Path, member: str) -> dict:
    info = {"exists": path.exists(), "count": None, "size": None, "mtime": None}
    if not info["exists"]:
        return info
    stat = path.stat()
    info["size"] = stat.st_size
    info["mtime"] = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            inner = member if member in names else (names[0] if names else None)
            if inner is None:
                raise ValueError("zip 为空")
            info["count"] = _count_items(archive.read(inner))
    except Exception as exc:  # noqa: BLE001 - 坏压缩包不抛
        info["error"] = str(exc)
    return info


def inspect_rule_files(output_dir: str, filename: str) -> dict:
    """扫描输出目录里 intel.yaml / intel.zip 的实际存在情况与条数。

    用于判断内网网闸是否已把 zip 取走:yaml 在而 zip 缺 → taken_by_gate。
    纯磁盘检查,不读数据库,不产生副作用。
    """
    rule_path = _safe_rule_path(Path(output_dir), filename)
    zip_path = rule_path.with_suffix(".zip")
    yaml_info = _inspect_yaml(rule_path)
    zip_info = _inspect_zip(zip_path, rule_path.name)

    consistent = None
    if yaml_info["count"] is not None and zip_info["count"] is not None:
        consistent = yaml_info["count"] == zip_info["count"]

    if yaml_info["exists"] and not zip_info["exists"]:
        taken_by_gate = True
        verdict = "zip 已被网闸取走(yaml 仍在)"
    elif yaml_info["exists"] and zip_info["exists"]:
        taken_by_gate = False
        verdict = "规则文件就绪,网闸尚未取走 zip"
        if consistent is False:
            verdict += "(注意:yaml 与 zip 条数不一致)"
    elif not yaml_info["exists"] and not zip_info["exists"]:
        taken_by_gate = False
        verdict = "无规则文件(尚未生成,或 yaml/zip 均已被移走)"
    else:  # zip 在但 yaml 缺
        taken_by_gate = False
        verdict = "异常:zip 存在但 yaml 缺失"

    return {
        "output_dir": str(rule_path.parent),
        "rule_filename": rule_path.name,
        "zip_filename": zip_path.name,
        "yaml": yaml_info,
        "zip": zip_info,
        "consistent": consistent,
        "taken_by_gate": taken_by_gate,
        "verdict": verdict,
    }


def save_uploaded_ioc_rule(output_dir: str, filename: str, content: bytes) -> dict:
    rule_path = _safe_rule_path(Path(output_dir), filename)
    rule_path.parent.mkdir(parents=True, exist_ok=True)
    if rule_path.suffix.lower() in {".yaml", ".yml"}:
        validate_ta_node_yaml(content)
    rule_path.write_bytes(content)
    zip_path = rule_path if rule_path.suffix.lower() == ".zip" else rule_path.with_suffix(".zip")
    if rule_path.suffix.lower() != ".zip":
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(rule_path, arcname=rule_path.name)
    return {"status": "saved", "rule_file": str(rule_path), "zip_file": str(zip_path)}


def validate_ta_node_yaml(content: bytes) -> None:
    parsed = yaml.safe_load(content) or {}
    if not isinstance(parsed, dict) or not isinstance(parsed.get("items"), list):
        raise ValueError("ta_node rule file must be YAML with top-level items list")
    for index, item in enumerate(parsed["items"]):
        if not isinstance(item, dict):
            raise ValueError(f"items[{index}] must be an object")
        for key in ("id", "type", "value", "category", "severity", "source", "enabled"):
            if key not in item:
                raise ValueError(f"items[{index}] missing required field: {key}")


def _safe_rule_path(output_dir: Path, filename: str) -> Path:
    name = Path(filename or "intel.yaml").name
    if not name:
        name = "intel.yaml"
    return output_dir / name


def pending_and_pushed_counts(db: Session) -> tuple[int, int]:
    pending = db.query(IntelIndicator).filter(
        IntelIndicator.platform_category == "traffic",
        IntelIndicator.to_ids.is_(True),
        IntelIndicator.pushed_to_ta_node.is_(False),
    ).count()
    pushed = db.query(IntelIndicator).filter(IntelIndicator.pushed_to_ta_node.is_(True)).count()
    return pending, pushed


def _state(db: Session) -> SyncState:
    state = db.query(SyncState).filter(SyncState.source_name == "ta_node_push").one_or_none()
    if state is None:
        state = SyncState(source_name="ta_node_push")
        db.add(state)
    return state


def _timestamp(value) -> int:
    if value is None:
        return int(datetime.now(timezone.utc).timestamp())
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return int(value.timestamp())
