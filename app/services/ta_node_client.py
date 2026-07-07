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


def map_indicator_to_ta_node_item(indicator: IntelIndicator) -> dict:
    value = indicator.normalized_value or indicator.value
    item_id = indicator.misp_attribute_uuid or hashlib.sha256(f"{indicator.misp_type}:{value}".encode()).hexdigest()
    return {
        "id": item_id,
        "type": TYPE_MAP.get(indicator.misp_type, "pattern"),
        "value": value,
        "category": derive_category(indicator),
        "severity": indicator.severity or "medium",
        "source": "",
        "description": "",
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
    now = datetime.now(timezone.utc)
    items = []
    for indicator in indicators:
        item = map_indicator_to_ta_node_item(indicator)
        item["source"] = s.ta_node_source_name
        item["description"] = f"MISP {indicator.misp_type} IOC from Threat Intel Hub"
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
