from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import IntelIndicator
from app.services.classifier import classify_indicator
from app.services.normalizer import normalize_value


def upsert_indicator(db: Session, attribute: dict) -> IntelIndicator:
    misp_type = attribute.get("type") or attribute.get("misp_type") or ""
    value = attribute.get("value") or ""
    normalized_type, normalized_value = normalize_value(misp_type, value)
    uuid = attribute.get("uuid") or attribute.get("misp_attribute_uuid")
    indicator = None
    if uuid:
        indicator = db.query(IntelIndicator).filter(IntelIndicator.misp_attribute_uuid == uuid).one_or_none()
    if indicator is None:
        indicator = IntelIndicator(misp_attribute_uuid=uuid)
        db.add(indicator)

    indicator.misp_event_id = str(attribute.get("event_id") or "") or None
    indicator.misp_event_uuid = attribute.get("event_uuid")
    indicator.platform_category = classify_indicator(attribute.get("category"), misp_type)
    indicator.misp_category = attribute.get("category")
    indicator.misp_type = misp_type
    indicator.value = value
    indicator.normalized_type = normalized_type
    indicator.normalized_value = normalized_value
    indicator.to_ids = bool(attribute.get("to_ids", False))
    indicator.tlp = extract_tlp(attribute.get("Tag") or attribute.get("tags") or [])
    indicator.confidence = _int_or_none(attribute.get("confidence"))
    indicator.threat_level = str(attribute.get("threat_level") or "") or None
    indicator.severity = severity_from_attribute(attribute)
    event = attribute.get("Event") or {}
    orgc = event.get("Orgc") or {}
    indicator.source_org = orgc.get("name") or attribute.get("source_org") or None
    indicator.tags = attribute.get("Tag") or attribute.get("tags") or []
    indicator.galaxies = attribute.get("Galaxy") or attribute.get("galaxies") or []
    indicator.raw = attribute
    indicator.last_seen = datetime.now(timezone.utc)
    return indicator


def extract_tlp(tags: list) -> str | None:
    for tag in tags:
        name = (tag.get("name") if isinstance(tag, dict) else str(tag)).lower()
        if name.startswith("tlp:"):
            return name.split(":", 1)[1]
    return None


def severity_from_attribute(attribute: dict) -> str:
    tags = " ".join((tag.get("name") if isinstance(tag, dict) else str(tag)).lower() for tag in attribute.get("Tag", []) or attribute.get("tags", []) or [])
    if any(word in tags for word in ("critical", "high", "apt", "malware", "c2")):
        return "high"
    confidence = _int_or_none(attribute.get("confidence"))
    if confidence is not None:
        if confidence >= 80:
            return "high"
        if confidence < 40:
            return "low"
    threat_level = str(attribute.get("threat_level") or "").lower()
    if threat_level in {"1", "high"}:
        return "high"
    if threat_level in {"3", "low"}:
        return "low"
    return "medium"


def _int_or_none(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
