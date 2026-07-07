from __future__ import annotations

from sqlalchemy.orm import Session

from app.config import DEFAULTS, ENV_KEYS, SECRET_KEYS, parse_bool, settings_from_values
from app.models import AppConfig


API_TO_ENV = {
    "misp_url": "MISP_URL",
    "misp_api_key": "MISP_API_KEY",
    "misp_verify_cert": "MISP_VERIFY_CERT",
    "misp_sync_interval_seconds": "MISP_SYNC_INTERVAL_SECONDS",
    "ta_node_enabled": "TA_NODE_ENABLED",
    "ta_node_base_url": "TA_NODE_BASE_URL",
    "ta_node_token": "TA_NODE_TOKEN",
    "ta_node_source_name": "TA_NODE_SOURCE_NAME",
    "ta_node_push_interval_seconds": "TA_NODE_PUSH_INTERVAL_SECONDS",
    "ioc_output_dir": "IOC_OUTPUT_DIR",
    "ioc_rule_filename": "IOC_RULE_FILENAME",
    "otx_api_key": "OTX_API_KEY",
    "whoisxml_api_key": "WHOISXML_API_KEY",
    "ta_node_top_per_source": "TA_NODE_TOP_PER_SOURCE",
    "ta_node_min_severity": "TA_NODE_MIN_SEVERITY",
    "whoisxml_enrich_limit": "WHOISXML_ENRICH_LIMIT",
    "whoisxml_enrich_interval_seconds": "WHOISXML_ENRICH_INTERVAL_SECONDS",
    "otx_sync_interval_seconds": "OTX_SYNC_INTERVAL_SECONDS",
    "otx_max_pulses": "OTX_MAX_PULSES",
}


def get_db_config_values(db: Session) -> dict[str, str]:
    rows = db.query(AppConfig).all()
    return {row.key: row.value or "" for row in rows if row.key in ENV_KEYS}


def get_effective_settings(db: Session):
    return settings_from_values(get_db_config_values(db))


def _upsert(db: Session, key: str, value: str, encrypted: bool = False) -> None:
    row = db.query(AppConfig).filter(AppConfig.key == key).one_or_none()
    if row is None:
        row = AppConfig(key=key, value=value, encrypted=encrypted)
        db.add(row)
    else:
        row.value = value
        row.encrypted = encrypted


def save_config(db: Session, payload: dict) -> None:
    for api_key, env_key in API_TO_ENV.items():
        if api_key not in payload:
            continue
        value = payload[api_key]
        if env_key in SECRET_KEYS and value in (None, ""):
            continue
        if isinstance(value, bool):
            value = "true" if value else "false"
        _upsert(db, env_key, str(value), env_key in SECRET_KEYS)
    db.commit()


def public_config(db: Session) -> dict:
    s = get_effective_settings(db)
    return {
        "misp_url": s.misp_url,
        "misp_api_key_masked": bool(s.misp_api_key),
        "misp_verify_cert": s.misp_verify_cert,
        "misp_sync_interval_seconds": s.misp_sync_interval_seconds,
        "ta_node_enabled": s.ta_node_enabled,
        "ta_node_base_url": s.ta_node_base_url,
        "ta_node_token_masked": bool(s.ta_node_token),
        "ta_node_source_name": s.ta_node_source_name,
        "ta_node_push_interval_seconds": s.ta_node_push_interval_seconds,
        "ioc_output_dir": s.ioc_output_dir,
        "ioc_rule_filename": s.ioc_rule_filename,
        "otx_api_key_masked": bool(s.otx_api_key),
        "whoisxml_api_key_masked": bool(s.whoisxml_api_key),
        "ta_node_top_per_source": s.ta_node_top_per_source,
        "ta_node_min_severity": s.ta_node_min_severity,
        "whoisxml_enrich_limit": s.whoisxml_enrich_limit,
        "whoisxml_enrich_interval_seconds": s.whoisxml_enrich_interval_seconds,
        "otx_sync_interval_seconds": s.otx_sync_interval_seconds,
        "otx_max_pulses": s.otx_max_pulses,
        "defaults": {
            "misp_verify_cert": parse_bool(DEFAULTS["MISP_VERIFY_CERT"]),
            "ta_node_enabled": parse_bool(DEFAULTS["TA_NODE_ENABLED"]),
        },
    }
