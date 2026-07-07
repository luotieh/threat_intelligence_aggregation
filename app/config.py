from __future__ import annotations

import os
from dataclasses import dataclass


DEFAULTS: dict[str, str] = {
    "APP_ENV": "development",
    "APP_HOST": "0.0.0.0",
    "APP_PORT": "18080",
    "DATABASE_URL": "sqlite:///./intel.db",
    "REDIS_URL": "redis://redis:6379/0",
    "MISP_URL": "https://misp.example.com",
    "MISP_API_KEY": "",
    "MISP_VERIFY_CERT": "true",
    "MISP_SYNC_INTERVAL_SECONDS": "600",
    "TA_NODE_ENABLED": "true",
    "TA_NODE_BASE_URL": "http://127.0.0.1:19090",
    "TA_NODE_TOKEN": "",
    "TA_NODE_SOURCE_NAME": "Threat Intel Hub",
    "TA_NODE_PUSH_INTERVAL_SECONDS": "600",
    "TA_NODE_TOP_PER_SOURCE": "10",
    "TA_NODE_MIN_SEVERITY": "high",
    "OTX_API_KEY": "",
    "WHOISXML_API_KEY": "",
    "WHOISXML_ENRICH_LIMIT": "10",
    "WHOISXML_ENRICH_INTERVAL_SECONDS": "86400",
    "EXPORT_DIR": "release",
    "IOC_OUTPUT_DIR": "/data/ftp/ioc",
    "IOC_RULE_FILENAME": "intel.yaml",
}

ENV_KEYS = set(DEFAULTS)
SECRET_KEYS = {"MISP_API_KEY", "TA_NODE_TOKEN", "OTX_API_KEY", "WHOISXML_API_KEY"}


def parse_bool(value: str | bool | None) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_env: str
    app_host: str
    app_port: int
    database_url: str
    redis_url: str
    misp_url: str
    misp_api_key: str
    misp_verify_cert: bool
    misp_sync_interval_seconds: int
    ta_node_enabled: bool
    ta_node_base_url: str
    ta_node_token: str
    ta_node_source_name: str
    ta_node_push_interval_seconds: int
    ta_node_top_per_source: int
    ta_node_min_severity: str
    otx_api_key: str
    whoisxml_api_key: str
    whoisxml_enrich_limit: int
    whoisxml_enrich_interval_seconds: int
    export_dir: str
    ioc_output_dir: str
    ioc_rule_filename: str


def value_for(key: str, db_values: dict[str, str] | None = None) -> str:
    if key in os.environ:
        return os.environ[key]
    if db_values and db_values.get(key) not in (None, ""):
        return str(db_values[key])
    return DEFAULTS[key]


def settings_from_values(db_values: dict[str, str] | None = None) -> Settings:
    return Settings(
        app_env=value_for("APP_ENV", db_values),
        app_host=value_for("APP_HOST", db_values),
        app_port=int(value_for("APP_PORT", db_values)),
        database_url=value_for("DATABASE_URL", db_values),
        redis_url=value_for("REDIS_URL", db_values),
        misp_url=value_for("MISP_URL", db_values),
        misp_api_key=value_for("MISP_API_KEY", db_values),
        misp_verify_cert=parse_bool(value_for("MISP_VERIFY_CERT", db_values)),
        misp_sync_interval_seconds=int(value_for("MISP_SYNC_INTERVAL_SECONDS", db_values)),
        ta_node_enabled=parse_bool(value_for("TA_NODE_ENABLED", db_values)),
        ta_node_base_url=value_for("TA_NODE_BASE_URL", db_values).rstrip("/"),
        ta_node_token=value_for("TA_NODE_TOKEN", db_values),
        ta_node_source_name=value_for("TA_NODE_SOURCE_NAME", db_values),
        ta_node_push_interval_seconds=int(value_for("TA_NODE_PUSH_INTERVAL_SECONDS", db_values)),
        ta_node_top_per_source=int(value_for("TA_NODE_TOP_PER_SOURCE", db_values)),
        ta_node_min_severity=value_for("TA_NODE_MIN_SEVERITY", db_values),
        otx_api_key=value_for("OTX_API_KEY", db_values),
        whoisxml_api_key=value_for("WHOISXML_API_KEY", db_values),
        whoisxml_enrich_limit=int(value_for("WHOISXML_ENRICH_LIMIT", db_values)),
        whoisxml_enrich_interval_seconds=int(value_for("WHOISXML_ENRICH_INTERVAL_SECONDS", db_values)),
        export_dir=value_for("EXPORT_DIR", db_values),
        ioc_output_dir=value_for("IOC_OUTPUT_DIR", db_values),
        ioc_rule_filename=value_for("IOC_RULE_FILENAME", db_values),
    )


settings = settings_from_values()
