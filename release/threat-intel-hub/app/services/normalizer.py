from __future__ import annotations

from urllib.parse import urlsplit


def normalize_value(misp_type: str, value: str) -> tuple[str, str]:
    misp_type = (misp_type or "").strip().lower()
    value = (value or "").strip()
    if misp_type in {"domain", "hostname"}:
        return misp_type, value.lower().rstrip(".")
    if misp_type in {"domain|ip", "hostname|port", "ip-src|port", "ip-dst|port"}:
        left = value.split("|", 1)[0].strip()
        normalized_type = "domain" if misp_type in {"domain|ip", "hostname|port"} else "ip_port"
        return normalized_type, left.lower().rstrip(".")
    if misp_type in {"url", "uri"}:
        if misp_type == "url":
            parts = urlsplit(value)
            if parts.scheme and parts.netloc:
                return "url", value.strip()
        return "url", value.strip()
    if misp_type in {"ip-src", "ip-dst"}:
        return "ip", value
    return misp_type, value
