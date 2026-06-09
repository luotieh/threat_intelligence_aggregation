TRAFFIC_TYPES = {
    "ip-src",
    "ip-dst",
    "ip-src|port",
    "ip-dst|port",
    "domain",
    "domain|ip",
    "hostname",
    "hostname|port",
    "url",
    "uri",
    "user-agent",
    "ja3-fingerprint-md5",
    "jarm-fingerprint",
    "pattern-in-traffic",
    "snort",
    "zeek",
    "bro",
}


def classify_indicator(misp_category: str | None, misp_type: str | None) -> str:
    if (misp_category or "").strip().lower() == "network activity":
        return "traffic"
    if (misp_type or "").strip().lower() in TRAFFIC_TYPES:
        return "traffic"
    return "other"
