from __future__ import annotations

import ipaddress

# 已知良性 IP(公共 DNS / 基础设施)。可按需扩展或对接 MISP warninglists 全量。
BENIGN_IPS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "114.114.114.114", "223.5.5.5", "223.6.6.6",
    "119.29.29.29", "180.76.76.76",
}
# 白名单域名(合法大厂/基础设施,命中该域或其子域视为良性)
BENIGN_DOMAINS = {
    "google.com", "gstatic.com", "googleapis.com", "googleusercontent.com",
    "microsoft.com", "windows.com", "windowsupdate.com", "office.com", "live.com",
    "apple.com", "icloud.com", "amazon.com", "amazonaws.com", "aws.amazon.com",
    "cloudflare.com", "cloudflare-dns.com", "cloudfront.net", "akamai.net",
    "akamaiedge.net", "fastly.net", "github.com", "githubusercontent.com",
    "mozilla.org", "wikipedia.org",
}


def is_benign(normalized_type: str | None, normalized_value: str | None) -> bool:
    """平台侧去误报,替代 MISP warninglist:私网/保留 IP、公共 DNS、白名单域名。"""
    if not normalized_value:
        return False
    raw = normalized_value.strip()
    if normalized_type == "ip":
        try:
            ip = ipaddress.ip_address(raw)
            if (ip.is_private or ip.is_loopback or ip.is_reserved
                    or ip.is_multicast or ip.is_link_local or ip.is_unspecified):
                return True
        except ValueError:
            pass
        return raw in BENIGN_IPS
    if normalized_type in {"domain", "hostname"}:
        value = raw.lower().rstrip(".")
        return any(value == d or value.endswith("." + d) for d in BENIGN_DOMAINS)
    return False
