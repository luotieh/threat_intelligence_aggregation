"""微步在线 ThreatBook 可疑 IP 研判 -> 平台 intel.yaml 规则的核心逻辑。

独立流程,不复用也不改动 MISP 入库/推送链路:查询结果只在本模块内转换为
ta_node_client.map_indicator_to_ta_node_item 同款的 item 结构。
Web(app.api.threatbook)与 CLI(scripts/threatbook_to_intel.py)共用本模块;
只依赖 requests / PyYAML,不涉及数据库,可独立导入。
"""

from __future__ import annotations

import hashlib
import io
import ipaddress
import zipfile
from datetime import datetime, timezone
from typing import Iterable

import requests
import yaml

TB_API = "https://api.threatbook.cn/v3"
BATCH_SIZE = 100
MAX_IPS_PER_RUN = 200  # web 端单次研判上限,防止误操作烧额度

# ThreatBook judgments -> 平台 category(c2/phishing/malware/botnet/scanner 词表)
JUDGMENT_CATEGORY = {
    "c2": "c2",
    "sinkhole c2": "c2",
    "botnet": "botnet",
    "zombie": "botnet",
    "scanner": "scanner",
    "brute force": "scanner",
    "spam": "scanner",
    "phishing": "phishing",
    "exploit": "malware",
    "malware": "malware",
    "coinminer": "malware",
    "miningpool": "malware",
}

# ThreatBook severity -> 平台 severity(high/medium/low 词表)
SEVERITY_MAP = {"critical": "high", "high": "high", "medium": "medium", "low": "low", "info": "low"}


def parse_ips(lines: Iterable[str]) -> tuple[list[str], list[str]]:
    """把输入行分成 (有效 IP 去重列表, 被跳过的行)。# 开头为注释。"""
    ips, skipped = [], []
    for raw in lines:
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        try:
            ipaddress.ip_address(value)
        except ValueError:
            skipped.append(value)
            continue
        ips.append(value)
    return list(dict.fromkeys(ips)), skipped


def query_ip_info(api_key: str, ips: list[str]) -> dict:
    """调 /v3/ip/query 逐个查询 IP 威胁情报,返回 {ip: hit} 的研判结果 map。

    ip/query 是 ThreatBook 基础威胁情报 IP 查询接口,按次计费。
    每个 IP 独立请求,单次返回该 IP 的 judgments/severity/tags_classes 等完整情报。
    """
    results = {}
    for ip in ips:
        try:
            resp = requests.post(
                f"{TB_API}/ip/query",
                params={"apikey": api_key},
                json={"ip": ip, "lang": "zh"},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("response_code") != 0:
                raise RuntimeError(f"ThreatBook 返回错误: {data.get('response_code')} {data.get('verbose_msg')}")
            # ip/query 的 data 字段可能是 {ip: {...}} 或直接 {...},兼容两种
            hit = (data.get("data") or {})
            if isinstance(hit, dict) and ip in hit and isinstance(hit[ip], dict):
                hit = hit[ip]
            results[ip] = hit
        except Exception:
            continue
    return results


def gang_tags_of(hit: dict) -> list[str]:
    tags = []
    for tc in hit.get("tags_classes") or []:
        tags.extend(str(t) for t in tc.get("tags") or [])
    return tags


def map_hit(hit: dict) -> dict:
    """ThreatBook 研判结论 -> 平台三字段(category/severity/recommended_action)。"""
    judgments = [str(j) for j in hit.get("judgments") or []]
    category = next((JUDGMENT_CATEGORY[j.lower()] for j in judgments if j.lower() in JUDGMENT_CATEGORY), "malware")
    severity = SEVERITY_MAP.get((hit.get("severity") or "").lower(), "medium")
    action = "block_and_report" if category in {"c2", "botnet"} or severity == "high" else "block"
    return {"category": category, "severity": severity, "recommended_action": action}


def summarize(ip: str, hit: dict) -> dict:
    """把一条 ThreatBook 研判结果总结成平台 intel.yaml 的 item 结构。

    字段对齐 ta_node_client.map_indicator_to_ta_node_item;必填键(id/type/value/
    category/severity/source/enabled)与 validate_ta_node_yaml 的校验一致。
    """
    judgments = [str(j) for j in hit.get("judgments") or []]
    gang_tags = gang_tags_of(hit)
    mapped = map_hit(hit)
    confidence = hit.get("confidence_level") or "unknown"
    threat_labels = judgments + gang_tags
    permalink = hit.get("permalink") or f"https://x.threatbook.com/v5/ip/{ip}"

    description_parts = []
    if judgments:
        description_parts.append(f"命中威胁: {', '.join(judgments)}")
    if gang_tags:
        description_parts.append(f"关联: {', '.join(gang_tags[:6])}")
    description_parts.append(f"来源: ThreatBook · 置信: {confidence} ({mapped['severity']})")
    if hit.get("update_time"):
        description_parts.append(f"情报更新: {hit['update_time']}")

    tags = ["source:threatbook", f'threatbook:severity="{hit.get("severity", "unknown")}"']
    tags += [f'threatbook:judgment="{j}"' for j in judgments]
    tags += [f'threatbook:tag="{t}"' for t in gang_tags[:5]]

    now = int(datetime.now(timezone.utc).timestamp())
    return {
        "id": hashlib.sha256(f"ip:{ip}".encode()).hexdigest(),
        "type": "ip",
        "value": ip,
        "category": mapped["category"],
        "severity": mapped["severity"],
        "source": "ThreatBook",
        "description": " | ".join(description_parts),
        "evidence": {
            "activity": judgments[0] if judgments else None,
            "threat_labels": threat_labels[:8],
            "source": "ThreatBook X",
            "cross_check": None,
            "confidence": f"{mapped['severity']} (1 source)",
            "tlp": None,
            "misp_event_id": None,
            "narrative": None,
            "permalink": permalink,
        },
        "recommended_action": mapped["recommended_action"],
        "tags": tags,
        "enabled": True,
        "created_at": now,
        "updated_at": now,
    }


def build_intel_yaml(items: list[dict]) -> str:
    """与 ta_node_client.write_ta_node_ioc_files 同款的顶层 {"items": [...]} 结构。"""
    return yaml.safe_dump({"items": items}, sort_keys=False, allow_unicode=True)


def build_intel_zip(yaml_text: str, arcname: str = "intel.yaml") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(arcname, yaml_text)
    return buf.getvalue()
