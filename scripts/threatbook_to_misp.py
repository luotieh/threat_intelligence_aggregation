#!/usr/bin/env python3
"""批量查询微步在线 ThreatBook,把判定恶意的 IP/域名导入本地 MISP 生成可下发规则。

ThreatBook 云 API 是查询型接口(无批量 feed),因此本脚本走"候选名单 -> 批量研判 ->
只留恶意项 -> 写 MISP"的路线:

1. 从输入文件读取候选 IP/域名(每行一个,# 开头为注释),也可以 --from-stdin 从管道读;
2. 调 ThreatBook 场景接口批量查询(默认 /v3/scene/dns,一个接口同时覆盖 IP 和域名);
3. 仅将 is_malicious=true 的结果生成 MISP 事件并发布,属性 to_ids=True;
4. 平台侧 sync_misp 按 publish_timestamp 增量拉取后即成为 traffic 规则,
   可经 export_traffic 导出 txt/csv/json 或推送 TA 节点。

已查询过的 IOC 记录在状态文件中,重复运行只查新增,避免消耗 API 额度。

用法:
    THREATBOOK_API_KEY=xxx MISP_API_KEY=yyy python3 scripts/threatbook_to_misp.py iocs.txt [--dry-run]
    cat iocs.txt | THREATBOOK_API_KEY=xxx MISP_API_KEY=yyy python3 scripts/threatbook_to_misp.py --from-stdin

环境变量(也可放 scripts/intel_sources.env 后 source):
    THREATBOOK_API_KEY     必填(X 情报中心账号的 API key)
    MISP_URL               默认 https://localhost:8443
    MISP_API_KEY           必填
    THREATBOOK_BATCH_SIZE  单次批量查询条数,默认 100
    THREATBOOK_MIN_SEVERITY 导入的最低严重级别(critical/high/medium/low),默认 low(全部恶意项)
"""

import argparse
import ipaddress
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TB_API = "https://api.threatbook.cn/v3"
STATE_FILE = Path(__file__).parent / ".state" / "threatbook_state.json"

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_iocs(lines) -> tuple[list[str], list[str]]:
    """把输入行分成 (ips, domains),忽略注释和无法识别的行。"""
    ips, domains = [], []
    for raw in lines:
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        if is_ip(value):
            ips.append(value)
        elif "." in value and " " not in value:
            domains.append(value.lower())
        else:
            print(f"[warn] 无法识别的行,已跳过: {value}", file=sys.stderr)
    return ips, domains


def query_scene(api_key: str, ips: list[str], domains: list[str]) -> dict:
    """调 /v3/scene/dns 批量查询,返回 {"ips": {...}, "domains": {...}}。

    注意:scene 接口的批量请求体按文档示例为 {"apikey", "ips", "domains"},
    若账号套餐不含此接口可改用 /v3/scene/ip_reputation + /v3/domain/query 单查。
    """
    payload = {"apikey": api_key, "lang": "zh"}
    if ips:
        payload["ips"] = ips
    if domains:
        payload["domains"] = domains
    resp = requests.post(f"{TB_API}/scene/dns", json=payload, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    if data.get("response_code") != 0:
        raise RuntimeError(f"ThreatBook 返回错误: {data.get('response_code')} {data.get('verbose_msg')}")
    return data.get("data") or {}


def severity_at_least(severity: str, minimum: str) -> bool:
    try:
        return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(minimum)
    except ValueError:
        return True  # 未知级别不丢,宁可多导入


def hit_to_attribute(kind: str, value: str, hit: dict) -> dict:
    severity = hit.get("severity") or "unknown"
    confidence = hit.get("confidence_level") or "unknown"
    judgments = ",".join(hit.get("judgments") or [])
    comment = f"severity={severity} confidence={confidence} judgments={judgments}"
    return {
        "type": "ip-dst" if kind == "ip" else "domain",
        "category": "Network activity",
        "value": value,
        "to_ids": True,
        "comment": comment[:255],
    }


def hit_to_tags(hit: dict) -> list[dict]:
    """把研判结论转成事件标签,标签名会被平台 severity_from_attribute 识别分级。

    如 judgments 含 C2 -> 标签含 "c2" -> high;severity=critical -> 标签含 "critical" -> high。
    """
    tags = [{"name": f'threatbook:severity="{hit.get("severity", "unknown")}"'}]
    for j in hit.get("judgments") or []:
        tags.append({"name": f'threatbook:judgment="{j}"'})
    for tc in (hit.get("tags_classes") or [])[:5]:
        for t in tc.get("tags") or []:
            tags.append({"name": f'threatbook:tag="{t}"'})
    return tags


def misp_request(method: str, path: str, misp_url: str, misp_key: str, payload=None):
    resp = requests.request(
        method, f"{misp_url}{path}",
        headers={"Authorization": misp_key, "Accept": "application/json",
                 "Content-Type": "application/json"},
        json=payload, verify=False, timeout=120,
        proxies={"http": None, "https": None},  # MISP 在本机,不走代理
    )
    resp.raise_for_status()
    return resp.json()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", help="候选 IOC 文件,每行一个 IP 或域名")
    parser.add_argument("--from-stdin", action="store_true", help="从标准输入读取候选 IOC")
    parser.add_argument("--dry-run", action="store_true", help="只查询和统计,不写入 MISP")
    args = parser.parse_args()

    if args.from_stdin:
        lines = sys.stdin
    elif args.input:
        lines = open(args.input, encoding="utf-8")
    else:
        parser.error("需要输入文件或 --from-stdin")

    tb_key = os.environ.get("THREATBOOK_API_KEY")
    misp_key = os.environ.get("MISP_API_KEY")
    misp_url = os.environ.get("MISP_URL", "https://localhost:8443").rstrip("/")
    if not tb_key or not misp_key:
        print("错误: 需要设置 THREATBOOK_API_KEY 和 MISP_API_KEY 环境变量", file=sys.stderr)
        return 2
    batch_size = int(os.environ.get("THREATBOOK_BATCH_SIZE", "100"))
    min_severity = os.environ.get("THREATBOOK_MIN_SEVERITY", "low").lower()

    state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {"queried": {}}
    ips, domains = parse_iocs(lines)
    # 只查状态文件里没有的,重复运行不消耗额度
    todo_ips = [v for v in dict.fromkeys(ips) if v not in state["queried"]]
    todo_domains = [v for v in dict.fromkeys(domains) if v not in state["queried"]]
    print(f"候选: IP {len(ips)}, 域名 {len(domains)}; 待查: IP {len(todo_ips)}, 域名 {len(todo_domains)}")

    today = datetime.now(timezone.utc).date().isoformat()
    failed = 0
    for kind, values in (("ip", todo_ips), ("domain", todo_domains)):
        for i in range(0, len(values), batch_size):
            chunk = values[i:i + batch_size]
            try:
                data = query_scene(tb_key, chunk if kind == "ip" else [], chunk if kind == "domain" else [])
            except (requests.RequestException, RuntimeError) as exc:
                failed += 1
                print(f"[fail] 查询 {kind} 批次 {i // batch_size}: {exc}", file=sys.stderr)
                continue
            hits = data.get("ips" if kind == "ip" else "domains") or {}
            attributes, tags, malicious = [], [], 0
            for value, hit in hits.items():
                state["queried"][value] = {"is_malicious": bool(hit.get("is_malicious")), "date": today}
                if not hit.get("is_malicious"):
                    continue
                if not severity_at_least((hit.get("severity") or "").lower(), min_severity):
                    continue
                malicious += 1
                attributes.append(hit_to_attribute(kind, value, hit))
                for tag in hit_to_tags(hit):
                    if tag not in tags:
                        tags.append(tag)
            if args.dry_run:
                print(f"[dry-run] {kind} 批次 {i // batch_size}: 查 {len(chunk)}, 恶意 {malicious}")
                continue
            if not attributes:
                continue
            event = {
                "info": f"ThreatBook | malicious-{kind}s | {today}",
                "date": today,
                "distribution": "0",
                "analysis": "2",
                "threat_level_id": "2",
                "published": False,
                "Attribute": attributes,
                "Tag": [{"name": "source:threatbook"}] + tags,
            }
            try:
                result = misp_request("POST", "/events/add", misp_url, misp_key, event)
                event_id = result["Event"]["id"]
                misp_request("POST", f"/events/publish/{event_id}", misp_url, misp_key)
                print(f"[ok] event {event_id}: {kind} 导入 {len(attributes)} 条恶意 IOC")
            except requests.RequestException as exc:
                failed += 1
                print(f"[fail] 导入 {kind} 批次 {i // batch_size}: {exc}", file=sys.stderr)

    STATE_FILE.parent.mkdir(exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=1))
    total_malicious = sum(1 for v in state["queried"].values() if v["is_malicious"])
    print(f"完成: 累计已查 {len(state['queried'])}, 其中恶意 {total_malicious}, 失败批次 {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
