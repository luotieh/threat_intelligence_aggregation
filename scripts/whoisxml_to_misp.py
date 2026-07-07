#!/usr/bin/env python3
"""下载 WhoisXML Threat Intelligence Data Feeds 并导入本地 MISP。

每个 feed 每天生成一个 MISP 事件(如 "WhoisXML | malicious-domains | 2026-07-06"),
发布后由平台 sync_misp 增量拉取。状态文件记录已导入的 (feed, 日期)。

用法:
    WHOISXML_API_KEY=xxx MISP_API_KEY=yyy python3 scripts/whoisxml_to_misp.py [--dry-run] [--date 2026-07-06]

环境变量:
    WHOISXML_API_KEY      必填(HTTPS 下载的用户名和密码都是它)
    MISP_URL              默认 https://localhost:8443
    MISP_API_KEY          必填
    WHOISXML_FEEDS        逗号分隔,默认 malicious-ips.v4,malicious-domains,malicious-urls,file-hashes
    WHOISXML_MAX_PER_FEED 每个 feed 导入上限,默认 5000(每日全量可能有数十万条)
"""

import argparse
import csv
import gzip
import io
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DOWNLOAD_BASE = "https://download.whoisxmlapi.com/datafeeds/Threat_Intelligence_Data_Feeds"
STATE_FILE = Path(__file__).parent / ".state" / "whoisxml_state.json"
DEFAULT_FEEDS = "malicious-ips.v4,malicious-domains,malicious-urls,file-hashes"

HASH_ALGO_TYPES = {"md5": "md5", "sha1": "sha1", "sha256": "sha256"}


def feed_row_to_attribute(feed: str, row: dict):
    threat = row.get("threatType", "")
    comment = f"threatType={threat} firstSeen={row.get('firstSeen', '')}"
    if feed.startswith("malicious-ips"):
        return {"type": "ip-dst", "category": "Network activity", "value": row["ip"],
                "to_ids": True, "comment": comment}
    if feed == "malicious-domains":
        return {"type": "domain", "category": "Network activity", "value": row["domainName"],
                "to_ids": True, "comment": comment}
    if feed == "malicious-urls":
        return {"type": "url", "category": "Network activity", "value": row["url"],
                "to_ids": True, "comment": comment}
    if feed == "file-hashes":
        mtype = HASH_ALGO_TYPES.get((row.get("algo") or "").lower())
        if not mtype:
            return None
        return {"type": mtype, "category": "Payload delivery", "value": row["hash"],
                "to_ids": True, "comment": comment}
    if feed.startswith("malicious-cidrs"):
        return {"type": "ip-dst", "category": "Network activity", "value": row["cidr"],
                "to_ids": True, "comment": comment}
    return None


def download_feed(api_key: str, feed: str, date: str) -> list[dict]:
    filename = f"tidf.{date}.daily.{feed}.csv.gz"
    url = f"{DOWNLOAD_BASE}/{filename}"
    resp = requests.get(url, auth=(api_key, api_key), timeout=300)
    if resp.status_code == 404:
        raise FileNotFoundError(f"{filename} 不存在(feed 名不对、当日文件未发布或订阅未含此 feed)")
    resp.raise_for_status()
    text = gzip.decompress(resp.content).decode("utf-8", errors="replace")
    return list(csv.DictReader(io.StringIO(text)))


def misp_request(method: str, path: str, misp_url: str, misp_key: str, payload=None):
    resp = requests.request(
        method, f"{misp_url}{path}",
        headers={"Authorization": misp_key, "Accept": "application/json",
                 "Content-Type": "application/json"},
        json=payload, verify=False, timeout=300,
        proxies={"http": None, "https": None},  # MISP 在本机,不走代理
    )
    resp.raise_for_status()
    return resp.json()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="只下载和统计,不写入 MISP")
    parser.add_argument("--date", help="导入指定日期(YYYY-MM-DD),默认昨天(每日 3AM UTC 发布)")
    args = parser.parse_args()

    api_key = os.environ.get("WHOISXML_API_KEY")
    misp_key = os.environ.get("MISP_API_KEY")
    misp_url = os.environ.get("MISP_URL", "https://localhost:8443").rstrip("/")
    if not api_key or not misp_key:
        print("错误: 需要设置 WHOISXML_API_KEY 和 MISP_API_KEY 环境变量", file=sys.stderr)
        return 2

    date = args.date or (datetime.now(timezone.utc) - timedelta(days=1)).date().isoformat()
    feeds = [f.strip() for f in os.environ.get("WHOISXML_FEEDS", DEFAULT_FEEDS).split(",") if f.strip()]
    cap = int(os.environ.get("WHOISXML_MAX_PER_FEED", "5000"))

    state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {"imported": []}
    failed = 0
    for feed in feeds:
        key = f"{feed}:{date}"
        if key in state["imported"]:
            print(f"[skip] {key} 已导入")
            continue
        try:
            rows = download_feed(api_key, feed, date)
        except FileNotFoundError as exc:
            print(f"[miss] {exc}", file=sys.stderr)
            failed += 1
            continue
        except requests.RequestException as exc:
            print(f"[fail] 下载 {feed}: {exc}", file=sys.stderr)
            failed += 1
            continue

        attributes = []
        for row in rows[:cap]:
            attr = feed_row_to_attribute(feed, row)
            if attr:
                attributes.append(attr)
        dropped = max(0, len(rows) - cap)
        if args.dry_run:
            print(f"[dry-run] {feed} {date}: 共 {len(rows)} 条, 将导入 {len(attributes)}, 截断 {dropped}")
            continue
        if not attributes:
            print(f"[empty] {feed} {date}: 无可导入条目")
            state["imported"].append(key)
            continue

        event = {
            "info": f"WhoisXML | {feed} | {date}",
            "date": date,
            "distribution": "0",
            "analysis": "2",
            "threat_level_id": "3",
            "published": False,
            "Attribute": attributes,
            "Tag": [{"name": "source:whoisxml"}, {"name": f'whoisxml:feed="{feed}"'}],
        }
        try:
            result = misp_request("POST", "/events/add", misp_url, misp_key, event)
            event_id = result["Event"]["id"]
            misp_request("POST", f"/events/publish/{event_id}", misp_url, misp_key)
            state["imported"].append(key)
            msg = f"[ok] event {event_id}: {feed} {date} 导入 {len(attributes)} 条"
            if dropped:
                msg += f"(截断 {dropped} 条, 可调 WHOISXML_MAX_PER_FEED)"
            print(msg)
        except requests.RequestException as exc:
            failed += 1
            print(f"[fail] 导入 {feed}: {exc}", file=sys.stderr)

    STATE_FILE.parent.mkdir(exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=1))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
