#!/usr/bin/env python3
"""同步 AlienVault OTX 订阅的 pulses 到本地 MISP。

每个 pulse 生成一个 MISP 事件并发布,平台侧由 sync_misp 按 publish_timestamp
增量拉取。已导入的 pulse 记录在状态文件中,重复运行只取新增/更新。

用法:
    OTX_API_KEY=xxx MISP_API_KEY=yyy python3 scripts/otx_to_misp.py [--dry-run]

环境变量(也可放 scripts/intel_sources.env 后 source):
    OTX_API_KEY        必填
    MISP_URL           默认 https://localhost:8443
    MISP_API_KEY       必填
    OTX_MODIFIED_SINCE 首次运行回溯天数,默认 7
    OTX_MAX_PULSES     单次运行上限,默认 200
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

OTX_API = "https://otx.alienvault.com/api/v1"
STATE_FILE = Path(__file__).parent / ".state" / "otx_state.json"

# OTX indicator type -> MISP attribute (type, category, to_ids)
TYPE_MAP = {
    "IPv4": ("ip-dst", "Network activity", True),
    "IPv6": ("ip-dst", "Network activity", True),
    "domain": ("domain", "Network activity", True),
    "hostname": ("hostname", "Network activity", True),
    "URL": ("url", "Network activity", True),
    "URI": ("uri", "Network activity", True),
    "FileHash-MD5": ("md5", "Payload delivery", True),
    "FileHash-SHA1": ("sha1", "Payload delivery", True),
    "FileHash-SHA256": ("sha256", "Payload delivery", True),
    "FileHash-IMPHASH": ("imphash", "Payload delivery", True),
    "FileHash-PEHASH": ("pehash", "Payload delivery", True),
    "email": ("email-src", "Payload delivery", True),
    "CVE": ("vulnerability", "External analysis", False),
    "Mutex": ("mutex", "Artifacts dropped", True),
    "FilePath": ("filename", "Artifacts dropped", False),
    "YARA": ("yara", "Artifacts dropped", False),
    "CIDR": ("ip-dst", "Network activity", True),
    "BitcoinAddress": ("btc", "Financial fraud", False),
    "JA3": ("ja3-fingerprint-md5", "Network activity", True),
}

TLP_TAGS = {"white": "tlp:white", "green": "tlp:green", "amber": "tlp:amber", "red": "tlp:red"}


def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"last_modified": None, "pulses": {}}


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=1))


def fetch_pulses(api_key: str, since: str, max_pulses: int):
    session = requests.Session()
    session.headers["X-OTX-API-KEY"] = api_key
    url = f"{OTX_API}/pulses/subscribed"
    params = {"modified_since": since, "limit": 50}
    got = 0
    while url and got < max_pulses:
        resp = session.get(url, params=params, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        for pulse in data.get("results", []):
            yield pulse
            got += 1
            if got >= max_pulses:
                return
        url = data.get("next")
        params = None  # next URL 已带全部参数


def pulse_to_event(pulse: dict) -> tuple[dict, int]:
    attributes, skipped = [], 0
    for ind in pulse.get("indicators", []):
        mapped = TYPE_MAP.get(ind.get("type"))
        if not mapped:
            skipped += 1
            continue
        mtype, category, to_ids = mapped
        attributes.append({
            "type": mtype,
            "category": category,
            "value": ind["indicator"],
            "to_ids": to_ids,
            "comment": (ind.get("title") or ind.get("description") or "")[:255],
        })
    tags = [{"name": "source:otx"}]
    tlp = TLP_TAGS.get((pulse.get("tlp") or "").lower())
    if tlp:
        tags.append({"name": tlp})
    for t in pulse.get("tags", [])[:10]:
        tags.append({"name": f'otx:tag="{t}"'})
    event = {
        "info": f"OTX | {pulse.get('name', pulse['id'])}",
        "date": (pulse.get("created") or "")[:10] or datetime.now(timezone.utc).date().isoformat(),
        "distribution": "0",
        "analysis": "2",
        "threat_level_id": "3",
        "published": False,
        "Attribute": attributes,
        "Tag": tags,
    }
    return event, skipped


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
    parser.add_argument("--dry-run", action="store_true", help="只拉取和转换,不写入 MISP")
    args = parser.parse_args()

    otx_key = os.environ.get("OTX_API_KEY")
    misp_key = os.environ.get("MISP_API_KEY")
    misp_url = os.environ.get("MISP_URL", "https://localhost:8443").rstrip("/")
    if not otx_key or not misp_key:
        print("错误: 需要设置 OTX_API_KEY 和 MISP_API_KEY 环境变量", file=sys.stderr)
        return 2

    state = load_state()
    since = state["last_modified"] or (
        datetime.now(timezone.utc) - timedelta(days=int(os.environ.get("OTX_MODIFIED_SINCE", "7")))
    ).strftime("%Y-%m-%dT%H:%M:%S")
    max_pulses = int(os.environ.get("OTX_MAX_PULSES", "200"))
    run_started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

    created = updated = failed = 0
    for pulse in fetch_pulses(otx_key, since, max_pulses):
        pid = pulse["id"]
        event, skipped = pulse_to_event(pulse)
        if not event["Attribute"]:
            continue
        if args.dry_run:
            print(f"[dry-run] {event['info']}: {len(event['Attribute'])} 个IOC, 跳过 {skipped} 个未映射类型")
            continue
        try:
            existing = state["pulses"].get(pid)
            if existing:
                # pulse 更新过:删除旧事件重建,保证 IOC 集合一致
                misp_request("DELETE", f"/events/delete/{existing}", misp_url, misp_key)
                updated += 1
            result = misp_request("POST", "/events/add", misp_url, misp_key, event)
            event_id = result["Event"]["id"]
            misp_request("POST", f"/events/publish/{event_id}", misp_url, misp_key)
            state["pulses"][pid] = event_id
            if not existing:
                created += 1
            print(f"[ok] event {event_id}: {event['info']} ({len(event['Attribute'])} IOC)")
        except requests.RequestException as exc:
            failed += 1
            print(f"[fail] pulse {pid}: {exc}", file=sys.stderr)

    if not args.dry_run and failed == 0:
        state["last_modified"] = run_started
    save_state(state)
    print(f"完成: 新建 {created}, 更新 {updated}, 失败 {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
