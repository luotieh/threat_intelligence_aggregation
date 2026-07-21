#!/usr/bin/env python3
"""可疑 IP 经微步在线 ThreatBook 研判,直接生成本平台 TA 节点规则文件 intel.yaml。

独立流程,不改动平台任何现有逻辑(不经过 MISP、不进 intel_indicator 表):
输入一批可疑 IP -> 调 ThreatBook 场景接口批量研判 -> 只保留判定恶意的 ->
按 ta_node_client 的规则结构写出 intel.yaml(+ intel.zip)。

核心逻辑(查询/总结/yaml 生成)在 app.services.threatbook,与 web 端「微步研判」
面板共用;本脚本只保留 CLI、查询缓存与落盘。

产物两种用法:
  1. 拷贝到平台 ioc.output_dir(默认 /data/ftp/ioc)供网闸取走;
  2. 走平台上传接口(会做 schema 校验并自动打 zip):
     curl -F "file=@intel.yaml" http://localhost:18080/ioc-rules/upload
  3. 或在平台「微步研判」页面粘贴 IP 在线研判并直接下载。

查询结果带本地缓存(scripts/.state/threatbook_intel_state.json),重复运行只查新增 IP,
已查过的按缓存结论出规则,不重复消耗 API 额度。

用法:
    THREATBOOK_API_KEY=xxx python3 scripts/threatbook_to_intel.py suspicious.txt [-o intel.yaml] [--dry-run]
    cat suspicious.txt | THREATBOOK_API_KEY=xxx python3 scripts/threatbook_to_intel.py --from-stdin

环境变量:
    THREATBOOK_API_KEY     必填(X 情报中心账号的 API key;全部命中缓存时可不设)
    THREATBOOK_BATCH_SIZE  单次批量查询条数,默认 100
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # 让 app 包可导入

from app.services.threatbook import (  # noqa: E402
    build_intel_yaml,
    build_intel_zip,
    parse_ips,
    query_scene_dns,
    summarize,
)

STATE_FILE = Path(__file__).parent / ".state" / "threatbook_intel_state.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", help="可疑 IP 文件,每行一个(# 开头为注释)")
    parser.add_argument("--from-stdin", action="store_true", help="从标准输入读取 IP")
    parser.add_argument("-o", "--output", default="intel.yaml", help="输出路径,默认 ./intel.yaml")
    parser.add_argument("--dry-run", action="store_true", help="只查询和打印摘要,不写文件")
    args = parser.parse_args()

    if args.from_stdin:
        lines = sys.stdin
    elif args.input:
        lines = open(args.input, encoding="utf-8")
    else:
        parser.error("需要输入文件或 --from-stdin")

    ips, skipped = parse_ips(lines)
    for value in skipped:
        print(f"[warn] 非 IP 行,已跳过: {value}", file=sys.stderr)
    if not ips:
        print("错误: 输入中没有可识别的 IP", file=sys.stderr)
        return 2

    cache = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    missing = [ip for ip in ips if ip not in cache]
    print(f"输入 {len(ips)} 个 IP,缓存命中 {len(ips) - len(missing)},待查 {len(missing)}")

    if missing:
        api_key = os.environ.get("THREATBOOK_API_KEY")
        if not api_key:
            print("错误: 有待查 IP,需要设置 THREATBOOK_API_KEY", file=sys.stderr)
            return 2
        batch_size = int(os.environ.get("THREATBOOK_BATCH_SIZE", "100"))
        for i in range(0, len(missing), batch_size):
            chunk = missing[i:i + batch_size]
            try:
                for ip, hit in query_scene_dns(api_key, chunk).items():
                    cache[ip] = hit
            except Exception as exc:  # noqa: BLE001 - 保存已查到的缓存再退出
                print(f"[fail] 查询批次 {i // batch_size}: {exc}", file=sys.stderr)
                STATE_FILE.parent.mkdir(exist_ok=True)
                STATE_FILE.write_text(json.dumps(cache, indent=1, ensure_ascii=False))
                return 1
        STATE_FILE.parent.mkdir(exist_ok=True)
        STATE_FILE.write_text(json.dumps(cache, indent=1, ensure_ascii=False))

    items, benign, unknown = [], [], []
    for ip in ips:
        hit = cache.get(ip)
        if hit is None:
            unknown.append(ip)
        elif hit.get("is_malicious"):
            items.append(summarize(ip, hit))
        else:
            benign.append(ip)
    print(f"研判结论: 恶意 {len(items)}, 非恶意 {len(benign)}, 未查到 {len(unknown)}")
    for ip in benign:
        print(f"  [benign] {ip} judgments={cache[ip].get('judgments')}")

    if args.dry_run:
        for item in items:
            print(f"[dry-run] {item['value']} category={item['category']} severity={item['severity']} "
                  f"action={item['recommended_action']}")
        return 0

    rule_path = Path(args.output)
    rule_path.parent.mkdir(parents=True, exist_ok=True)
    rule_path.write_text(build_intel_yaml(items), encoding="utf-8")
    zip_path = rule_path.with_suffix(".zip")
    zip_path.write_bytes(build_intel_zip(build_intel_yaml(items), arcname=rule_path.name))
    print(f"完成: {rule_path} ({len(items)} 条) + {zip_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
