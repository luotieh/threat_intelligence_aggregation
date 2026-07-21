import json
import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db import get_db
from app.services.config_service import get_effective_settings
from app.services.llm import build_narrative
from app.services.threatbook import (
    BATCH_SIZE,
    MAX_IPS_PER_RUN,
    build_intel_yaml,
    build_intel_zip,
    gang_tags_of,
    map_hit,
    parse_ips,
    query_ip_info,
    summarize,
)

AUDIT_FILE = "threatbook_audit.jsonl"


def _audit_log(db: Session, entry: dict) -> None:
    """追加一条审计记录到 IOC_OUTPUT_DIR 下的 JSONL 文件。"""
    s = get_effective_settings(db)
    out_dir = Path(s.ioc_output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    entry["ts"] = datetime.now(timezone.utc).isoformat()
    with open(out_dir / AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


router = APIRouter()


class QueryRequest(BaseModel):
    ips_text: str


class GenerateRequest(BaseModel):
    # 前端把 /threatbook/query 的 results 原样回传,服务端不再二次查询(省额度)
    results: list[dict]


@router.get("/threatbook/status")
def threatbook_status(db: Session = Depends(get_db)):
    return {"configured": bool(get_effective_settings(db).threatbook_api_key)}


@router.post("/threatbook/query")
def threatbook_query(payload: QueryRequest, db: Session = Depends(get_db)):
    api_key = get_effective_settings(db).threatbook_api_key
    if not api_key:
        raise HTTPException(status_code=400, detail="未配置 ThreatBook API Key(在「情报源」页填写)")
    ips, skipped = parse_ips(payload.ips_text.splitlines())
    if not ips:
        raise HTTPException(status_code=400, detail="输入中没有可识别的 IP")
    if len(ips) > MAX_IPS_PER_RUN:
        raise HTTPException(status_code=400, detail=f"单次最多 {MAX_IPS_PER_RUN} 个 IP(当前 {len(ips)} 个)")

    results, failed_batches = [], 0
    for i in range(0, len(ips), BATCH_SIZE):
        chunk = ips[i:i + BATCH_SIZE]
        try:
            hits = query_ip_info(api_key, chunk)
        except Exception as exc:  # noqa: BLE001 - 单批失败不拖垮整次研判,交给前端提示
            failed_batches += 1
            for ip in chunk:
                results.append({"ip": ip, "error": str(exc)})
            continue
        for ip in chunk:
            hit = hits.get(ip)
            if hit is None:
                results.append({"ip": ip, "error": "接口未返回该 IP 的结果"})
                continue
            if isinstance(hit, dict) and "_error" in hit:
                results.append({"ip": ip, "error": hit["_error"]})
                continue
            results.append({
                "ip": ip,
                "is_malicious": bool(hit.get("is_malicious")),
                "severity_raw": hit.get("severity"),
                "confidence_level": hit.get("confidence_level"),
                "judgments": hit.get("judgments") or [],
                "gang_tags": gang_tags_of(hit),
                "permalink": hit.get("permalink") or f"https://x.threatbook.com/v5/ip/{ip}",
                **map_hit(hit),
                "hit": hit,  # 原样保留,供 /threatbook/generate 回传,避免二次查询
            })
    malicious = sum(1 for r in results if r.get("is_malicious"))
    resp = {
        "total": len(ips),
        "malicious": malicious,
        "benign": sum(1 for r in results if r.get("is_malicious") is False),
        "errors": sum(1 for r in results if r.get("error")),
        "skipped_input": skipped,
        "failed_batches": failed_batches,
        "results": results,
    }
    _audit_log(db, {"type": "query", "ips": ips, "total": resp["total"], "malicious": resp["malicious"], "benign": resp["benign"], "errors": resp["errors"]})
    return resp


@router.post("/threatbook/generate")
def threatbook_generate(payload: GenerateRequest, fmt: str = "yaml", db: Session = Depends(get_db)):
    """把研判结果中判定恶意的 IP 生成 intel.yaml / intel.zip 下载。"""
    s = get_effective_settings(db)
    items = []
    for r in payload.results:
        hit = r.get("hit")
        if r.get("is_malicious") and isinstance(hit, dict) and r.get("ip"):
            items.append(summarize(r["ip"], hit))
    for item in items:
        if s.llm_enabled and s.llm_api_key:
            try:
                text = build_narrative(db, item["evidence"], item["value"])
                if text and len(text) >= 20:
                    item["description"] = text
                    item["evidence"]["narrative"] = text
            except Exception:
                pass
    yaml_text = build_intel_yaml(items)
    if fmt == "zip":
        return Response(
            content=build_intel_zip(yaml_text),
            media_type="application/zip",
            headers={"Content-Disposition": 'attachment; filename="intel.zip"'},
        )
    return Response(
        content=yaml_text,
        media_type="text/yaml; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="intel.yaml"'},
    )


class SaveToGateRequest(BaseModel):
    results: list[dict]
    selected_ips: list[str]


@router.post("/threatbook/save-to-gate")
def save_to_gate(payload: SaveToGateRequest, db: Session = Depends(get_db)):
    """把研判结果中用户勾选的恶意 IP 生成规则,写入网闸目录。"""
    s = get_effective_settings(db)
    selected = set(payload.selected_ips)
    items = []
    for r in payload.results:
        ip = r.get("ip")
        hit = r.get("hit")
        if ip in selected and r.get("is_malicious") and isinstance(hit, dict):
            items.append(summarize(ip, hit))
    for item in items:
        if s.llm_enabled and s.llm_api_key:
            try:
                text = build_narrative(db, item["evidence"], item["value"])
                if text and len(text) >= 20:
                    item["description"] = text
                    item["evidence"]["narrative"] = text
            except Exception:
                pass
    yaml_text = build_intel_yaml(items)
    if items:
        out_dir = Path(s.ioc_output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        base = Path(s.ioc_rule_filename)
        yaml_path = out_dir / base.with_suffix(".yaml").name
        zip_path = out_dir / base.with_suffix(".zip").name
        yaml_path.write_text(yaml_text, encoding="utf-8")
        zip_path.write_bytes(build_intel_zip(yaml_text, arcname=base.with_suffix(".yaml").name))
    return {"status": "ok", "saved": len(items), "ips": [i["value"] for i in items]}


class ManualAddRequest(BaseModel):
    ip: str
    category: str = "malware"
    severity: str = "high"
    judgments: list[str] = []
    description: str = ""


@router.post("/threatbook/manual-add")
def manual_add(payload: ManualAddRequest, db: Session = Depends(get_db)):
    """手动录入恶意 IP（API 额度用完后从微步 Web 控制台查询的结果）。

    根据手动填写的 IP + 威胁信息生成规则,写入网闸目录。
    """
    s = get_effective_settings(db)
    hit = {
        "is_malicious": True,
        "severity": payload.severity,
        "judgments": payload.judgments or [payload.category],
        "confidence_level": "high",
        "tags_classes": [],
        "permalink": "",
    }
    item = summarize(payload.ip, hit)
    if payload.description:
        item["description"] = payload.description
        item["evidence"]["narrative"] = payload.description
    elif s.llm_enabled and s.llm_api_key:
        try:
            text = build_narrative(db, item["evidence"], item["value"])
            if text and len(text) >= 20:
                item["description"] = text
                item["evidence"]["narrative"] = text
        except Exception:
            pass

    yaml_text = build_intel_yaml([item])
    out_dir = Path(s.ioc_output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    base = Path(s.ioc_rule_filename)
    yaml_path = out_dir / base.with_suffix(".yaml").name
    zip_path = out_dir / base.with_suffix(".zip").name
    yaml_path.write_text(yaml_text, encoding="utf-8")
    zip_path.write_bytes(build_intel_zip(yaml_text, arcname=base.with_suffix(".yaml").name))
    resp = {
        "status": "ok",
        "ip": payload.ip,
        "category": item["category"],
        "severity": item["severity"],
        "yaml": str(yaml_path),
        "zip": str(zip_path),
    }
    _audit_log(db, {"type": "manual", "ip": payload.ip, "category": payload.category, "severity": payload.severity, "judgments": payload.judgments})
    return resp


@router.get("/threatbook/logs")
def threatbook_logs(db: Session = Depends(get_db), limit: int = 50):
    """读取研判审计日志,最新在前。"""
    s = get_effective_settings(db)
    log_path = Path(s.ioc_output_dir) / AUDIT_FILE
    if not log_path.exists():
        return {"logs": []}
    lines = log_path.read_text(encoding="utf-8").strip().split("\n")
    entries = []
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return {"logs": entries[:limit]}
