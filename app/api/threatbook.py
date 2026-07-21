from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db import get_db
from app.services.config_service import get_effective_settings
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
    return {
        "total": len(ips),
        "malicious": malicious,
        "benign": sum(1 for r in results if r.get("is_malicious") is False),
        "errors": sum(1 for r in results if r.get("error")),
        "skipped_input": skipped,
        "failed_batches": failed_batches,
        "results": results,
    }


@router.post("/threatbook/generate")
def threatbook_generate(payload: GenerateRequest, fmt: str = "yaml"):
    """把研判结果中判定恶意的 IP 生成 intel.yaml / intel.zip,以附件形式下载。

    只产出下载文件,不写服务器磁盘、不覆盖平台正在推送的规则文件。
    """
    items = []
    for r in payload.results:
        hit = r.get("hit")
        if r.get("is_malicious") and isinstance(hit, dict) and r.get("ip"):
            items.append(summarize(r["ip"], hit))
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
