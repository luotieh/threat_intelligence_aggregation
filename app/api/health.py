import os

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db import get_db
from app.services.config_service import get_effective_settings
from app.services.llm import llm_health
from app.services.misp_client import check_misp_health

import httpx

router = APIRouter()


@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/health/misp")
def health_misp(db: Session = Depends(get_db)):
    return check_misp_health(db)


@router.get("/health/ta-node")
def health_ta_node(db: Session = Depends(get_db)):
    s = get_effective_settings(db)
    try:
        with httpx.Client(timeout=10) as client:
            response = client.get(f"{s.ta_node_base_url}/api/v1/health")
            response.raise_for_status()
        return {"status": "ok", "ta_node_base_url": s.ta_node_base_url}
    except Exception as exc:
        return {"status": "failed", "error": str(exc), "ta_node_base_url": s.ta_node_base_url}


def _outbound_proxy() -> str | None:
    """外部情报源在公网,容器经 socat 转发器出网(见 OUTBOUND_HTTPS_PROXY)。"""
    return os.environ.get("OUTBOUND_HTTPS_PROXY") or None


@router.get("/health/otx")
def health_otx(db: Session = Depends(get_db)):
    s = get_effective_settings(db)
    if not s.otx_api_key:
        return {"status": "unconfigured", "error": "OTX_API_KEY 未配置"}
    try:
        with httpx.Client(timeout=15, proxy=_outbound_proxy()) as client:
            response = client.get(
                "https://otx.alienvault.com/api/v1/user/me",
                headers={"X-OTX-API-KEY": s.otx_api_key},
            )
            response.raise_for_status()
        return {"status": "ok", "username": response.json().get("username")}
    except Exception as exc:
        return {"status": "failed", "error": str(exc)}


@router.get("/health/whoisxml")
def health_whoisxml(db: Session = Depends(get_db)):
    s = get_effective_settings(db)
    if not s.whoisxml_api_key:
        return {"status": "unconfigured", "error": "WHOISXML_API_KEY 未配置"}
    try:
        with httpx.Client(timeout=15, proxy=_outbound_proxy()) as client:
            response = client.get(
                "https://user.whoisxmlapi.com/user-service/account-balance",
                params={"apiKey": s.whoisxml_api_key, "output_format": "JSON"},
            )
            response.raise_for_status()
        return {"status": "ok"}
    except Exception as exc:
        return {"status": "failed", "error": str(exc)}


@router.get("/health/llm")
def health_llm(db: Session = Depends(get_db)):
    return llm_health(db)
