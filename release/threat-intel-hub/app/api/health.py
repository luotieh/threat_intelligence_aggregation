from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db import get_db
from app.services.config_service import get_effective_settings
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
