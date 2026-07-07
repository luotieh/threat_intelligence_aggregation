from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db import get_db
from app.services.enrichment import enrich_high_severity_indicators

router = APIRouter()


@router.post("/enrich/whoisxml")
def enrich_whoisxml(limit: int | None = None, db: Session = Depends(get_db)):
    """立即对 high 档 domain/ip 做一次 WhoisXML 富化(默认取配置的每日条数)。"""
    return enrich_high_severity_indicators(db, limit=limit)


@router.post("/enrich/narrative")
def enrich_narrative(limit: int | None = None, db: Session = Depends(get_db)):
    """用 LLM 对 high 档证据生成自然语言告警叙述(存 raw.narrative,已生成的不重复)。"""
    from app.services.llm import enrich_narratives
    return enrich_narratives(db, limit=limit)
