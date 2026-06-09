from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db import get_db
from app.schemas.config import ConfigPayload
from app.services.config_service import public_config, save_config

router = APIRouter()


@router.get("/api/config")
def get_config(db: Session = Depends(get_db)):
    return public_config(db)


@router.post("/api/config")
def post_config(payload: ConfigPayload, db: Session = Depends(get_db)):
    save_config(db, payload.model_dump(exclude_unset=True))
    return {"status": "saved"}
