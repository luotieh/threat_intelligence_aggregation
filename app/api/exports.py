from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session

from app.db import get_db
from app.services.config_service import get_effective_settings
from app.services.export_service import export_traffic

router = APIRouter()


@router.get("/exports/traffic")
def export_traffic_api(format: str = "json", db: Session = Depends(get_db)):
    try:
        media_type, content = export_traffic(db, format)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return Response(content=content, media_type=media_type)


@router.get("/downloads/latest")
def download_latest(db: Session = Depends(get_db)):
    export_dir = Path(get_effective_settings(db).export_dir)
    candidates = sorted(export_dir.glob("threat-intel-hub.*"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        raise HTTPException(status_code=404, detail="release package not found")
    return FileResponse(candidates[0])


@router.get("/downloads/{filename}")
def download_file(filename: str, db: Session = Depends(get_db)):
    allowed = {
        "threat-intel-hub.zip",
        "threat-intel-hub.tar.gz",
        "traffic-ioc.txt",
        "traffic-ioc.csv",
        "traffic-ioc.json",
    }
    if filename not in allowed:
        raise HTTPException(status_code=404, detail="file not found")
    path = Path(get_effective_settings(db).export_dir) / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="file not found")
    return FileResponse(path)
