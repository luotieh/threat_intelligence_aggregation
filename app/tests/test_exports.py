import json
import pytest

from fastapi import HTTPException

from app.api.exports import download_latest, download_file
from app.models import AppConfig
from app.services.export_service import export_traffic


def test_download_latest_release(db, tmp_path):
    path = tmp_path / "threat-intel-hub.zip"
    path.write_text("zip")
    db.add(AppConfig(key="EXPORT_DIR", value=str(tmp_path)))
    db.commit()
    response = download_latest(db)
    assert response.path == path


def test_download_missing_file_returns_404(db):
    with pytest.raises(HTTPException) as exc:
        download_file("threat-intel-hub.zip", db)
    assert exc.value.status_code == 404


def test_export_traffic_txt(db, make_indicator):
    db.add(make_indicator())
    db.commit()
    assert export_traffic(db, "txt")[1] == "evil.example.com\n"


def test_export_traffic_csv(db, make_indicator):
    db.add(make_indicator())
    db.commit()
    text = export_traffic(db, "csv")[1]
    assert "type,value,category,severity,tags,last_seen" in text
    assert "evil.example.com" in text


def test_export_traffic_json(db, make_indicator):
    db.add(make_indicator())
    db.commit()
    data = json.loads(export_traffic(db, "json")[1])
    assert data[0]["value"] == "evil.example.com"
