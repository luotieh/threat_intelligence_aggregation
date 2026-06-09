from app.models import AppConfig
from app.schemas.config import ConfigPayload
from app.services.config_service import public_config, save_config
from app.api.health import health_ta_node


def test_get_config_masks_secret(db):
    db.add(AppConfig(key="MISP_API_KEY", value="secret"))
    db.commit()
    data = public_config(db)
    assert data["misp_api_key_masked"] is True
    assert "secret" not in str(data)


def test_post_config_updates_misp_url(db):
    save_config(db, ConfigPayload(misp_url="https://misp.local").model_dump(exclude_unset=True))
    assert public_config(db)["misp_url"] == "https://misp.local"


def test_post_config_empty_secret_keeps_old_secret(db):
    db.add(AppConfig(key="TA_NODE_TOKEN", value="old"))
    db.commit()
    save_config(db, ConfigPayload(ta_node_token="").model_dump(exclude_unset=True))
    assert public_config(db)["ta_node_token_masked"] is True


def test_health_ta_node_success(db, monkeypatch):
    class Response:
        def raise_for_status(self):
            pass

    class Client:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, url):
            return Response()

    monkeypatch.setattr("app.api.health.httpx.Client", Client)
    assert health_ta_node(db)["status"] == "ok"


def test_health_ta_node_failed(db, monkeypatch):
    class Client:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, url):
            raise RuntimeError("connection refused")

    monkeypatch.setattr("app.api.health.httpx.Client", Client)
    assert health_ta_node(db)["status"] == "failed"
