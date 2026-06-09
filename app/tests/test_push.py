from app.models import AppConfig
from app.services.ta_node_client import push_traffic_to_ta_node


class FakeResponse:
    def __init__(self, fail=False):
        self.fail = fail

    def raise_for_status(self):
        if self.fail:
            raise RuntimeError("connection refused")


class FakeClient:
    calls = []
    fail = False

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def post(self, url, headers=None, json=None):
        self.calls.append({"url": url, "headers": headers or {}, "json": json})
        return FakeResponse(self.fail)


def add_cfg(db, key, value):
    db.add(AppConfig(key=key, value=value))


def test_push_disabled_skips(db, make_indicator):
    add_cfg(db, "TA_NODE_ENABLED", "false")
    db.add(make_indicator())
    db.commit()
    assert push_traffic_to_ta_node(db)["status"] == "skipped"


def test_push_sends_sync_source_payload(db, make_indicator, monkeypatch):
    FakeClient.calls = []
    monkeypatch.setattr("app.services.ta_node_client.httpx.Client", FakeClient)
    db.add(make_indicator())
    db.commit()
    result = push_traffic_to_ta_node(db)
    assert result["status"] == "success"
    assert FakeClient.calls[0]["json"]["source"] == "Threat Intel Hub"
    assert FakeClient.calls[0]["json"]["items"][0]["value"] == "evil.example.com"


def test_push_with_token_sets_authorization_header(db, make_indicator, monkeypatch):
    FakeClient.calls = []
    monkeypatch.setattr("app.services.ta_node_client.httpx.Client", FakeClient)
    add_cfg(db, "TA_NODE_TOKEN", "secret")
    db.add(make_indicator())
    db.commit()
    push_traffic_to_ta_node(db)
    assert FakeClient.calls[0]["headers"]["Authorization"] == "Bearer secret"


def test_push_failure_records_error(db, make_indicator, monkeypatch):
    class FailingClient(FakeClient):
        fail = True

    monkeypatch.setattr("app.services.ta_node_client.httpx.Client", FailingClient)
    indicator = make_indicator()
    db.add(indicator)
    db.commit()
    result = push_traffic_to_ta_node(db)
    db.refresh(indicator)
    assert result["status"] == "failed"
    assert indicator.push_error


def test_full_push_includes_all_traffic_ioc(db, make_indicator, monkeypatch):
    FakeClient.calls = []
    monkeypatch.setattr("app.services.ta_node_client.httpx.Client", FakeClient)
    db.add(make_indicator(pushed_to_ta_node=True))
    db.commit()
    result = push_traffic_to_ta_node(db, mode="full")
    assert result["count"] == 1


def test_incremental_push_includes_unpushed_only(db, make_indicator, monkeypatch):
    FakeClient.calls = []
    monkeypatch.setattr("app.services.ta_node_client.httpx.Client", FakeClient)
    db.add(make_indicator(value="a", normalized_value="a", pushed_to_ta_node=True))
    db.add(make_indicator(value="b", normalized_value="b", pushed_to_ta_node=False))
    db.commit()
    result = push_traffic_to_ta_node(db, mode="incremental")
    assert result["count"] == 1
    assert FakeClient.calls[0]["json"]["items"][0]["value"] == "b"
