import zipfile
from pathlib import Path

import pytest
import yaml

from app.models import AppConfig
from app.services.ta_node_client import push_traffic_to_ta_node, save_uploaded_ioc_rule


def add_cfg(db, key, value):
    db.add(AppConfig(key=key, value=value))


def output_cfg(db, tmp_path):
    add_cfg(db, "IOC_OUTPUT_DIR", str(tmp_path))
    add_cfg(db, "IOC_RULE_FILENAME", "intel.yaml")


def test_push_disabled_skips(db, make_indicator, tmp_path):
    add_cfg(db, "TA_NODE_ENABLED", "false")
    output_cfg(db, tmp_path)
    db.add(make_indicator())
    db.commit()
    assert push_traffic_to_ta_node(db)["status"] == "skipped"


def test_generate_writes_ta_node_yaml_and_same_name_zip(db, make_indicator, tmp_path):
    output_cfg(db, tmp_path)
    db.add(make_indicator())
    db.commit()
    result = push_traffic_to_ta_node(db)
    assert result["status"] == "success"

    rule_path = Path(result["rule_file"])
    zip_path = Path(result["zip_file"])
    data = yaml.safe_load(rule_path.read_text())
    assert data["items"][0]["value"] == "evil.example.com"
    assert data["items"][0]["source"] == "Threat Intel Hub"
    assert {"id", "type", "value", "category", "severity", "source", "enabled"} <= set(data["items"][0])
    with zipfile.ZipFile(zip_path) as archive:
        assert archive.namelist() == ["intel.yaml"]


def test_generate_uses_custom_source_name(db, make_indicator, tmp_path):
    output_cfg(db, tmp_path)
    add_cfg(db, "TA_NODE_SOURCE_NAME", "MISP Hub")
    db.add(make_indicator())
    db.commit()
    result = push_traffic_to_ta_node(db)
    data = yaml.safe_load(Path(result["rule_file"]).read_text())
    assert data["items"][0]["source"] == "MISP Hub"


def test_generate_failure_records_error(db, make_indicator, tmp_path, monkeypatch):
    output_cfg(db, tmp_path)
    indicator = make_indicator()
    db.add(indicator)
    db.commit()

    def fail(*args, **kwargs):
        raise RuntimeError("cannot write")

    monkeypatch.setattr("app.services.ta_node_client.write_ta_node_ioc_files", fail)
    result = push_traffic_to_ta_node(db)
    db.refresh(indicator)
    assert result["status"] == "failed"
    assert indicator.push_error == "cannot write"


def test_full_push_includes_all_traffic_ioc(db, make_indicator, tmp_path):
    output_cfg(db, tmp_path)
    db.add(make_indicator(pushed_to_ta_node=True))
    db.commit()
    result = push_traffic_to_ta_node(db, mode="full")
    assert result["count"] == 1


def test_incremental_push_includes_unpushed_only(db, make_indicator, tmp_path):
    output_cfg(db, tmp_path)
    db.add(make_indicator(value="a", normalized_value="a", pushed_to_ta_node=True))
    db.add(make_indicator(value="b", normalized_value="b", pushed_to_ta_node=False))
    db.commit()
    result = push_traffic_to_ta_node(db, mode="incremental")
    data = yaml.safe_load(Path(result["rule_file"]).read_text())
    assert result["count"] == 1
    assert data["items"][0]["value"] == "b"


def test_upload_yaml_validates_and_creates_same_name_zip(tmp_path):
    content = b"""
items:
  - id: ioc-1
    type: domain
    value: evil.example.com
    category: c2
    severity: high
    source: Threat Intel Hub
    enabled: true
"""
    result = save_uploaded_ioc_rule(str(tmp_path), "intel.yaml", content)
    assert Path(result["rule_file"]).exists()
    with zipfile.ZipFile(result["zip_file"]) as archive:
        assert archive.namelist() == ["intel.yaml"]


def test_upload_yaml_rejects_invalid_ta_node_format(tmp_path):
    with pytest.raises(ValueError):
        save_uploaded_ioc_rule(str(tmp_path), "intel.yaml", b"items: [{type: domain}]")
