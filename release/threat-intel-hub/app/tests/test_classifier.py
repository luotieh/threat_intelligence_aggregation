from app.services.classifier import classify_indicator


def test_network_activity_category_is_traffic():
    assert classify_indicator("Network activity", "sha256") == "traffic"


def test_ip_src_type_is_traffic():
    assert classify_indicator("Payload delivery", "ip-src") == "traffic"


def test_domain_type_is_traffic():
    assert classify_indicator("External analysis", "domain") == "traffic"


def test_sha256_type_is_other():
    assert classify_indicator("Payload delivery", "sha256") == "other"


def test_vulnerability_type_is_other():
    assert classify_indicator("External analysis", "vulnerability") == "other"
