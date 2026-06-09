from app.services.ta_node_client import map_indicator_to_ta_node_item


def test_map_ip_src_to_ta_node_ip(make_indicator):
    item = map_indicator_to_ta_node_item(make_indicator(misp_type="ip-src", normalized_type="ip", normalized_value="1.2.3.4"))
    assert item["type"] == "ip"


def test_map_domain_to_ta_node_domain(make_indicator):
    item = map_indicator_to_ta_node_item(make_indicator(misp_type="domain"))
    assert item["type"] == "domain"


def test_map_url_to_ta_node_url(make_indicator):
    item = map_indicator_to_ta_node_item(make_indicator(misp_type="url", normalized_type="url", normalized_value="https://evil.example/a"))
    assert item["type"] == "url"


def test_map_ja3_to_ta_node_ja3(make_indicator):
    item = map_indicator_to_ta_node_item(make_indicator(misp_type="ja3-fingerprint-md5", normalized_value="abc"))
    assert item["type"] == "ja3"


def test_map_unknown_traffic_type_to_pattern(make_indicator):
    item = map_indicator_to_ta_node_item(make_indicator(misp_type="unknown-traffic"))
    assert item["type"] == "pattern"


def test_indicator_without_uuid_generates_stable_id(make_indicator):
    indicator = make_indicator(misp_attribute_uuid=None)
    assert map_indicator_to_ta_node_item(indicator)["id"] == map_indicator_to_ta_node_item(indicator)["id"]
