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


def test_map_builds_structured_evidence(make_indicator):
    ind = make_indicator(
        misp_type="domain", normalized_value="evil.com", severity="high", tlp="white",
        tags=[{"name": "source:otx"}, {"name": "tlp:white"}, {"name": 'otx:tag="akira"'},
              {"name": 'otx:tag="adaptixc2"'}],
        raw={"Event": {"info": "OTX | Akira ransomware campaign", "id": "5"},
             "whoisxml": {"results": [{"threatType": "malware",
                                       "firstSeen": "2025-01-01T00:00:00Z",
                                       "lastSeen": "2026-01-01T00:00:00Z"}]}})
    item = map_indicator_to_ta_node_item(ind)
    ev = item["evidence"]
    assert "akira" in ev["threat_labels"] and "adaptixc2" in ev["threat_labels"]
    assert ev["cross_check"].startswith("WhoisXML=malware")
    assert ev["source"] == "otx"
    assert "2 sources" in ev["confidence"]
    assert "Akira ransomware campaign" in item["description"]
    assert item["recommended_action"] == "block_and_report"


def test_map_evidence_without_enrichment(make_indicator):
    ind = make_indicator(misp_type="domain", severity="medium", tags=[{"name": "source:circl"}], raw={})
    item = map_indicator_to_ta_node_item(ind)
    assert item["evidence"]["cross_check"] is None
    assert "1 source" in item["evidence"]["confidence"]
    assert item["recommended_action"] == "block"
