from app.services.normalizer import normalize_value


def test_normalizes_domain_case_and_dot():
    assert normalize_value("domain", "Example.COM.") == ("domain", "example.com")


def test_domain_ip_prefers_domain():
    assert normalize_value("domain|ip", "Example.com|1.2.3.4") == ("domain", "example.com")
