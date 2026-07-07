from app.services.warninglist import is_benign


def test_private_and_reserved_ip_is_benign():
    assert is_benign("ip", "10.0.0.1")
    assert is_benign("ip", "192.168.1.1")
    assert is_benign("ip", "172.16.0.9")
    assert is_benign("ip", "127.0.0.1")


def test_public_dns_is_benign():
    assert is_benign("ip", "8.8.8.8")
    assert is_benign("ip", "1.1.1.1")


def test_whitelist_domain_and_subdomain():
    assert is_benign("domain", "google.com")
    assert is_benign("domain", "mail.google.com")
    assert is_benign("domain", "s3.amazonaws.com")


def test_malicious_not_benign():
    assert not is_benign("ip", "45.66.77.88")
    assert not is_benign("domain", "evil.example.com")
    assert not is_benign("domain", "notgoogle.com")
