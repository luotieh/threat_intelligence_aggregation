from app.services.type_quota import parse_ratio, type_quotas


def test_parse_ratio_valid():
    assert parse_ratio("6:2:2") == (6, 2, 2)
    assert parse_ratio("3:1:1") == (3, 1, 1)
    assert parse_ratio(" 6 : 2 : 2 ") == (6, 2, 2)


def test_parse_ratio_bad_falls_back_to_default():
    for bad in ["", "bad", "1:2", "1:2:3:4", "0:0:0", "-1:2:2", None]:
        assert parse_ratio(bad) == (6, 2, 2)


def test_quotas_sum_to_target():
    assert type_quotas(100, (6, 2, 2)) == {"ip": 60, "domain": 20, "url": 20}
    assert type_quotas(10, (6, 2, 2)) == {"ip": 6, "domain": 2, "url": 2}
    for target in (1, 3, 7, 13, 50, 99):
        q = type_quotas(target, (6, 2, 2))
        assert sum(q.values()) == target


def test_quotas_largest_remainder_tiebreak():
    # target=7, 6:2:2 → raw ip4.2/dom1.4/url1.4 → floor 4/1/1=6,余1
    # 小数部分 dom与url 并列 .4,按 ip>domain>url 优先给 domain
    assert type_quotas(7, (6, 2, 2)) == {"ip": 4, "domain": 2, "url": 1}


def test_quotas_zero_target():
    assert type_quotas(0, (6, 2, 2)) == {"ip": 0, "domain": 0, "url": 0}
