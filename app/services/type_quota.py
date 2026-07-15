from __future__ import annotations

DEFAULT_RATIO = (6, 2, 2)  # ip : domain : url
_PRIORITY = {"ip": 0, "domain": 1, "url": 2}  # 余数分配的并列优先级


def parse_ratio(value: str | None) -> tuple[int, int, int]:
    """解析 "ip:domain:url" 权重;非法(非三段/非数字/负数/全零)回落默认 6:2:2。"""
    if not value or not isinstance(value, str):
        return DEFAULT_RATIO
    parts = [p.strip() for p in value.split(":")]
    if len(parts) != 3:
        return DEFAULT_RATIO
    try:
        weights = tuple(int(p) for p in parts)
    except ValueError:
        return DEFAULT_RATIO
    if any(w < 0 for w in weights) or sum(weights) == 0:
        return DEFAULT_RATIO
    return weights  # type: ignore[return-value]


def type_quotas(target: int, ratio: tuple[int, int, int]) -> dict[str, int]:
    """按 ratio 把 target 分成 ip/domain/url 三档配额,用最大余数法保证精确求和到 target。

    并列余数按 ip > domain > url 的优先级分配。
    """
    if target <= 0:
        return {"ip": 0, "domain": 0, "url": 0}
    ip_w, dom_w, url_w = ratio
    total_w = ip_w + dom_w + url_w
    raw = {
        "ip": target * ip_w / total_w,
        "domain": target * dom_w / total_w,
        "url": target * url_w / total_w,
    }
    quota = {k: int(v) for k, v in raw.items()}
    remainder = target - sum(quota.values())
    order = sorted(raw, key=lambda k: (-(raw[k] - quota[k]), _PRIORITY[k]))
    for k in order[:remainder]:
        quota[k] += 1
    return quota
