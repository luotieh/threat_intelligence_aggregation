from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy.orm import Session

from app.models import SyncState
from app.services.config_service import get_effective_settings

OTX_API = "https://otx.alienvault.com/api/v1"

# OTX indicator type -> (MISP type, category, to_ids)
TYPE_MAP = {
    "IPv4": ("ip-dst", "Network activity", True),
    "IPv6": ("ip-dst", "Network activity", True),
    "domain": ("domain", "Network activity", True),
    "hostname": ("hostname", "Network activity", True),
    "URL": ("url", "Network activity", True),
    "URI": ("uri", "Network activity", True),
    "FileHash-MD5": ("md5", "Payload delivery", True),
    "FileHash-SHA1": ("sha1", "Payload delivery", True),
    "FileHash-SHA256": ("sha256", "Payload delivery", True),
    "email": ("email-src", "Payload delivery", True),
    "CVE": ("vulnerability", "External analysis", False),
    "Mutex": ("mutex", "Artifacts dropped", True),
    "CIDR": ("ip-dst", "Network activity", True),
}
TLP_TAGS = {"white": "tlp:white", "green": "tlp:green", "amber": "tlp:amber", "red": "tlp:red"}


def _outbound_proxy() -> str | None:
    return os.environ.get("OUTBOUND_HTTPS_PROXY") or None


def _otx_state(db: Session) -> SyncState:
    state = db.query(SyncState).filter(SyncState.source_name == "otx").one_or_none()
    if state is None:
        state = SyncState(source_name="otx")
        db.add(state)
    return state


def pulse_to_event(pulse: dict) -> dict:
    attributes = []
    for ind in pulse.get("indicators", []):
        mapped = TYPE_MAP.get(ind.get("type"))
        if not mapped:
            continue
        mtype, category, to_ids = mapped
        attributes.append({
            "type": mtype, "category": category, "value": ind["indicator"],
            "to_ids": to_ids, "comment": (ind.get("title") or ind.get("description") or "")[:255],
        })
    tags = [{"name": "source:otx"}]
    tlp = TLP_TAGS.get((pulse.get("tlp") or "").lower())
    if tlp:
        tags.append({"name": tlp})
    for t in (pulse.get("tags") or [])[:10]:
        tags.append({"name": f'otx:tag="{t}"'})
    date = (pulse.get("created") or "")[:10] or datetime.now(timezone.utc).date().isoformat()
    return {
        "info": f"OTX | {pulse.get('name', pulse['id'])}",
        "date": date, "distribution": "0", "analysis": "2", "threat_level_id": "3",
        "published": False, "Attribute": attributes, "Tag": tags,
    }


def fetch_pulses(api_key: str, since: str, max_pulses: int):
    got = 0
    url = f"{OTX_API}/pulses/subscribed"
    params = {"modified_since": since, "limit": 50}
    with httpx.Client(timeout=60, proxy=_outbound_proxy(),
                      headers={"X-OTX-API-KEY": api_key}) as client:
        while url and got < max_pulses:
            resp = client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
            for pulse in data.get("results", []):
                yield pulse
                got += 1
                if got >= max_pulses:
                    return
            url = data.get("next")
            params = None  # next 已带全部参数


def _misp_post(misp_url: str, misp_key: str, path: str, payload: dict) -> dict:
    # MISP 在本地(host.docker.internal),不走出网代理:trust_env=False
    with httpx.Client(timeout=120, verify=False, trust_env=False) as client:
        resp = client.post(f"{misp_url}{path}",
                           headers={"Authorization": misp_key, "Accept": "application/json"},
                           json=payload)
        resp.raise_for_status()
        return resp.json()


def sync_otx_to_misp(db: Session, max_pulses: int | None = None) -> dict:
    """增量拉取 OTX 订阅的 pulses,每个转为一个 MISP 事件并发布。"""
    s = get_effective_settings(db)
    if not s.otx_api_key:
        return {"status": "skipped", "reason": "OTX_API_KEY 未配置"}
    if not s.misp_api_key:
        return {"status": "skipped", "reason": "MISP_API_KEY 未配置"}
    max_pulses = s.otx_max_pulses if max_pulses is None else max_pulses
    state = _otx_state(db)
    since = state.last_timestamp or (
        datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")
    run_started = datetime.now(timezone.utc)
    created = failed = 0
    try:
        for pulse in fetch_pulses(s.otx_api_key, since, max_pulses):
            event = pulse_to_event(pulse)
            if not event["Attribute"]:
                continue
            try:
                result = _misp_post(s.misp_url, s.misp_api_key, "/events/add", event)
                event_id = result["Event"]["id"]
                _misp_post(s.misp_url, s.misp_api_key, f"/events/publish/{event_id}", {})
                created += 1
            except Exception:  # noqa: BLE001 - 单个事件失败不中断整批
                failed += 1
        state.last_timestamp = run_started.strftime("%Y-%m-%dT%H:%M:%S")
        state.last_success_at = run_started
        state.status = "success"
        state.error_message = None
        db.commit()
        return {"status": "success", "created": created, "failed": failed}
    except Exception as exc:  # noqa: BLE001
        state.status = "failed"
        state.error_message = str(exc)
        db.commit()
        return {"status": "failed", "error": str(exc)}
