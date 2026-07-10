from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy.orm import Session

from app.models import SyncState
from app.services.config_service import get_effective_settings
from app.services.indicator_service import upsert_indicator
from app.services.normalizer import normalize_value
from app.services.warninglist import is_benign

OTX_API = "https://otx.alienvault.com/api/v1"

# OTX indicator type -> (平台 misp_type, category, to_ids)
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


def pulse_to_attributes(pulse: dict):
    """一个 pulse -> 若干 attribute dict,直接喂给 upsert_indicator(不经 MISP)。

    源与威胁标签打在 attribute 级(Tag),来源画像放 Event.info,均可被证据提取复用。
    """
    tags = [{"name": "source:otx"}]
    tlp = TLP_TAGS.get((pulse.get("tlp") or "").lower())
    if tlp:
        tags.append({"name": tlp})
    for t in (pulse.get("tags") or [])[:10]:
        tags.append({"name": f'otx:tag="{t}"'})
    event = {"info": f"OTX | {pulse.get('name', pulse['id'])}",
             "id": str(pulse.get("id", "")), "Orgc": {"name": "OTX"}}
    for ind in pulse.get("indicators", []):
        mapped = TYPE_MAP.get(ind.get("type"))
        if not mapped:
            continue
        mtype, category, to_ids = mapped
        yield {
            "uuid": f"otx-{pulse.get('id')}-{ind.get('id') or ind.get('indicator')}",
            "type": mtype, "category": category, "value": ind["indicator"],
            "to_ids": to_ids, "comment": (ind.get("title") or ind.get("description") or "")[:255],
            "Tag": tags, "Event": event,
        }


def sync_otx_direct(db: Session, max_pulses: int | None = None) -> dict:
    """直连:拉 OTX 订阅 pulses,平台侧去误报后直接 upsert 进 intel_indicator(不经 MISP)。"""
    s = get_effective_settings(db)
    if not s.otx_api_key:
        return {"status": "skipped", "reason": "OTX_API_KEY 未配置"}
    max_pulses = s.otx_max_pulses if max_pulses is None else max_pulses
    state = _otx_state(db)
    since = state.last_timestamp or (
        datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")
    run_started = datetime.now(timezone.utc)
    imported = filtered = 0
    # OTX 同一 pulse 偶发返回重复 indicator(相同 id → 相同 uuid);SessionLocal 关了
    # autoflush,upsert 的按 uuid 去重看不到本批次 pending 行,重复 uuid 会一起进 flush
    # 批次并撞唯一约束 intel_indicator_misp_attribute_uuid_key。故在此按 uuid 批内去重。
    seen: set[str] = set()
    try:
        for pulse in fetch_pulses(s.otx_api_key, since, max_pulses):
            for attr in pulse_to_attributes(pulse):
                uid = attr.get("uuid")
                if uid and uid in seen:
                    continue
                ntype, nval = normalize_value(attr["type"], attr["value"])
                if is_benign(ntype, nval):
                    filtered += 1
                    continue
                upsert_indicator(db, attr)
                if uid:
                    seen.add(uid)
                imported += 1
        state.last_timestamp = run_started.strftime("%Y-%m-%dT%H:%M:%S")
        state.last_success_at = run_started
        state.status = "success"
        state.error_message = None
        db.commit()
        return {"status": "success", "imported": imported, "filtered_benign": filtered}
    except Exception as exc:  # noqa: BLE001
        # 先回滚清掉中毒事务,否则后续(如 daily_pipeline 的查询)会连锁抛
        # PendingRollbackError,拖垮整条流水线。rollback 后重取 state 再记错。
        db.rollback()
        state = _otx_state(db)
        state.status = "failed"
        state.error_message = str(exc)
        db.commit()
        return {"status": "failed", "error": str(exc)}
