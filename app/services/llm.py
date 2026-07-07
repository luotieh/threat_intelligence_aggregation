from __future__ import annotations

import json
import os

import httpx
from sqlalchemy.orm import Session

from app.services.config_service import get_effective_settings

NARRATIVE_SYSTEM = (
    "你是威胁情报分析助手。只依据用户给出的结构化证据,用简洁中文写一段面向 SOC 的流量告警通告。"
    "严禁编造证据之外的任何信息(不得杜撰家族、IP、域名、时间或归因)。证据不足时如实说明。"
)


def _proxy_for(base_url: str) -> str | None:
    """本地 LLM(Ollama/vLLM)直连,外部 LLM 经出网代理。"""
    if any(h in (base_url or "") for h in ("host.docker.internal", "localhost", "127.0.0.1")):
        return None
    return os.environ.get("OUTBOUND_HTTPS_PROXY") or None


def chat_completion(base_url: str, api_key: str, model: str, messages: list[dict],
                    max_tokens: int = 400, timeout: int = 60) -> str:
    """OpenAI 兼容 /chat/completions。"""
    url = base_url.rstrip("/") + "/chat/completions"
    with httpx.Client(timeout=timeout, proxy=_proxy_for(base_url), trust_env=False) as client:
        resp = client.post(
            url,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": model, "messages": messages, "max_tokens": max_tokens, "temperature": 0.2},
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]


def llm_health(db: Session) -> dict:
    s = get_effective_settings(db)
    if not s.llm_enabled:
        return {"status": "disabled", "reason": "LLM_ENABLED 为 false"}
    if not s.llm_api_key or not s.llm_base_url:
        return {"status": "unconfigured", "error": "LLM_BASE_URL / LLM_API_KEY 未配置"}
    try:
        reply = chat_completion(s.llm_base_url, s.llm_api_key, s.llm_model,
                                [{"role": "user", "content": "reply with the single word OK"}],
                                max_tokens=5, timeout=30)
        return {"status": "ok", "model": s.llm_model, "reply": (reply or "").strip()[:60]}
    except Exception as exc:  # noqa: BLE001
        return {"status": "failed", "error": str(exc)}


def build_narrative(db: Session, evidence: dict, value: str) -> str:
    """把结构化证据润色成自然语言告警(只重述证据,不新增事实)。"""
    s = get_effective_settings(db)
    user = (f"IOC: {value}\n结构化证据(JSON):\n{json.dumps(evidence, ensure_ascii=False)}\n\n"
            "请写 50-120 字的告警通告:威胁性质、判定依据、建议处置。只使用上面证据里的事实。")
    return chat_completion(s.llm_base_url, s.llm_api_key, s.llm_model,
                           [{"role": "system", "content": NARRATIVE_SYSTEM},
                            {"role": "user", "content": user}], max_tokens=800)


def generate_narrative(db: Session, indicator, retries: int = 3) -> str | None:
    """对单个 indicator 生成 narrative,失败或返回空则重试;成功返回文本,否则 None。"""
    from app.services.ta_node_client import build_evidence
    value = indicator.normalized_value or indicator.value
    for _ in range(max(1, retries)):
        try:
            text = build_narrative(db, build_evidence(indicator), value)
            if text and text.strip():
                return text.strip()
        except Exception:  # noqa: BLE001 - 重试
            continue
    return None


def enrich_narratives(db: Session, limit: int | None = None) -> dict:
    """对 high 档证据生成告警叙述,存 raw.narrative;失败/空自动重试,已生成的不重复。"""
    from app.models import IntelIndicator

    s = get_effective_settings(db)
    if not s.llm_enabled:
        return {"status": "disabled", "reason": "LLM_ENABLED 为 false"}
    if not s.llm_api_key:
        return {"status": "unconfigured", "error": "LLM_BASE_URL / LLM_API_KEY 未配置"}
    limit = 10 if limit is None else limit
    candidates = (db.query(IntelIndicator)
                  .filter(IntelIndicator.severity == "high")
                  .order_by(IntelIndicator.last_seen.desc()).all())
    todo = [c for c in candidates if not (c.raw or {}).get("narrative")][:limit]
    generated = failed = 0
    for ind in todo:
        text = generate_narrative(db, ind)
        if text:
            raw = {**(ind.raw or {}), "narrative": text}
            raw.pop("narrative_error", None)
            ind.raw = raw
            generated += 1
        else:
            ind.raw = {**(ind.raw or {}), "narrative_error": "LLM 多次重试仍为空"}
            failed += 1
    db.commit()
    return {"status": "success", "queued": len(todo), "generated": generated, "failed": failed}
