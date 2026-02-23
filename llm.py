from __future__ import annotations

import json
import os
import re
from typing import Optional

from models import EmailRecord, LLMResult


_CODE_FENCE_RE = re.compile(
    r"```(?:json)?\s*(.*?)\s*```",
    re.DOTALL | re.IGNORECASE
)


def _extract_json_candidate(text: str) -> str:
    t = (text or "").strip()

    # Prefer fenced JSON if present.
    m = _CODE_FENCE_RE.search(t)
    if m:
        return m.group(1).strip()

    # Try to grab first JSON object
    obj_start = t.find("{")
    obj_end = t.rfind("}")
    if 0 <= obj_start < obj_end:
        return t[obj_start:obj_end + 1].strip()

    return t


def classify_with_llm(email: EmailRecord) -> Optional[LLMResult]:
    """
    LLM 기반 스팸 분류

    Required:
        GEMINI_API_KEY

    Optional:
        GEMINI_MODEL (default: gemini-1.5-flash-latest)
    """

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY not found in environment variables")

    try:
        import google.generativeai as genai
    except Exception as e:
        raise RuntimeError(f"google.generativeai import failed: {str(e)}")

    model_name = os.getenv("GEMINI_MODEL") or "gemini-1.5-flash-latest"

    # Gemini 설정
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(model_name)

    payload = {
        "task": "Classify whether the email is spam or ham.",
        "output_format": {
            "label": "spam|ham",
            "confidence": "0-1 (optional)",
            "rationale": "short explanation"
        },
        "email": {
            "subject": email.subject,
            "from": email.from_addr,
            "to": email.to_addrs,
            "date": email.date,
            "body_excerpt": (email.body_text or "")[:4000],
        },
    }

    prompt = (
        "You are a careful security analyst.\n"
        "Return ONLY valid JSON (no markdown, no code fences).\n"
        + json.dumps(payload, ensure_ascii=False)
    )

    try:
        resp = model.generate_content(
            prompt,
            generation_config={"temperature": 0}
        )
    except Exception as e:
        raise RuntimeError(f"Gemini API call failed: {str(e)}")

    content = (getattr(resp, "text", "") or "").strip()
    json_text = _extract_json_candidate(content)

    try:
        data = json.loads(json_text)
    except Exception:
        # JSON 파싱 실패해도 시스템 안죽게 처리
        return LLMResult(
            label="unknown",
            confidence=None,
            rationale="LLM returned non-JSON response",
            raw={"raw_text": content},
        )

    if not isinstance(data, dict):
        return LLMResult(
            label="unknown",
            confidence=None,
            rationale="LLM returned unexpected format",
            raw={"data": data},
        )

    return LLMResult(
        label=str(data.get("label", "unknown")),
        confidence=data.get("confidence"),
        rationale=data.get("rationale"),
        raw=data,
    )
