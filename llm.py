from __future__ import annotations

import json
import os
import re
from typing import Optional

from .models import EmailRecord, LLMResult


_CODE_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)


def _extract_json_candidate(text: str) -> str:
    t = (text or "").strip()

    # Prefer fenced JSON if present.
    m = _CODE_FENCE_RE.search(t)
    if m:
        return m.group(1).strip()

    # Otherwise, try to grab the first JSON object/array looking substring.
    obj_start = t.find("{")
    obj_end = t.rfind("}")
    if 0 <= obj_start < obj_end:
        return t[obj_start : obj_end + 1].strip()

    arr_start = t.find("[")
    arr_end = t.rfind("]")
    if 0 <= arr_start < arr_end:
        return t[arr_start : arr_end + 1].strip()

    return t


def classify_with_llm(email: EmailRecord) -> Optional[LLMResult]:
    """Attempt an LLM-based classification.

    Returns None if LLM integration isn't configured.

    Gemini configuration:
    - GEMINI_API_KEY (required)
    - GEMINI_MODEL (optional, default: gemini-1.5-flash)
    """

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return None

    try:
        import google.generativeai as genai  # type: ignore
    except Exception:
        return None

    model_name = os.getenv("GEMINI_MODEL") or "gemini-1.5-flash"

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(model_name=model_name)

    # Keep prompt small; body can be large.
    payload = {
        "task": "Classify whether the email is spam or ham.",
        "output_format": {
            "label": "spam|ham",
            "confidence": "0-1 (optional)",
            "rationale": "short explanation",
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

    resp = model.generate_content(
        prompt,
        generation_config={"temperature": 0},
    )

    content = (getattr(resp, "text", "") or "").strip()
    json_text = _extract_json_candidate(content)

    try:
        data = json.loads(json_text)
    except Exception:
        # If model returns non-JSON, still capture it.
        return LLMResult(label="unknown", rationale=content, raw={"raw_text": content})

    return LLMResult(
        label=str(getattr(data, "get", lambda _k, _d=None: _d)("label", "unknown") or "unknown"),
        confidence=data.get("confidence") if isinstance(data, dict) else None,
        rationale=data.get("rationale") if isinstance(data, dict) else None,
        raw=data if isinstance(data, dict) else {"data": data},
    )
