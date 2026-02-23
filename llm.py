from __future__ import annotations
import json
import os
import re
from typing import Optional
from models import EmailRecord, LLMResult

_CODE_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)

def _extract_json_candidate(text: str) -> str:
    t = (text or "").strip()
    m = _CODE_FENCE_RE.search(t)
    if m: return m.group(1).strip()
    obj_start = t.find("{")
    obj_end = t.rfind("}")
    if 0 <= obj_start < obj_end: return t[obj_start:obj_end + 1].strip()
    return t

def classify_with_llm(email: EmailRecord) -> Optional[LLMResult]:
    api_key = os.getenv("GEMINI_API_KEY", "").strip() # 공백 제거 추가
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY not found in environment variables")

    try:
        import google.generativeai as genai
    except Exception as e:
        raise RuntimeError(f"google.generativeai import failed: {str(e)}")

    # 모델명 결정
    raw_model_name = os.getenv("GEMINI_MODEL") or "gemini-1.5-flash-latest"
    final_model_name = raw_model_name if raw_model_name.startswith("models/") else f"models/{raw_model_name}"

    try:
        genai.configure(api_key=api_key)
        # 명시적으로 v1 API를 사용하도록 유도
        model = genai.GenerativeModel(model_name=final_model_name)
        
        payload = {
            "task": "Classify whether the email is spam or ham.",
            "output_format": {"label": "spam|ham", "confidence": "0-1", "rationale": "short explanation"},
            "email": {
                "subject": email.subject,
                "from": email.from_addr,
                "body_excerpt": (email.body_text or "")[:3000],
            },
        }

        prompt = "Return ONLY valid JSON.\n" + json.dumps(payload, ensure_ascii=False)
        
        resp = model.generate_content(prompt, generation_config={"temperature": 0})
        
        content = (getattr(resp, "text", "") or "").strip()
        json_text = _extract_json_candidate(content)
        data = json.loads(json_text)

        return LLMResult(
            label=str(data.get("label", "unknown")),
            confidence=data.get("confidence"),
            rationale=data.get("rationale"),
            raw=data,
        )
    except Exception as e:
        # 에러 메시지에 모델명을 포함시켜 디버깅 용이하게 변경
        raise RuntimeError(f"Gemini API Error [Model: {final_model_name}]: {str(e)}")
