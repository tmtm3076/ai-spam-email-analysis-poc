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
        GEMINI_API_KEY (환경 변수)

    Optional:
        GEMINI_MODEL (default: models/gemini-1.5-flash-latest)
    """

    # 1. API 키 확인
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY not found in environment variables")

    # 2. 라이브러리 임포트
    try:
        import google.generativeai as genai
    except Exception as e:
        raise RuntimeError(f"google.generativeai import failed: {str(e)}")

    # 3. 모델 이름 결정 (404 에러 방지 로직)
    # 환경 변수에서 가져오되, 없으면 가장 안정적인 latest 모델 사용
    raw_model_name = os.getenv("GEMINI_MODEL") or "gemini-1.5-flash-latest"
    
    # 모델명 앞에 'models/'가 없으면 붙여줌 (SDK 권장 사항)
    if not raw_model_name.startswith("models/"):
        final_model_name = f"models/{raw_model_name}"
    else:
        final_model_name = raw_model_name

    # 4. Gemini 설정 및 모델 초기화
    try:
        genai.configure(api_key=api_key)
    # 정의한 final_model_name을 사용하여 모델 객체 생성
        model = genai.GenerativeModel(model_name=final_model_name)
    except Exception as e:
        raise RuntimeError(f"Gemini Model Initialization failed: {str(e)}")

    # 5. 분석용 데이터 준비
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

    # 6. AI 분석 실행
    try:
        resp = model.generate_content(
            prompt,
            generation_config={"temperature": 0}
        )
    except Exception as e:
        # 이 시점에서 404가 나면 라이브러리 버전 문제일 가능성이 큼
        raise RuntimeError(f"Gemini API call failed (Check library version): {str(e)}")

    # 7. 결과 파싱
    content = (getattr(resp, "text", "") or "").strip()
    json_text = _extract_json_candidate(content)

    try:
        data = json.loads(json_text)
    except Exception:
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
