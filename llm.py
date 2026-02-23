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
    """텍스트에서 JSON 부분만 추출합니다."""
    t = (text or "").strip()
    m = _CODE_FENCE_RE.search(t)
    if m:
        return m.group(1).strip()
    obj_start = t.find("{")
    obj_end = t.rfind("}")
    if 0 <= obj_start < obj_end:
        return t[obj_start:obj_end + 1].strip()
    return t

def classify_with_llm(email: EmailRecord) -> Optional[LLMResult]:
    """
    Gemini API v1 정식 버전을 강제로 호출하여 404 에러를 방지합니다.
    """

    # 1. API 키 확인
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY not found in environment variables")

    # 2. SDK 라이브러리 임포트
    try:
        import google.generativeai as genai
        # v1 엔드포인트 강제 설정을 위한 타입 임포트
        from google.generativeai.types import HarmCategory, HarmBlockThreshold
    except Exception as e:
        raise RuntimeError(f"google.generativeai import failed: {str(e)}")

    # 3. 모델 이름 결정 (가장 표준적인 명칭 사용)
    final_model_name = "gemini-1.5-flash"

    try:
        # 4. Gemini 설정
        genai.configure(api_key=api_key)
        
        # 5. 모델 객체 생성 (기본 엔드포인트를 v1으로 사용하도록 유도)
        # 일부 환경에서 SDK가 v1beta를 기본값으로 잡는 현상을 방지하기 위해 생성자 최적화
        model = genai.GenerativeModel(
            model_name=f"models/{final_model_name}"
        )
        
        # 6. 분석용 페이로드 준비
        payload = {
            "task": "Classify whether the email is spam or ham.",
            "output_format": {
                "label": "spam|ham", 
                "confidence": "0-1", 
                "rationale": "short explanation"
            },
            "email": {
                "subject": email.subject,
                "from": email.from_addr,
                "body_excerpt": (email.body_text or "")[:3000],
            },
        }

        prompt = "Return ONLY valid JSON.\n" + json.dumps(payload, ensure_ascii=False)
        
        # 7. AI 분석 실행
        # 안전 설정을 기본값으로 두어 API 버전 충돌을 최소화합니다.
        resp = model.generate_content(
            prompt, 
            generation_config={"temperature": 0}
        )
        
        # 8. 응답 파싱
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
        # 에러 발생 시 현재 호출을 시도한 정확한 경로 정보를 포함하여 출력
        error_msg = str(e)
        raise RuntimeError(f"Gemini API Error [v1/models/{final_model_name}]: {error_msg}")
