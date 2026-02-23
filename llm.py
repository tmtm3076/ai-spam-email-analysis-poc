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
    # 마크다운 코드 펜스 처리
    m = _CODE_FENCE_RE.search(t)
    if m:
        return m.group(1).strip()
    # 중괄호 기준 추출
    obj_start = t.find("{")
    obj_end = t.rfind("}")
    if 0 <= obj_start < obj_end:
        return t[obj_start:obj_end + 1].strip()
    return t

def classify_with_llm(email: EmailRecord) -> Optional[LLMResult]:
    """
    Gemini API를 사용하여 이메일을 분석합니다.
    v1beta 404 에러 방지를 위해 모델명을 명시적으로 고정하여 호출합니다.
    """

    # 1. API 키 확인 (앞뒤 공백 제거)
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY not found in environment variables")

    # 2. SDK 라이브러리 임포트
    try:
        import google.generativeai as genai
    except Exception as e:
        raise RuntimeError(f"google.generativeai import failed: {str(e)}")

    # 3. 모델 이름 결정
    # v1beta 404 에러를 방지하기 위해 가장 안정적인 정식 명칭을 사용합니다.
    # 환경변수 GEMINI_MODEL이 없어도 'models/gemini-1.5-flash'로 작동합니다.
    final_model_name = "models/gemini-1.5-flash"

    try:
        # 4. Gemini 설정
        genai.configure(api_key=api_key)
        
        # 5. 모델 객체 생성
        model = genai.GenerativeModel(model_name=final_model_name)
        
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
        
        # 7. AI 분석 실행 (온도 0으로 설정하여 결정론적 결과 유도)
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
        # 404 에러 발생 시 원인 파악을 위해 에러 문구에 모델명을 포함합니다.
        raise RuntimeError(f"Gemini API Error [Model: {final_model_name}]: {str(e)}")
