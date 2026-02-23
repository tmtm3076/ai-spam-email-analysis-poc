from __future__ import annotations
import json
import os
import re
import requests
from typing import Optional
from models import EmailRecord, LLMResult

def _extract_json_candidate(text: str) -> str:
    """텍스트에서 JSON 부분만 안전하게 추출합니다."""
    t = (text or "").strip()
    # 마크다운 코드 펜스 제거
    t = re.sub(r"```(?:json)?\s*|\s*```", "", t, flags=re.IGNORECASE | re.DOTALL)
    
    obj_start = t.find("{")
    obj_end = t.rfind("}")
    if 0 <= obj_start < obj_end:
        return t[obj_start:obj_end + 1].strip()
    return t

def classify_with_llm(email: EmailRecord) -> Optional[LLMResult]:
    """
    Gemini 3 Flash 모델을 사용하여 이메일을 분류합니다.
    SDK를 사용하지 않고 직접 REST API(v1)를 호출하여 환경 변수 꼬임을 방지합니다.
    """
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY missing in environment variables")

    # [핵심] Gemini 3 Flash 모델의 정식 v1 엔드포인트
    api_url = f"https://generativelanguage.googleapis.com/v1/models/gemini-3-flash:generateContent?key={api_key}"

    # 최신 모델에 최적화된 프롬프트
    prompt_text = (
        "Role: Professional Security Analyst\n"
        "Task: Classify the following email as 'spam' or 'ham'.\n"
        "Constraint: Return ONLY a valid JSON object.\n\n"
        "Format: {\"label\": \"spam\"|\"ham\", \"confidence\": 0.0-1.0, \"rationale\": \"string\"}\n\n"
        f"Subject: {email.subject}\n"
        f"From: {email.from_addr}\n"
        f"Body: {email.body_text[:3000]}"
    )

    # Gemini 3 Flash 규격에 맞춘 페이로드
    payload = {
        "contents": [{
            "parts": [{"text": prompt_text}]
        }],
        "generationConfig": {
            "temperature": 0,
            "topP": 0.95,
            "maxOutputTokens": 1024,
            "responseMimeType": "application/json"  # 모델 수준에서 JSON 출력 강제
        }
    }

    try:
        # App Runner 캐시 영향을 받지 않는 표준 HTTP 호출
        headers = {'Content-Type': 'application/json'}
        response = requests.post(api_url, headers=headers, json=payload, timeout=25)
        res_json = response.json()

        if response.status_code != 200:
            error_msg = res_json.get("error", {}).get("message", "Unknown API Error")
            # 여기서 404가 난다면 API Key의 권한/지역 문제입니다.
            raise RuntimeError(f"Gemini 3 API Error: {error_msg}")

        # 응답 데이터 파싱
        try:
            ai_text = res_json['candidates'][0]['content']['parts'][0]['text']
            json_text = _extract_json_candidate(ai_text)
            data = json.loads(json_text)
        except (KeyError, IndexError, json.JSONDecodeError) as parse_err:
            raise RuntimeError(f"Response Parsing Failed: {str(parse_err)}")

        return LLMResult(
            label=str(data.get("label", "unknown")),
            confidence=float(data.get("confidence", 0.0)),
            rationale=str(data.get("rationale", "")),
            raw=data,
        )

    except Exception as e:
        # 상세 에러 추적을 위한 접두어 추가
        raise RuntimeError(f"GEMINI_3_FLASH_ERROR: {str(e)}")
