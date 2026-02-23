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
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY missing")

    # 주소는 그대로 유지합니다 (Gemini 3 Flash)
    api_url = f"https://generativelanguage.googleapis.com/v1/models/gemini-3-flash:generateContent?key={api_key}"

    prompt_text = (
        "Role: Expert Security Analyst\n"
        "Task: Classify if the email is 'spam' or 'ham'.\n"
        "Output: Return ONLY a valid JSON object. No preamble, no markdown.\n"
        "Format: {\"label\": \"spam\"|\"ham\", \"confidence\": 0.0-1.0, \"rationale\": \"string\"}\n\n"
        f"Subject: {email.subject}\n"
        f"Body: {email.body_text[:2500]}"
    )

    # 에러가 났던 responseMimeType을 제거하고 가장 표준적인 설정만 남깁니다.
    payload = {
        "contents": [{
            "parts": [{"text": prompt_text}]
        }],
        "generationConfig": {
            "temperature": 0,
            "topP": 0.95,
            "maxOutputTokens": 1024
            # responseMimeType 필드를 삭제하여 호환성 문제를 해결했습니다.
        }
    }

    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.post(api_url, headers=headers, json=payload, timeout=25)
        res_json = response.json()

        if response.status_code != 200:
            error_msg = res_json.get("error", {}).get("message", "Unknown API Error")
            raise RuntimeError(f"Gemini 3 API Error: {error_msg}")

        # AI 응답 텍스트 추출
        ai_text = res_json['candidates'][0]['content']['parts'][0]['text']
        
        # JSON 후보 추출 로직 실행
        json_text = _extract_json_candidate(ai_text)
        data = json.loads(json_text)

        return LLMResult(
            label=str(data.get("label", "unknown")),
            confidence=float(data.get("confidence", 0.0)),
            rationale=str(data.get("rationale", "")),
            raw=data,
        )

    except Exception as e:
        raise RuntimeError(f"GEMINI_3_FLASH_RETRY_ERROR: {str(e)}")
