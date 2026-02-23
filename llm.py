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

    # [최종 결정] v1 정식 주소와 가장 범용적인 모델명을 조합합니다.
    # gemini-1.5-flash는 v1 엔드포인트에서 가장 표준적으로 지원되는 이름입니다.
    api_url = f"https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash:generateContent?key={api_key}"

    prompt_text = (
        "Return ONLY a JSON object.\n"
        "Format: {\"label\": \"spam\"|\"ham\", \"confidence\": 0.0-1.0, \"rationale\": \"string\"}\n\n"
        f"Subject: {email.subject}\n"
        f"Body: {email.body_text[:2000]}"
    )

    payload = {
        "contents": [{"parts": [{"text": prompt_text}]}],
        "generationConfig": {
            "temperature": 0,
            "maxOutputTokens": 800
        }
    }

    try:
        # SDK가 아닌 Requests를 사용하므로 App Runner의 구버전 찌꺼기 영향을 받지 않습니다.
        headers = {'Content-Type': 'application/json'}
        response = requests.post(api_url, headers=headers, json=payload, timeout=20)
        res_json = response.json()

        if response.status_code != 200:
            error_msg = res_json.get("error", {}).get("message", "Unknown Error")
            # 여기서 또 404가 난다면 모델명이 아니라 'API 키 자체의 활성화 상태' 문제입니다.
            raise RuntimeError(f"API Error: {error_msg}")

        ai_text = res_json['candidates'][0]['content']['parts'][0]['text']
        data = json.loads(_extract_json_candidate(ai_text))

        return LLMResult(
            label=data.get("label", "unknown"),
            confidence=float(data.get("confidence", 0.0)),
            rationale=data.get("rationale", ""),
            raw=data
        )
    except Exception as e:
        raise RuntimeError(f"FINAL_STABLE_CALL_ERROR: {str(e)}")
