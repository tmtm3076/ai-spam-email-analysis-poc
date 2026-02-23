from __future__ import annotations
import json
import os
import re
import requests  # 직접 호출을 위해 추가
from typing import Optional
from models import EmailRecord, LLMResult

def _extract_json_candidate(text: str) -> str:
    t = (text or "").strip()
    obj_start = t.find("{")
    obj_end = t.rfind("}")
    if 0 <= obj_start < obj_end:
        return t[obj_start:obj_end + 1].strip()
    return t

def classify_with_llm(email: EmailRecord) -> Optional[LLMResult]:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY missing")

    # 1. 경로 강제 지정 (v1beta가 아닌 v1을 직접 주소에 박습니다)
    # 이 주소는 SDK를 거치지 않고 구글 서버로 바로 가는 정식 루트입니다.
    api_url = f"https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash:generateContent?key={api_key}"

    # 2. 페이로드 작성
    prompt_text = (
        "Analyze this email for security.\n"
        "Return ONLY a JSON object with: {\"label\": \"spam\"|\"ham\", \"confidence\": 0.0-1.0, \"rationale\": \"string\"}\n\n"
        f"Subject: {email.subject}\n"
        f"Body: {email.body_text[:2000]}"
    )

    payload = {
        "contents": [{
            "parts": [{"text": prompt_text}]
        }],
        "generationConfig": {
            "temperature": 0,
            "topP": 0.95,
            "maxOutputTokens": 1024,
        }
    }

    try:
        # 3. SDK 대신 requests로 직접 전송 (v1beta로 꺾일 일이 없습니다)
        headers = {'Content-Type': 'application/json'}
        response = requests.post(api_url, headers=headers, json=payload)
        res_json = response.json()

        if response.status_code != 200:
            error_detail = res_json.get("error", {}).get("message", "Unknown error")
            raise RuntimeError(f"Google API Direct Call Error: {error_detail}")

        # 4. 응답 파싱
        ai_text = res_json['candidates'][0]['content']['parts'][0]['text']
        json_text = _extract_json_candidate(ai_text)
        data = json.loads(json_text)

        return LLMResult(
            label=str(data.get("label", "unknown")),
            confidence=data.get("confidence", 0.5),
            rationale=data.get("rationale", ""),
            raw=data,
        )

    except Exception as e:
        # 여기서도 v1beta 에러가 난다면, 그건 정말로 구글 계정 설정 문제입니다.
        raise RuntimeError(f"REST_API_ERROR: {str(e)}")
