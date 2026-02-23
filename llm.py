from __future__ import annotations
import json
import os
import re
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
    # 1. API 키 확인
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY not found")

    try:
        import google.generativeai as genai
    except Exception as e:
        raise RuntimeError(f"Import failed: {str(e)}")

    try:
        # 2. 아주 기본적인 설정
        genai.configure(api_key=api_key)
        
        # 3. 모델명을 'models/' 없이 그냥 'gemini-1.5-flash'만 써봅니다.
        # SDK 버전에 따라 models/ 가 붙으면 v1beta로 오해하는 경우가 있습니다.
        model = genai.GenerativeModel("gemini-1.5-flash")
        
        # 4. 프롬프트 단순화
        prompt = f"Analyze this email and return only JSON with labels 'spam' or 'ham'. Subject: {email.subject} Body: {email.body_text[:1000]}"
        
        # 5. 호출
        resp = model.generate_content(prompt)
        
        content = resp.text
        json_text = _extract_json_candidate(content)
        data = json.loads(json_text)

        return LLMResult(
            label=str(data.get("label", "unknown")),
            confidence=data.get("confidence", 0.5),
            rationale=data.get("rationale", ""),
            raw=data,
        )

    except Exception as e:
        # 에러 메시지를 아주 상세하게 찍어서 정체를 밝힙니다.
        raise RuntimeError(f"DEBUG_INFO: {str(e)}")
