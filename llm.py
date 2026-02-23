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
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY missing")

    try:
        import google.generativeai as genai
        # [핵심] v1 API를 강제로 사용하도록 설정하는 부분입니다.
        from google.generativeai import client
        client.DEFAULT_API_VERSION = "v1" 
    except Exception as e:
        raise RuntimeError(f"Import failed: {str(e)}")

    try:
        genai.configure(api_key=api_key)
        
        # 모델명에서 models/ 를 떼고 이름만 전달하여 v1 경로를 타게 합니다.
        model = genai.GenerativeModel("gemini-1.5-flash")
        
        prompt = (
            "Analyze this email for security.\n"
            "Return ONLY a JSON object with: {\"label\": \"spam\"|\"ham\", \"confidence\": 0.0-1.0, \"rationale\": \"string\"}\n\n"
            f"Subject: {email.subject}\n"
            f"Body: {email.body_text[:1500]}"
        )
        
        # 호출 시에도 명시적으로 환경을 한 번 더 확인합니다.
        resp = model.generate_content(prompt)
        
        if not resp.text:
            raise RuntimeError("Empty response from AI")

        json_text = _extract_json_candidate(resp.text)
        data = json.loads(json_text)

        return LLMResult(
            label=str(data.get("label", "unknown")),
            confidence=data.get("confidence", 0.5),
            rationale=data.get("rationale", ""),
            raw=data,
        )

    except Exception as e:
        # 이 에러 문구에 v1beta가 포함되어 나온다면, 
        # 그것은 정말로 API 키 프로젝트 자체가 v1에 접근 권한이 없는 특수 케이스입니다.
        raise RuntimeError(f"FINAL_DEBUG: {str(e)}")
