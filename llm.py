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

    model_name = "gemini-2.5-flash"

    api_url = (
        f"https://generativelanguage.googleapis.com/v1/models/"
        f"{model_name}:generateContent?key={api_key}"
    )

    prompt_text = (
        "Return ONLY a JSON object.\n"
        "Format: {\"label\": \"spam\"|\"ham\", \"confidence\": 0.0-1.0, \"rationale\": \"string\"}\n\n"
        f"Subject: {email.subject}\n"
        f"Body: {email.body_text[:2000]}"
    )

    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt_text}
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0,
            "maxOutputTokens": 1500
        }
    }

    try:
        headers = {"Content-Type": "application/json"}

        # DEBUG 로그
        print("==== GEMINI REQUEST PAYLOAD ====")
        print(payload)
        print("================================")

        response = requests.post(
            api_url,
            headers=headers,
            json=payload,
            timeout=20
        )

        print("==== GEMINI RESPONSE STATUS ====", response.status_code)
        print("==== GEMINI RESPONSE TEXT ====")
        print(response.text)
        print("================================")

        if response.status_code != 200:
            try:
                res_json = response.json()
                error_msg = res_json.get("error", {}).get("message", "Unknown Error")
            except Exception:
                error_msg = response.text
            raise RuntimeError(f"API Error: {error_msg}")

        res_json = response.json()

        if not res_json.get("candidates"):
            raise RuntimeError("No candidates returned from Gemini")

        ai_text = res_json["candidates"][0]["content"]["parts"][0]["text"]

        try:
            data = json.loads(_extract_json_candidate(ai_text))
        except json.JSONDecodeError:
            return LLMResult(
                label="unknown",
                confidence=0.0,
                rationale="Invalid JSON returned from LLM",
                raw={"raw_text": ai_text}
            )

        return LLMResult(
            label=data.get("label", "unknown"),
            confidence=float(data.get("confidence", 0.0)),
            rationale=data.get("rationale", ""),
            raw=data
        )

    except Exception as e:
        raise RuntimeError(f"FINAL_STABLE_CALL_ERROR: {str(e)}")
