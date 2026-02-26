import os
import json
import re
import google.generativeai as genai


GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY is not set")

genai.configure(api_key=GEMINI_API_KEY)

model = genai.GenerativeModel("gemini-2.5-flash")


def safe_json_parse(text: str) -> dict:
    try:
        return json.loads(text)
    except Exception:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            return json.loads(match.group())
        raise


def classify_with_llm(email):

    prompt = f"""
당신은 침해사고 대응을 수행하는 보안 전문가입니다.
감정적 표현 없이, 기술적 근거 중심으로 단계별 분석하십시오.
반드시 모든 출력은 한국어로 작성하십시오.
반드시 JSON만 출력하십시오.
코드블록 사용 금지.
설명 문장 금지.
JSON 외 텍스트 출력 금지.

형식:
{{
  "label": "spam | phishing | ham | malicious | unknown",
  "confidence": 0.0,
  "rationale": "보안 전문가 관점의 단계별 분석 근거(반드시 한글)"
}}

메일 내용:
{email.body_text[:6000]}
"""

    try:
        response = model.generate_content(
            prompt,
            generation_config={
                "temperature": 0.2
            }
        )

        text = response.text.strip()
        parsed = safe_json_parse(text)

        return {
            "label": parsed.get("label", "unknown"),
            "confidence": float(parsed.get("confidence", 0)),
            "rationale": parsed.get("rationale", "분석 근거 없음")
        }

    except Exception as e:
        return {
            "label": "unknown",
            "confidence": 0,
            "rationale": f"Gemini 분석 실패: {str(e)}"
        }
