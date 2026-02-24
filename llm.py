import os
import json
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def classify_with_llm(email):

    prompt = f"""
당신은 침해사고 대응을 수행하는 보안 분석 전문가입니다.
감정적인 표현 없이, 기술적 근거 기반으로 단계별 분석하십시오.

반드시 아래 JSON 형식으로만 응답하십시오.

{{
  "label": "spam | phishing | malicious | ham | unknown",
  "confidence": 0~1 사이 실수,
  "rationale": "보안 전문가 관점에서 기술적 분석 근거를 단계별 설명"
}}

메일 내용:
{email.body_text[:4000]}
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            temperature=0.2,
            response_format={"type": "json_object"},
            messages=[
                {"role": "user", "content": prompt}
            ],
        )

        content = response.choices[0].message.content

        data = json.loads(content)

        # 🔒 필드 안정성 보정
        return {
            "label": data.get("label", "unknown"),
            "confidence": float(data.get("confidence", 0)),
            "rationale": data.get("rationale", "")
        }

    except Exception as e:
        return {
            "label": "unknown",
            "confidence": 0,
            "rationale": f"LLM 분석 실패: {str(e)}"
        }
