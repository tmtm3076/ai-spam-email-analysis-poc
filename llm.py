import json
from openai import OpenAI

client = OpenAI()


def classify_with_llm(email):

    prompt = f"""
당신은 침해사고 분석을 수행하는 보안 전문가입니다.
감정적 표현 없이 기술적 근거 기반으로 분석하십시오.

반드시 아래 형식의 JSON으로만 답하십시오.

{{
  "label": "spam | phishing | ham | malicious | unknown",
  "confidence": 0과 1 사이의 실수,
  "rationale": "보안 전문가 관점에서 단계별 분석 근거"
}}

메일 내용:
{email.body_text}
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You must return valid JSON only."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            response_format={"type": "json_object"}
        )

        content = response.choices[0].message.content

        return json.loads(content)

    except Exception as e:
        return {
            "label": "unknown",
            "confidence": 0,
            "rationale": f"LLM 분석 실패: {str(e)}"
        }
