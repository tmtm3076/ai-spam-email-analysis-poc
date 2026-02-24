import json
from openai import OpenAI

client = OpenAI()


def classify_with_llm(email):

    prompt = f"""
당신은 침해사고 분석을 수행하는 보안 전문가입니다.
감정적인 표현 없이, 기술적 근거 기반으로 분석하십시오.

반드시 아래 JSON 형식으로만 답변하십시오.

{{
  "label": "spam | phishing | ham | malicious | unknown",
  "confidence": 0~1 사이 실수,
  "rationale": "보안 전문가 관점에서 근거를 단계별로 설명"
}}

메일 내용:
{email.body_text}
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2
        )

        text = response.choices[0].message.content.strip()

        # JSON 파싱 안정화
        if "```" in text:
            text = text.split("```")[1]
            text = text.replace("json", "").strip()

        return json.loads(text)

    except Exception as e:
        return {
            "label": "unknown",
            "confidence": 0,
            "rationale": f"LLM 분석 실패: {str(e)}"
        }
