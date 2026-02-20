from __future__ import annotations
import os

def analyze_with_ai(email_text: str) -> str:
    # 1. 환경 변수 확인
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not set")

    # 2. SDK 임포트
    try:
        from google import genai
    except ImportError:
        raise RuntimeError("google-genai 패키지가 없습니다. pip install google-genai 를 실행하세요.")

    # 3. 클라이언트 초기화
    client = genai.Client(api_key=api_key)
    
    # 아까 리스트에서 확인된 모델 중 가장 안정적인 이름을 사용합니다.
    model_id = "gemini-flash-latest" 

    prompt = f"""
너는 기업 정보보호팀의 보안 분석가다.
아래 이메일이 스팸 또는 피싱 메일인지 분석하라.

[이메일 본문]
{email_text}

아래 형식으로만 답변하라.

스팸 가능성: (높음 / 중간 / 낮음)
의심 포인트:
- 항목1
- 항목2
조치 권고:
- 항목1
- 항목2
""".strip()

    try:
        # 4. 분석 요청
        response = client.models.generate_content(
            model=model_id,
            contents=prompt,
            config={
                "temperature": 0.2,
            }
        )
        
        if response and response.text:
            return response.text.strip()
        else:
            return "AI가 응답을 생성했지만 텍스트 내용이 없습니다."

    except Exception as e:
        # 429 에러(할당량)가 나면 잠시 기다려달라는 메시지를 포함합니다.
        if "429" in str(e):
            return "현재 API 호출량이 초과되었습니다. 1분만 기다렸다가 다시 실행해 주세요."
        return f"AI 분석 중 오류 발생: {str(e)}"