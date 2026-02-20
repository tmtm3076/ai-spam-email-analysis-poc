import requests
import time
import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
if not VT_API_KEY:
    raise ValueError("VIRUSTOTAL_API_KEY environment variable is not set")

VT_HEADERS = {
    "x-apikey": VT_API_KEY,
    "accept": "application/json"
}

def submit_url(url: str) -> str:
    """
    URL을 VirusTotal에 제출하고 analysis_id를 받는다
    """
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=VT_HEADERS,
        data={"url": url},
        timeout=10
    )
    response.raise_for_status()
    return response.json()["data"]["id"]


def get_result(analysis_id: str, max_retries: int = 20, initial_delay: int = 5) -> dict:
    """
    VirusTotal 분석 결과를 가져온다
    
    Args:
        analysis_id: VirusTotal analysis ID
        max_retries: 최대 재시도 횟수 (기본값: 20)
        initial_delay: 초기 대기 시간 (기본값: 5초)
    """
    delay = initial_delay
    
    for attempt in range(max_retries):
        response = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=VT_HEADERS,
            timeout=10
        )
        response.raise_for_status()

        data = response.json()
        status = data["data"]["attributes"]["status"]

        if status == "completed":
            return data
        
        # queued 상태 처리
        if attempt < max_retries - 1:
            print(f"⏳ 분석 중... (상태: {status}, {attempt + 1}/{max_retries})")
            time.sleep(delay)
            # 지수 백오프: 최대 10초까지
            delay = min(delay * 1.2, 10)

    raise Exception(f"VirusTotal 분석 시간 초과 ({max_retries * initial_delay}초 이상 대기, 최종 상태: {status})")


def extract_stats(result: dict) -> dict:
    """
    악성/의심 개수만 뽑는다
    """
    stats = result["data"]["attributes"]["stats"]
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0)
    }
