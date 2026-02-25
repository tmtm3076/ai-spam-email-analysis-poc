import requests
import time
import os
import hashlib
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
if not VT_API_KEY:
    raise ValueError("VIRUSTOTAL_API_KEY environment variable is not set")

VT_HEADERS = {
    "x-apikey": VT_API_KEY,
    "accept": "application/json"
}

VT_BASE_URL = "https://www.virustotal.com/api/v3"


# ==========================================================
# 🔷 URL 분석
# ==========================================================

def submit_url(url: str) -> str:
    """
    URL을 VirusTotal에 제출하고 analysis_id를 받는다
    """
    response = requests.post(
        f"{VT_BASE_URL}/urls",
        headers=VT_HEADERS,
        data={"url": url},
        timeout=10
    )
    response.raise_for_status()
    return response.json()["data"]["id"]


def get_result(analysis_id: str, max_retries: int = 20, initial_delay: int = 5) -> dict:
    """
    URL 분석 결과 가져오기
    """
    delay = initial_delay
    status = "unknown"

    for attempt in range(max_retries):
        response = requests.get(
            f"{VT_BASE_URL}/analyses/{analysis_id}",
            headers=VT_HEADERS,
            timeout=10
        )
        response.raise_for_status()

        data = response.json()
        status = data["data"]["attributes"]["status"]

        if status == "completed":
            return data

        if attempt < max_retries - 1:
            time.sleep(delay)
            delay = min(delay * 1.2, 10)

    raise Exception(f"VirusTotal URL 분석 시간 초과 (최종 상태: {status})")


def extract_stats(result: dict) -> dict:
    """
    malicious / suspicious / harmless 추출
    """
    stats = result["data"]["attributes"]["stats"]
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0)
    }


# ==========================================================
# 🔷 파일 해시 기반 분석 (무료 플랜 대응)
# ==========================================================

def calculate_sha256(file_bytes: bytes) -> str:
    """
    파일 SHA256 계산
    """
    sha256 = hashlib.sha256()
    sha256.update(file_bytes)
    return sha256.hexdigest()


def get_file_report_by_hash(file_hash: str) -> dict | None:
    """
    해시 기반으로 기존 분석 결과 조회
    무료 플랜에서는 파일 업로드 대신 이 방식 추천
    """
    response = requests.get(
        f"{VT_BASE_URL}/files/{file_hash}",
        headers=VT_HEADERS,
        timeout=10
    )

    if response.status_code == 404:
        # VT에 아직 없는 파일
        return None

    response.raise_for_status()
    return response.json()


def extract_file_stats(result: dict) -> dict:
    """
    파일 분석 통계 추출
    """
    stats = result["data"]["attributes"]["last_analysis_stats"]

    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0)
    }
