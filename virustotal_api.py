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
# 🔷 파일 분석 (해시 조회 → 없으면 업로드 → 분석 대기)
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
    """
    response = requests.get(
        f"{VT_BASE_URL}/files/{file_hash}",
        headers=VT_HEADERS,
        timeout=10
    )

    if response.status_code == 404:
        return None

    response.raise_for_status()
    return response.json()


def upload_file_to_vt(file_bytes: bytes, filename: str) -> str:
    """
    VT에 파일 업로드 후 analysis_id 반환
    """
    files = {
        "file": (filename, file_bytes)
    }

    response = requests.post(
        f"{VT_BASE_URL}/files",
        headers={"x-apikey": VT_API_KEY},
        files=files,
        timeout=30
    )

    response.raise_for_status()
    return response.json()["data"]["id"]


def wait_for_file_analysis(analysis_id: str, max_retries: int = 25, initial_delay: int = 5) -> dict:
    """
    파일 분석 완료까지 대기
    """
    delay = initial_delay
    status = "unknown"

    for attempt in range(max_retries):
        response = requests.get(
            f"{VT_BASE_URL}/analyses/{analysis_id}",
            headers=VT_HEADERS,
            timeout=15
        )
        response.raise_for_status()

        data = response.json()
        status = data["data"]["attributes"]["status"]

        if status == "completed":
            return data

        if attempt < max_retries - 1:
            time.sleep(delay)
            delay = min(delay * 1.2, 15)

    raise Exception(f"파일 분석 시간 초과 (최종 상태: {status})")


def analyze_file_with_vt(file_bytes: bytes, filename: str) -> dict:
    """
    1️⃣ SHA256 계산
    2️⃣ 기존 분석 조회
    3️⃣ 없으면 업로드
    4️⃣ 분석 완료 대기
    5️⃣ 최종 파일 리포트 반환
    """
    file_hash = calculate_sha256(file_bytes)

    # 1️⃣ 기존 결과 조회
    report = get_file_report_by_hash(file_hash)

    if report:
        return report

    # 2️⃣ 없으면 업로드
    analysis_id = upload_file_to_vt(file_bytes, filename)

    # 3️⃣ 분석 대기
    wait_for_file_analysis(analysis_id)

    # 4️⃣ 다시 해시 조회
    final_report = get_file_report_by_hash(file_hash)

    if not final_report:
        raise Exception("파일 분석 완료 후에도 리포트 조회 실패")

    return final_report


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
