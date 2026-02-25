import time
from typing import Dict

from virustotal_api import (
    get_file_report_by_hash,
    upload_file,
    get_analysis_result,
    extract_file_stats,
)

# 간단 메모리 저장소 (PoC용)
ANALYSIS_STORE: Dict[str, dict] = {}


def process_file_analysis(file_hash: str, file_bytes: bytes):
    """
    Background Task에서 실행됨
    """

    try:
        # 1️⃣ 먼저 해시 조회
        result = get_file_report_by_hash(file_hash)

        if result:
            stats = extract_file_stats(result)
            ANALYSIS_STORE[file_hash] = {
                "status": "completed",
                "stats": stats,
            }
            return

        # 2️⃣ VT에 없으면 업로드
        analysis_id = upload_file(file_bytes, file_hash)

        ANALYSIS_STORE[file_hash] = {
            "status": "analyzing",
            "analysis_id": analysis_id,
        }

        # 3️⃣ 분석 완료까지 폴링
        analysis_result = get_analysis_result(analysis_id)

        stats = analysis_result["data"]["attributes"]["stats"]

        ANALYSIS_STORE[file_hash] = {
            "status": "completed",
            "stats": stats,
        }

    except Exception as e:
        ANALYSIS_STORE[file_hash] = {
            "status": "error",
            "error": str(e),
        }
