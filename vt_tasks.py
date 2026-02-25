import time
from typing import Dict

from virustotal_api import (
    get_file_report_by_hash,
    upload_file_to_vt,
    wait_for_file_analysis,
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
        analysis_id = upload_file_to_vt(file_bytes, file_hash)

        ANALYSIS_STORE[file_hash] = {
            "status": "analyzing",
            "analysis_id": analysis_id,
        }

        # 3️⃣ 분석 완료까지 대기
        wait_for_file_analysis(analysis_id)

        # 4️⃣ 다시 해시 조회
        final_result = get_file_report_by_hash(file_hash)

        if not final_result:
            raise Exception("분석 완료 후 리포트 조회 실패")

        stats = extract_file_stats(final_result)

        ANALYSIS_STORE[file_hash] = {
            "status": "completed",
            "stats": stats,
        }

    except Exception as e:
        ANALYSIS_STORE[file_hash] = {
            "status": "error",
            "error": str(e),
        }
