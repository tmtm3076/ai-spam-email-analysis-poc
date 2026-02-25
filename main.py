from fastapi import FastAPI, UploadFile, File, BackgroundTasks
from fastapi.responses import JSONResponse
import uuid
import tempfile

from src.email_parser import parse_email_file
from virustotal_api import calculate_sha256
from vt_tasks import process_file_analysis, ANALYSIS_STORE

app = FastAPI()


@app.post("/analyze-email/")
async def analyze_email(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    """
    EML 업로드 → 첨부파일 추출 → VT 분석 (비동기)
    """

    if not file.filename.endswith(".eml"):
        return JSONResponse(
            status_code=400,
            content={"error": "Only .eml files are supported"}
        )

    # 임시파일 저장
    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name

    # email_parser 사용
    email_record = parse_email_file(tmp_path)

    attachments = email_record.attachments

    if not attachments:
        return {"message": "첨부파일 없음"}

    response_data = []

    for attachment in attachments:
        filename = attachment["filename"]
        file_bytes = attachment["content"]

        file_hash = calculate_sha256(file_bytes)

        # 초기 상태 저장
        ANALYSIS_STORE[file_hash] = {
            "status": "pending"
        }

        # 백그라운드 분석 시작
        background_tasks.add_task(
            process_file_analysis,
            file_hash,
            file_bytes
        )

        response_data.append({
            "filename": filename,
            "sha256": file_hash,
            "status": "analysis_started"
        })

    return {
        "message": "VT 분석 시작됨 (비동기)",
        "files": response_data
    }


@app.get("/analysis-result/{file_hash}")
def get_analysis_result_api(file_hash: str):
    """
    분석 결과 조회 API
    """

    result = ANALYSIS_STORE.get(file_hash)

    if not result:
        return {"status": "not_found"}

    return result
