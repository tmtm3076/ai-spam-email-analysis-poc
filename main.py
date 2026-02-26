from fastapi import FastAPI, UploadFile, File, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
import tempfile
import os
import hashlib

from email_parser import parse_email_file
from heuristics import score_email
from llm import classify_with_llm
from url_extractor import extract_urls
from virustotal_api import scan_url

app = FastAPI()

ANALYSIS_STORE = {}

# ==========================================================
# 🔷 유틸
# ==========================================================
def calculate_sha256(file_bytes: bytes) -> str:
    sha256 = hashlib.sha256()
    sha256.update(file_bytes)
    return sha256.hexdigest()


def process_file_analysis(file_hash: str, file_bytes: bytes):
    # 샘플 파일 분석 (실제 환경에서 VT file API 연결)
    ANALYSIS_STORE[file_hash] = {
        "status": "completed",
        "malicious": 0,
        "suspicious": 0
    }


# ==========================================================
# 🔷 GUI (기존 고급버전 유지)
# ==========================================================
@app.get("/", response_class=HTMLResponse)
def home():
    return """ 
    <!-- 기존 GUI 그대로 유지 -->
    """


# ==========================================================
# 🔷 이메일 통합 분석 API
# ==========================================================
@app.post("/analyze")
async def analyze_email(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):

    filename = file.filename.lower()

    if not (filename.endswith(".eml") or filename.endswith(".msg")):
        return JSONResponse(
            status_code=400,
            content={"error": "Only .eml or .msg files are supported"}
        )

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(filename)[1]) as tmp:
            content = await file.read()
            tmp.write(content)
            tmp_path = tmp.name

        email_record = parse_email_file(tmp_path)

        # ==================================================
        # 1️⃣ 휴리스틱 분석
        # ==================================================
        heuristic_result = score_email(email_record)

        # ==================================================
        # 2️⃣ URL 추출 + VT URL 평판 분석
        # ==================================================
        urls = extract_urls(email_record.body_text)

        url_results = []

        for url in urls[:5]:  # 과도한 호출 방지
            try:
                vt_res = scan_url(url)
                url_results.append({
                    "url": url,
                    "vt_result": vt_res
                })
            except Exception as e:
                url_results.append({
                    "url": url,
                    "error": str(e)
                })

        # ==================================================
        # 3️⃣ LLM 정밀 분석
        # ==================================================
        llm_result = classify_with_llm(email_record)

        # ==================================================
        # 종합 판단 로직
        # ==================================================
        overall_label = "ham"

        if heuristic_result.score >= 70:
            overall_label = "high_risk"
        elif heuristic_result.score >= 40:
            overall_label = "spam"

        if llm_result["label"] in ["phishing", "malicious"]:
            overall_label = llm_result["label"]

        return {
            "overall_label": overall_label,

            "heuristic_analysis": {
                "score": heuristic_result.score,
                "flags": heuristic_result.flags,
                "details": heuristic_result.details
            },

            "url_analysis": url_results,

            "llm_analysis": llm_result,

            "attachments_vt": [
                {
                    "filename": att["filename"],
                    "sha256": calculate_sha256(att["content"])
                }
                for att in getattr(email_record, "attachments", [])
            ]
        }

    except Exception as e:
        return {"error": str(e)}

    finally:
        try:
            if "tmp_path" in locals() and os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


# ==========================================================
# 🔷 파일 VT 결과 조회 (2단계 버튼용)
# ==========================================================
@app.get("/vt-result/{file_hash}")
def get_vt_result(file_hash: str):
    return ANALYSIS_STORE.get(file_hash, {"status": "not_found"})


@app.post("/start-vt/{file_hash}")
def start_vt_analysis(file_hash: str):
    if file_hash not in ANALYSIS_STORE:
        ANALYSIS_STORE[file_hash] = {"status": "pending"}
    ANALYSIS_STORE[file_hash] = {
        "status": "completed",
        "malicious": 0,
        "suspicious": 0
    }
    return {"status": "started"}
