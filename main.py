from fastapi import FastAPI, UploadFile, File, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
import tempfile
import os
import hashlib

from mail_analyzer import analyze_mail
from email_parser import parse_email_file

app = FastAPI()

# ==========================================================
# 🔷 VT 분석 상태 저장소 (메모리)
# ==========================================================
ANALYSIS_STORE = {}


# ==========================================================
# 🔷 SHA256 계산
# ==========================================================
def calculate_sha256(file_bytes: bytes) -> str:
    sha256 = hashlib.sha256()
    sha256.update(file_bytes)
    return sha256.hexdigest()


# ==========================================================
# 🔷 실제 VT 분석 처리 (백그라운드)
# ==========================================================
def process_file_analysis(file_hash: str, file_bytes: bytes):
    try:
        # TODO: 여기에 실제 VT API 호출 코드 넣으면 됨
        # 지금은 테스트용 성공 처리
        ANALYSIS_STORE[file_hash] = {
            "status": "completed",
            "result": "VT 분석 완료 (샘플 응답)"
        }
    except Exception as e:
        ANALYSIS_STORE[file_hash] = {
            "status": "error",
            "error": str(e)
        }


# ==========================================================
# 🔷 GUI 화면
# ==========================================================
@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>AI Email Security Analyzer</title>
        <meta charset="UTF-8">
    </head>
    <body>
        <h2>📧 AI Email Security Analyzer</h2>
        <p>.eml 또는 .msg 파일 업로드</p>

        <input type="file" id="fileElem" accept=".eml,.msg">
        <button onclick="uploadFile()">분석하기</button>

        <h3>결과</h3>
        <pre id="result"></pre>

        <script>
            async function uploadFile() {
                const fileInput = document.getElementById('fileElem');
                const file = fileInput.files[0];

                if (!file) {
                    alert("파일을 선택하세요.");
                    return;
                }

                const formData = new FormData();
                formData.append("file", file);

                const res = await fetch("/analyze", {
                    method: "POST",
                    body: formData
                });

                const data = await res.json();
                document.getElementById("result").textContent =
                    JSON.stringify(data, null, 2);
            }
        </script>
    </body>
    </html>
    """


# ==========================================================
# 🔷 이메일 분석 API (통합 버전)
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
        # 1️⃣ 임시파일 저장
        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=os.path.splitext(filename)[1]
        ) as tmp:
            tmp.write(await file.read())
            tmp_path = tmp.name

        # 2️⃣ 이메일 파싱
        email_record = parse_email_file(tmp_path)

        # 3️⃣ 본문 AI 분석
        body_analysis = analyze_mail(email_record.body_text)

        attachments = getattr(email_record, "attachments", [])

        vt_results = []

        # 4️⃣ 첨부파일 VT 비동기 분석
        for attachment in attachments:
            attach_filename = attachment["filename"]
            file_bytes = attachment["content"]

            file_hash = calculate_sha256(file_bytes)

            ANALYSIS_STORE[file_hash] = {
                "status": "pending"
            }

            background_tasks.add_task(
                process_file_analysis,
                file_hash,
                file_bytes
            )

            vt_results.append({
                "filename": attach_filename,
                "sha256": file_hash,
                "status": "analysis_started"
            })

        return {
            "ai_body_analysis": body_analysis,
            "attachments_vt": vt_results if vt_results else "첨부파일 없음"
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
# 🔷 VT 결과 조회 API
# ==========================================================
@app.get("/vt-result/{file_hash}")
def get_vt_result(file_hash: str):
    result = ANALYSIS_STORE.get(file_hash)

    if not result:
        return {"status": "not_found"}

    return result
