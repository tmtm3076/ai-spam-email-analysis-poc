from fastapi import FastAPI, UploadFile, File, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
import tempfile
import os
import hashlib

from mail_analyzer import analyze_mail
from email_parser import parse_email_file

app = FastAPI()

ANALYSIS_STORE = {}


def calculate_sha256(file_bytes: bytes) -> str:
    sha256 = hashlib.sha256()
    sha256.update(file_bytes)
    return sha256.hexdigest()


def process_file_analysis(file_hash: str, file_bytes: bytes):
    try:
        # TODO: 실제 VT API 연동 부분
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
# 🔷 고급 GUI
# ==========================================================
@app.get("/", response_class=HTMLResponse)
def home():
    return """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>AI Email Security Analyzer</title>
<style>
body {
    font-family: Arial, sans-serif;
    background-color: #f4f6f9;
    padding: 40px;
}
.container {
    background: white;
    padding: 30px;
    border-radius: 10px;
    box-shadow: 0 4px 10px rgba(0,0,0,0.1);
}
button {
    background-color: #007bff;
    color: white;
    border: none;
    padding: 10px 20px;
    border-radius: 6px;
    cursor: pointer;
}
button:hover {
    background-color: #0056b3;
}
.result-box {
    margin-top: 20px;
    background: #111;
    color: #0f0;
    padding: 15px;
    border-radius: 6px;
    white-space: pre-wrap;
}
.error {
    color: red;
    font-weight: bold;
}
.loading {
    color: orange;
}
.copy-btn {
    margin-top: 10px;
    background: #28a745;
}
</style>
</head>
<body>
<div class="container">
<h2>📧 AI Email Security Analyzer</h2>
<p>.eml 또는 .msg 파일 업로드</p>

<input type="file" id="fileElem" accept=".eml,.msg">
<button onclick="uploadFile()">분석하기</button>

<div id="status" class="loading"></div>

<div class="result-box" id="result"></div>
<button class="copy-btn" onclick="copyResult()">결과 복사</button>
</div>

<script>
async function uploadFile() {
    const fileInput = document.getElementById('fileElem');
    const file = fileInput.files[0];

    if (!file) {
        alert("파일을 선택하세요.");
        return;
    }

    document.getElementById("status").innerText = "분석 중...";
    document.getElementById("result").innerText = "";

    const formData = new FormData();
    formData.append("file", file);

    try {
        const res = await fetch("/analyze", {
            method: "POST",
            body: formData
        });

        const data = await res.json();

        if (data.error) {
            document.getElementById("status").innerHTML =
                "<span class='error'>오류 발생</span>";
            document.getElementById("result").innerText =
                JSON.stringify(data, null, 2);
            return;
        }

        document.getElementById("status").innerText = "분석 완료";

        let formatted = JSON.stringify(data, null, 2);

        document.getElementById("result").innerText = formatted;

    } catch (err) {
        document.getElementById("status").innerHTML =
            "<span class='error'>서버 오류</span>";
        document.getElementById("result").innerText = err;
    }
}

function copyResult() {
    const text = document.getElementById("result").innerText;
    navigator.clipboard.writeText(text);
    alert("결과가 복사되었습니다.");
}
</script>
</body>
</html>
"""


# ==========================================================
# 🔷 분석 API
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
        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=os.path.splitext(filename)[1]
        ) as tmp:
            tmp.write(await file.read())
            tmp_path = tmp.name

        email_record = parse_email_file(tmp_path)

        body_analysis = analyze_mail(email_record.body_text)

        attachments = getattr(email_record, "attachments", [])

        vt_results = []

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


@app.get("/vt-result/{file_hash}")
def get_vt_result(file_hash: str):
    return ANALYSIS_STORE.get(file_hash, {"status": "not_found"})
