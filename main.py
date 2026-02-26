from fastapi import FastAPI, UploadFile, File, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
import tempfile
import os
import hashlib

from mail_analyzer import analyze_mail
from email_parser import parse_email_file

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
    """
    실제 환경에서는 여기서 VirusTotal API 호출
    """
    try:
        # 샘플 응답
        ANALYSIS_STORE[file_hash] = {
            "status": "completed",
            "malicious": 0,
            "suspicious": 0
        }
    except Exception as e:
        ANALYSIS_STORE[file_hash] = {
            "status": "error",
            "error": str(e)
        }


# ==========================================================
# 🔷 1️⃣ GUI
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
    font-family: Arial;
    background: #0f172a;
    color: #e2e8f0;
    text-align: center;
    padding: 40px;
}
.container {
    background: #1e293b;
    padding: 30px;
    border-radius: 12px;
    max-width: 1000px;
    margin: auto;
}
#drop-area {
    border: 2px dashed #3b82f6;
    padding: 30px;
    border-radius: 10px;
    cursor: pointer;
}
table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
}
th, td {
    border: 1px solid #334155;
    padding: 8px;
}
th {
    background: #0f172a;
}
.bad { color:#dc2626; font-weight:bold; }
.good { color:#16a34a; font-weight:bold; }
</style>
</head>
<body>

<div class="container">
<h2>🛡 AI Email Threat Intelligence Platform</h2>

<div id="drop-area">
📂 클릭하여 이메일 파일 선택
<input type="file" id="fileElem" accept=".eml,.msg" style="display:none">
</div>

<button onclick="uploadFile()">🔍 분석 시작</button>

<h3>📊 AI 분석 요약</h3>
<div id="aiSummary"></div>

<h3>📎 첨부파일 VT 분석</h3>
<div id="vtTable"></div>

</div>

<script>
const dropArea = document.getElementById('drop-area');
const fileElem = document.getElementById('fileElem');
let selectedFile = null;
let vtHashes = [];

dropArea.addEventListener('click', () => fileElem.click());

fileElem.addEventListener('change', (e) => {
    selectedFile = e.target.files[0];
});

async function uploadFile() {
    if (!selectedFile) {
        alert("파일을 선택하세요.");
        return;
    }

    const formData = new FormData();
    formData.append("file", selectedFile);

    document.getElementById("aiSummary").innerHTML = "분석 중...";
    document.getElementById("vtTable").innerHTML = "";

    const response = await fetch("/analyze", {
        method: "POST",
        body: formData
    });

    const data = await response.json();

    if (data.error) {
        document.getElementById("aiSummary").innerHTML =
            "<span class='bad'>오류: " + data.error + "</span>";
        return;
    }

    renderAISummary(data.ai_body_analysis);
    renderVTTable(data.attachments_vt || []);
}

function renderAISummary(ai) {
    if (!ai) {
        document.getElementById("aiSummary").innerHTML = "AI 분석 결과 없음";
        return;
    }

    let risk = ai.risk_level || "unknown";
    let cls = risk === "high" ? "bad" : "good";

    let html = `
        <p>위험도: <span class="${cls}">${risk}</span></p>
        <p>요약: ${ai.summary || "-"}</p>
    `;

    document.getElementById("aiSummary").innerHTML = html;
}

async function renderVTTable(files) {
    if (files.length === 0) {
        document.getElementById("vtTable").innerHTML = "첨부파일 없음";
        return;
    }

    let html = `
    <table>
        <tr>
            <th>파일명</th>
            <th>SHA256</th>
            <th>상태</th>
            <th>Malicious</th>
            <th>Suspicious</th>
        </tr>
    `;

    for (let f of files) {
        const res = await fetch("/vt-result/" + f.sha256);
        const result = await res.json();

        html += `
        <tr>
            <td>${f.filename}</td>
            <td>${f.sha256.substring(0,12)}...</td>
            <td>${result.status}</td>
            <td>${result.malicious ?? "-"}</td>
            <td>${result.suspicious ?? "-"}</td>
        </tr>
        `;
    }

    html += "</table>";
    document.getElementById("vtTable").innerHTML = html;
}
</script>

</body>
</html>
"""
# ==========================================================
# 🔷 2️⃣ 이메일 분석 API
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

        ai_result = analyze_mail(email_record.body_text)

        vt_results = []

        for attachment in getattr(email_record, "attachments", []):
            file_hash = calculate_sha256(attachment["content"])

            ANALYSIS_STORE[file_hash] = {"status": "pending"}

            background_tasks.add_task(
                process_file_analysis,
                file_hash,
                attachment["content"]
            )

            vt_results.append({
                "filename": attachment["filename"],
                "sha256": file_hash
            })

        return {
            "ai_body_analysis": ai_result,
            "attachments_vt": vt_results
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
