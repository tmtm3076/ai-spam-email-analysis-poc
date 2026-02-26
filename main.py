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
<title>Email Threat Intelligence Console</title>
<style>

:root{
    --bg:#0b1220;
    --card:#111827;
    --border:#1f2937;
    --primary:#2563eb;
    --safe:#16a34a;
    --danger:#dc2626;
    --warning:#f59e0b;
    --text:#e5e7eb;
    --muted:#9ca3af;
}

body{
    margin:0;
    font-family: 'Segoe UI', Arial;
    background:var(--bg);
    color:var(--text);
}

.header{
    padding:20px 40px;
    background:#0f172a;
    border-bottom:1px solid var(--border);
    font-size:20px;
    font-weight:600;
    letter-spacing:1px;
}

.wrapper{
    padding:40px;
    max-width:1200px;
    margin:auto;
}

.card{
    background:var(--card);
    border:1px solid var(--border);
    border-radius:12px;
    padding:25px;
    margin-bottom:25px;
}

.card h3{
    margin-top:0;
    margin-bottom:15px;
    font-weight:600;
}

.upload-box{
    border:2px dashed var(--primary);
    padding:40px;
    text-align:center;
    border-radius:10px;
    cursor:pointer;
    transition:0.3s;
}

.upload-box:hover{
    background:#1e293b;
}

button{
    background:var(--primary);
    border:none;
    padding:10px 18px;
    border-radius:6px;
    color:white;
    cursor:pointer;
    font-weight:500;
}

button:hover{
    opacity:0.9;
}

.badge{
    padding:4px 10px;
    border-radius:20px;
    font-size:12px;
    font-weight:600;
}

.badge-safe{ background:var(--safe); }
.badge-danger{ background:var(--danger); }
.badge-warning{ background:var(--warning); }

table{
    width:100%;
    border-collapse:collapse;
}

th, td{
    padding:10px;
    border-bottom:1px solid var(--border);
    text-align:left;
    font-size:14px;
}

th{
    color:var(--muted);
    font-weight:500;
}

tr:hover{
    background:#1f2937;
}

.small{
    font-size:12px;
    color:var(--muted);
}

</style>
</head>
<body>

<div class="header">
🛡 Email Threat Intelligence Console
</div>

<div class="wrapper">

<div class="card">
<h3>📂 이메일 업로드</h3>

<div class="upload-box" onclick="fileElem.click()">
클릭하여 .eml 또는 .msg 파일 업로드
<input type="file" id="fileElem" accept=".eml,.msg" style="display:none">
</div>

<br>
<button onclick="uploadFile()">AI 분석 실행</button>

</div>

<div class="card">
<h3>📊 AI 위협 분석 결과</h3>
<div id="aiSummary" class="small">분석 대기중...</div>
</div>

<div class="card">
<h3>📎 첨부파일 위협 평판 (VirusTotal)</h3>
<div id="vtTable" class="small">첨부파일 없음</div>
</div>

</div>

<script>

let selectedFile = null;

const fileElem = document.getElementById("fileElem");
fileElem.addEventListener("change", e => {
    selectedFile = e.target.files[0];
});

async function uploadFile(){

    if(!selectedFile){
        alert("파일을 선택하세요");
        return;
    }

    document.getElementById("aiSummary").innerHTML="AI 분석 중...";
    document.getElementById("vtTable").innerHTML="분석 중...";

    const formData = new FormData();
    formData.append("file", selectedFile);

    const res = await fetch("/analyze", {
        method:"POST",
        body:formData
    });

    const data = await res.json();

    if(data.error){
        document.getElementById("aiSummary").innerHTML =
            "<span class='badge badge-danger'>ERROR</span> " + data.error;
        return;
    }

    renderAI(data.ai_body_analysis);
    renderVT(data.attachments_vt || []);
}

function renderAI(ai){

    if(!ai){
        document.getElementById("aiSummary").innerHTML="결과 없음";
        return;
    }

    let risk = ai.risk_level || "unknown";
    let badgeClass = "badge-safe";

    if(risk === "high") badgeClass = "badge-danger";
    else if(risk === "medium") badgeClass = "badge-warning";

    document.getElementById("aiSummary").innerHTML = `
        <div>
            위험도:
            <span class="badge ${badgeClass}">
                ${risk.toUpperCase()}
            </span>
        </div>
        <br>
        <div>${ai.summary || "-"}</div>
    `;
}

async function renderVT(files){

    if(files.length === 0){
        document.getElementById("vtTable").innerHTML="첨부파일 없음";
        return;
    }

    let html = `
    <table>
        <tr>
            <th>파일명</th>
            <th>해시</th>
            <th>상태</th>
            <th>Malicious</th>
            <th>Suspicious</th>
        </tr>
    `;

    for(let f of files){

        const res = await fetch("/vt-result/" + f.sha256);
        const result = await res.json();

        let statusBadge = "<span class='badge badge-warning'>PENDING</span>";

        if(result.status === "completed"){
            statusBadge = "<span class='badge badge-safe'>COMPLETED</span>";
        }

        if(result.status === "error"){
            statusBadge = "<span class='badge badge-danger'>ERROR</span>";
        }

        html += `
        <tr>
            <td>${f.filename}</td>
            <td class="small">${f.sha256.substring(0,16)}...</td>
            <td>${statusBadge}</td>
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
