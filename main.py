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
# 🔷 1️⃣ GUI
# ==========================================================
@app.get("/", response_class=HTMLResponse)
def home():
    return """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>COSMAX Email Threat Intelligence Console</title>

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
    font-family:'Segoe UI',Arial;
    background:var(--bg);
    color:var(--text);
}

.header{
    padding:20px 40px;
    background:#0f172a;
    border-bottom:1px solid var(--border);
    font-size:20px;
    font-weight:600;
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

.upload-box{
    border:2px dashed var(--primary);
    padding:40px;
    text-align:center;
    border-radius:10px;
    cursor:pointer;
    transition:0.3s;
}

.upload-box.dragover{
    background:#1e293b;
}

.file-status{
    margin-top:15px;
    font-size:14px;
    color:var(--muted);
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

button:hover{ opacity:0.9; }

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

pre{
    background:#0f172a;
    padding:15px;
    border-radius:8px;
    font-size:12px;
    overflow:auto;
}

</style>
</head>
<body>

<div class="header">
🛡 COSMAX Email Threat Intelligence Console
</div>

<div class="wrapper">

<div class="card">
<h3>📂 이메일 업로드</h3>

<div id="drop-area" class="upload-box">
드래그 앤 드롭 또는 클릭하여 업로드
<input type="file" id="fileElem" accept=".eml,.msg" style="display:none">
</div>

<div id="fileStatus" class="file-status">
파일 미선택
</div>

<br>
<button onclick="uploadFile()">AI 분석 실행</button>

</div>

<div class="card">
<h3>📊 AI 위협 분석 결과</h3>
<div id="aiSummary">분석 대기중...</div>
</div>

<div class="card">
<h3>📎 첨부파일 위협 평판 (VirusTotal)</h3>
<div id="vtTable">첨부파일 없음</div>
</div>

<div class="card">
<h3>🧾 Raw JSON (Debug)</h3>
<pre id="rawJson">-</pre>
</div>

</div>

<script>

let selectedFile = null;
const dropArea = document.getElementById("drop-area");
const fileElem = document.getElementById("fileElem");
const fileStatus = document.getElementById("fileStatus");

dropArea.addEventListener("click", () => fileElem.click());

fileElem.addEventListener("change", e => {
    selectedFile = e.target.files[0];
    updateFileStatus();
});

["dragenter","dragover"].forEach(evt=>{
    dropArea.addEventListener(evt, e=>{
        e.preventDefault();
        dropArea.classList.add("dragover");
    });
});

["dragleave","drop"].forEach(evt=>{
    dropArea.addEventListener(evt, e=>{
        e.preventDefault();
        dropArea.classList.remove("dragover");
    });
});

dropArea.addEventListener("drop", e=>{
    selectedFile = e.dataTransfer.files[0];
    updateFileStatus();
});

function updateFileStatus(){
    if(!selectedFile){
        fileStatus.innerHTML="파일 미선택";
        return;
    }

    fileStatus.innerHTML=
        "<span class='badge badge-safe'>업로드 완료</span> "
        + selectedFile.name;
}

async function uploadFile(){

    if(!selectedFile){
        alert("파일을 선택하세요");
        return;
    }

    document.getElementById("aiSummary").innerHTML="AI 분석 중...";
    document.getElementById("vtTable").innerHTML="분석 중...";
    document.getElementById("rawJson").textContent="-";

    const formData = new FormData();
    formData.append("file", selectedFile);

    const res = await fetch("/analyze",{
        method:"POST",
        body:formData
    });

    const data = await res.json();

    document.getElementById("rawJson").textContent =
        JSON.stringify(data,null,2);

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

    if(risk === "high") badgeClass="badge-danger";
    else if(risk === "medium") badgeClass="badge-warning";

    document.getElementById("aiSummary").innerHTML = `
        위험도:
        <span class="badge ${badgeClass}">
            ${risk.toUpperCase()}
        </span>
        <br><br>
        ${ai.summary || "-"}
    `;
}

async function renderVT(files){

    if(files.length===0){
        document.getElementById("vtTable").innerHTML="첨부파일 없음";
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

    for(let f of files){

        const res = await fetch("/vt-result/" + f.sha256);
        const result = await res.json();

        let badge="<span class='badge badge-warning'>PENDING</span>";

        if(result.status==="completed")
            badge="<span class='badge badge-safe'>COMPLETED</span>";

        if(result.status==="error")
            badge="<span class='badge badge-danger'>ERROR</span>";

        html+=`
        <tr>
            <td>${f.filename}</td>
            <td>${f.sha256.substring(0,16)}...</td>
            <td>${badge}</td>
            <td>${result.malicious ?? "-"}</td>
            <td>${result.suspicious ?? "-"}</td>
        </tr>
        `;
    }

    html+="</table>";

    document.getElementById("vtTable").innerHTML=html;
}

</script>

</body>
</html>
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
