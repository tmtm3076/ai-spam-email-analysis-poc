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
        # TODO: VT 실제 연동 부분
        ANALYSIS_STORE[file_hash] = {
            "status": "completed",
            "malicious": 0,
            "suspicious": 0,
            "message": "VT 분석 완료 (샘플 응답)"
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
    box-shadow: 0 10px 40px rgba(0,0,0,0.6);
    max-width: 1000px;
    margin: auto;
}
#drop-area {
    border: 2px dashed #3b82f6;
    padding: 30px;
    border-radius: 10px;
    background: #0f172a;
    cursor: pointer;
}
#drop-area.dragover {
    background: #1d4ed8;
}
button {
    padding: 10px 20px;
    border: none;
    background: #3b82f6;
    color: white;
    border-radius: 6px;
    cursor: pointer;
    margin-top: 10px;
}
button:hover { background:#2563eb; }
textarea {
    width:100%;
    height:280px;
    padding:10px;
    font-size:13px;
    background:#0f172a;
    color:#22c55e;
    border:1px solid #334155;
}
pre {
    text-align:left;
    background:#111827;
    color:#cbd5e1;
    padding:10px;
    font-size:12px;
    border:1px solid #334155;
    max-height:300px;
    overflow-y:auto;
}
.section-title {
    margin-top:25px;
    color:#38bdf8;
}
.badge {
    padding:4px 8px;
    border-radius:6px;
    font-size:12px;
}
.badge-danger { background:#dc2626; }
.badge-safe { background:#16a34a; }
</style>
</head>
<body>

<div class="container">
<h2>🛡 AI Email Threat Intelligence Platform</h2>
<p>휴리스틱 + AI 정밀 분석 + VirusTotal 파일 평판 분석</p>

<div id="drop-area">
📂 드래그 앤 드롭 또는 클릭하여 파일 선택
<input type="file" id="fileElem" accept=".eml,.msg" style="display:none">
</div>

<div id="file-info" style="margin-top:10px; display:none;">
📄 <span id="file-name"></span>
</div>

<button onclick="uploadFile()">🔍 분석 시작</button>

<h3 class="section-title">📊 분석 요약</h3>
<div id="summary-box" style="display:none;">
<textarea id="summaryText" readonly></textarea>
<button onclick="copySummary()" style="background:#16a34a;">📋 결과 복사</button>
</div>

<h3 class="section-title">📎 첨부파일 VT 분석 상태</h3>
<pre id="vtStatus"></pre>

<h3 class="section-title">🧾 Raw JSON</h3>
<pre id="rawResult"></pre>

</div>

<script>
const dropArea = document.getElementById('drop-area');
const fileElem = document.getElementById('fileElem');
const fileInfo = document.getElementById('file-info');
const fileName = document.getElementById('file-name');
const rawResult = document.getElementById('rawResult');
const summaryBox = document.getElementById('summary-box');
const summaryText = document.getElementById('summaryText');
const vtStatus = document.getElementById('vtStatus');

let selectedFile = null;
let vtHashes = [];

dropArea.addEventListener('click', () => fileElem.click());

fileElem.addEventListener('change', (e) => {
    selectedFile = e.target.files[0];
    showFileInfo();
});

['dragenter','dragover','dragleave','drop'].forEach(eventName => {
    dropArea.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
    }, false);
});

dropArea.addEventListener('dragover', () => dropArea.classList.add('dragover'));
dropArea.addEventListener('dragleave', () => dropArea.classList.remove('dragover'));

dropArea.addEventListener('drop', (e) => {
    dropArea.classList.remove('dragover');
    selectedFile = e.dataTransfer.files[0];
    showFileInfo();
});

function showFileInfo() {
    if (!selectedFile) return;
    fileName.textContent = selectedFile.name;
    fileInfo.style.display = "block";
}

async function uploadFile() {
    if (!selectedFile) {
        alert("파일을 선택하세요.");
        return;
    }

    const formData = new FormData();
    formData.append("file", selectedFile);

    rawResult.textContent = "⏳ 분석 중...";
    vtStatus.textContent = "";
    summaryBox.style.display = "none";

    const response = await fetch("/analyze", {
        method: "POST",
        body: formData
    });

    const data = await response.json();
    rawResult.textContent = JSON.stringify(data, null, 2);

    if (data.error) {
        summaryText.value = "❌ 오류: " + data.error;
        summaryBox.style.display = "block";
        return;
    }

    // 요약 생성
    let output = "";

    if (data.ai_body_analysis) {
        output += "[🤖 AI 본문 분석]\\n";
        output += JSON.stringify(data.ai_body_analysis, null, 2) + "\\n\\n";
    }

    if (data.attachments_vt && Array.isArray(data.attachments_vt)) {
        output += "[📎 첨부파일 VT 분석 시작]\\n";
        data.attachments_vt.forEach(f => {
            output += f.filename + " → " + f.sha256 + "\\n";
        });

        vtHashes = data.attachments_vt.map(f => f.sha256);
        pollVT();
    } else {
        output += "첨부파일 없음\\n";
    }

    summaryText.value = output;
    summaryBox.style.display = "block";
}

async function pollVT() {
    vtStatus.textContent = "VT 분석 진행 중...";

    for (let hash of vtHashes) {
        const res = await fetch("/vt-result/" + hash);
        const result = await res.json();
        vtStatus.textContent += "\\n" + hash + " → " + JSON.stringify(result);
    }
}

function copySummary() {
    summaryText.select();
    document.execCommand('copy');
    alert("복사되었습니다.");
}
</script>

</body>
</html>
"""


# ==========================================================
# 🔷 2️⃣ 이메일 분석 API (AI + VT 통합)
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
