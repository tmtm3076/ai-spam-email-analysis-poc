from fastapi import FastAPI, UploadFile, File, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
import tempfile
import os
import hashlib

from email_parser import parse_email_file
from heuristics import score_email
from llm import classify_with_llm
from url_extractor import extract_urls
from virustotal_api import submit_url, get_result, extract_stats, analyze_file_with_vt, extract_file_stats

app = FastAPI()

ANALYSIS_STORE = {}

# ==========================================================
# 🔷 유틸
# ==========================================================

def calculate_sha256(file_bytes: bytes) -> str:
    sha256 = hashlib.sha256()
    sha256.update(file_bytes)
    return sha256.hexdigest()


# ✅ virustotal_api.py에 scan_url 없음 → submit_url → get_result → extract_stats 로 직접 구현
def scan_url(url: str) -> dict:
    analysis_id = submit_url(url)
    result = get_result(analysis_id)
    return extract_stats(result)


def process_file_analysis(file_hash: str, file_bytes: bytes):
    ANALYSIS_STORE[file_hash] = {
        "status": "completed",
        "malicious": 0,
        "suspicious": 0
    }


# ==========================================================
# 🔷 GUI
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
body{ margin:0; font-family:'Segoe UI',Arial; background:var(--bg); color:var(--text); }
.header{ padding:20px 40px; background:#0f172a; border-bottom:1px solid var(--border); font-size:20px; font-weight:600; }
.wrapper{ padding:40px; max-width:1200px; margin:auto; }
.card{ background:var(--card); border:1px solid var(--border); border-radius:12px; padding:25px; margin-bottom:25px; }
.upload-box{ border:2px dashed var(--primary); padding:40px; text-align:center; border-radius:10px; cursor:pointer; transition:0.3s; }
.upload-box.dragover{ background:#1e293b; border-color:#60a5fa; }
.file-status{ margin-top:15px; font-size:14px; color:var(--muted); }
button{ background:var(--primary); border:none; padding:10px 18px; border-radius:6px; color:white; cursor:pointer; font-weight:500; }
button:hover{ opacity:0.9; }
.badge{ padding:4px 10px; border-radius:20px; font-size:12px; font-weight:600; }
.badge-safe{ background:var(--safe); }
.badge-danger{ background:var(--danger); }
.badge-warning{ background:var(--warning); color:#000; }
table{ width:100%; border-collapse:collapse; }
th,td{ padding:10px; border-bottom:1px solid var(--border); text-align:left; font-size:14px; }
th{ color:var(--muted); font-weight:500; }
tr:hover{ background:#1f2937; }
pre{ background:#0f172a; padding:15px; border-radius:8px; font-size:12px; overflow:auto; }
</style>
</head>
<body>

<div class="header">🛡 COSMAX Email Threat Intelligence Console</div>

<div class="wrapper">

<div class="card">
<h3>📂 이메일 업로드</h3>

<div id="drop-area" class="upload-box">
    📁 드래그 앤 드롭 또는 클릭하여 업로드<br>
    <small style="color:var(--muted)">.eml / .msg 파일 지원</small>
</div>
<input type="file" id="fileElem" accept=".eml,.msg" style="display:none">

<div id="fileStatus" class="file-status">파일 미선택</div>
<br>
<button onclick="uploadFile()">AI 분석 실행</button>
</div>

<div class="card">
<h3>📊 AI 위협 분석 결과</h3>
<div id="aiSummary">분석 대기중...</div>
</div>

<div class="card">
<h3>🔗 URL 위협 평판 (VirusTotal)</h3>
<div id="urlTable">URL 없음</div>
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
var selectedFile = null;
var dropArea = document.getElementById("drop-area");
var fileElem = document.getElementById("fileElem");
var fileStatus = document.getElementById("fileStatus");

dropArea.addEventListener("click", function(){ fileElem.click(); });

fileElem.addEventListener("change", function(e){
    var f = e.target.files[0];
    if(f) setFile(f);
});

dropArea.addEventListener("dragenter", function(e){ e.preventDefault(); dropArea.classList.add("dragover"); });
dropArea.addEventListener("dragover",  function(e){ e.preventDefault(); dropArea.classList.add("dragover"); });
dropArea.addEventListener("dragleave", function(e){ dropArea.classList.remove("dragover"); });
dropArea.addEventListener("drop", function(e){
    e.preventDefault();
    dropArea.classList.remove("dragover");
    var files = e.dataTransfer.files;
    if(files && files.length > 0) setFile(files[0]);
});

function setFile(f){
    var name = f.name.toLowerCase();
    if(!name.endsWith(".eml") && !name.endsWith(".msg")){
        alert(".eml 또는 .msg 파일만 업로드 가능합니다.");
        selectedFile = null;
        fileStatus.innerHTML = "파일 미선택";
        return;
    }
    selectedFile = f;
    fileStatus.innerHTML = "<span class='badge badge-safe'>선택완료</span> " + f.name;
}

async function uploadFile(){
    if(!selectedFile){ alert("파일을 선택하세요"); return; }

    document.getElementById("aiSummary").innerHTML = "AI 분석 중...";
    document.getElementById("urlTable").innerHTML  = "분석 중...";
    document.getElementById("vtTable").innerHTML   = "분석 중...";
    document.getElementById("rawJson").textContent = "-";

    var formData = new FormData();
    formData.append("file", selectedFile);

    var res  = await fetch("/analyze", { method:"POST", body:formData });
    var data = await res.json();

    document.getElementById("rawJson").textContent = JSON.stringify(data, null, 2);

    if(data.error){
        document.getElementById("aiSummary").innerHTML = "<span class='badge badge-danger'>ERROR</span> " + data.error;
        return;
    }

    renderAI(data.ai_body_analysis);
    renderURLs(data.url_analysis   || []);
    renderVT(data.attachments_vt   || []);
}

function renderAI(ai){
    if(!ai){ document.getElementById("aiSummary").innerHTML = "결과 없음"; return; }

    var risk = ai.risk_level || "unknown";
    var badgeClass = (risk === "high") ? "badge-danger" : (risk === "medium") ? "badge-warning" : "badge-safe";
    var conf = (ai.confidence !== undefined)
        ? "<br><small style='color:var(--muted)'>신뢰도: " + (ai.confidence * 100).toFixed(0) + "%</small>"
        : "";
    var rationale = ai.rationale ? "<br><br><b>분석 근거:</b><br>" + formatRationale(ai.rationale) : "";

    document.getElementById("aiSummary").innerHTML =
        "위험도: <span class='badge " + badgeClass + "'>" + risk.toUpperCase() + "</span>"
        + conf
        + "<br><br>" + (ai.summary || "-")
        + rationale;
}

function formatRationale(text){
    if(!text) return "";
    var parts = text.split(String.fromCharCode(10));
    return "<span style='line-height:2.0'>" + parts.join("<br>") + "</span>";
}

function renderURLs(urls){
    if(urls.length === 0){ document.getElementById("urlTable").innerHTML = "URL 없음"; return; }

    var html = "<table><tr><th>URL</th><th>Malicious</th><th>Suspicious</th><th>Harmless</th></tr>";
    for(var i=0; i<urls.length; i++){
        var u  = urls[i];
        var vt = u.vt_result || {};
        var err = u.error;
        html += "<tr>"
            + "<td style='word-break:break-all'>" + u.url + "</td>"
            + "<td>" + (err ? "<span class='badge badge-warning'>ERROR</span>" : (vt.malicious  !== undefined ? vt.malicious  : "-")) + "</td>"
            + "<td>" + (err ? "-" : (vt.suspicious !== undefined ? vt.suspicious : "-")) + "</td>"
            + "<td>" + (err ? "-" : (vt.harmless   !== undefined ? vt.harmless   : "-")) + "</td>"
            + "</tr>";
    }
    html += "</table>";
    document.getElementById("urlTable").innerHTML = html;
}

async function renderVT(files){
    if(files.length === 0){ document.getElementById("vtTable").innerHTML = "첨부파일 없음"; return; }

    var html = "<table><tr><th>파일명</th><th>SHA256</th><th>상태</th><th>Malicious</th><th>Suspicious</th></tr>";
    for(var i=0; i<files.length; i++){
        var f   = files[i];
        var res = await fetch("/vt-result/" + f.sha256);
        var result = await res.json();

        var badge = "<span class='badge badge-warning'>PENDING</span>";
        if(result.status === "completed") badge = "<span class='badge badge-safe'>COMPLETED</span>";
        if(result.status === "error")     badge = "<span class='badge badge-danger'>ERROR</span>";

        var stats = result.stats || {};
        html += "<tr>"
            + "<td>" + f.filename + "</td>"
            + "<td>" + f.sha256.substring(0,16) + "...</td>"
            + "<td>" + badge + "</td>"
            + "<td>" + (stats.malicious  !== undefined ? stats.malicious  : (result.malicious  !== undefined ? result.malicious  : "-")) + "</td>"
            + "<td>" + (stats.suspicious !== undefined ? stats.suspicious : (result.suspicious !== undefined ? result.suspicious : "-")) + "</td>"
            + "</tr>";
    }
    html += "</table>";
    document.getElementById("vtTable").innerHTML = html;
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
        return JSONResponse(status_code=400, content={"error": "Only .eml or .msg files are supported"})

    tmp_path = None

    try:
        suffix = os.path.splitext(filename)[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            content = await file.read()
            tmp.write(content)
            tmp_path = tmp.name

        email_record = parse_email_file(tmp_path)

        # 1️⃣ 휴리스틱 분석
        heuristic_result = score_email(email_record)

        # 2️⃣ URL 추출 + VT URL 평판 분석
        body_text = email_record.body_text or ""
        urls = extract_urls(body_text)

        url_results = []
        for url in urls[:5]:
            try:
                vt_res = scan_url(url)
                url_results.append({"url": url, "vt_result": vt_res})
            except Exception as e:
                url_results.append({"url": url, "vt_result": None, "error": str(e)})

        # 3️⃣ LLM 정밀 분석
        llm_result = classify_with_llm(email_record)

        # 종합 위험도 판정
        risk_level = "low"
        if heuristic_result.score >= 70:
            risk_level = "high"
        elif heuristic_result.score >= 40:
            risk_level = "medium"

        if llm_result.get("label") in ["phishing", "malicious"]:
            risk_level = "high"
        elif llm_result.get("label") == "spam" and risk_level == "low":
            risk_level = "medium"

        overall_label = "ham"
        if risk_level == "high":
            overall_label = llm_result.get("label", "high_risk")
        elif risk_level == "medium":
            overall_label = "spam"

        # ✅ attachments: Pydantic Attachment 모델 → .filename .sha256 속성 접근
        attachments_vt = []
        for att in email_record.attachments:
            try:
                file_bytes = att.content  # Attachment 모델의 실제 필드명 확인 필요
                vt_report = analyze_file_with_vt(file_bytes, att.filename)
                stats = extract_file_stats(vt_report)
                ANALYSIS_STORE[att.sha256] = {
                    "status":     "completed",
                    "malicious":  stats["malicious"],
                    "suspicious": stats["suspicious"],
                    "harmless":   stats["harmless"],
                    "undetected": stats["undetected"],
                }
                attachments_vt.append({
                    "filename": att.filename,
                    "sha256":   att.sha256,
                })
            except Exception as e:
                ANALYSIS_STORE[att.sha256] = {"status": "error", "message": str(e)}
                attachments_vt.append({
                    "filename": att.filename,
                    "sha256":   att.sha256,
                })

        return {
            "overall_label": overall_label,
            "ai_body_analysis": {
                "risk_level": risk_level,
                "label":      llm_result.get("label", "unknown"),
                "confidence": llm_result.get("confidence", 0),
                "summary":    "[" + llm_result.get("label","unknown").upper() + "] 휴리스틱 점수: " + str(heuristic_result.score) + "/100",
                "rationale":  llm_result.get("rationale", ""),
            },
            "heuristic_analysis": {
                "score":   heuristic_result.score,
                "flags":   heuristic_result.flags,
                "details": heuristic_result.details,
            },
            "url_analysis":    url_results,
            "attachments_vt":  attachments_vt,
        }

    except Exception as e:
        return {"error": str(e)}

    finally:
        try:
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


# ==========================================================
# 🔷 VT 결과 조회
# ==========================================================

@app.get("/vt-result/{file_hash}")
def get_vt_result(file_hash: str):
    return ANALYSIS_STORE.get(file_hash, {"status": "not_found"})
