from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse
from email import policy
from email.parser import BytesParser

from mail_analyzer import analyze_mail

app = FastAPI()

# ==========================================================
# 🔷 1️⃣ GUI 화면
# ==========================================================
@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>AI Email Security Analyzer</title>
        <meta charset="UTF-8">
        <style>
            body { font-family: Arial; background: #f4f6f9; text-align: center; padding: 40px; }
            .container { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); max-width: 900px; margin: auto; }
            #drop-area { border: 2px dashed #aaa; padding: 30px; border-radius: 10px; background: #fafafa; cursor: pointer; }
            #drop-area.dragover { border-color: #007bff; background: #eef5ff; }
            button { padding: 10px 20px; border: none; background: #007bff; color: white; border-radius: 6px; cursor: pointer; margin-top: 10px; }
            pre { text-align: left; background: #f5f5f5; color: #333; padding: 10px; font-size: 12px; border: 1px solid #ddd; max-height: 400px; overflow-y: auto; }
            textarea { width:100%; height:300px; padding:10px; font-size:14px; }
            #file-info { margin-top:10px; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>📧 AI Email Security Analyzer</h2>
            <p>.eml 파일을 업로드하면 휴리스틱 + VirusTotal + AI 정밀 분석을 수행합니다.</p>

            <div id="drop-area">
                📂 드래그 앤 드롭 또는 클릭하여 파일 선택
                <input type="file" id="fileElem" accept=".eml" style="display:none">
            </div>

            <div id="file-info" style="display:none;">
                📄 <span id="file-name"></span>
            </div>
            
            <button onclick="uploadFile()">분석하기</button>

            <h3>🔎 분석 결과 (요약)</h3>

            <div id="summary-box" style="display:none; margin-top:15px;">
                <textarea id="replyText" readonly></textarea>
                <button onclick="copyReply()" style="margin-top:8px; background:#28a745;">📋 결과 복사</button>
            </div>

            <h3>🧾 Raw JSON</h3>
            <pre id="rawResult"></pre>
        </div>

        <script>
            const dropArea = document.getElementById('drop-area');
            const fileElem = document.getElementById('fileElem');
            const fileInfo = document.getElementById('file-info');
            const fileName = document.getElementById('file-name');
            const rawResult = document.getElementById('rawResult');
            const summaryBox = document.getElementById('summary-box');
            const replyText = document.getElementById('replyText');

            let selectedFile = null;

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
                rawResult.textContent = "파일 준비 완료. '분석하기' 버튼을 눌러주세요.";
            }

            async function uploadFile() {
                if (!selectedFile) {
                    alert("파일을 선택하세요.");
                    return;
                }

                const formData = new FormData();
                formData.append("file", selectedFile);

                rawResult.textContent = "⏳ 분석 중...";
                summaryBox.style.display = "none";

                try {
                    const response = await fetch("/analyze", {
                        method: "POST",
                        body: formData
                    });

                    const data = await response.json();
                    rawResult.textContent = JSON.stringify(data, null, 2);

                    if (data.error) {
                        replyText.value = "❌ 오류 발생: " + data.error;
                        summaryBox.style.display = "block";
                        return;
                    }

                    // reply_text 우선 표시
                    if (data.reply_text) {
                        replyText.value = data.reply_text;
                        summaryBox.style.display = "block";
                        return;
                    }

                    // fallback 요약 생성
                    let output = "";

                    if (data.heuristic) {
                        output += "[📌 휴리스틱 분석]\\n";
                        output += "Risk Level: " + (data.heuristic.risk_level ?? "-") + "\\n";
                        output += "Score: " + (data.heuristic.score ?? "-") + "\\n\\n";
                    }

                    if (data.virustotal && data.virustotal.length > 0) {
                        output += "[🛡 VirusTotal 분석]\\n";
                        data.virustotal.forEach(v => {
                            output += "URL: " + (v.url ?? "-") + "\\n";
                            output += "  - malicious: " + (v.malicious ?? 0) + "\\n";
                            output += "  - suspicious: " + (v.suspicious ?? 0) + "\\n\\n";
                        });
                    }

                    if (data.ai_analysis) {
                        output += "[🤖 AI 정밀 분석]\\n";
                        output += "Label: " + (data.ai_analysis.label ?? "unknown") + "\\n";
                        output += "Confidence: " + (data.ai_analysis.confidence ?? "-") + "\\n";
                        output += "Rationale:\\n" + (data.ai_analysis.rationale ?? "-") + "\\n";
                    }

                    if (output) {
                        replyText.value = output;
                        summaryBox.style.display = "block";
                    }

                } catch (error) {
                    rawResult.textContent = "❌ 오류 발생: " + error;
                }
            }

            function copyReply() {
                replyText.select();
                document.execCommand('copy');
                alert("복사되었습니다.");
            }
        </script>
    </body>
    </html>
    """

# ==========================================================
# 🔷 2️⃣ .eml 파일 분석 API
# ==========================================================
@app.post("/analyze")
async def analyze_email(file: UploadFile = File(...)):
    if not file.filename.endswith(".eml"):
        return {"error": "Only .eml files are supported."}

    content = await file.read()

    try:
        msg = BytesParser(policy=policy.default).parsebytes(content)

        subject = msg["subject"] or ""
        from_addr = msg["from"] or ""

        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body += part.get_content()
        else:
            body = msg.get_content()

        full_email_text = f"Subject: {subject}\\nFrom: {from_addr}\\n\\n{body}".strip()

        result = analyze_mail(full_email_text)
        return result

    except Exception as e:
        return {"error": str(e)}
