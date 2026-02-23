from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse
import email
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
        <title>AI Spam Email Analyzer</title>
        <meta charset="UTF-8">
        <style>
            body {
                font-family: Arial;
                background: #f4f6f9;
                text-align: center;
                padding: 40px;
            }
            .container {
                background: white;
                padding: 30px;
                border-radius: 12px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                max-width: 800px;
                margin: auto;
            }
            #drop-area {
                border: 2px dashed #aaa;
                padding: 30px;
                border-radius: 10px;
                background: #fafafa;
                cursor: pointer;
            }
            #drop-area.dragover {
                border-color: #007bff;
                background: #eef5ff;
            }
            button {
                padding: 10px 20px;
                border: none;
                background: #007bff;
                color: white;
                border-radius: 6px;
                cursor: pointer;
                margin-top: 10px;
            }
            pre {
                text-align: left;
                background: #111;
                color: #0f0;
                padding: 15px;
                border-radius: 8px;
                overflow-x: auto;
                max-height: 400px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>📧 AI Email Security Analyzer</h2>
            <p>.eml 파일을 업로드하면 분석합니다</p>

            <div id="drop-area">
                📂 드래그 앤 드롭 또는 클릭하여 파일 선택
                <input type="file" id="fileElem" accept=".eml" style="display:none">
            </div>

            <!-- 👇 파일 표시 영역 추가 -->
            <div id="file-info" style="margin-top:10px; display:none;">
                <span id="file-icon">📄</span>
                <span id="file-name"></span>
            </div>
            
            <button onclick="uploadFile()">분석하기</button>

            <h3>🔎 분석 결과</h3>

            <div id="summary-box" style="display:none; margin-top:15px;">
                <textarea id="replyText"
                    style="width:100%; height:200px; padding:10px; font-size:14px;"
                    readonly></textarea>

                <button onclick="copyReply()" style="margin-top:8px;">
                    📋 결과 복사
                </button>
            </div>

<pre id="rawResult" style="margin-top:20px; background:#f5f5f5; padding:10px; font-size:12px;"></pre>
        </div>

        <script>
            const dropArea = document.getElementById('drop-area');
            const fileElem = document.getElementById('fileElem');
            const fileInfo = document.getElementById('file-info');
            const fileName = document.getElementById('file-name');

            let selectedFile = null;

            // 클릭으로 파일 선택
            dropArea.addEventListener('click', () => fileElem.click());

            // 파일 선택 시 표시
            fileElem.addEventListener('change', (e) => {
                selectedFile = e.target.files[0];
                showFileInfo();
            });

            // 드래그 오버 효과
            dropArea.addEventListener('dragover', (e) => {
                e.preventDefault();
                dropArea.classList.add('dragover');
            });

            dropArea.addEventListener('dragleave', () => {
                dropArea.classList.remove('dragover');
            });

            // 드롭 시 파일 표시
            dropArea.addEventListener('drop', (e) => {
                e.preventDefault();
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

                const resultBox = document.getElementById("result");
                resultBox.textContent = "⏳ 분석 중...";

                try {
                    const response = await fetch("/analyze", {
                        method: "POST",
                        body: formData
                    });

                    const data = await response.json();

                    let output = "";

                    // -----------------------------
                    // 1️⃣ 휴리스틱 분석
                    // -----------------------------
                    if (data.heuristic) {
                        output += "📌 휴리스틱 분석\n";
                        output += "----------------------------------\n";
                        output += "Score: " + (data.heuristic.score ?? "-") + "\n";
                        output += "Reason: " + (data.heuristic.reason ?? "-") + "\n\n";
                    }

                    // -----------------------------
                    // 2️⃣ VirusTotal 분석
                    // -----------------------------
                    if (data.virustotal && data.virustotal.length > 0) {
                        output += "🌐 URL 분석 (VirusTotal)\n";
                        output += "----------------------------------\n";

                        data.virustotal.forEach(v => {
                            output += "URL: " + v.url + "\n";
                            output += "Malicious: " + (v.malicious ?? 0) + "\n";
                            output += "Suspicious: " + (v.suspicious ?? 0) + "\n\n";
                        });
                    }

                    // -----------------------------
                    // 3️⃣ AI 분석
                    // -----------------------------
                    if (data.ai_analysis) {
                        output += "🤖 AI 종합 판단\n";
                        output += "----------------------------------\n";
                        output += "Label: " + (data.ai_analysis.label ?? "unknown") + "\n";
                        output += "Confidence: " + (data.ai_analysis.confidence ?? "-") + "\n";
                        output += "Rationale: " + (data.ai_analysis.rationale ?? "-") + "\n\n";
                    }

                    resultBox.textContent = output;

                } catch (error) {
                    resultBox.textContent = "❌ 오류 발생: " + error;
                }
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

        # 🔥 전체 원문을 Gemini에 전달하기 위해
        full_email_text = f"""
Subject: {subject}
From: {from_addr}

{body}
""".strip()

        result = analyze_mail(full_email_text)

        return result

    except Exception as e:
        return {"error": str(e)}
