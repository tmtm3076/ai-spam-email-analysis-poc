from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse
import email
from email import policy
from email.parser import BytesParser

# 사용자님의 기존 분석 함수 (기존 구조 유지)
from mail_analyzer import analyze_mail

app = FastAPI()

# ==========================================================
# 🔷 1️⃣ GUI 화면 (수정된 HTML/JS)
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
            body { font-family: Arial; background: #f4f6f9; text-align: center; padding: 40px; }
            .container { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); max-width: 800px; margin: auto; }
            #drop-area { border: 2px dashed #aaa; padding: 30px; border-radius: 10px; background: #fafafa; cursor: pointer; }
            #drop-area.dragover { border-color: #007bff; background: #eef5ff; }
            button { padding: 10px 20px; border: none; background: #007bff; color: white; border-radius: 6px; cursor: pointer; margin-top: 10px; }
            pre { text-align: left; background: #111; color: #0f0; padding: 15px; border-radius: 8px; overflow-x: auto; max-height: 400px; }
            #file-info { margin-top:10px; font-weight: bold; }
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

            <div id="file-info" style="display:none;">
                📄 <span id="file-name"></span>
            </div>
            
            <button onclick="uploadFile()">분석하기</button>

            <h3>🔎 분석 결과</h3>

            <div id="summary-box" style="display:none; margin-top:15px;">
                <textarea id="replyText" style="width:100%; height:200px; padding:10px; font-size:14px;" readonly></textarea>
                <button onclick="copyReply()" style="margin-top:8px; background:#28a745;">📋 결과 복사</button>
            </div>

            <pre id="rawResult" style="margin-top:20px; background:#f5f5f5; color:#333; padding:10px; font-size:12px; border: 1px solid #ddd;"></pre>
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

            // 1. 클릭으로 파일 선택
            dropArea.addEventListener('click', () => fileElem.click());

            // 2. 파일 선택 시 처리
            fileElem.addEventListener('change', (e) => {
                selectedFile = e.target.files[0];
                showFileInfo();
            });

            // 3. 드래그 앤 드롭 방지 및 스타일 처리
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
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
                    
                    // 상세 로그 출력
                    rawResult.textContent = JSON.stringify(data, null, 2);

                    // 화면 표시용 요약 텍스트 생성
                    let output = "";
                    if (data.heuristic) {
                        output += `[📌 휴리스틱 분석]\\nScore: ${data.heuristic.score ?? "-"}\\nReason: ${data.heuristic.reason ?? "-"}\\n\\n`;
                    }
                    if (data.ai_analysis) {
                        output += `[🤖 AI 종합 판단]\\nLabel: ${data.ai_analysis.label ?? "unknown"}\\nConfidence: ${data.ai_analysis.confidence ?? "-"}\\nRationale: ${data.ai_analysis.rationale ?? "-"}\\n`;
                    }

                    if(output) {
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
# 🔷 2️⃣ .eml 파일 분석 API (기존 로직 100% 동일)
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

        # 기존 함수 호출 유지
        result = analyze_mail(full_email_text)
        return result

    except Exception as e:
        return {"error": str(e)}
