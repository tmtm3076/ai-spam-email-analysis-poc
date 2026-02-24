from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse
import tempfile
import os

from mail_analyzer import analyze_mail
from email_parser import parse_email_file  # ✅ 우리가 만든 통합 파서 사용

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
# 🔷 2️⃣ 이메일 분석 API (안정화 버전)
# ==========================================================
@app.post("/analyze")
async def analyze_email(file: UploadFile = File(...)):

    filename = file.filename.lower()

    if not (filename.endswith(".eml") or filename.endswith(".msg")):
        return {"error": "Only .eml or .msg files are supported."}

    try:
        # 🔹 1️⃣ 임시 파일로 저장 (msg 파싱 위해 필요)
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(filename)[1]) as tmp:
            content = await file.read()
            tmp.write(content)
            tmp_path = tmp.name

        # 🔹 2️⃣ 통합 파서 호출
        email_record = parse_email_file(tmp_path)

        # 🔹 3️⃣ 분석 실행
        result = analyze_mail(email_record.body_text)

        return result

    except Exception as e:
        return {"error": str(e)}

    finally:
        # 🔹 4️⃣ 임시 파일 삭제 (AppRunner 디스크 누수 방지)
        try:
            if "tmp_path" in locals() and os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
