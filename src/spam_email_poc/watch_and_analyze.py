import time
from pathlib import Path
import subprocess
from mail_sender import send_result

WATCH_DIR = Path("C:/spam_eml")
DONE_DIR = WATCH_DIR / "done"

DONE_DIR.mkdir(exist_ok=True)

while True:
    for eml in WATCH_DIR.glob("*.eml"):
        print(f"📧 분석 시작: {eml.name}")

        result = subprocess.run(
            ["spam-email-analyze", "--input", str(eml)],
            capture_output=True,
            text=True
        )

        analysis_text = result.stdout

        send_result(
            to="security.alert@cosmax.com",
            body=analysis_text
        )

        eml.rename(DONE_DIR / eml.name)

    time.sleep(10)
