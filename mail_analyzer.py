from url_extractor import extract_urls
from virustotal_api import submit_url, get_result, extract_stats
from heuristics import score_email
from llm import classify_with_llm
from models import EmailRecord


def analyze_mail(email_text: str) -> dict:
    """
    메일 본문을 분석하여
    1) 휴리스틱 분석
    2) VirusTotal URL 분석
    3) LLM 전체 메일 AI 분석
    4) 회신용 텍스트 자동 생성
    결과를 통합 반환한다.
    """

    # ==========================================================
    # EmailRecord 객체 생성 (안전 생성)
    # ==========================================================
    try:
        email = EmailRecord(
            subject="",
            body_text=email_text or "",
            from_addr=""
        )
    except Exception as e:
        return {
            "error": f"EmailRecord creation failed: {str(e)}"
        }

    result = {
        "heuristic": {},
        "urls": [],
        "virustotal": [],
        "ai_analysis": {},
        "reply_text": ""
    }

    # ==========================================================
    # 1️⃣ 휴리스틱 분석
    # ==========================================================
    try:
        heuristic_result = score_email(email)
        result["heuristic"] = (
            heuristic_result.model_dump()
            if hasattr(heuristic_result, "model_dump")
            else {}
        )
    except Exception as e:
        result["heuristic"] = {"error": str(e)}

    # ==========================================================
    # 2️⃣ URL 추출 및 VirusTotal 분석
    # ==========================================================
    try:
        urls = extract_urls(email_text or "")
    except Exception as e:
        result["urls"] = []
        result["virustotal"].append({"error": f"URL extraction failed: {str(e)}"})
        urls = []

    if urls:
        urls = urls[:3]  # 무료 API 보호
        result["urls"] = urls

        for url in urls:
            try:
                analysis_id = submit_url(url)

                if not analysis_id:
                    result["virustotal"].append({
                        "url": url,
                        "error": "No analysis_id returned"
                    })
                    continue

                vt_result = get_result(analysis_id)

                if not vt_result:
                    result["virustotal"].append({
                        "url": url,
                        "error": "No result from VirusTotal"
                    })
                    continue

                stats = extract_stats(vt_result) or {}

                result["virustotal"].append({
                    "url": url,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0)
                })

            except Exception as e:
                result["virustotal"].append({
                    "url": url,
                    "error": str(e)
                })

    # ==========================================================
    # 3️⃣ LLM 분석
    # ==========================================================
    try:
        llm_result = classify_with_llm(email)

        if llm_result and hasattr(llm_result, "model_dump"):
            result["ai_analysis"] = llm_result.model_dump()
        else:
            result["ai_analysis"] = {"error": "LLM returned None"}

    except Exception as e:
        result["ai_analysis"] = {"error": str(e)}

    # ==========================================================
    # 4️⃣ 🔹 회신용 텍스트 자동 생성 (안전 템플릿 기반)
    # ==========================================================
    try:
        heuristic_data = result.get("heuristic", {}) or {}
        ai_data = result.get("ai_analysis", {}) or {}

        risk = heuristic_data.get("risk_level", "판단불가")

        malicious_count = 0
        suspicious_count = 0

        for item in result.get("virustotal", []):
            if isinstance(item, dict):
                malicious_count += item.get("malicious", 0) or 0
                suspicious_count += item.get("suspicious", 0) or 0

        ai_label = ai_data.get("label")
        ai_confidence = ai_data.get("confidence")

        # 🔹 종합 판단 로직
        if malicious_count > 0:
            final_judgement = "악성 가능성이 높습니다."
        elif suspicious_count > 0:
            final_judgement = "주의가 필요합니다."
        elif ai_label == "spam":
            final_judgement = "AI 분석 결과 스팸 가능성이 있습니다."
        elif ai_label == "ham":
            final_judgement = "정상 메일로 판단됩니다."
        else:
            final_judgement = "현재까지 악성 징후는 발견되지 않았습니다."

        reply_lines = []
        reply_lines.append("[보안 분석 결과 안내]\n")
        reply_lines.append("신고해주신 메일에 대해 보안 분석을 진행하였습니다.\n")
        reply_lines.append(f"■ 휴리스틱 위험도: {risk}")
        reply_lines.append(f"■ 악성 탐지 수: {malicious_count}")
        reply_lines.append(f"■ 의심 탐지 수: {suspicious_count}")

        if ai_label:
            reply_lines.append(f"■ AI 판단: {ai_label}")
        if ai_confidence:
            reply_lines.append(f"   (신뢰도: {ai_confidence})")

        reply_lines.append("")
        reply_lines.append(f"▶ 종합 판단: {final_judgement}")
        reply_lines.append("")
        reply_lines.append("해당 메일은 클릭/응답 전 반드시 주의하시기 바랍니다.")
        reply_lines.append("추가 문의가 있으시면 I&S팀으로 연락 부탁드립니다.")

        result["reply_text"] = "\n".join(reply_lines)

    except Exception as e:
        result["reply_text"] = f"회신 문구 생성 실패: {str(e)}"

    return result
