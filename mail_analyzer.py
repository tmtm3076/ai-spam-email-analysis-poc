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
        # EmailRecord 생성 실패 시에도 서버 죽지 않게 처리
        return {
            "error": f"EmailRecord creation failed: {str(e)}"
        }

    result = {
        "heuristic": {},
        "urls": [],
        "virustotal": [],
        "ai_analysis": {}
    }

    # ==========================================================
    # 1️⃣ 휴리스틱 분석
    # ==========================================================
    try:
        heuristic_result = score_email(email)
        result["heuristic"] = heuristic_result.model_dump()
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

        if llm_result:
            result["ai_analysis"] = llm_result.model_dump()
        else:
            result["ai_analysis"] = {"error": "LLM returned None"}

    except Exception as e:
        # GEMINI_API_KEY 없거나 API 오류 등
        result["ai_analysis"] = {"error": str(e)}

    return result
