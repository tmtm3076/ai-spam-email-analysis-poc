from url_extractor import extract_urls
from virustotal_api import submit_url, get_result, extract_stats
from heuristics import analyze_mail_heuristic
from llm import analyze_mail_llm


def analyze_mail(email_text: str) -> dict:
    """
    메일 본문을 분석하여
    1) 휴리스틱 분석
    2) VirusTotal URL 분석
    3) Gemini 전체 메일 AI 분석
    결과를 통합 반환한다.
    """

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
        result["heuristic"] = analyze_mail_heuristic(email_text)
    except Exception as e:
        result["heuristic"] = {"error": str(e)}

    # ==========================================================
    # 2️⃣ URL 추출 및 VirusTotal 분석
    # ==========================================================
    urls = extract_urls(email_text)

    if urls:
        urls = urls[:3]  # 무료 API 보호
        result["urls"] = urls

        for url in urls:
            try:
                analysis_id = submit_url(url)
                vt_result = get_result(analysis_id)
                stats = extract_stats(vt_result)

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
    # 3️⃣ Gemini 전체 메일 원문 분석
    # ==========================================================
    try:
        result["ai_analysis"] = analyze_mail_llm(email_text)
    except Exception as e:
        result["ai_analysis"] = {"error": str(e)}

    return result