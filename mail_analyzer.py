from url_extractor import extract_urls
from virustotal_api import (
    submit_url,
    get_result,
    extract_stats,
    calculate_sha256,
    get_file_report_by_hash,
    extract_file_stats,
)
from heuristics import score_email
from llm import classify_with_llm
from models import EmailRecord
from attachments import extract_attachments_from_eml


def analyze_mail(email_text: str, eml_bytes: bytes | None = None) -> dict:
    """
    메일 분석 전체 흐름
    1) 휴리스틱
    2) URL VirusTotal
    3) 첨부파일 SHA256 기반 VirusTotal 조회
    4) LLM 정밀 분석
    5) 전문가형 회신 텍스트 생성
    """

    # ==========================================================
    # 0️⃣ Email 객체 생성
    # ==========================================================
    try:
        email = EmailRecord(
            subject="",
            body_text=email_text or "",
            from_addr=""
        )
    except Exception as e:
        return {"error": f"EmailRecord creation failed: {str(e)}"}

    result = {
        "heuristic": {},
        "urls": [],
        "virustotal": [],
        "attachments": [],
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
    # 2️⃣ URL + VirusTotal
    # ==========================================================
    try:
        urls = extract_urls(email_text or "")
        urls = urls[:3]
        result["urls"] = urls

        for url in urls:
            try:
                analysis_id = submit_url(url)
                vt_result = get_result(analysis_id)
                stats = extract_stats(vt_result) or {}

                result["virustotal"].append({
                    "url": url,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0)
                })

            except Exception as e:
                result["virustotal"].append({
                    "url": url,
                    "error": str(e)
                })

    except Exception as e:
        result["virustotal"].append({"error": f"VT failed: {str(e)}"})

    # ==========================================================
    # 3️⃣ 첨부파일 SHA256 기반 분석
    # ==========================================================
    try:
        attachment_malicious_total = 0
        attachment_suspicious_total = 0

        if eml_bytes:
            attachments = extract_attachments_from_eml(eml_bytes)

            for file in attachments:
                try:
                    file_hash = calculate_sha256(file["content"])
                    vt_report = get_file_report_by_hash(file_hash)

                    if vt_report:
                        stats = extract_file_stats(vt_report)

                        attachment_malicious_total += stats.get("malicious", 0)
                        attachment_suspicious_total += stats.get("suspicious", 0)

                        result["attachments"].append({
                            "filename": file["filename"],
                            "sha256": file_hash,
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "harmless": stats.get("harmless", 0),
                            "undetected": stats.get("undetected", 0),
                        })
                    else:
                        result["attachments"].append({
                            "filename": file["filename"],
                            "sha256": file_hash,
                            "message": "VirusTotal에 아직 등록되지 않은 파일"
                        })

                except Exception as e:
                    result["attachments"].append({
                        "filename": file.get("filename", "unknown"),
                        "error": str(e)
                    })

    except Exception as e:
        result["attachments"] = [{"error": str(e)}]

    # ==========================================================
    # 4️⃣ LLM 전문가형 분석
    # ==========================================================
    try:
        llm_result = classify_with_llm(email)
        result["ai_analysis"] = llm_result if isinstance(llm_result, dict) else {}
    except Exception as e:
        result["ai_analysis"] = {"error": str(e)}

    # ==========================================================
    # 5️⃣ 전문가형 종합 판단 텍스트 생성
    # ==========================================================
    try:
        heuristic = result.get("heuristic", {})
        vt = result.get("virustotal", [])
        ai = result.get("ai_analysis", {})
        attachments = result.get("attachments", [])

        url_malicious = sum(i.get("malicious", 0) for i in vt if isinstance(i, dict))
        url_suspicious = sum(i.get("suspicious", 0) for i in vt if isinstance(i, dict))

        file_malicious = sum(i.get("malicious", 0) for i in attachments if isinstance(i, dict))
        file_suspicious = sum(i.get("suspicious", 0) for i in attachments if isinstance(i, dict))

        final_reason = []

        final_reason.append("■ 휴리스틱 분석")
        final_reason.append(f"- 위험도: {heuristic.get('risk_level', 'N/A')}")
        final_reason.append(f"- 점수: {heuristic.get('score', 'N/A')}")
        final_reason.append("")

        final_reason.append("■ URL VirusTotal 분석")
        final_reason.append(f"- 악성 탐지 수: {url_malicious}")
        final_reason.append(f"- 의심 탐지 수: {url_suspicious}")
        final_reason.append("")

        final_reason.append("■ 첨부파일 분석")
        final_reason.append(f"- 악성 탐지 수: {file_malicious}")
        final_reason.append(f"- 의심 탐지 수: {file_suspicious}")
        final_reason.append("")

        final_reason.append("■ AI 정밀 분석")
        final_reason.append(f"- 분류: {ai.get('label', 'unknown')}")
        final_reason.append(f"- 신뢰도: {ai.get('confidence', 0)}")
        final_reason.append("- 분석 근거:")
        final_reason.append(f"{ai.get('rationale', '근거 없음')}")
        final_reason.append("")

        # 최종 종합 판단
        if file_malicious > 0 or url_malicious > 0:
            final = "다수 보안엔진에서 악성으로 탐지되어 매우 위험합니다."
        elif file_suspicious > 0 or url_suspicious > 0:
            final = "일부 엔진에서 의심 탐지되어 주의가 필요합니다."
        elif ai.get("label") == "phishing":
            final = "피싱 메일 가능성이 높습니다."
        elif ai.get("label") == "spam":
            final = "스팸 가능성이 높습니다."
        elif ai.get("label") == "ham":
            final = "정상 메일로 판단됩니다."
        else:
            final = "현재 악성 정황은 확인되지 않았습니다."

        final_reason.append("■ 종합 판단")
        final_reason.append(final)

        result["reply_text"] = "\n".join(final_reason)

    except Exception as e:
        result["reply_text"] = f"결과 생성 실패: {str(e)}"

    return result
