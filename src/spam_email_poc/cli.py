from __future__ import annotations

import argparse
from pathlib import Path

from spam_email_poc.email_parser import parse_eml
from spam_email_poc.heuristics import score_email

# ✅ URL / VirusTotal 관련 모듈
from spam_email_poc.url_extractor import extract_urls
from spam_email_poc.virustotal_api import submit_url, get_result, extract_stats

# ✅ 이메일 전송 모듈
from spam_email_poc.mail_sender import send_result


def create_html_report(label: str, score: int, flags: list, heur_details: dict, vt_results: list, ai_result: str, subject: str, sender: str = "없음") -> str:
    """분석 결과를 HTML 형식으로 변환"""
    import datetime
    import re
    
    # 현재 시간
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # AI 분석 결과에서 위험도 추출
    ai_lower = ai_result.lower()
    
    # AI 분석 결과로부터 점수 및 판정 추출
    ai_score = score  # 기본값은 휴리스틱 점수
    ai_label = label
    
    # AI 분석에서 점수 패턴 찾기 (예: "75점", "score: 80", "75/100" 등)
    score_patterns = [
        r'(\d+)\s*[점/]\s*(?:100)?',
        r'score[:\s]+(\d+)',
        r'(\d+)\s*/\s*100'
    ]
    
    for pattern in score_patterns:
        match = re.search(pattern, ai_lower)
        if match:
            try:
                extracted_score = int(match.group(1))
                if 0 <= extracted_score <= 100:
                    ai_score = extracted_score
                    break
            except:
                pass
    
    # AI 분석에서 판정 추출
    if '스팸' in ai_lower or 'spam' in ai_lower:
        if '아님' not in ai_lower and 'not spam' not in ai_lower:
            ai_label = 'spam'
    elif '피싱' in ai_lower or 'phishing' in ai_lower:
        ai_label = 'phishing'
    elif '정상' in ai_lower or 'ham' in ai_lower or '안전' in ai_lower:
        ai_label = 'ham'
    
    # 위험도 키워드 기반 점수 조정
    high_risk_keywords = ['피싱', 'phishing', '사기', 'scam', '악성', 'malicious', '위험']
    medium_risk_keywords = ['의심', 'suspicious', '경고', 'warning']
    
    high_count = sum(1 for kw in high_risk_keywords if kw in ai_lower)
    medium_count = sum(1 for kw in medium_risk_keywords if kw in ai_lower)
    
    # 키워드 기반 점수 조정 (기존 점수가 없는 경우)
    if ai_score == score:  # AI에서 명시적 점수를 찾지 못한 경우
        if high_count >= 2:
            ai_score = max(ai_score, 75)
        elif high_count >= 1:
            ai_score = max(ai_score, 60)
        elif medium_count >= 2:
            ai_score = max(ai_score, 50)
    
    # 스팸 위험도에 따른 색상 결정 (AI 기반 점수 사용)
    if ai_score >= 70:
        risk_color = "#dc3545"  # 빨강 (높음)
        risk_level = "🔴 높음"
        bg_color = "#f8d7da"
    elif ai_score >= 40:
        risk_color = "#ffc107"  # 노랑 (중간)
        risk_level = "🟡 중간"
        bg_color = "#fff3cd"
    else:
        risk_color = "#28a745"  # 초록 (낮음)
        risk_level = "🟢 낮음"
        bg_color = "#d4edda"
    
    # 플래그 HTML 생성 (중요한 플래그는 볼드 처리)
    important_flags = ["suspicious_link", "phishing", "urgent", "suspicious_sender"]
    flags_html = ""
    if flags:
        for flag in flags:
            if any(imp in flag.lower() for imp in important_flags):
                flags_html += f"<li><strong>⚠️ {flag}</strong></li>"
            else:
                flags_html += f"<li>{flag}</li>"
    else:
        flags_html = "<li>없음</li>"
    
    # VirusTotal 결과 HTML
    vt_html = ""
    for vt in vt_results:
        if "악성" in vt and "의심" in vt:
            # 악성/의심 건수 추출
            if "악성 0" not in vt and "의심 0" not in vt:
                vt_html += f"<tr><td style='color: #dc3545;'><strong>{vt}</strong></td></tr>"
            else:
                vt_html += f"<tr><td>{vt}</td></tr>"
        else:
            vt_html += f"<tr><td>{vt}</td></tr>"
    
    # AI 분석 결과에서 중요 키워드 볼드 처리
    ai_html = ai_result
    keywords_to_bold = ["스팸", "phishing", "피싱", "위험", "의심", "사기", "malicious", "악성"]
    for keyword in keywords_to_bold:
        ai_html = ai_html.replace(keyword, f"<strong>{keyword}</strong>")
    
    # 개행문자 HTML 변환
    ai_html = ai_html.replace("\n", "<br>")
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 900px;
                margin: 0 auto;
                padding: 20px;
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: #ffffff !important;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 30px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }}
            .header h1 {{
                color: #ffffff !important;
                margin: 0 0 15px 0;
            }}
            .header p {{
                color: #ffffff !important;
                margin: 5px 0;
                font-size: 14px;
            }}
            .risk-badge {{
                display: inline-block;
                padding: 10px 20px;
                background-color: {bg_color};
                color: {risk_color};
                border: 2px solid {risk_color};
                border-radius: 25px;
                font-size: 18px;
                font-weight: bold;
                margin: 10px 0;
            }}
            .section {{
                background: white;
                padding: 20px;
                margin-bottom: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                border-left: 4px solid #667eea;
            }}
            .section h2 {{
                color: #667eea;
                margin-top: 0;
                border-bottom: 2px solid #f0f0f0;
                padding-bottom: 10px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 15px 0;
            }}
            th {{
                background-color: #667eea;
                color: white;
                padding: 12px;
                text-align: left;
                font-weight: bold;
            }}
            td {{
                padding: 10px 12px;
                border-bottom: 1px solid #e0e0e0;
            }}
            tr:hover {{
                background-color: #f5f5f5;
            }}
            ul {{
                list-style-type: none;
                padding-left: 0;
            }}
            ul li {{
                padding: 8px;
                margin: 5px 0;
                background-color: #f8f9fa;
                border-left: 3px solid #667eea;
                padding-left: 15px;
            }}
            .score-display {{
                font-size: 48px;
                font-weight: bold;
                color: {risk_color};
                text-align: center;
                margin: 20px 0;
            }}
            .ai-section {{
                background-color: #f8f9fa;
                padding: 15px;
                border-radius: 5px;
                border-left: 4px solid #28a745;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>📧 스팸 이메일 분석 결과</h1>
            <p><strong>분석 일시:</strong> {current_time}</p>
            <p><strong>신고자 (From):</strong> {sender}</p>
            <p><strong>제목:</strong> {subject}</p>
        </div>
        
        <div class="section">
            <h2>🚨 AI 기반 위험도 평가</h2>
            <div class="risk-badge">스팸 가능성: {risk_level}</div>
            <div class="score-display">{ai_score} / 100</div>
            <table>
                <tr>
                    <th>항목</th>
                    <th>값</th>
                </tr>
                <tr>
                    <td><strong>AI 판정</strong></td>
                    <td style="color: {risk_color}; font-weight: bold;">{ai_label.upper()}</td>
                </tr>
                <tr>
                    <td><strong>AI 위험 점수</strong></td>
                    <td><strong>{ai_score}</strong> / 100</td>
                </tr>
                <tr>
                    <td><strong>휴리스틱 점수</strong></td>
                    <td>{score} / 100</td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>⚠️ 감지된 의심 포인트</h2>
            <table>
                <tr>
                    <th>의심 항목</th>
                </tr>
                {"" if not flags else "".join([f"<tr><td>{'<strong>⚠️ ' + flag + '</strong>' if any(imp in flag.lower() for imp in ['suspicious_link', 'phishing', 'urgent', 'suspicious_sender']) else flag}</td></tr>" for flag in flags])}
                {"<tr><td>없음</td></tr>" if not flags else ""}
            </table>
        </div>
        
        <div class="section">
            <h2>🔍 휴리스틱 분석 상세</h2>
            <table>
                <tr>
                    <th>항목</th>
                    <th>값</th>
                </tr>
                {"" if not heur_details else "".join([f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in heur_details.items()])}
            </table>
        </div>
        
        <div class="section">
            <h2>🧪 VirusTotal URL 분석</h2>
            <table>
                <tr>
                    <th>URL 분석 결과</th>
                </tr>
                {vt_html}
            </table>
        </div>
        
        <div class="section">
            <h2>🤖 AI 분석 결과</h2>
            <div class="ai-section">
                {ai_html}
            </div>
        </div>
        
        <div style="text-align: center; margin-top: 30px; padding: 20px; background-color: #f8f9fa; border-radius: 5px;">
            <p style="color: #666; font-size: 12px;">이 메일은 자동으로 생성되었습니다. | Cosmax Security Alert System</p>
        </div>
    </body>
    </html>
    """
    
    return html


def main():
    # Load optional .env (useful for GEMINI_API_KEY, VT_API_KEY during local dev)
    try:
        from dotenv import load_dotenv  # type: ignore
        load_dotenv()
    except Exception:
        pass

    parser = argparse.ArgumentParser(description="Spam Email Analyzer")
    parser.add_argument(
        "--input",
        required=True,
        help="분석할 이메일 파일 경로 (.eml 또는 .txt)"
    )
    parser.add_argument(
        "--llm",
        action="store_true",
        default=True,
        help="AI(LLM) 분석을 함께 수행합니다 (GEMINI_API_KEY 필요, 기본값: True)"
    )
    parser.add_argument(
        "--no-llm",
        action="store_false",
        dest="llm",
        help="AI(LLM) 분석을 비활성화합니다"
    )

    args = parser.parse_args()
    input_path = Path(args.input)

    if not input_path.exists():
        print("❌ 입력 파일이 존재하지 않습니다.")
        return

    # -------------------------------------------------
    # 1️⃣ 이메일 파싱
    # -------------------------------------------------
    email = parse_eml(input_path)

    # -------------------------------------------------
    # 2️⃣ 휴리스틱 분석
    # -------------------------------------------------
    heur = score_email(email)
    label = heur.details.get("label") or ("spam" if heur.score >= 50 else "ham")

    print(f"\nLabel: {label}")
    print(f"Score: {heur.score}")
    print(f"Flags: {', '.join(heur.flags) if heur.flags else 'None'}")

    print("\nHeuristics details:")
    print(heur.details)

    # 결과 수집을 위한 변수
    result_text = f"""=== 스팸 이메일 분석 결과 ===

[기본 정보]
Label: {label}
Score: {heur.score}
Flags: {', '.join(heur.flags) if heur.flags else 'None'}

[휴리스틱 분석]
{heur.details}
"""

    # -------------------------------------------------
    # 3️⃣ VirusTotal URL 분석 (자동)
    # -------------------------------------------------
    print("\n🧪 VirusTotal URL 분석 결과")

    email_body = getattr(email, "body_text", "") or ""
    urls = extract_urls(email_body)

    vt_results = []
    if not urls:
        print("URL 없음")
        vt_results.append("URL 없음")
    else:
        # 무료 VT API 보호 (최대 3개)
        urls = urls[:3]

        for url in urls:
            print(f"\n🔗 URL: {url}")

            try:
                analysis_id = submit_url(url)
                vt_result = get_result(analysis_id)
                stats = extract_stats(vt_result)

                result_line = f"→ 악성 {stats['malicious']} / 의심 {stats['suspicious']}"
                print(result_line)
                vt_results.append(f"URL: {url}\n{result_line}")

            except Exception as e:
                error_msg = f"→ VirusTotal 분석 실패: {e}"
                print(error_msg)
                vt_results.append(f"URL: {url}\n{error_msg}")

    result_text += f"\n[VirusTotal URL 분석]\n" + "\n".join(vt_results)

    # -------------------------------------------------
    # 4️⃣ AI 분석 (옵션)
    # -------------------------------------------------
    print("\n🤖 AI 분석 결과")

    ai_result_text = ""
    if not args.llm:
        ai_result_text = "AI 분석 생략 (--no-llm 옵션 사용)"
        print(ai_result_text)
    else:
        try:
            from spam_email_poc.ai_analyzer import analyze_with_ai

            ai_input = f"""
[Subject]
{getattr(email, 'subject', '')}

[Body]
{email_body}
""".strip()

            ai_result = analyze_with_ai(ai_input)
            ai_result_text = ai_result
            print(ai_result)

        except Exception as e:
            ai_result_text = f"AI 분석 실패: {e}"
            print(ai_result_text)

    result_text += f"\n\n[AI 분석]\n{ai_result_text}"

    # -------------------------------------------------
    # 5️⃣ 이메일 전송
    # -------------------------------------------------
    print("\n📧 분석 결과 이메일 전송 중...")
    try:
        # HTML 리포트 생성
        html_report = create_html_report(
            label=label,
            score=heur.score,
            flags=heur.flags,
            heur_details=heur.details,
            vt_results=vt_results,
            ai_result=ai_result_text,
            subject=getattr(email, 'subject', '제목 없음'),
            sender=getattr(email, 'from', '없음')
        )
        
        # HTML 형식으로 전송 (텍스트는 fallback용)
        send_result("security.alert@cosmax.com", result_text, html_report)
        print("✅ 이메일 전송 완료: security.alert@cosmax.com")
    except Exception as e:
        print(f"❌ 이메일 전송 실패: {e}")


if __name__ == "__main__":
    main()
