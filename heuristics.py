from __future__ import annotations

import re
from urllib.parse import urlparse

from .models import EmailRecord, HeuristicResult

# 고위험 키워드 (각 20점)
_HIGH_RISK_KEYWORDS = [
    # 금융/계정 피싱
    "account suspended", "계정 정지", "계정이 정지", "계정 잠금",
    "verify your account", "계정 확인", "인증하세요", "본인인증",
    "password reset", "비밀번호 재설정", "비밀번호 변경", "비밀번호 확인",
    "unauthorized access", "무단 접근", "불법 접근", "비정상 로그인",
    "unusual activity", "비정상적인 활동", "의심스러운 활동",
    
    # 금전 관련
    "wire transfer", "송금", "계좌이체", "환불", "환급",
    "bitcoin", "비트코인", "암호화폐", "crypto",
    "gift card", "상품권", "기프트카드", "쿠폰",
    
    # 피싱/사기
    "confirm your identity", "신원 확인", "부정 사용", "비정상 거래",
    "suspended account", "회원 탈퇴", "회원탈퇴",
    "security alert", "보안 경고", "보안경고",
]

# 중간 위험 키워드 (각 10점)
_MEDIUM_RISK_KEYWORDS = [
    # 긴급성 강조
    "urgent", "긴급", "긴급히", "즘시", "즉시", "바로",
    "immediate", "immediately", "지금 바로", "하루 이내",
    "act now", "지금 행동", "지금 클릭",
    "limited time", "제한 시간", "마감 임박", "마감임박",
    "expires", "만료", "유효기간",
    
    # 공지/확인 요청
    "verify", "verification", "확인", "검증",
    "confirm", "confirmation", "승인", "승인 필요",
    "click here", "여기를 클릭", "클릭하세요", "클릭하기",
    "update required", "업데이트 필요", "갱신 필요",
    
    # 경품/혜택
    "congratulations", "축하", "축하합니다", "당첨",
    "winner", "당첨자", "선정",
    "prize", "경품", "상품",
    "free", "무료", "무료로",
    
    # 금융/세금
    "invoice", "세금계산서", "청구서", "결제",
    "payment", "결제하기", "결제 문제",
    "overdue", "연체", "연체된",
    "refund", "환불금", "환불 처리",
    "tax", "세금", "부가세",
]

# 낮은 위험 키워드 (각 5점)
_LOW_RISK_KEYWORDS = [
    "offer", "제안", "특가", "할인",
    "special", "특별", "특별한",
    "deal", "거래", "딩",
    "promotion", "프로모션", "이벤트",
    "subscribe", "구독", "구독하기",
    "unsubscribe", "구독 취소", "수신거부",
]

_URL_RE = re.compile(r"https?://[^\s)\]}>\"']+", re.IGNORECASE)

# 의심스러운 URL 패턴
_SUSPICIOUS_URL_PATTERNS = [
    r'bit\.ly', r'tinyurl', r'goo\.gl', r't\.co',  # URL 단축
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP 주소
    r'-.*login', r'-.*signin', r'-.*verify', r'-.*account',  # 피싱 패턴
    r'@',  # URL에 @ 포함 (피싱 기법)
]

# 의심스러운 발신자 패턴
_SUSPICIOUS_SENDER_PATTERNS = [
    r'no-?reply@',
    r'do-?not-?reply@',
    r'noreply@',
    r'info@',
    r'support@.*\.(?:xyz|top|tk|ml|ga|cf|gq)',  # 의심스러운 TLD
]


def _extract_domains(text: str) -> set[str]:
    domains: set[str] = set()
    for m in _URL_RE.finditer(text or ""):
        try:
            u = urlparse(m.group(0))
            if u.hostname:
                domains.add(u.hostname.lower())
        except Exception:
            continue
    return domains


def score_email(email: EmailRecord) -> HeuristicResult:
    body = (email.body_text or "").lower()
    subj = (email.subject or "").lower()
    combined_text = f"{subj} {body}"

    flags: list[str] = []
    score = 0
    keyword_details = {"high": [], "medium": [], "low": []}

    # 1. 고위험 키워드 검사 (20점씩, 최대 60점)
    high_risk_hits = [kw for kw in _HIGH_RISK_KEYWORDS if kw in combined_text]
    if high_risk_hits:
        flags.append("high_risk_keywords")
        keyword_details["high"] = high_risk_hits[:5]  # 상위 5개만 표시
        score += min(60, 20 * len(high_risk_hits))

    # 2. 중간 위험 키워드 검사 (10점씩, 최대 40점)
    medium_risk_hits = [kw for kw in _MEDIUM_RISK_KEYWORDS if kw in combined_text]
    if medium_risk_hits:
        flags.append("medium_risk_keywords")
        keyword_details["medium"] = medium_risk_hits[:5]
        score += min(40, 10 * len(medium_risk_hits))

    # 3. 낮은 위험 키워드 검사 (5점씩, 최대 20점)
    low_risk_hits = [kw for kw in _LOW_RISK_KEYWORDS if kw in combined_text]
    if low_risk_hits:
        keyword_details["low"] = low_risk_hits[:5]
        score += min(20, 5 * len(low_risk_hits))

    # 4. URL 분석
    domains = _extract_domains(email.body_text)
    suspicious_url_count = 0
    
    if domains:
        flags.append("contains_links")
        
        # URL 수에 따른 기본 점수
        if len(domains) >= 5:
            score += 20
            flags.append("excessive_links")
        elif len(domains) >= 3:
            score += 15
        else:
            score += 8
        
        # 의심스러운 URL 패턴 검사
        for domain in domains:
            for pattern in _SUSPICIOUS_URL_PATTERNS:
                if re.search(pattern, domain, re.IGNORECASE):
                    suspicious_url_count += 1
                    break
        
        if suspicious_url_count > 0:
            flags.append("suspicious_url_pattern")
            score += min(25, 15 * suspicious_url_count)

    # 5. 발신자 분석
    from_addr = email.from_addr.lower()
    from_domain = ""
    if "@" in from_addr:
        from_domain = from_addr.split("@")[-1].strip("<> \"'").lower()
    
    # 의심스러운 발신자 패턴
    for pattern in _SUSPICIOUS_SENDER_PATTERNS:
        if re.search(pattern, from_addr, re.IGNORECASE):
            flags.append("suspicious_sender")
            score += 15
            break
    
    # From-domain과 link domain 불일치
    if from_domain and domains:
        # 발신자 도메인이 모든 링크 도메인과 다른 경우
        if all(from_domain not in d and not d.endswith(from_domain) for d in domains):
            flags.append("from_domain_mismatch")
            score += 20

    # 6. 제목 분석
    # 과도한 문장부호 / 대문자
    if subj:
        exclamation_count = subj.count("!")
        question_count = subj.count("?")
        
        if exclamation_count >= 3:
            flags.append("excessive_punctuation")
            score += 12
        
        if subj.isupper() and len(subj) >= 8:
            flags.append("shouting_subject")
            score += 12
        
        # 제목이 "Re:" 또는 "Fwd:"로 시작하지만 결제/인증 키워드 포함
        if (subj.startswith("re:") or subj.startswith("fwd:")) and any(kw in subj for kw in ["결제", "인증", "verify", "payment"]):
            flags.append("fake_reply")
            score += 15

    # 7. 본문 분석
    if body:
        # HTML 태그가 많은 경우 (이미지 기반 스팸)
        html_tag_count = body.count("<img") + body.count("<iframe") + body.count("<script")
        if html_tag_count >= 3:
            flags.append("html_heavy")
            score += 10
        
        # 지나치게 짧은 본문 + 링크 (피싱 특징)
        if len(body.strip()) < 100 and len(domains) >= 1:
            flags.append("short_body_with_links")
            score += 15

    # 8. 숫자가 많은 제목/본문 (무작위 문자열)
    digit_ratio = sum(c.isdigit() for c in combined_text) / max(len(combined_text), 1)
    if digit_ratio > 0.3:
        flags.append("high_digit_ratio")
        score += 10

    # 최종 점수 조정
    score = max(0, min(100, score))

    # 판정 (임계값 40으로 하향 조정)
    if score >= 70:
        label = "high_risk_spam"
    elif score >= 40:
        label = "spam"
    else:
        label = "ham"
    
    details = {
        "high_risk_keywords": keyword_details["high"],
        "medium_risk_keywords": keyword_details["medium"],
        "low_risk_keywords": keyword_details["low"],
        "link_domains": sorted(domains)[:10],  # 상위 10개만
        "suspicious_url_count": suspicious_url_count,
        "from_domain": from_domain,
        "from_address": email.from_addr,
        "label_threshold": "40 (spam), 70 (high_risk)",
        "label": label,
        "total_links": len(domains),
    }

    return HeuristicResult(score=score, flags=flags, details=details)
