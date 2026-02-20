import re

URL_REGEX = re.compile(r'https?://[^\s<>"\']+')

def extract_urls(text: str) -> list[str]:
    """
    메일 본문에서 URL만 추출한다
    """
    urls = URL_REGEX.findall(text)
    return list(set(urls))  # 중복 제거
