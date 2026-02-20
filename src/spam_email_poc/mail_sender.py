import win32com.client

def send_result(to: str, body: str, html_body: str = None):
    """이메일 전송 (HTML 지원)
    
    Args:
        to: 수신자 이메일
        body: 일반 텍스트 본문 (HTML 미지원 클라이언트용)
        html_body: HTML 본문 (선택사항, 제공시 HTML 형식으로 전송)
    """
    outlook = win32com.client.Dispatch("Outlook.Application")
    mail = outlook.CreateItem(0)
    mail.To = to
    mail.Subject = "[자동 분석] 스팸메일 분석 결과"
    
    if html_body:
        mail.HTMLBody = html_body
    else:
        mail.Body = body
    
    mail.Send()
