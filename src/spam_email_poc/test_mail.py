from mail_sender import send_result

send_result(
    to="security.alert@cosmax.com",
    body="✅ SMTP 테스트 메일입니다.\n이 메일이 오면 성공입니다."
)
