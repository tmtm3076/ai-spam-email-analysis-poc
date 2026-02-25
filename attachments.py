from __future__ import annotations

import hashlib
from email import message_from_bytes
from email.policy import default
from typing import List, Optional

from pydantic import BaseModel


class Attachment(BaseModel):
    """
    추출된 첨부파일 정보
    """
    filename: str
    content_type: Optional[str] = None
    size: int
    sha256: str
    content: bytes


def calculate_sha256(file_bytes: bytes) -> str:
    """
    파일 바이트로부터 SHA256 해시 계산
    """
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_bytes)
    return sha256_hash.hexdigest()


def extract_attachments_from_eml(file_bytes: bytes) -> List[Attachment]:
    """
    .eml 파일 바이트에서 첨부파일을 추출한다.

    Args:
        file_bytes: 업로드된 eml 파일의 raw bytes

    Returns:
        Attachment 객체 리스트
    """
    attachments: List[Attachment] = []

    try:
        msg = message_from_bytes(file_bytes, policy=default)
    except Exception as e:
        raise ValueError(f"EML 파싱 실패: {e}")

    if not msg.is_multipart():
        return attachments

    for part in msg.walk():
        content_disposition = part.get_content_disposition()

        # attachment 인 경우만 처리
        if content_disposition != "attachment":
            continue

        filename = part.get_filename()
        payload = part.get_payload(decode=True)

        if not payload:
            continue

        try:
            sha256 = calculate_sha256(payload)
            attachment = Attachment(
                filename=filename or "unknown",
                content_type=part.get_content_type(),
                size=len(payload),
                sha256=sha256,
                content=payload,
            )
            attachments.append(attachment)

        except Exception:
            # 특정 파일 하나 실패해도 전체 중단하지 않음
            continue

    return attachments