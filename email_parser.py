from __future__ import annotations

import email
import email.policy
from email.message import Message
from pathlib import Path
from typing import Dict, List, Tuple

import hashlib

from models import EmailRecord

# msg 지원
try:
    import extract_msg
except ImportError:
    extract_msg = None


# ==========================================================
# 공통 유틸
# ==========================================================

def _get_addresses(msg: Message, header_name: str) -> List[str]:
    vals = msg.get_all(header_name, [])
    addrs: List[str] = []
    for v in vals:
        addrs.extend([p.strip() for p in v.split(",") if p.strip()])
    return addrs


def _extract_body_text(msg: Message, max_chars: int = 20000) -> str:
    if msg.is_multipart():
        parts: List[Tuple[str, str]] = []

        for part in msg.walk():
            ctype = part.get_content_type()
            disp = (part.get("Content-Disposition") or "").lower()

            if disp.startswith("attachment"):
                continue

            if ctype in ("text/plain", "text/html"):
                try:
                    text = part.get_content()
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    charset = part.get_content_charset() or "utf-8"
                    text = payload.decode(charset, errors="replace")

                parts.append((ctype, text))

        plain = "\n\n".join(t for c, t in parts if c == "text/plain").strip()
        if plain:
            return plain[:max_chars]

        html = "\n\n".join(t for c, t in parts if c == "text/html").strip()
        return html[:max_chars]

    try:
        return (msg.get_content() or "")[:max_chars]
    except Exception:
        payload = msg.get_payload(decode=True) or b""
        charset = msg.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")[:max_chars]


# ==========================================================
# 첨부파일 추출 (EML용)
# ==========================================================

def _extract_attachments_from_eml(msg: Message) -> List[Dict]:
    attachments: List[Dict] = []

    for part in msg.walk():
        disp = (part.get("Content-Disposition") or "").lower()
        if not disp.startswith("attachment"):
            continue

        filename = part.get_filename()
        payload = part.get_payload(decode=True)

        if not filename or not payload:
            continue

        sha256 = hashlib.sha256(payload).hexdigest()

        attachments.append({
            "filename": filename,
            "content": payload,
            "sha256": sha256,
            "size": len(payload),
        })

    return attachments


# ==========================================================
# EML 파싱
# ==========================================================

def parse_eml(path: str | Path, *, max_chars: int = 20000) -> EmailRecord:
    p = Path(path)
    raw = p.read_bytes()
    msg = email.message_from_bytes(raw, policy=email.policy.default)

    raw_headers: Dict[str, str] = {}
    for k, v in msg.items():
        raw_headers[str(k)] = str(v)

    attachments = _extract_attachments_from_eml(msg)

    return EmailRecord(
        subject=str(msg.get("Subject") or ""),
        **{
            "from": str(msg.get("From") or ""),
            "to": _get_addresses(msg, "To"),
        },
        date=str(msg.get("Date") or ""),
        body_text=_extract_body_text(msg, max_chars=max_chars),
        raw_headers=raw_headers,
        attachments=attachments,   # 🔥 추가됨
    )


# ==========================================================
# MSG 파싱 (Outlook)
# ==========================================================

def parse_msg(path: str | Path, *, max_chars: int = 20000) -> EmailRecord:
    if not extract_msg:
        raise RuntimeError("extract-msg library not installed")

    p = Path(path)

    msg = extract_msg.Message(str(p))

    subject = msg.subject or ""
    sender = msg.sender or ""
    body = msg.body or ""

    raw_headers = {
        "Subject": subject,
        "From": sender,
    }

    attachments: List[Dict] = []

    # extract_msg 첨부파일 처리
    try:
        for att in msg.attachments:
            filename = att.longFilename or att.shortFilename
            payload = att.data

            if not filename or not payload:
                continue

            sha256 = hashlib.sha256(payload).hexdigest()

            attachments.append({
                "filename": filename,
                "content": payload,
                "sha256": sha256,
                "size": len(payload),
            })
    except Exception:
        pass

    return EmailRecord(
        subject=subject,
        **{
            "from": sender,
            "to": [],
        },
        date="",
        body_text=body[:max_chars],
        raw_headers=raw_headers,
        attachments=attachments,   # 🔥 추가됨
    )


# ==========================================================
# 자동 판별 함수 (웹 업로드용)
# ==========================================================

def parse_email_file(path: str | Path, *, max_chars: int = 20000) -> EmailRecord:
    p = Path(path)
    suffix = p.suffix.lower()

    if suffix == ".eml":
        return parse_eml(p, max_chars=max_chars)

    if suffix == ".msg":
        return parse_msg(p, max_chars=max_chars)

    raise ValueError("Unsupported file format (.eml or .msg only)")
