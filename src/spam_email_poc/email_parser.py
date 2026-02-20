from __future__ import annotations

import email
import email.policy
from email.message import Message
from pathlib import Path
from typing import Dict, List, Tuple

from .models import EmailRecord


def _get_addresses(msg: Message, header_name: str) -> List[str]:
    vals = msg.get_all(header_name, [])
    addrs: List[str] = []
    for v in vals:
        # Very lightweight parsing; good enough for PoC.
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

        # Prefer text/plain; fall back to html.
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


def parse_eml(path: str | Path, *, max_chars: int = 20000) -> EmailRecord:
    p = Path(path)
    raw = p.read_bytes()
    msg = email.message_from_bytes(raw, policy=email.policy.default)

    raw_headers: Dict[str, str] = {}
    for k, v in msg.items():
        raw_headers[str(k)] = str(v)

    return EmailRecord(
        subject=str(msg.get("Subject") or ""),
        **{
            "from": str(msg.get("From") or ""),
            "to": _get_addresses(msg, "To"),
        },
        date=str(msg.get("Date") or ""),
        body_text=_extract_body_text(msg, max_chars=max_chars),
        raw_headers=raw_headers,
    )
