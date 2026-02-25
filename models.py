from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ==========================================================
# 첨부파일 모델 (확장 대비)
# ==========================================================

class Attachment(BaseModel):
    filename: str
    content: bytes
    sha256: str
    size: int


# ==========================================================
# 이메일 레코드
# ==========================================================

class EmailRecord(BaseModel):
    subject: str = ""
    from_addr: str = Field(default="", alias="from")
    to_addrs: List[str] = Field(default_factory=list, alias="to")
    date: str = ""
    body_text: str = ""
    raw_headers: Dict[str, str] = Field(default_factory=dict)

    # 🔥 추가됨 (첨부파일 지원)
    attachments: List[Attachment] = Field(default_factory=list)


# ==========================================================
# 휴리스틱 결과
# ==========================================================

class HeuristicResult(BaseModel):
    score: int
    flags: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)


# ==========================================================
# LLM 결과
# ==========================================================

class LLMResult(BaseModel):
    label: str
    confidence: Optional[float] = None
    rationale: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None


# ==========================================================
# 최종 분석 결과
# ==========================================================

class AnalysisResult(BaseModel):
    label: str
    score: int
    flags: List[str] = Field(default_factory=list)
    heuristics: HeuristicResult
    llm: Optional[LLMResult] = None
