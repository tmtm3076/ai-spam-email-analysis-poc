from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class EmailRecord(BaseModel):
    subject: str = ""
    from_addr: str = Field(default="", alias="from")
    to_addrs: List[str] = Field(default_factory=list, alias="to")
    date: str = ""
    body_text: str = ""
    raw_headers: Dict[str, str] = Field(default_factory=dict)


class HeuristicResult(BaseModel):
    score: int
    flags: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)


class LLMResult(BaseModel):
    label: str
    confidence: Optional[float] = None
    rationale: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None


class AnalysisResult(BaseModel):
    label: str
    score: int
    flags: List[str] = Field(default_factory=list)
    heuristics: HeuristicResult
    llm: Optional[LLMResult] = None
