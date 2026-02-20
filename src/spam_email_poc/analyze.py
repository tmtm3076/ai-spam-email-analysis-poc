from __future__ import annotations

from .heuristics import score_email
from .llm import classify_with_llm
from .models import AnalysisResult, EmailRecord


def analyze_email(email: EmailRecord, *, use_llm: bool = False) -> AnalysisResult:
    heur = score_email(email)

    llm = classify_with_llm(email) if use_llm else None

    # Prefer LLM label if available and meaningful.
    if llm and llm.label in ("spam", "ham"):
        label = llm.label
    else:
        label = "spam" if heur.score >= 50 else "ham"

    return AnalysisResult(
        label=label,
        score=heur.score,
        flags=heur.flags,
        heuristics=heur,
        llm=llm,
    )
