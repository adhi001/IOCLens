from datetime import datetime, timezone
from math import prod

from .schemas import EvidenceIn, EvidenceOut

SEVERITY_WEIGHT = {
    "info": 5.0,
    "low": 15.0,
    "medium": 35.0,
    "high": 60.0,
    "critical": 85.0,
}


def score_evidence(items: list[EvidenceIn], now: datetime | None = None):
    """Return transparent risk score, confidence, evidence details, and explanations.

    Each evidence contribution is severity × source confidence × freshness.
    Independent evidence is combined with a diminishing-return noisy-OR model.
    """
    now = now or datetime.now(timezone.utc)
    details: list[EvidenceOut] = []
    explanations: list[str] = []

    for item in items:
        age_hours = max(0.0, (now - item.observed_at).total_seconds() / 3600)
        freshness = 0.5 ** (age_hours / (24 * 30))
        contribution = min(100.0, SEVERITY_WEIGHT[item.severity.value] * item.confidence * freshness)
        details.append(EvidenceOut(**item.model_dump(), age_hours=round(age_hours, 2),
                                   contribution=round(contribution, 2)))
        explanations.append(
            f"{item.source}: {item.severity.value} {item.category} evidence "
            f"(source confidence {item.confidence:.0%}, freshness factor {freshness:.2f}) "
            f"contributed {contribution:.1f} points. {item.summary}"
        )

    if not details:
        return None, 0.0, details, ["No evidence supplied; risk is unknown, not confirmed benign."]

    score = 100 * (1 - prod(1 - min(0.99, d.contribution / 100) for d in details))
    confidence = 1 - prod(1 - d.confidence for d in details)
    return round(score), round(confidence, 3), details, explanations


def verdict_for(score: int | None) -> str:
    if score is None:
        return "unknown"
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "suspicious"
    if score >= 15:
        return "low-risk"
    return "informational"
