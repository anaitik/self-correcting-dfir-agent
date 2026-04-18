"""
utils/scoring.py
Confidence scoring and evidence quality helpers for DFIR findings.

Scoring philosophy:
  - Evidence must be corroborated across multiple sources to earn high confidence
  - A single tool hit is 'suspicious'; two independent sources = 'confirmed'
  - Contradictions between sources ALWAYS lower the score
  - Missing expected artifacts cap the maximum achievable score
"""

from typing import Optional


# ------------------------------------------------------------------ #
#  Scoring constants                                                   #
# ------------------------------------------------------------------ #

# Minimum score a finding can have (floor prevents zero-confidence noise)
MIN_CONFIDENCE = 0.05

# Corroboration bonuses (added when multiple independent sources agree)
CORROBORATION_BONUS = 0.15

# Penalties
CONTRADICTION_PENALTY = 0.25
MISSING_EVIDENCE_PENALTY = 0.10
WEAK_SINGLE_SOURCE_PENALTY = 0.15

# Flag thresholds
CONFIRMED_THRESHOLD = 0.75
SUSPICIOUS_THRESHOLD = 0.40


# ------------------------------------------------------------------ #
#  Core scoring helpers                                                #
# ------------------------------------------------------------------ #

def clamp(value: float, lo: float = MIN_CONFIDENCE, hi: float = 1.0) -> float:
    """Ensure a score stays within [lo, hi]."""
    return max(lo, min(hi, value))


def compute_finding_confidence(
    base_score: float,
    num_corroborating_sources: int = 1,
    has_contradiction: bool = False,
    missing_expected_artifacts: int = 0,
    is_single_source: bool = True,
) -> float:
    """
    Adjust a base confidence score using evidence quality signals.

    Args:
        base_score: Initial score from the triage agent (0.0 – 1.0)
        num_corroborating_sources: Number of *independent* tool outputs
            that all point to the same conclusion.
        has_contradiction: True if any tool output contradicts this finding.
        missing_expected_artifacts: Count of artifacts we *expect* to see
            given this hypothesis but cannot find.
        is_single_source: True if only one tool produced evidence.

    Returns:
        Adjusted confidence score clamped to [MIN_CONFIDENCE, 1.0]
    """
    score = base_score

    # Reward multi-source corroboration
    bonus = (num_corroborating_sources - 1) * CORROBORATION_BONUS
    score += bonus

    # Penalise contradictions
    if has_contradiction:
        score -= CONTRADICTION_PENALTY

    # Penalise missing expected evidence
    score -= missing_expected_artifacts * MISSING_EVIDENCE_PENALTY

    # Penalise weak single-source findings
    if is_single_source and base_score > 0.5:
        score -= WEAK_SINGLE_SOURCE_PENALTY

    return clamp(score)


def assign_flag(confidence: float) -> str:
    """
    Assign a human-readable flag based on the confidence score.

    Returns:
        'confirmed'     — strong multi-source evidence, high confidence
        'suspicious'    — partial evidence, moderate confidence
        'inconsistent'  — contradictions or major gaps detected
    """
    if confidence >= CONFIRMED_THRESHOLD:
        return "confirmed"
    elif confidence >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    else:
        return "inconsistent"


def score_overall_analysis(findings: list[dict]) -> dict:
    """
    Compute summary statistics for an entire set of findings.

    Returns a dict with:
        - average_confidence
        - confirmed_count
        - suspicious_count
        - inconsistent_count
        - overall_quality: 'high' | 'medium' | 'low'
    """
    if not findings:
        return {
            "average_confidence": 0.0,
            "confirmed_count": 0,
            "suspicious_count": 0,
            "inconsistent_count": 0,
            "overall_quality": "low",
        }

    scores = [f.get("confidence", 0.0) for f in findings]
    avg = sum(scores) / len(scores)

    flags = [f.get("flag", "inconsistent") for f in findings]
    confirmed = flags.count("confirmed")
    suspicious = flags.count("suspicious")
    inconsistent = flags.count("inconsistent")

    if avg >= 0.70 and inconsistent == 0:
        quality = "high"
    elif avg >= 0.50:
        quality = "medium"
    else:
        quality = "low"

    return {
        "average_confidence": round(avg, 3),
        "confirmed_count": confirmed,
        "suspicious_count": suspicious,
        "inconsistent_count": inconsistent,
        "overall_quality": quality,
    }
