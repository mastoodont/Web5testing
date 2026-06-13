"""
scoring.py — Hybrid deterministic + ML risk scoring engine.

Combines regex-pattern threat signals with ML ensemble confidence into
a single 0-100 risk score used to make block/pass decisions.

    Severity-weighted base scores  (low=5, medium=15, high=30, critical=50)
    Threat-type multipliers        (chunk_indirect_injection highest at 1.6×)
    Source multipliers             (user_query 1.4× vs chunk 1.0×)
    Cross-chunk penalty            (+15 pts when ≥2 distinct chunks poisoned)
    ML contribution cap            (up to 45 pts from ensemble confidence)

This module is part of the proprietary SecureRAG Guard detection engine.
The public repository exposes the interface; the implementation is closed-source.

Integration / licensing inquiries: contact@your-domain.com
"""

from typing import List, Dict, Tuple


def compute_score(
    threats: List[Dict],
    ml_result: Dict | None = None,
) -> Tuple[int, Dict, bool, List[str]]:
    """Compute a 0-100 risk score from detected threats and ML output.

    Args:
        threats:    List of threat dicts from security_engine.scan_query /
                    security_engine.scan_chunks.
        ml_result:  Optional dict from classifier.predict():
                    {"malicious": bool, "confidence": float, "ml_score": int, ...}
                    Pass None to use regex signals only.

    Returns:
        Tuple of:
            risk_score    (int)   0-100
            score_details (dict)  per-threat breakdown + ML contribution
            blocked       (bool)  True when risk_score >= BLOCK_THRESHOLD (70)
            reasons       (List[str])  human-readable explanation strings
    """
    raise NotImplementedError(
        "scoring is proprietary. "
        "See https://github.com/mastoodont/Web4QA for integration options."
    )
