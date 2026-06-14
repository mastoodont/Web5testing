"""
ml/continuous_learning.py — Continuous learning system.

Automatically improves the ML model on real production traffic:

    Every scan is logged to the learning DB
    Clear attacks / clear benign queries are auto-labeled
    Ambiguous cases wait for operator feedback via POST /feedback
    Model auto-retrains when NEW_SAMPLES_THRESHOLD samples accumulate
    Background scheduler retrains every RETRAIN_INTERVAL_HOURS if new data exists
    All model versions are saved with F1 metrics and training sample counts
    Hot-reload: model updates without server restart

API surface (used by routes.py):
    log_scan(text, ml_confidence, regex_threat_count, risk_score, blocked)
    submit_feedback(sample_id, label, source)
    retrain_with_new_data(trigger_reason)
    get_learning_stats()
    start_scheduler()   ← called once at app startup
    stop_scheduler()    ← called at shutdown

This module is part of the proprietary SecureRAG Guard detection engine.
Integration / licensing inquiries: contact@securerag.guard
"""

from typing import Optional


def log_scan(
    text: str,
    ml_confidence: float,
    regex_threat_count: int,
    risk_score: int,
    blocked: bool,
    auto_label: Optional[int] = None,
) -> Optional[int]:
    """Log a scan to the learning DB. Returns sample ID for feedback."""
    raise NotImplementedError("continuous_learning is proprietary.")


def submit_feedback(
    sample_id: int,
    label: int,
    source: str = 'human',
) -> bool:
    """Submit human feedback: label=1 (attack), label=0 (benign/false positive)."""
    raise NotImplementedError("continuous_learning is proprietary.")


def retrain_with_new_data(trigger_reason: str = 'manual') -> dict:
    """Merge base training data with labeled samples and retrain the ensemble."""
    raise NotImplementedError("continuous_learning is proprietary.")


def get_learning_stats() -> dict:
    """Return current learning system status for monitoring."""
    raise NotImplementedError("continuous_learning is proprietary.")


def start_scheduler():
    """Start background auto-retrain scheduler. Call once at app startup."""
    raise NotImplementedError("continuous_learning is proprietary.")


def stop_scheduler():
    """Graceful shutdown of the learning scheduler."""
    raise NotImplementedError("continuous_learning is proprietary.")


def init_learning_db():
    """Initialize learning database tables."""
    raise NotImplementedError("continuous_learning is proprietary.")
