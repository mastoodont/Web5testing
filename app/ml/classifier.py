"""
ml/classifier.py — Ensemble ML classifier for prompt-injection detection.

Architecture:
    Two-pipeline soft-vote ensemble:
      1. char n-gram TF-IDF (2-5) + Logistic Regression   — catches obfuscation
      2. word-level TF-IDF (1-3) + LinearSVC (calibrated) — catches semantic patterns

    p_malicious = 0.55 * p_char + 0.45 * p_word

    Trained on 416 labeled samples across 9 languages.
    F1 >= 0.90 on held-out validation split.
    MALICIOUS_THRESHOLD = 0.60

    Auto-retrains on accumulated feedback via continuous_learning module.

This module is part of the proprietary SecureRAG Guard detection engine.
Integration / licensing inquiries: contact@securerag.guard
"""

from typing import Dict


def predict(text: str) -> Dict:
    """Run the ensemble classifier on a single text string.

    Args:
        text: Any text (query or chunk). Pre-processing is handled internally.

    Returns:
        {
            "malicious":  bool,
            "confidence": float,   # ensemble p(malicious), 0.0-1.0
            "ml_score":   int,     # 0-100
            "char_conf":  float,   # char-pipeline sub-score
            "word_conf":  float,   # word-pipeline sub-score
        }
    """
    raise NotImplementedError(
        "classifier is proprietary. "
        "Contact contact@securerag.guard for licensing."
    )


def retrain() -> Dict:
    """Retrain the ensemble on updated training data and hot-reload in memory.

    Returns:
        {"status": "ok", "char_f1": float, "word_f1": float, "ensemble_f1": float}
    """
    raise NotImplementedError("classifier is proprietary.")
