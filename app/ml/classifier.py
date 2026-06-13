"""
ml/classifier.py — Ensemble ML classifier for prompt-injection detection.

Architecture:
    Two-pipeline soft-vote ensemble:
      1. char n-gram TF-IDF (2-5) + Logistic Regression   — catches obfuscation
      2. word-level TF-IDF (1-3) + LinearSVC (calibrated) — catches semantic patterns

    p_malicious = 0.55 * p_char + 0.45 * p_word

    Trained on 377 labeled samples.
    F1 ≈ 0.93 on held-out validation split.
    MALICIOUS_THRESHOLD = 0.60

Why two pipelines?
    Char n-grams generalise across multilingual and encoded attacks.
    Word n-grams capture semantic role-manipulation phrases.
    Combining both reduces single-model blind spots without requiring a GPU.

This module is part of the proprietary SecureRAG Guard detection engine.
The public repository exposes the interface; the implementation is closed-source.

Integration / licensing inquiries: contact@your-domain.com
"""

from typing import Dict


def predict(text: str) -> Dict:
    """Run the ensemble classifier on a single text string.

    Args:
        text: Any text (query or chunk). Pre-processing is handled internally.

    Returns:
        {
            "malicious":  bool,   # True when p_ensemble >= MALICIOUS_THRESHOLD
            "confidence": float,  # ensemble p(malicious), 0.0-1.0
            "ml_score":   int,    # 0-100, consumed by scoring.compute_score()
            "char_conf":  float,  # char-pipeline sub-score (diagnostic)
            "word_conf":  float,  # word-pipeline sub-score (diagnostic)
        }
    """
    raise NotImplementedError(
        "classifier is proprietary. "
        "See https://github.com/mastoodont/Web4QA for integration options."
    )


def retrain() -> Dict:
    """Retrain the ensemble on updated training data and hot-reload the in-memory bundle.

    Returns:
        {"status": "ok", "char_f1": float, "word_f1": float, "ensemble_f1": float}
    """
    raise NotImplementedError("classifier is proprietary.")
