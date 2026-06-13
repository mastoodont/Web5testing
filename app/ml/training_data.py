"""
ml/training_data.py — Labeled training corpus for the ML classifier.

Contains 377 manually curated and validated samples across:
    Malicious classes: prompt injection, role jailbreak, data exfiltration,
                       indirect injection, multilingual attacks (8 languages),
                       homoglyph / encoding obfuscation, DAN / developer-mode prompts
    Benign class:      legitimate user queries and normal document content

    Balanced class distribution (≈50/50 after augmentation)
    Multilingual coverage: EN, FR, DE, ES, RU, AR, HE, ZH, JA
    Hard negatives included to minimise false positives on edge cases

This dataset is proprietary and is NOT included in the public repository.
Training data leakage would allow adversaries to craft targeted bypass attacks.

To request access for academic research or security auditing:
    contact@your-domain.com

This module is part of the proprietary SecureRAG Guard detection engine.
"""

from typing import List, Tuple


def get_training_data() -> Tuple[List[str], List[int]]:
    """Return (texts, labels) where label 1 = malicious, 0 = benign.

    Returns:
        texts  : List[str] — raw text samples
        labels : List[int] — 1 (malicious) or 0 (benign)
    """
    raise NotImplementedError(
        "training_data is proprietary and not included in the public repository. "
        "See https://github.com/mastoodont/Web4QA for contact information."
    )
