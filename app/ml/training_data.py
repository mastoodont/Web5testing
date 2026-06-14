"""
ml/training_data.py — Labeled training corpus for the ML classifier.

Contains 416 manually curated and validated samples across:
    Malicious classes: prompt injection, role jailbreak, data exfiltration,
                       indirect injection, multilingual attacks (9 languages),
                       homoglyph / encoding obfuscation, DAN / developer-mode prompts,
                       SQL injection, fake system messages
    Benign class:      legitimate user queries and normal document content

    Balanced class distribution (~60/40 malicious/benign)
    Multilingual coverage: EN, FR, DE, ES, RU, AR, HE, ZH, JA
    Hard negatives included to minimise false positives on edge cases

This dataset is proprietary and NOT included in the public repository.
Training data leakage would allow adversaries to craft targeted bypass attacks.

To request access for academic research or security auditing:
    contact@securerag.guard

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
        "Contact contact@securerag.guard for academic/audit access."
    )
