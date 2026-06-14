"""
security_engine.py — Deterministic threat detection for RAG pipelines.

Detects prompt injection, document poisoning, data exfiltration, role jailbreaks,
and multilingual / homoglyph-obfuscated attacks across user queries and retrieved chunks.

    26+ regex pattern groups (prompt_injection, data_exfiltration,
    context_injection, chunk_indirect_injection)
    Unicode NFKC normalisation — catches homoglyph & zero-width attacks
    Per-chunk scanning with chunk-specific pattern set
    Deduplication across normalised + original text passes
    Multilingual: EN, RU, HE, AR, FR, DE, ES, ZH, JA

This module is part of the proprietary SecureRAG Guard detection engine.
The public repository exposes the interface; the implementation is closed-source.

To evaluate the engine, use the live demo:
    POST https://your-app.railway.app/demo/scan
    POST https://your-app.railway.app/demo/scan-files

Integration / licensing inquiries: contact@securerag.guard
"""

from typing import List, Dict, Tuple


def scan_query(user_query: str) -> List[Dict]:
    """Scan a user query string for prompt injection and related threats.

    Args:
        user_query: Raw text submitted by the end-user.

    Returns:
        List of threat dicts, each containing:
            threat_type (str), severity (str), source (str),
            description (str), matched_text (str)
    """
    raise NotImplementedError(
        "security_engine is proprietary. "
        "Contact contact@securerag.guard for licensing."
    )


def scan_chunks(chunks: List[str]) -> Tuple[List[Dict], List[int]]:
    """Scan retrieved document chunks for indirect injection and poisoning.

    Args:
        chunks: List of text chunks returned by the vector store / retriever.

    Returns:
        Tuple of (all_threats: List[Dict], unsafe_chunk_indices: List[int])
    """
    raise NotImplementedError(
        "security_engine is proprietary. "
        "Contact contact@securerag.guard for licensing."
    )


def detect_threats_in_text(
    text: str,
    source: str,
    is_chunk: bool = False,
) -> List[Dict]:
    """Low-level scanner — run all pattern groups against one text string.

    Args:
        text:     The text to scan (query or chunk).
        source:   Label written into threat dicts ('user_query' | 'chunk_N').
        is_chunk: When True, also runs chunk-specific indirect-injection patterns.

    Returns:
        List of threat dicts.
    """
    raise NotImplementedError("security_engine is proprietary.")
