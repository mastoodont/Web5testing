"""
security_engine.py — Deterministic threat detection for RAG pipelines.

Detects prompt injection, document poisoning, data exfiltration, role jailbreaks,
and multilingual / homoglyph-obfuscated attacks across user queries and retrieved chunks.

    26+ regex pattern groups (prompt_injection, data_exfiltration,
    context_injection, chunk_indirect_injection)
    Unicode NFKC normalisation — catches homoglyph & zero-width attacks
    Per-chunk scanning with chunk-specific pattern set
    Deduplication across normalised + original text passes

This module is part of the proprietary SecureRAG Guard detection engine.
The public repository exposes the interface; the implementation is closed-source.

To evaluate the engine, use the live demo:
    POST https://your-app.railway.app/demo/scan       (text, 3 free scans/IP)
    POST https://your-app.railway.app/demo/scan-files (PDF/DOCX)

Integration / licensing inquiries: contact@your-domain.com
"""

from typing import List, Dict, Tuple


def scan_query(user_query: str) -> List[Dict]:
    """Scan a user query string for prompt injection and related threats.

    Args:
        user_query: Raw text submitted by the end-user.

    Returns:
        List of threat dicts, each containing:
            threat_type (str), severity (str), source (str), description (str)
    """
    raise NotImplementedError(
        "security_engine is proprietary. "
        "See https://github.com/mastoodont/Web4QA for integration options."
    )


def scan_chunks(chunks: List[str]) -> Tuple[List[Dict], List[int]]:
    """Scan retrieved document chunks for indirect injection and poisoning.

    Args:
        chunks: List of text chunks returned by the vector store / retriever.

    Returns:
        Tuple of (all_threats: List[Dict], unsafe_chunk_indices: List[int])
        unsafe_chunk_indices contains the 0-based positions of poisoned chunks.
    """
    raise NotImplementedError(
        "security_engine is proprietary. "
        "See https://github.com/mastoodont/Web4QA for integration options."
    )


def detect_threats_in_text(
    text: str,
    source: str,
    is_chunk: bool = False,
) -> List[Dict]:
    """Low-level scanner — run all applicable pattern groups against one text string.

    Args:
        text:     The text to scan (query or chunk).
        source:   Label written into threat dicts ('user_query' | 'chunk_N').
        is_chunk: When True, also runs the chunk-specific indirect-injection patterns.

    Returns:
        List of threat dicts (see scan_query for schema).
    """
    raise NotImplementedError("security_engine is proprietary.")
