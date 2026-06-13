import hashlib
import time
import uuid
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.auth.api_key import verify_api_key
from app.models.schemas import (
    SecureRetrieveRequest,
    SecureRetrieveResponse,
    DemoStatusResponse,
    ThreatDetail,
    HealthResponse,
)
from app.core.security_engine import scan_query, scan_chunks
from app.core.scoring import compute_score
from app.ml.classifier import predict as ml_predict
from app.db.database import (
    get_db,
    save_request,
    save_threats,
    save_score_audit,
    check_db_connection,
    get_demo_usage,
    increment_demo_usage,
    DEMO_LIMIT,
)
from app.config import get_settings

router = APIRouter()


# ── Shared scan logic (used by both paid + demo endpoints) ────────────────────

def _run_scan(payload: SecureRetrieveRequest, db: Session, api_key_hint: str | None):
    request_id = str(uuid.uuid4())
    t_start = time.perf_counter()

    query_threats = scan_query(payload.user_query)
    chunk_threats, unsafe_chunk_indices = scan_chunks(payload.retrieved_chunks)
    all_threats = query_threats + chunk_threats
    ml_result = ml_predict(payload.user_query)
    risk_score, component_scores, blocked, reasons = compute_score(
        all_threats, ml_result=ml_result
    )

    safe_chunks: List[str] = [
        chunk for i, chunk in enumerate(payload.retrieved_chunks)
        if i not in unsafe_chunk_indices
    ]
    if blocked and (query_threats or ml_result.get("malicious")):
        safe_chunks = []

    processing_time_ms = (time.perf_counter() - t_start) * 1000
    query_hash = hashlib.sha256(payload.user_query.encode()).hexdigest()

    save_request(
        db=db, request_id=request_id, user_id=payload.user_id,
        query_hash=query_hash, risk_score=risk_score, blocked=blocked,
        chunks_received=len(payload.retrieved_chunks), chunks_passed=len(safe_chunks),
        threats_detected=len(all_threats), processing_time_ms=processing_time_ms,
        api_key_hint=api_key_hint,
    )
    if all_threats:
        save_threats(db=db, request_id=request_id, threats=all_threats)
    component_scores["ml_result"] = ml_result
    save_score_audit(db=db, request_id=request_id,
                     component_scores=component_scores, final_score=risk_score)

    threats = [
        ThreatDetail(
            threat_type=t["threat_type"], description=t["description"],
            severity=t["severity"], matched_pattern=t.get("matched_pattern"),
            source=t["source"],
        )
        for t in all_threats
    ]

    return dict(
        request_id=request_id, safe_chunks=safe_chunks, risk_score=risk_score,
        blocked=blocked, reasons=reasons, threats=threats,
        chunks_filtered=len(payload.retrieved_chunks) - len(safe_chunks),
        processing_time_ms=round(processing_time_ms, 2),
        timestamp=datetime.now(timezone.utc),
    )


# ── Paid endpoint ─────────────────────────────────────────────────────────────

@router.post("/secure-retrieve", response_model=SecureRetrieveResponse)
async def secure_retrieve(
    payload: SecureRetrieveRequest,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    result = _run_scan(payload, db, (api_key[:8] + "…") if api_key else None)
    return SecureRetrieveResponse(**result)


# ── Demo endpoints (no auth, IP-limited to DEMO_LIMIT scans lifetime) ─────────

def _ip_hash(request: Request) -> str:
    ip = request.headers.get("x-forwarded-for", request.client.host or "unknown")
    ip = ip.split(",")[0].strip()          # take first IP if behind proxy
    return hashlib.sha256(ip.encode()).hexdigest()


@router.get("/demo/status", response_model=DemoStatusResponse)
async def demo_status(request: Request, db: Session = Depends(get_db)):
    """Return how many demo scans this IP has used. No auth required."""
    ip_hash = _ip_hash(request)
    used = get_demo_usage(db, ip_hash)
    return DemoStatusResponse(
        scans_used=used,
        scans_limit=DEMO_LIMIT,
        scans_remaining=max(0, DEMO_LIMIT - used),
        exhausted=used >= DEMO_LIMIT,
    )


@router.post("/demo/scan", response_model=SecureRetrieveResponse)
async def demo_scan(
    payload: SecureRetrieveRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Demo scan — no API key required.
    Hard limit: DEMO_LIMIT scans per IP address, lifetime (never resets).
    """
    ip_hash = _ip_hash(request)
    used = get_demo_usage(db, ip_hash)

    if used >= DEMO_LIMIT:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "demo_limit_exhausted",
                "message": f"Demo limit of {DEMO_LIMIT} scans reached. Subscribe to continue.",
                "scans_used": used,
                "scans_limit": DEMO_LIMIT,
            },
        )

    result = _run_scan(payload, db, "demo")
    new_count = increment_demo_usage(db, ip_hash)

    return SecureRetrieveResponse(
        **result,
        demo_scans_used=new_count,
        demo_scans_remaining=max(0, DEMO_LIMIT - new_count),
    )


# ── Health ────────────────────────────────────────────────────────────────────

@router.get("/health", response_model=HealthResponse)
async def health():
    settings = get_settings()
    return HealthResponse(
        status="ok",
        version=settings.app_version,
        db_connected=check_db_connection(),
        timestamp=datetime.now(timezone.utc),
    )
